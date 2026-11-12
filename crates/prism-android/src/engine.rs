use crate::profile::{self, Session};
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jstring},
    JNIEnv,
};
use prism_core::{
    hub::{Hub, Source},
    net,
};
use serde_json::{json, Value};
use std::{
    io,
    os::fd::FromRawFd,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, sync::mpsc as channel};
use tokio_util::sync::CancellationToken;

struct Running {
    cancel: CancellationToken,
    join: std::thread::JoinHandle<()>,
    hub: Arc<Hub>,
    handle: Handle,
    alive: Arc<AtomicBool>,
    changes: channel::UnboundedSender<()>,
    started: Instant,
    session_id: u64,
    node_name: String,
    node_id: String,
    direct_rules: usize,
}
static ENGINE: Mutex<Option<Running>> = Mutex::new(None);
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
fn traffic_snapshot(hub: &Hub, node_id: &str, session_id: u64) -> Value {
    let stats = hub.core().tunnel.stats.clone();
    let buckets: Vec<_> = stats
        .traffic
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .map(|((node, policy), counts)| (node.clone(), policy.clone(), counts.clone()))
        .collect();
    let buckets: Vec<_> = buckets.into_iter().map(|(node, policy, counts)| json!({
        "node":if node == "手机节点" {node_id.to_owned()} else {node}, "policy":policy,
        "upload":counts.upload.load(Ordering::Relaxed), "download":counts.download.load(Ordering::Relaxed)
    })).collect();
    json!({"sessionId":session_id.to_string(),"buckets":buckets})
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_traffic(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    ffi(&mut env, |_| {
        let slot = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = slot.as_ref() else {
            return json!({"error":"内核未运行"});
        };
        traffic_snapshot(&r.hub, &r.node_id, r.session_id)
    })
}
fn text(env: &mut JNIEnv, value: Value) -> jstring {
    env.new_string(value.to_string())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
fn ffi(env: &mut JNIEnv, run: impl FnOnce(&mut JNIEnv) -> Value) -> jstring {
    let v = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(env)))
        .unwrap_or_else(|_| json!({"error":"内核操作失败"}));
    text(env, v)
}
fn input(env: &mut JNIEnv, s: &JString) -> Result<String, ()> {
    env.get_string(s).map(Into::into).map_err(|_| ())
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_connections(
    mut env: JNIEnv,
    _: JClass,
    raw: JString,
) -> jstring {
    ffi(&mut env, |env| {
        let Ok(query) =
            input(env, &raw).and_then(|s| crate::connections::Query::parse(&s).map_err(|_| ()))
        else {
            return json!({"error":"连接查询参数无效"});
        };
        let snapshot = {
            let slot = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
            slot.as_ref()
                .filter(|r| r.alive.load(Ordering::Acquire))
                .map(|r| (r.hub.core().tunnel.stats.clone(), r.session_id.to_string()))
        };
        match snapshot {
            Some((stats, session)) => {
                serde_json::to_value(query.snapshot(&stats, session)).unwrap()
            }
            None => json!({"error":"内核未运行"}),
        }
    })
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_closeConnection(
    mut env: JNIEnv,
    _: JClass,
    raw: JString,
) -> jstring {
    ffi(&mut env, |env| {
        let Ok(request) = input(env, &raw).and_then(|s| {
            if s.len() > 512 {
                return Err(());
            }
            serde_json::from_str::<crate::connections::Close>(&s).map_err(|_| ())
        }) else {
            return json!({"error":"关闭请求无效"});
        };
        let slot = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = slot.as_ref().filter(|r| {
            r.alive.load(Ordering::Acquire) && r.session_id.to_string() == request.session_id
        }) else {
            return json!({"error":"连接会话已变化，请刷新"});
        };
        json!({"closed":r.hub.core().tunnel.stats.close(&request.id)})
    })
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_importProfile(
    mut env: JNIEnv,
    _: JClass,
    raw: JString,
) -> jstring {
    ffi(&mut env, |env| {
        let Ok(raw) = input(env, &raw) else {
            return json!({"error":"无法读取导入内容"});
        };
        match profile::import(&raw) {
            Ok(p) => serde_json::to_value(p).unwrap(),
            Err(e) => json!({"error":e.to_string()}), // Import errors contain no parser excerpts.
        }
    })
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_start(
    mut env: JNIEnv,
    _: JClass,
    fd: jint,
    raw: JString,
    home: JString,
    service: JObject,
) -> jstring {
    ffi(&mut env, |env| {
        let Ok(raw) = input(env, &raw) else {
            return json!({"error":"无法读取配置"});
        };
        let Ok(home) = input(env, &home) else {
            return json!({"error":"无法读取应用目录"});
        };
        let Ok(session) = serde_json::from_str::<Session>(&raw) else {
            return json!({"error":"节点配置无效"});
        };
        let node_name = session.node.name.clone();
        let node_id = serde_json::from_str::<Value>(&raw)
            .ok()
            .and_then(|v| v["node"]["_id"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "legacy".into());
        let direct_rules = session.direct.len();
        let Ok((profile, reload)) = profile::build(session) else {
            return json!({"error":"节点或直连规则不受支持"});
        };
        let mut slot = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_some() {
            return json!({"error":"已有连接，请先断开"});
        }
        let Ok(vm) = env.get_java_vm() else {
            return json!({"error":"无法接入 Android 运行环境"});
        };
        let Ok(service) = env.new_global_ref(service) else {
            return json!({"error":"无法接入 VPN 服务"});
        };
        let vm = Arc::new(vm);
        let vm_protect = vm.clone();
        let service_protect = service.clone();
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return json!({"error":"无效的 VPN 句柄"});
        }
        let descriptor = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) };
        net::set_android_protector(Some(Arc::new(move |socket| {
            let mut env = vm_protect
                .attach_current_thread()
                .map_err(|_| io::Error::other("VPN thread unavailable"))?;
            match env
                .call_method(
                    service_protect.as_obj(),
                    "protectSocket",
                    "(I)Z",
                    &[JValue::Int(socket)],
                )
                .and_then(|v| v.z())
            {
                Ok(true) => Ok(()),
                _ => {
                    let _ = env.exception_clear();
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "VPN protect() refused",
                    ))
                }
            }
        })));
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let alive = Arc::new(AtomicBool::new(false));
        let living = alive.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (changes, mut changes_rx) = channel::unbounded_channel();
        let join = std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> anyhow::Result<()> {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?;
                    let result = runtime.block_on(async {
                    let home = PathBuf::from(home); std::fs::create_dir_all(&home)?;
                    let hub = tokio::time::timeout(Duration::from_secs(8), Hub::new(Source::default(), home, profile)).await??;
                    let tun = prism_core::tun::attach_android(descriptor, hub.clone(), stop.clone())?;
                    living.store(true, Ordering::Release);
                    let _ = ready_tx.send((hub.clone(), Handle::current(), Instant::now()));
                    tokio::pin!(tun);
                    let mut last_change = Instant::now() - Duration::from_secs(5);
                    loop {
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            result = &mut tun => {result?; break;},
                            event = changes_rx.recv() => {
                                if event.is_none() {break}
                                if last_change.elapsed() < Duration::from_secs(3) {continue}
                                last_change = Instant::now();
                                // Rebuild sockets and DNS; preserve the VPN fd and fake-IP mappings.
                                let rebuilt = tokio::select! {
                                    _ = stop.cancelled() => break,
                                    r = tokio::time::timeout(Duration::from_secs(8),hub.reload(Some(reload.clone()))) => r,
                                };
                                if matches!(rebuilt,Ok(Ok(()))) {hub.core().tunnel.stats.close_all();}
                            }
                        }
                    }
                    hub.core().shutdown.cancel();
                    Ok::<(),anyhow::Error>(())
                });
                    runtime.shutdown_timeout(Duration::from_secs(1));
                    result
                },
            ));
            living.store(false, Ordering::Release);
            net::set_resolver(None);
            net::set_android_protector(None);
            if let Ok(mut env) = vm.attach_current_thread() {
                let _ = env.call_method(service.as_obj(), "onCoreStopped", "()V", &[]);
                let _ = env.exception_clear();
            }
        });
        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok((hub, handle, started)) => {
                *slot = Some(Running {
                    cancel,
                    join,
                    hub,
                    handle,
                    alive,
                    changes,
                    started,
                    session_id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
                    node_name,
                    node_id,
                    direct_rules,
                });
                json!({"ok":true})
            }
            Err(_) => {
                cancel.cancel();
                let _ = join.join();
                json!({"error":"内核启动失败，请检查节点参数"})
            }
        }
    })
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_validateSession(
    mut env: JNIEnv,
    _: JClass,
    raw: JString,
) -> jstring {
    ffi(&mut env, |env| {
        let Ok(raw) = input(env, &raw) else {
            return json!({"error":"配置无效"});
        };
        match serde_json::from_str::<Session>(&raw)
            .ok()
            .and_then(|s| profile::build(s).ok())
        {
            Some(_) => json!({"ok":true}),
            None => json!({"error":"节点或直连规则不受支持"}),
        }
    })
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_stop(_: JNIEnv, _: JClass) {
    let _ = std::panic::catch_unwind(|| {
        if let Some(running) = ENGINE.lock().unwrap_or_else(|p| p.into_inner()).take() {
            running.cancel.cancel();
            let _ = running.join.join();
        }
    });
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_stopAndTraffic(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    ffi(&mut env, |_| {
        let mut slot = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = slot.take() else {
            return json!({"error":"内核未运行"});
        };
        r.cancel.cancel();
        let _ = r.join.join();
        // All relay tasks have stopped. Capture the final counters before dropping the hub.
        traffic_snapshot(&r.hub, &r.node_id, r.session_id)
    })
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_networkChanged(_: JNIEnv, _: JClass) {
    let _ = std::panic::catch_unwind(|| {
        if let Some(r) = ENGINE.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            let _ = r.changes.send(());
        }
    });
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_status(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    ffi(&mut env, |_| {
        let slot = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
        match slot.as_ref() {
            Some(r) => {
                let s = r.hub.core().tunnel.stats.clone();
                let (received, sent) = prism_core::tun::android_packet_counts();
                let connections = s.conns.lock().unwrap_or_else(|p| p.into_inner()).len();
                json!({"running":r.alive.load(Ordering::Acquire),"upload":s.upload.load(Ordering::Relaxed),"download":s.download.load(Ordering::Relaxed),"tunReceived":received,"tunSent":sent,
                    "sessionId":r.session_id.to_string(),"uptimeMs":r.started.elapsed().as_millis() as u64,
                    "connections":connections,"nodeName":r.node_name,"directRules":r.direct_rules})
            }
            None => json!({"running":false,"upload":0,"download":0}),
        }
    })
}
#[no_mangle]
pub extern "system" fn Java_dev_prism_android_CoreBridge_probe(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    ffi(&mut env, |_| {
        let Some((hub, handle)) = ENGINE
            .lock()
            .unwrap()
            .as_ref()
            .map(|r| (r.hub.clone(), r.handle.clone()))
        else {
            return json!({"error":"请先连接"});
        };
        let (tx, rx) = mpsc::channel();
        handle.spawn(async move {
            use prism_core::{common::Address,tunnel::{Metadata,Network}};
            use tokio::io::{AsyncReadExt,AsyncWriteExt};
            let start=Instant::now();
            let result=tokio::time::timeout(Duration::from_secs(5),async {
                let t=hub.core().tunnel.clone();
                let mut m=Metadata::new(Network::Tcp,"AndroidProbe","127.0.0.1:0".parse().unwrap(),Address::new("www.gstatic.com",80),None);
                let mut dial=t.dial(&mut m).await?;
                dial.stream.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n").await?;
                let mut bytes=[0;128]; let n=dial.stream.read(&mut bytes).await?;
                let line=String::from_utf8_lossy(&bytes[..n]);
                if !line.starts_with("HTTP/1.1 204") && !line.starts_with("HTTP/1.1 200") {return Err(io::Error::other("probe response"))}
                Ok::<(),io::Error>(())
            }).await;
            let _=tx.send(if matches!(result,Ok(Ok(()))) {json!({"ms":start.elapsed().as_millis()})} else {json!({"error":"当前节点探测失败"})});
        });
        rx.recv_timeout(Duration::from_secs(6))
            .unwrap_or(json!({"error":"探测已取消"}))
    })
}
