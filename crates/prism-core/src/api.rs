//! Clash-compatible REST API (the subset GUI clients use), so the same GUI
//! can drive prism-core, mihomo and sing-box.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;

use crate::config::{Mode, DEFAULT_TEST_URL};
use crate::hub::Hub;
use crate::outbound::Outbound;
use crate::provider;
use crate::Core;

type St = State<Arc<Hub>>;

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "message": msg.into() }))).into_response()
}

async fn auth(State(hub): St, req: Request, next: Next) -> Response {
    let core = hub.core();
    if core.general.secret.is_empty() || req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);
    let token = req
        .uri()
        .query()
        .and_then(|q| url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "token").map(|(_, v)| v.into_owned()));
    if bearer.or(token).as_deref() == Some(core.general.secret.as_str()) {
        next.run(req).await
    } else {
        err(StatusCode::UNAUTHORIZED, "Unauthorized")
    }
}

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/", get(|| async { Json(json!({ "hello": "prism" })) }))
        .route("/version", get(|| async { Json(json!({ "version": concat!("prism-", env!("CARGO_PKG_VERSION")), "meta": true })) }))
        .route("/configs", get(get_configs).patch(patch_configs).put(reload_configs))
        .route("/proxies", get(get_proxies))
        .route("/proxies/{name}", get(get_proxy).put(select_proxy))
        .route("/proxies/{name}/delay", get(proxy_delay))
        .route("/group", get(get_groups))
        .route("/group/{name}/delay", get(group_delay))
        .route("/connections", get(get_connections).delete(close_all))
        .route("/connections/{id}", axum::routing::delete(close_one))
        .route("/rules", get(get_rules))
        .route("/traffic", get(traffic))
        .route("/memory", get(|| async { Json(json!({ "inuse": 0, "oslimit": 0 })) }))
        .route("/cache/fakeip/flush", axum::routing::post(|| async { StatusCode::NO_CONTENT }))
        .route("/restart", axum::routing::post(|| async { StatusCode::NO_CONTENT }))
        .route("/dns/query", get(dns_query))
        .route("/providers/proxies", get(get_proxy_providers))
        .route("/providers/proxies/{name}", get(get_proxy_provider).put(update_proxy_provider))
        .route("/providers/proxies/{name}/healthcheck", get(healthcheck_provider))
        .route("/providers/rules", get(get_rule_providers))
        .route("/providers/rules/{name}", put(update_rule_provider))
        .route("/upgrade/geo", put(|| async { StatusCode::NOT_IMPLEMENTED }))
        .layer(middleware::from_fn_with_state(hub.clone(), auth))
        .layer(CorsLayer::very_permissive())
        .with_state(hub)
}

/// `PUT /configs`: reload the config file (or `{"path": ...}` /
/// `{"payload": ...}`) without dropping listeners.
async fn reload_configs(State(hub): St, body: Option<Json<Value>>) -> Response {
    let body = body.map(|Json(b)| b).unwrap_or(Value::Null);
    let payload = match (body.get("payload").and_then(|p| p.as_str()), body.get("path").and_then(|p| p.as_str())) {
        (Some(p), _) if !p.is_empty() => Some(p.to_string()),
        (_, Some(path)) if !path.is_empty() => match std::fs::read_to_string(path) {
            Ok(c) => Some(c),
            Err(e) => return err(StatusCode::BAD_REQUEST, format!("read {path}: {e}")),
        },
        _ => None,
    };
    match hub.reload(payload).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

fn proxy_provider_json(core: &Core, p: &provider::ProxyProviderInfo) -> Value {
    let proxies: Vec<Value> = p.proxies.iter().filter_map(|n| core.tunnel.reg.get(n)).map(|o| proxy_json(core, &o)).collect();
    json!({
        "name": p.cfg.name,
        "type": "Proxy",
        "vehicleType": provider::vehicle(&p.cfg.kind),
        "proxies": proxies,
        "testUrl": p.cfg.health_check_url.clone().unwrap_or_else(|| DEFAULT_TEST_URL.into()),
        "updatedAt": p.updated_at.map(|t| t.to_rfc3339()),
    })
}

async fn get_proxy_providers(State(hub): St) -> Json<Value> {
    let core = hub.core();
    let map: serde_json::Map<String, Value> =
        core.proxy_providers.iter().map(|p| (p.cfg.name.clone(), proxy_provider_json(&core, p))).collect();
    Json(json!({ "providers": map }))
}

async fn get_proxy_provider(State(hub): St, Path(name): Path<String>) -> Response {
    let core = hub.core();
    match core.proxy_providers.iter().find(|p| p.cfg.name == name) {
        Some(p) => Json(proxy_provider_json(&core, p)).into_response(),
        None => err(StatusCode::NOT_FOUND, "resource not found"),
    }
}

/// Downloads an http provider now and reloads if it changed.
async fn refresh_provider(hub: &Arc<Hub>, url: Option<String>, path: Option<std::path::PathBuf>, via: Option<String>) -> Response {
    let (Some(url), Some(path)) = (url, path) else { return StatusCode::NO_CONTENT.into_response() };
    let out = via.and_then(|n| hub.core().tunnel.reg.get(&n));
    match provider::fetch_to_file(&url, &path, out.as_ref()).await {
        Ok(true) => match hub.reload(None).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
        },
        Ok(false) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("{e:#}")),
    }
}

async fn update_proxy_provider(State(hub): St, Path(name): Path<String>) -> Response {
    let core = hub.core();
    let Some(p) = core.proxy_providers.iter().find(|p| p.cfg.name == name) else {
        return err(StatusCode::NOT_FOUND, "resource not found");
    };
    let (url, path, via) = (p.cfg.url.clone(), p.path.clone(), p.cfg.proxy.clone());
    refresh_provider(&hub, url, path, via).await
}

async fn healthcheck_provider(State(hub): St, Path(name): Path<String>) -> Response {
    let core = hub.core();
    let Some(p) = core.proxy_providers.iter().find(|p| p.cfg.name == name) else {
        return err(StatusCode::NOT_FOUND, "resource not found");
    };
    let url = p.cfg.health_check_url.clone().unwrap_or_else(|| DEFAULT_TEST_URL.into());
    let reg = core.tunnel.reg.clone();
    let tests = p.proxies.iter().map(|n| crate::delay::url_test(&reg, n, &url, Duration::from_secs(5)));
    futures::future::join_all(tests).await;
    StatusCode::NO_CONTENT.into_response()
}

async fn get_rule_providers(State(hub): St) -> Json<Value> {
    let core = hub.core();
    let map: serde_json::Map<String, Value> = core
        .rule_providers
        .iter()
        .map(|p| {
            (
                p.cfg.name.clone(),
                json!({
                    "name": p.cfg.name,
                    "type": "Rule",
                    "vehicleType": provider::vehicle(&p.cfg.kind),
                    "behavior": p.cfg.behavior,
                    "format": p.cfg.format,
                    "ruleCount": p.count,
                    "updatedAt": p.updated_at.map(|t| t.to_rfc3339()),
                }),
            )
        })
        .collect();
    Json(json!({ "providers": map }))
}

async fn update_rule_provider(State(hub): St, Path(name): Path<String>) -> Response {
    let core = hub.core();
    let Some(p) = core.rule_providers.iter().find(|p| p.cfg.name == name) else {
        return err(StatusCode::NOT_FOUND, "resource not found");
    };
    let (url, path, via) = (p.cfg.url.clone(), p.path.clone(), p.cfg.proxy.clone());
    refresh_provider(&hub, url, path, via).await
}

async fn get_configs(State(hub): St) -> Json<Value> {
    let core = hub.core();
    let g = &core.general;
    Json(json!({
        "port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0,
        "mixed-port": g.mixed_port,
        "allow-lan": g.allow_lan,
        "bind-address": g.bind_address,
        "mode": core.tunnel.mode().as_str(),
        "log-level": g.log_level,
        "ipv6": true,
        "tun": { "enable": g.tun.enable },
    }))
}

async fn patch_configs(State(hub): St, Json(body): Json<Value>) -> Response {
    let core = hub.core();
    if let Some(m) = body.get("mode").and_then(|m| m.as_str()) {
        match Mode::parse(m) {
            Some(mode) => {
                *core.tunnel.mode.write().unwrap() = mode;
                tracing::info!("mode switched to {}", mode.as_str());
                core.tunnel.stats.close_all();
            }
            None => return err(StatusCode::BAD_REQUEST, format!("unknown mode {m}")),
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

fn proxy_json(core: &Core, out: &Arc<dyn Outbound>) -> Value {
    let name = out.name();
    let mut v = json!({
        "name": name,
        "type": out.api_type(),
        "udp": out.udp(),
        "xudp": false,
        "tfo": false,
        "alive": core.tunnel.reg.delays.alive(name),
        "history": core.tunnel.reg.delays.history(name),
        "extra": {},
    });
    if let Some(g) = out.as_group() {
        v["all"] = json!(g.members());
        v["now"] = json!(g.now());
        v["testUrl"] = json!(g.cfg.url);
        v["hidden"] = json!(false);
    }
    v
}

async fn get_proxies(State(hub): St) -> Json<Value> {
    let core = hub.core();
    let reg = &core.tunnel.reg;
    let map: serde_json::Map<String, Value> =
        reg.order.iter().filter_map(|n| reg.get(n)).map(|o| (o.name().to_string(), proxy_json(&core, &o))).collect();
    Json(json!({ "proxies": map }))
}

async fn get_groups(State(hub): St) -> Json<Value> {
    let core = hub.core();
    let reg = &core.tunnel.reg;
    let list: Vec<Value> = reg
        .order
        .iter()
        .filter_map(|n| reg.get(n))
        .filter(|o| o.as_group().is_some())
        .map(|o| proxy_json(&core, &o))
        .collect();
    Json(json!({ "proxies": list }))
}

async fn get_proxy(State(hub): St, Path(name): Path<String>) -> Response {
    let core = hub.core();
    match core.tunnel.reg.get(&name) {
        Some(o) => Json(proxy_json(&core, &o)).into_response(),
        None => err(StatusCode::NOT_FOUND, "resource not found"),
    }
}

async fn select_proxy(State(hub): St, Path(name): Path<String>, Json(body): Json<Value>) -> Response {
    let core = hub.core();
    let Some(o) = core.tunnel.reg.get(&name) else { return err(StatusCode::NOT_FOUND, "resource not found") };
    let Some(g) = o.as_group() else { return err(StatusCode::BAD_REQUEST, "must be a Selector") };
    let Some(target) = body.get("name").and_then(|n| n.as_str()) else {
        return err(StatusCode::BAD_REQUEST, "body must contain name");
    };
    match g.select(target) {
        Ok(()) => {
            tracing::info!("[{name}] selected {target}");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

fn test_params(q: &HashMap<String, String>) -> (String, Duration) {
    let url = q.get("url").cloned().filter(|u| !u.is_empty()).unwrap_or_else(|| DEFAULT_TEST_URL.to_string());
    let ms = q.get("timeout").and_then(|t| t.parse().ok()).unwrap_or(5000u64);
    (url, Duration::from_millis(ms))
}

async fn proxy_delay(State(hub): St, Path(name): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let core = hub.core();
    if core.tunnel.reg.get(&name).is_none() {
        return err(StatusCode::NOT_FOUND, "resource not found");
    }
    let (url, timeout) = test_params(&q);
    match crate::delay::url_test(&core.tunnel.reg, &name, &url, timeout).await {
        Ok(d) => Json(json!({ "delay": d })).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => err(StatusCode::REQUEST_TIMEOUT, "Timeout"),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("An error occurred in the delay test: {e}")),
    }
}

async fn group_delay(State(hub): St, Path(name): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let core = hub.core();
    let Some(o) = core.tunnel.reg.get(&name) else { return err(StatusCode::NOT_FOUND, "resource not found") };
    let Some(g) = o.as_group() else { return err(StatusCode::BAD_REQUEST, "not a group") };
    let (url, timeout) = test_params(&q);
    let reg = core.tunnel.reg.clone();
    let tests = g.members().iter().cloned().map(|m| {
        let (reg, url) = (reg.clone(), url.clone());
        async move {
            let d = crate::delay::url_test(&reg, &m, &url, timeout).await.ok();
            (m, d)
        }
    });
    let results = futures::future::join_all(tests).await;
    let map: serde_json::Map<String, Value> =
        results.into_iter().filter_map(|(m, d)| d.map(|d| (m, json!(d)))).collect();
    Json(Value::Object(map)).into_response()
}

async fn get_connections(State(hub): St) -> Json<Value> {
    let core = hub.core();
    let stats = &core.tunnel.stats;
    let conns: Vec<Value> = stats
        .snapshot()
        .iter()
        .map(|c| {
            let m = &c.meta;
            json!({
                "id": c.id,
                "metadata": {
                    "network": m.network.as_str(),
                    "type": m.inbound,
                    "sourceIP": m.src.ip().to_string(),
                    "sourcePort": m.src.port().to_string(),
                    "destinationIP": m.dst.ip().or(m.dst_ip).map(|i| i.to_string()).unwrap_or_default(),
                    "destinationPort": m.dst.port().to_string(),
                    "host": m.dst.domain().unwrap_or_default(),
                    "dnsMode": "normal",
                    "process": m.process.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
                    "processPath": m.process.as_ref().map(|p| p.path.clone()).unwrap_or_default(),
                },
                "upload": c.upload.load(Ordering::Relaxed),
                "download": c.download.load(Ordering::Relaxed),
                "start": c.start.to_rfc3339(),
                "chains": c.chains,
                "rule": c.rule,
                "rulePayload": c.rule_payload,
            })
        })
        .collect();
    Json(json!({
        "downloadTotal": stats.download.load(Ordering::Relaxed),
        "uploadTotal": stats.upload.load(Ordering::Relaxed),
        "connections": conns,
        "memory": 0,
    }))
}

async fn close_all(State(hub): St) -> StatusCode {
    let core = hub.core();
    core.tunnel.stats.close_all();
    StatusCode::NO_CONTENT
}

async fn close_one(State(hub): St, Path(id): Path<String>) -> StatusCode {
    let core = hub.core();
    core.tunnel.stats.close(&id);
    StatusCode::NO_CONTENT
}

async fn get_rules(State(hub): St) -> Json<Value> {
    let core = hub.core();
    let rules: Vec<Value> = core
        .tunnel
        .router
        .rules
        .iter()
        .map(|r| {
            let ty = r.display();
            let ty = ty.split('(').next().unwrap_or_default().to_string();
            json!({ "type": ty, "payload": r.payload, "proxy": r.target, "size": -1 })
        })
        .collect();
    Json(json!({ "rules": rules }))
}

/// mihomo's `/dns/query?name=&type=A|AAAA`: real addresses (never fake-ip)
/// from the DNS module, else the system resolver.
async fn dns_query(State(hub): St, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(name) = q.get("name").map(|n| n.trim_end_matches('.').to_string()).filter(|n| !n.is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "name is required");
    };
    let v6 = q.get("type").is_some_and(|t| t.eq_ignore_ascii_case("AAAA"));
    let ips = match hub.core().dns.clone() {
        Some(r) => r.lookup(&name).await,
        None => crate::net::resolve(&name, 0).await.map(|a| a.into_iter().map(|s| s.ip()).collect()),
    };
    let qtype = if v6 { 28 } else { 1 };
    let answer: Vec<Value> = ips
        .unwrap_or_default()
        .into_iter()
        .filter(|ip| ip.is_ipv6() == v6)
        .map(|ip| json!({ "name": format!("{name}."), "type": qtype, "TTL": 60, "data": ip.to_string() }))
        .collect();
    let status = if answer.is_empty() { 3 } else { 0 };
    Json(json!({ "Status": status, "Question": [{ "name": format!("{name}."), "qtype": qtype, "qclass": 1 }], "Answer": answer })).into_response()
}

/// Streams `{"up":..,"down":..}` (bytes/s) once per second, like mihomo.
async fn traffic(State(hub): St) -> Response {
    let core = hub.core();
    let stats = core.tunnel.stats.clone();
    let start = (stats.upload.load(Ordering::Relaxed), stats.download.load(Ordering::Relaxed));
    let stream = futures::stream::unfold((stats, start), |(stats, (lu, ld))| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (u, d) = (stats.upload.load(Ordering::Relaxed), stats.download.load(Ordering::Relaxed));
        let line = format!("{}\n", json!({ "up": u - lu, "down": d - ld }));
        Some((Ok::<_, std::io::Error>(line), (stats, (u, d))))
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .unwrap()
}
