//! Clash-compatible synchronous configuration overwrite. A fresh QuickJS realm
//! has no host I/O bindings, loader, async jobs, or shared-memory blocking API.
use rquickjs::{Context, Function, Runtime, Value};
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const MAX_CONFIG: usize = 4 * 1024 * 1024;
pub const MAX_SCRIPT: usize = 128 * 1024;
pub const HEAP_LIMIT: usize = 64 * 1024 * 1024;
const STACK_LIMIT: usize = 256 * 1024;
const TIME_BUDGET: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Input,
    Limit,
    Execution,
    Timeout,
    Result,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Input => "覆写输入须为 JSON 配置对象",
            Self::Limit => "配置、脚本或名称超过大小限制",
            Self::Execution => "覆写脚本执行失败或超过内存/栈限制",
            Self::Timeout => "覆写脚本超过执行预算",
            Self::Result => "覆写脚本须同步返回大小受限的配置对象",
        })
    }
}
impl std::error::Error for Failure {}

/// Returns a new document. Never changes the input, persists settings, or
/// replaces a live configuration; callers must validate before activation.
pub fn apply(input: &str, source: &str, profile_name: &str) -> Result<String, Failure> {
    if input.len() > MAX_CONFIG || source.len() > MAX_SCRIPT || profile_name.len() > 256 {
        return Err(Failure::Limit);
    }
    if !serde_json::from_str::<serde_json::Value>(input)
        .map_err(|_| Failure::Input)?
        .is_object()
    {
        return Err(Failure::Input);
    }
    if source.trim().is_empty() {
        return Ok(input.to_owned());
    }
    let rt = Runtime::new().map_err(|_| Failure::Execution)?;
    // Do not enable rquickjs's rust-alloc/custom allocator features: those
    // bypass QuickJS's heap accounting and would invalidate this limit.
    rt.set_memory_limit(HEAP_LIMIT);
    rt.set_max_stack_size(STACK_LIMIT);
    let deadline = Instant::now() + TIME_BUDGET;
    let expired = Arc::new(AtomicBool::new(false));
    let interrupted = expired.clone();
    rt.set_interrupt_handler(Some(Box::new(move || {
        let stop = Instant::now() >= deadline;
        if stop {
            interrupted.store(true, Ordering::Relaxed);
        }
        stop
    })));
    let context = Context::full(&rt).map_err(|_| Failure::Execution)?;
    let result = context.with(|ctx| -> Result<String, Failure> {
        ctx.eval::<(), _>("delete globalThis.Atomics; delete globalThis.SharedArrayBuffer;")
            .map_err(|_| Failure::Execution)?;
        ctx.eval::<(), _>(source).map_err(|_| Failure::Execution)?;
        let main: Function = ctx.globals().get("main").map_err(|_| Failure::Execution)?;
        let config = ctx.json_parse(input).map_err(|_| Failure::Execution)?;
        let value: Value = main
            .call((config, profile_name))
            .map_err(|_| Failure::Execution)?;
        if !value.is_object() || value.is_array() || value.is_promise() || value.is_function() {
            return Err(Failure::Result);
        }
        let json = ctx
            .json_stringify(value)
            .map_err(|_| Failure::Execution)?
            .ok_or(Failure::Result)?;
        let bytes = json.to_cstring().map_err(|_| Failure::Execution)?;
        if bytes.len() > MAX_CONFIG {
            return Err(Failure::Result);
        }
        let output = bytes.as_str();
        if !serde_json::from_str::<serde_json::Value>(output)
            .map_err(|_| Failure::Result)?
            .is_object()
        {
            return Err(Failure::Result);
        }
        Ok(output.to_owned())
    });
    if expired.load(Ordering::Relaxed) {
        Err(Failure::Timeout)
    } else {
        result
    }
}
