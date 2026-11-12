//! Mobile-only policy and JNI boundary. No desktop services or API listener.
#[cfg(target_os = "android")]
mod engine;
pub mod profile;
