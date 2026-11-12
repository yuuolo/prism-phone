//! Mobile-only policy and JNI boundary. No desktop services or API listener.
pub mod adblock;
pub mod automatic;
pub mod connections;
pub mod diagnostics;
#[cfg(target_os = "android")]
mod engine;
pub mod geodata;
pub mod local_proxy;
pub mod profile;
pub mod routing;
