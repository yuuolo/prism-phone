//! Mobile-only policy and JNI boundary. No desktop services or API listener.
pub mod adblock;
pub mod automatic;
pub mod chain;
pub mod connections;
pub mod diagnostics;
pub mod document;
pub mod dns;
#[cfg(target_os = "android")]
mod engine;
pub mod geodata;
pub mod local_proxy;
pub mod profile;
#[cfg(any(target_os = "android", test))]
mod recovery;
pub mod routing;
pub mod script;
mod yaml_document;
