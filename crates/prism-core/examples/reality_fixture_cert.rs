//! Host-only camouflage TLS certificate for owned Android protocol fixtures.
//! No app trust store changes. Never built into the Android JNI or APK.
use std::{io::Write, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("provide a new fixture directory")?,
    );
    std::fs::create_dir_all(&dir)?;
    let cert = rcgen::generate_simple_self_signed(vec!["reality.fixture.test".into()])?;
    // Refuse to overwrite any existing fixture or key.
    for (name, pem) in [
        ("camouflage-cert.pem", cert.cert.pem()),
        ("camouflage-key.pem", cert.key_pair.serialize_pem()),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))?;
        file.write_all(pem.as_bytes())?;
    }
    println!("Created host-only Reality camouflage certificate fixture");
    Ok(())
}
