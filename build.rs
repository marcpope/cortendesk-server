// Modified by the CortenDesk Server project on 2026-11-04: writes
// src/version.rs itself instead of through hbb_common. See CHANGES.md.
// This file is part of a modified version of rustdesk-server, distributed under
// the AGPL-3.0 like the original.

use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=Cargo.toml");
    let version = env::var("CARGO_PKG_VERSION")?;
    let contents = format!("pub const VERSION: &str = \"{version}\";\n");
    if fs::read_to_string("src/version.rs").ok().as_deref() != Some(contents.as_str()) {
        fs::write("src/version.rs", contents)?;
    }
    Ok(())
}
