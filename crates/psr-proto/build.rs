// SPDX-License-Identifier: AGPL-3.0-only
//! Compiles takion.proto with protox (a pure-Rust protobuf compiler), so building needs no `protoc`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/takion.proto");
    let descriptors = protox::compile(["takion.proto"], ["proto"])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
