use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto = manifest_dir.join("../../contracts/proto/authz/v1/authz.proto");
    let include_dir = manifest_dir.join("../../contracts/proto");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    println!("cargo:rerun-if-changed={}", proto.display());

    let mut prost = tonic_prost_build::Config::new();
    prost.protoc_executable(protoc);

    tonic_prost_build::configure().compile_with_config(prost, &[proto], &[include_dir])?;

    Ok(())
}
