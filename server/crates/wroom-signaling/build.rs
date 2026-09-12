fn main() {
    println!("cargo:rerun-if-changed=../../../proto");
    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path().expect("vendored protoc"))
        .compile_protos(
            &["../../../proto/signaling/v1/signaling.proto"],
            &["../../../proto"],
        )
        .expect("compile protos");
}
