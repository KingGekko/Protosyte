fn main() {
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&["../proto/protosyte.proto"], &["../proto/"])
        .unwrap();
}

