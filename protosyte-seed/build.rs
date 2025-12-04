// Build script for eBPF programs
// Compiles C eBPF code to bytecode using clang and LLVM

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only build eBPF if feature is enabled
    if env::var("CARGO_FEATURE_EBPF").is_ok() {
        build_ebpf();
    }
    
    // Existing prost build
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&["../proto/protosyte.proto"], &["../proto/"])
        .unwrap();
}

fn build_ebpf() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ebpf_dir = PathBuf::from("bpf");
    let bpf_object = out_dir.join("protosyte_hook.bpf.o");
    
    // Check if clang is available
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("Warning: clang not found. eBPF programs will not be compiled.");
        eprintln!("Install clang to enable eBPF support: sudo apt-get install clang llvm");
        return;
    }
    
    // Compile eBPF program
    let status = Command::new("clang")
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(ebpf_dir.join("protosyte_hook.bpf.c"))
        .arg("-o")
        .arg(&bpf_object)
        .arg("-I")
        .arg("/usr/include/bpf")
        .arg("-I")
        .arg("/usr/include")
        .status();
    
    if let Err(e) = status {
        eprintln!("Warning: Failed to compile eBPF program: {}", e);
        eprintln!("eBPF support will be unavailable.");
        return;
    }
    
    if !status.unwrap().success() {
        eprintln!("Warning: eBPF compilation failed. eBPF support will be unavailable.");
        return;
    }
    
    // Copy to target directory for inclusion
    let target_dir = PathBuf::from("target/bpf");
    std::fs::create_dir_all(&target_dir).ok();
    std::fs::copy(&bpf_object, target_dir.join("protosyte_hook.bpf.o")).ok();
    
    println!("cargo:rerun-if-changed=bpf/protosyte_hook.bpf.c");
}
