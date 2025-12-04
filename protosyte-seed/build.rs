// Build script for eBPF programs
// Compiles C eBPF code to bytecode using clang and LLVM

use std::env;
use std::path::{PathBuf, Path};
use std::process::Command;

fn main() {
    // Only build eBPF if feature is enabled
    if env::var("CARGO_FEATURE_EBPF").is_ok() {
        build_ebpf();
    }
    
    // Check for ONNX model to embed (if AI filtering is enabled)
    if env::var("CARGO_FEATURE_AI_FILTERING").is_ok() {
        check_and_embed_model();
    }
    
    // Existing prost build
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&["../proto/protosyte.proto"], &["../proto/"])
        .unwrap();
}

fn check_and_embed_model() {
    use std::path::Path;
    
    // Check for model in multiple locations
    let model_paths = vec![
        "models/ner_model.onnx",
        "../models/ner_model.onnx",
        "protosyte-seed/models/ner_model.onnx",
    ];
    
    let model_found = model_paths.iter()
        .find(|path| Path::new(path).exists());
    
    if let Some(model_path) = model_found {
        // Check if user wants to embed (via environment variable)
        let should_embed = env::var("PROTOSYTE_EMBED_MODEL")
            .unwrap_or_else(|_| "auto".to_string());
        
        if should_embed == "1" || should_embed == "true" {
            // User explicitly wants to embed - enable compile-time embedding
            println!("cargo:rustc-cfg=embed_model");
            println!("cargo:warning=ONNX model found at: {}", model_path);
            println!("cargo:warning=Model will be embedded in binary at compile time");
            println!("cargo:rerun-if-changed={}", model_path);
        } else {
            // Model found but embedding not requested - just inform user
            println!("cargo:warning=Found ONNX model at: {}", model_path);
            println!("cargo:warning=To embed it in binary, set PROTOSYTE_EMBED_MODEL=1");
            println!("cargo:warning=Or use: PROTOSYTE_EMBED_MODEL=1 cargo build --features ai-filtering");
            println!("cargo:warning=Model can still be loaded at runtime from this location");
        }
    } else {
        // No model found - this is OK, user can provide at runtime
        println!("cargo:warning=No ONNX model found. AI filtering will require runtime model path.");
        println!("cargo:warning=Place model at: models/ner_model.onnx");
        println!("cargo:warning=Or provide model path: AIDataFilter::new(Some(\"path/to/model.onnx\"))");
    }
}

fn build_ebpf() {
    // Only compile if eBPF feature is enabled
    if env::var("CARGO_FEATURE_EBPF").is_err() {
        return;
    }
    
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ebpf_dir = PathBuf::from("bpf");
    let ebpf_source = ebpf_dir.join("protosyte_hook.bpf.c");
    
    // Check if source file exists
    if !ebpf_source.exists() {
        eprintln!("Warning: eBPF source file not found: {:?}", ebpf_source);
        eprintln!("eBPF feature enabled but source file missing.");
        return;
    }
    
    let bpf_object = out_dir.join("protosyte_hook.bpf.o");
    
    // Check if clang is available
    let clang_check = Command::new("clang")
        .arg("--version")
        .output();
    
    if clang_check.is_err() {
        eprintln!("Warning: clang not found. eBPF programs will not be compiled.");
        eprintln!("Install clang to enable eBPF support:");
        eprintln!("  Ubuntu/Debian: sudo apt-get install clang llvm libbpf-dev");
        eprintln!("  Fedora/RHEL: sudo dnf install clang llvm libbpf-devel");
        eprintln!("  Arch: sudo pacman -S clang llvm libbpf");
        return;
    }
    
    // Find libbpf headers - try common locations
    let libbpf_include = find_libbpf_include();
    
    // Compile eBPF program
    let mut clang_cmd = Command::new("clang");
    clang_cmd
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(&ebpf_source)
        .arg("-o")
        .arg(&bpf_object);
    
    // Add include paths
    if let Some(libbpf_path) = &libbpf_include {
        clang_cmd.arg("-I").arg(libbpf_path);
    }
    
    // Try common header locations
    for include_path in &["/usr/include", "/usr/include/bpf", "/usr/local/include"] {
        if PathBuf::from(include_path).exists() {
            clang_cmd.arg("-I").arg(include_path);
        }
    }
    
    let status = clang_cmd.status();
    
    if let Err(e) = status {
        eprintln!("Warning: Failed to compile eBPF program: {}", e);
        eprintln!("eBPF support will be unavailable.");
        return;
    }
    
    if !status.unwrap().success() {
        eprintln!("Warning: eBPF compilation failed. Check error messages above.");
        eprintln!("eBPF support will be unavailable.");
        return;
    }
    
    // Verify output file was created
    if !bpf_object.exists() {
        eprintln!("Warning: eBPF object file was not created.");
        return;
    }
    
    // Copy to target directory for inclusion
    let target_dir = PathBuf::from("target/bpf");
    std::fs::create_dir_all(&target_dir).ok();
    let target_file = target_dir.join("protosyte_hook.bpf.o");
    
    if let Err(e) = std::fs::copy(&bpf_object, &target_file) {
        eprintln!("Warning: Failed to copy eBPF object to target: {}", e);
        // Still continue - can load from OUT_DIR
    }
    
    println!("cargo:rerun-if-changed=bpf/protosyte_hook.bpf.c");
    println!("cargo:warning=eBPF program compiled successfully");
}

fn find_libbpf_include() -> Option<String> {
    // Try common libbpf locations
    let possible_paths = vec![
        "/usr/include/bpf",
        "/usr/local/include/bpf",
        "/usr/include",
    ];
    
    for path in possible_paths {
        let bpf_helpers = PathBuf::from(path).join("bpf").join("bpf_helpers.h");
        if bpf_helpers.exists() {
            return Some(path.to_string());
        }
    }
    
    None
}
