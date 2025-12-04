# Quick Start: Embedding Your ONNX Model

## Yes, You Can Embed Your Model Before Runtime!

The `embedded_model()` function now supports **compile-time embedding**. Here's how:

## Quick Steps

### 1. Place Your Model

```bash
# Place your trained ONNX model here:
protosyte-seed/models/ner_model.onnx
```

### 2. Build with Embedding

```bash
cd protosyte-seed

# This embeds the model into the binary at compile time
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
```

### 3. Done!

The model is now **embedded in the binary** - no separate file needed at runtime!

## How It Works

1. **build.rs detects model** at `protosyte-seed/models/ner_model.onnx`
2. **Sets cfg flag**: `cargo:rustc-cfg=embed_model`
3. **Rust code compiles** with `#[cfg(embed_model)]` enabled
4. **include_bytes!** embeds model bytes into binary
5. **Runtime**: Model automatically loaded from embedded bytes

## Verify Embedding

```bash
# Binary should be larger (model size added)
ls -lh target/release/protosyte-seed

# Use without model file (it's embedded!)
./target/release/protosyte-seed
```

## Alternative: Runtime Loading

If you prefer not to embed:

```rust
// Provide model path at runtime
let filter = AIDataFilter::new(Some("path/to/model.onnx"))?;
```

## Documentation

- **Complete guide**: `docs/MODEL_INTEGRATION.md`
- **Training guide**: `docs/AI_FILTERING.md`
- **Model directory**: `protosyte-seed/models/README.md`

