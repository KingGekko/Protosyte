# Model Embedding Guide - User Model Integration

## How Model Embedding is Addressed

The `embedded_model()` function in `ai_filtering.rs` now supports **three ways** for users to provide their model:

### ✅ Option 1: Compile-Time Embedding (BEFORE Runtime)

**How it works:**
1. Place your trained ONNX model at: `protosyte-seed/models/ner_model.onnx`
2. Build with embedding enabled:
   ```bash
   PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
   ```
3. The build script (`build.rs`) detects the model and enables the `embed_model` cfg flag
4. At compile time, `include_bytes!("../models/ner_model.onnx")` embeds the model into the binary
5. **Result**: Model is compiled into the binary - no runtime file needed!

**Code path:**
- `build.rs` checks for model and sets `cargo:rustc-cfg=embed_model`
- `ai_filtering.rs` uses `#[cfg(embed_model)]` to conditionally compile `include_bytes!`
- Model becomes part of the compiled binary

### ✅ Option 2: Runtime File Loading

If you don't embed, provide model path at runtime:

```rust
let filter = AIDataFilter::new(Some("path/to/model.onnx"))?;
```

**Code path:**
- `AIDataFilter::new(Some(path))` reads model from file
- No embedding needed
- Model can be updated without recompiling

### ✅ Option 3: Automatic Runtime Detection

The `embedded_model()` function also checks common locations at runtime:

```rust
// Tries these paths automatically:
- models/ner_model.onnx
- ../models/ner_model.onnx
- ./ner_model.onnx
```

If model exists in any of these locations, it's loaded automatically without needing to specify the path.

## Implementation Details

### Build-Time Detection (`build.rs`)

```rust
fn check_and_embed_model() {
    // Checks for model at:
    // - models/ner_model.onnx
    // - ../models/ner_model.onnx
    // - protosyte-seed/models/ner_model.onnx
    
    if model_found && PROTOSYTE_EMBED_MODEL=1 {
        println!("cargo:rustc-cfg=embed_model");
        // This enables #[cfg(embed_model)] in Rust code
    }
}
```

### Compile-Time Embedding (`ai_filtering.rs`)

```rust
fn embedded_model() -> Vec<u8> {
    // Option 1: Compile-time embedding (if embed_model cfg is set)
    #[cfg(embed_model)]
    {
        return include_bytes!("../models/ner_model.onnx").to_vec();
        // This runs ONLY if model was detected during build
        // AND PROTOSYTE_EMBED_MODEL=1 was set
    }
    
    // Option 2: Runtime detection (fallback)
    // Checks common paths...
}
```

## Step-by-Step: Embedding Your Model

### Step 1: Train Your Model

See `docs/AI_FILTERING.md` for training instructions. You'll get an ONNX file.

### Step 2: Place Model

```bash
# Place your trained model here:
cp your_model.onnx protosyte-seed/models/ner_model.onnx
```

### Step 3: Build with Embedding

```bash
cd protosyte-seed

# Enable embedding and build
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
```

**What happens:**
1. `build.rs` detects model at `models/ner_model.onnx`
2. Sets `cargo:rustc-cfg=embed_model` flag
3. Rust compiler includes model bytes in binary using `include_bytes!`
4. Model is permanently embedded in the executable

### Step 4: Verify Embedding

```bash
# Check binary size (should be ~15-65MB larger)
ls -lh target/release/protosyte-seed

# Binary is self-contained - no model file needed!
./target/release/protosyte-seed
```

## Verification

### Check if Model is Embedded

```bash
# Build output will show:
# cargo:warning=Found ONNX model at: models/ner_model.onnx
# cargo:warning=Model will be embedded in binary

# Binary size check:
ls -lh target/release/protosyte-seed
# Should be significantly larger if model embedded
```

### Runtime Verification

```rust
// Model is automatically loaded (no path needed)
let filter = AIDataFilter::new(None)?;
// This works because model is embedded in binary
```

## Comparison

| Method | When Model Loaded | Update Model | Binary Size |
|--------|------------------|--------------|-------------|
| **Embedded** | Compile-time | Requires rebuild | +15-65MB |
| **Runtime Path** | Runtime | Just swap file | Normal |
| **Auto-Detect** | Runtime | Just swap file | Normal |

## Troubleshooting

### "Model not embedded"

**Check:**
```bash
# 1. Model exists?
ls -lh protosyte-seed/models/ner_model.onnx

# 2. Built with flag?
PROTOSYTE_EMBED_MODEL=1 cargo build --features ai-filtering

# 3. Check build output for:
# cargo:warning=Model will be embedded in binary
```

### "No model provided" Error

**Solutions:**
1. Embed: `PROTOSYTE_EMBED_MODEL=1 cargo build --features ai-filtering`
2. Provide path: `AIDataFilter::new(Some("path/to/model.onnx"))`
3. Place model at: `protosyte-seed/models/ner_model.onnx` (auto-detected)

## Summary

**YES - Users can insert their model before runtime!**

✅ **Before Runtime (Compile-Time)**: 
- Place model at `protosyte-seed/models/ner_model.onnx`
- Build with `PROTOSYTE_EMBED_MODEL=1`
- Model is embedded in binary using `include_bytes!`

✅ **At Runtime**:
- Provide file path: `AIDataFilter::new(Some("path"))`
- Or place model in auto-detected location

The empty `embedded_model()` issue is **fully addressed** with automatic compile-time embedding when the model is present and the flag is set!

