# ONNX Model Integration Guide

Complete guide for integrating trained ONNX models into Protosyte for AI-driven filtering.

## Overview

The AI filtering feature requires a trained ONNX model. You have **three options** for providing the model:

1. **Embed at Build Time** (Recommended for deployment)
2. **Runtime File Loading** (Flexible, update without recompiling)
3. **Automatic Detection** (If model exists in expected location)

## Option 1: Embed Model at Build Time

### Step 1: Train and Export Model

Follow the training guide in `docs/AI_FILTERING.md` to:
1. Train a BERT/RoBERTa NER model
2. Export to ONNX format
3. Quantize to int8 (optional, reduces size)

### Step 2: Place Model

```bash
# Place your trained model here:
protosyte-seed/models/ner_model.onnx
```

### Step 3: Build with Embedding

```bash
# Set environment variable to enable embedding
export PROTOSYTE_EMBED_MODEL=1

# Build with AI filtering feature
cargo build --release --features ai-filtering
```

The build system will:
- Detect the model at `protosyte-seed/models/ner_model.onnx`
- Embed it into the binary using `include_bytes!`
- Create a single self-contained binary

### Step 4: Verify Embedding

```bash
# Check binary size (should be ~15-65MB larger than without model)
ls -lh target/release/protosyte-seed

# Run - model is automatically loaded
./target/release/protosyte-seed
```

## Option 2: Runtime File Loading

### Step 1: Train and Export Model

Same as Option 1, but you can place the model anywhere.

### Step 2: Build Without Embedding

```bash
# Build normally (model not embedded)
cargo build --release --features ai-filtering
```

### Step 3: Provide Model at Runtime

```rust
use protosyte_seed::ai_filtering::AIDataFilter;

// Load model from file path
let filter = AIDataFilter::new(Some("/path/to/your/model.onnx"))?;

// Use filter
if let Some(result) = filter.filter(data) {
    // Process filtered data
}
```

### Benefits

- ✅ Update model without recompiling
- ✅ Smaller binary size
- ✅ Can switch models dynamically
- ✅ Multiple models for different scenarios

## Option 3: Automatic Model Detection

If you place the model at `protosyte-seed/models/ner_model.onnx`, the build system will detect it and offer to embed:

```bash
# Build with AI filtering
cargo build --release --features ai-filtering

# Output will show:
# cargo:warning=Found ONNX model at: models/ner_model.onnx
# cargo:warning=To embed it, set PROTOSYTE_EMBED_MODEL=1 and rebuild
```

Then rebuild with embedding enabled as in Option 1.

## Build Process Details

### What Happens During Build

1. **build.rs checks for model**:
   ```rust
   // Checks these locations:
   - models/ner_model.onnx
   - ../models/ner_model.onnx
   - protosyte-seed/models/ner_model.onnx
   ```

2. **If model found and PROTOSYTE_EMBED_MODEL=1**:
   - Creates build flag: `cargo:rustc-cfg=embed_model`
   - Enables `include_bytes!` macro in code

3. **Rust code compiles**:
   - If `embed_model` cfg is set, includes model bytes
   - Otherwise, model loading happens at runtime

### Build Script Logic

```rust
// In build.rs:
if model exists AND PROTOSYTE_EMBED_MODEL=1:
    enable embed_model cfg
    model will be included in binary
else if model exists:
    warn user to set PROTOSYTE_EMBED_MODEL=1
else:
    warn that model needed at runtime
```

## Manual Embedding (Advanced)

If automatic embedding doesn't work, you can manually embed:

### Step 1: Place Model

```bash
protosyte-seed/models/ner_model.onnx
```

### Step 2: Edit Source Code

In `protosyte-seed/src/ai_filtering.rs`, uncomment:

```rust
fn embedded_model() -> Vec<u8> {
    // Uncomment this line:
    include_bytes!("../models/ner_model.onnx").to_vec()
}
```

### Step 3: Rebuild

```bash
cargo build --release --features ai-filtering
```

## Model Requirements

### File Format
- **Extension**: `.onnx`
- **Format**: ONNX 1.0+ (standard ONNX format)
- **Size**: < 100MB recommended (for embedded use)

### Architecture
- **Type**: Named Entity Recognition (NER)
- **Input**: Tokenized text (sequence of token IDs)
- **Output**: Token labels (BIO tagging scheme)

### Labels
- `0`: O (outside/other)
- `1`: B-CREDENTIAL (beginning of credential)
- `2`: I-CREDENTIAL (inside credential)
- `3`: B-PRIVATE_KEY
- `4`: I-PRIVATE_KEY
- (Add more as needed)

### Recommended Models

| Model | Size (int8) | Accuracy | Speed |
|-------|------------|----------|-------|
| DistilBERT | ~65MB | High | Medium |
| MobileBERT | ~25MB | Good | Fast |
| TinyBERT | ~15MB | Good | Very Fast |

## Example Workflow

### Complete Example

```bash
# 1. Train model (see docs/AI_FILTERING.md)
python3 scripts/train-ner-model.sh

# 2. Verify model
python3 -c "import onnx; onnx.load('protosyte-seed/models/ner_model.onnx')"

# 3. Build with embedded model
cd protosyte-seed
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering

# 4. Verify binary size
ls -lh target/release/protosyte-seed

# 5. Test (model automatically loaded)
./target/release/protosyte-seed --help
```

### Runtime Loading Example

```bash
# 1. Build without embedding
cargo build --release --features ai-filtering

# 2. Place model anywhere
cp trained_model.onnx /opt/protosyte/model.onnx

# 3. Use with model path
export PROTOSYTE_MODEL_PATH=/opt/protosyte/model.onnx
./target/release/protosyte-seed
```

## Troubleshooting

### "No model provided" Error

**Problem**: Model not found at runtime or build time.

**Solutions**:
1. Provide model path: `AIDataFilter::new(Some("path/to/model.onnx"))`
2. Embed model: Set `PROTOSYTE_EMBED_MODEL=1` during build
3. Place model at: `protosyte-seed/models/ner_model.onnx`

### Model Not Embedded

**Problem**: Built with `PROTOSYTE_EMBED_MODEL=1` but model not in binary.

**Check**:
1. Model exists at `protosyte-seed/models/ner_model.onnx`?
2. Build output shows "Model will be embedded"?
3. Binary size increased (~15-65MB)?

**Fix**:
```bash
# Verify model exists
ls -lh protosyte-seed/models/ner_model.onnx

# Clean and rebuild
cargo clean
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
```

### Binary Too Large

**Problem**: Embedded model makes binary too large.

**Solutions**:
1. Use quantized int8 model (4x smaller)
2. Use smaller architecture (MobileBERT/TinyBERT)
3. Use runtime loading instead of embedding

### Model Format Error

**Problem**: "Failed to load ONNX model" error.

**Check**:
```bash
# Verify ONNX format
python3 -c "import onnx; print(onnx.load('model.onnx'))"

# Check file integrity
file model.onnx  # Should show "ONNX"
```

## Best Practices

1. **For Deployment**: Embed model (single binary)
2. **For Development**: Runtime loading (easier updates)
3. **For Testing**: Runtime loading (try different models)
4. **For Production**: Embedded + runtime fallback (best of both)

## Security Considerations

- **Embedded Models**: Compiled into binary (harder to extract)
- **Runtime Models**: Separate file (easier to update/swap)
- **Model Signing**: Consider signing models for integrity verification
- **Access Control**: Protect model files with proper permissions

## See Also

- `docs/AI_FILTERING.md` - Complete AI filtering guide
- `protosyte-seed/models/README.md` - Model directory guide
- `scripts/train-ner-model.sh` - Model training script template

