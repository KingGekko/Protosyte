# ONNX Model Directory

Place your trained ONNX model here to embed it in the binary.

## Quick Start

1. **Train your model** (see `docs/AI_FILTERING.md` for instructions)
2. **Export to ONNX** and save as `ner_model.onnx`
3. **Place in this directory**: `protosyte-seed/models/ner_model.onnx`
4. **Build with embedding**:
   ```bash
   PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
   ```

## Model Requirements

- **Format**: ONNX (`.onnx` file)
- **Recommended**: Quantized int8 (smaller size)
- **Max Size**: < 100MB recommended (for binary size)
- **Architecture**: NER model (BERT/RoBERTa-based)

## Embedding Options

### Option 1: Automatic Embedding (Recommended)

If model exists in this directory and you set `PROTOSYTE_EMBED_MODEL=1`, it will be automatically embedded:

```bash
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
```

### Option 2: Manual Embedding

1. Place model at: `protosyte-seed/models/ner_model.onnx`
2. Uncomment this line in `src/ai_filtering.rs`:
   ```rust
   include_bytes!("../models/ner_model.onnx").to_vec()
   ```
3. Rebuild: `cargo build --release --features ai-filtering`

### Option 3: Runtime Loading

Don't embed - load from file at runtime:

```rust
let filter = AIDataFilter::new(Some("path/to/model.onnx"))?;
```

## File Structure

```
protosyte-seed/
├── models/
│   ├── README.md          (this file)
│   └── ner_model.onnx     (your model - not in git)
└── src/
    └── ai_filtering.rs    (handles model loading)
```

## Benefits of Embedding

✅ **Single Binary**: No separate model file needed  
✅ **Deployment**: Easier distribution  
✅ **Security**: Model is compiled into binary  
⚠️ **Size**: Increases binary size (~15-65MB)

## Benefits of Runtime Loading

✅ **Flexibility**: Can update model without recompiling  
✅ **Smaller Binary**: Model loaded separately  
✅ **Multiple Models**: Can switch models at runtime  
⚠️ **Dependency**: Requires model file at runtime

## Verifying Embedding

After building with `PROTOSYTE_EMBED_MODEL=1`, check binary size:

```bash
ls -lh target/release/protosyte-seed
```

Embedded model will increase binary size by model size (~15-65MB for quantized models).

## Troubleshooting

**"Model not found"**
- Ensure model is at `protosyte-seed/models/ner_model.onnx`
- Check file permissions
- Verify ONNX format: `file models/ner_model.onnx`

**"Model not embedded"**
- Set `PROTOSYTE_EMBED_MODEL=1` environment variable
- Check build output for warnings
- Verify model file exists before building

**"Binary too large"**
- Use quantized int8 model (4x smaller)
- Use smaller model (MobileBERT/TinyBERT instead of BERT)
- Consider runtime loading instead

