# AI-Driven Data Filtering

## Overview

The AI filtering module uses ONNX Runtime to perform Named Entity Recognition (NER) for identifying high-value data such as credentials, private keys, API keys, and PII. This replaces brittle regex-based filtering with context-aware machine learning.

## Quick Start

### Without a Model (Default)

**You don't need a model!** The framework gracefully falls back to regex filtering:

```bash
# Build without AI filtering (uses regex only)
cargo build --release

# Or build with feature but no model (still uses regex)
cargo build --release --features ai-filtering
```

### With a Model

1. **Train your model** (see "Training Your Own Model" below)
2. **Place model** at `protosyte-seed/models/ner_model.onnx`
3. **Build with embedding**:
   ```bash
   PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
   ```

## Model Integration Options

### Option 1: Compile-Time Embedding (Recommended)

Embed model in binary at build time:

```bash
# 1. Place model
cp your_model.onnx protosyte-seed/models/ner_model.onnx

# 2. Build with embedding
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering

# Model is now embedded in binary - single file deployment!
```

**How it works:**
- `build.rs` detects model and sets `embed_model` cfg flag
- `include_bytes!` embeds model at compile time
- No separate model file needed at runtime

### Option 2: Runtime File Loading

Load model from file at runtime:

```rust
use protosyte_seed::ai_filtering::AIDataFilter;

// Provide model path
let filter = AIDataFilter::new(Some("path/to/model.onnx"))?;
```

**Benefits:**
- Update model without recompiling
- Smaller binary size
- Can switch models dynamically

### Option 3: Automatic Detection

Place model at `protosyte-seed/models/ner_model.onnx` - framework auto-detects it:

```bash
# Model will be found automatically at runtime
./target/release/protosyte-seed
```

## Behavior Without a Model

**Short answer**: Framework gracefully falls back to regex filtering. AI filtering is **optional**.

### What Happens

1. **Build succeeds** - No errors during compilation
2. **Runtime**: `AIDataFilter::new(None)` returns error (expected)
3. **Graceful degradation**: `HookManager` uses regex filtering instead
4. **Fully functional** - All filtering works via regex patterns

### Filtering Methods

The framework uses a **hierarchical approach**:

1. **AI Filtering** (if model available)
   - Context-aware Named Entity Recognition
   - Lower false positives
   - Better at complex patterns

2. **Regex Filtering** (always available)
   - Pattern-based detection
   - Always works (no model needed)
   - Fast and reliable

3. **Both** (when model available)
   - AI filter runs first
   - Regex acts as backup/secondary check

### Regex Patterns (Always Available)

Even without AI model, framework filters:
- **Private Keys**: `-----BEGIN.*PRIVATE KEY-----`
- **Passwords**: `password|passwd|pwd\s*[=:]\s*...`
- **API Keys**: `api[_-]?key\s*[=:]\s*...`
- **Session Tokens**: Various token patterns
- **Network Flows**: IP addresses, ports
- **File Metadata**: Sensitive file paths

## Training Your Own Model

### Step 1: Prepare Dataset

Create labeled examples:

```json
{
  "examples": [
    {
      "text": "password=secret123",
      "entities": [
        {"text": "password=secret123", "label": "CREDENTIAL", "start": 0, "end": 17}
      ]
    }
  ]
}
```

### Step 2: Choose Model Architecture

**Recommended for embedded use:**

| Model | Size (int8) | Accuracy | Speed |
|-------|------------|----------|-------|
| DistilBERT | ~65MB | High | Medium |
| MobileBERT | ~25MB | Good | Fast |
| TinyBERT | ~15MB | Good | Very Fast |

### Step 3: Train with Transformers

```python
from transformers import AutoTokenizer, AutoModelForTokenClassification
from transformers import TrainingArguments, Trainer

# Load model
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(
    model_name,
    num_labels=5  # O, B-CREDENTIAL, I-CREDENTIAL, B-PRIVATE_KEY, I-PRIVATE_KEY
)

# Train
trainer = Trainer(
    model=model,
    args=TrainingArguments(output_dir="./results", num_train_epochs=3),
    train_dataset=train_dataset,
)
trainer.train()
```

### Step 4: Export to ONNX

```python
from optimum.onnxruntime import ORTModelForTokenClassification

onnx_model = ORTModelForTokenClassification.from_pretrained(
    "./results",
    export=True
)
onnx_model.save_pretrained("./protosyte-seed/models/ner_model.onnx")
```

### Step 5: Quantize Model (Optional)

Quantize to int8 for 4x size reduction:

```python
from optimum.onnxruntime import ORTQuantizer
from optimum.onnxruntime.configuration import AutoQuantizationConfig

quantizer = ORTQuantizer.from_pretrained("./protosyte-seed/models/ner_model.onnx")
qconfig = AutoQuantizationConfig.avx512_vnni(is_static=False, per_channel=False)
quantizer.quantize(
    save_dir="./protosyte-seed/models/ner_model_quantized.onnx",
    quantization_config=qconfig
)
```

### Training Script

See `scripts/train-ner-model.sh` for a complete template.

## Model Requirements

### File Format
- **Extension**: `.onnx`
- **Format**: ONNX 1.0+ (standard ONNX format)
- **Size**: < 100MB recommended (for embedded use)

### Architecture
- **Type**: Named Entity Recognition (NER)
- **Input**: Tokenized text (sequence of token IDs)
- **Output**: Token labels (BIO tagging scheme)

### Labels (BIO Tagging)
- `0`: O (outside/other)
- `1`: B-CREDENTIAL (beginning)
- `2`: I-CREDENTIAL (inside)
- `3`: B-PRIVATE_KEY
- `4`: I-PRIVATE_KEY
- (Add more as needed)

### Vocabulary
- Must match your training tokenizer
- Default: BERT/DistilBERT vocabulary
- Custom vocabularies require code changes

## Usage

### Basic Usage

```rust
use protosyte_seed::ai_filtering::AIDataFilter;

// Create filter (auto-detects model)
let filter = AIDataFilter::new(None)?;

// Or provide explicit path
let filter = AIDataFilter::new(Some("path/to/model.onnx"))?;

// Filter data
if let Some(result) = filter.filter(data) {
    if result.should_capture {
        println!("Detected: {:?}", result.entities);
        println!("Confidence: {}", result.confidence);
    }
}
```

### Entity Types

- `Credential`: Passwords, usernames, authentication tokens
- `PrivateKey`: SSH keys, SSL certificates, private keys
- `ApiKey`: API keys, access tokens, bearer tokens
- `Token`: OAuth tokens, session tokens
- `Pii`: Personal identifiable information

## Building

### Enable AI Filtering

```bash
# Build with AI filtering feature
cargo build --release --features ai-filtering
```

### Embed Model at Build Time

```bash
# Place model first
cp your_model.onnx protosyte-seed/models/ner_model.onnx

# Build with embedding
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
```

## Performance

### Model Size
- **DistilBERT (int8)**: ~65MB
- **MobileBERT (int8)**: ~25MB
- **TinyBERT (int8)**: ~15MB

### Inference Speed
- **CPU**: 1-5ms per text sample
- **Memory**: ~10-50MB runtime usage
- **Binary Size**: +15-65MB for embedded model

### Optimization Tips
1. **Quantize to int8**: 4x size reduction
2. **Limit sequence length**: 128 tokens vs 512
3. **Use smaller models**: MobileBERT/TinyBERT
4. **Batch inference**: Process multiple samples together

## Troubleshooting

### "No model provided" Error

**Solutions:**
1. Embed model: `PROTOSYTE_EMBED_MODEL=1 cargo build --features ai-filtering`
2. Provide path: `AIDataFilter::new(Some("path/to/model.onnx"))`
3. Place at: `protosyte-seed/models/ner_model.onnx` (auto-detected)
4. **Or just use regex** - framework works without model!

### Model Not Embedded

**Check:**
```bash
# Verify model exists
ls -lh protosyte-seed/models/ner_model.onnx

# Clean and rebuild
cargo clean
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering

# Check binary size increased
ls -lh target/release/protosyte-seed
```

### "Model file not found"

```bash
# Verify ONNX format
python3 -c "import onnx; onnx.load('model.onnx')"

# Check file permissions
ls -l model.onnx
```

### "Input shape mismatch"

- Verify tokenizer matches training
- Check sequence length matches model expectations
- Review model input/output schema

### Poor Accuracy

- Retrain with more domain-specific data
- Increase training epochs
- Use larger model (if size allows)
- Fine-tune on your specific data types

## Advantages Over Regex

1. **Context Awareness**: Understands context, not just patterns
2. **Low False Positives**: Reduces false matches
3. **Adaptability**: Can learn new patterns without code changes
4. **Multilingual**: Can detect entities in multiple languages
5. **Fuzzy Matching**: Handles variations and obfuscation

## Configuration

```rust
let filter = AIDataFilter::new(Some("path/to/model.onnx"))?;

// Adjust confidence threshold (default: 0.7)
filter.set_confidence_threshold(0.8);
```

## Limitations

1. **Text Only**: Currently supports text data only
2. **Model Size**: Embedded models increase binary size
3. **Accuracy**: Depends on training data quality
4. **Language**: Default model optimized for English

## Architecture

### Components

1. **ONNX Runtime Integration** (`src/ai_filtering.rs`)
   - Loads and runs ONNX models
   - Tokenizes input text
   - Performs inference
   - Extracts entities with confidence scores

2. **Integration Points**
   - Hook manager uses AI filter as primary method
   - Falls back to regex if AI unavailable
   - Configurable confidence threshold

### Build Process

1. **build.rs checks for model**:
   ```rust
   // Checks these locations:
   - models/ner_model.onnx
   - ../models/ner_model.onnx
   - protosyte-seed/models/ner_model.onnx
   ```

2. **If model found and PROTOSYTE_EMBED_MODEL=1**:
   - Sets `cargo:rustc-cfg=embed_model`
   - Enables `include_bytes!` macro

3. **Rust code compiles**:
   - If `embed_model` cfg set, includes model bytes
   - Otherwise, model loading happens at runtime

## Requirements

- `ort` crate (ONNX Runtime)
- `ndarray` for tensor operations
- Trained ONNX model file (optional - regex fallback available)

## Pre-trained Models

**Note**: We do not provide pre-trained models due to:
1. Model size (even quantized, ~15-65MB)
2. Custom training requirements (domain-specific data)
3. Security considerations (models could be reverse-engineered)

**Recommendation**: Train your own model on domain-specific data for best results.

## See Also

- `protosyte-seed/models/README.md` - Model directory guide
- `scripts/train-ner-model.sh` - Model training script template
- `protosyte-seed/MODEL_QUICKSTART.md` - Quick reference
