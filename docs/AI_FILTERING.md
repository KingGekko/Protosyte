# AI-Driven Data Filtering Implementation

## Overview

The AI filtering module uses ONNX Runtime to perform Named Entity Recognition (NER) for identifying high-value data such as credentials, private keys, API keys, and PII. This replaces brittle regex-based filtering with context-aware machine learning.

## Model Integration

### Current Status

The `embedded_model()` function currently returns an empty vector. **You must provide your own trained ONNX model** to use AI filtering.

### Option 1: Provide Model File Path

```rust
use protosyte_seed::ai_filtering::AIDataFilter;

// Load model from file
let filter = AIDataFilter::new(Some("path/to/ner_model.onnx"))?;
```

### Option 2: Embed Model in Binary

1. **Place your trained model** at `protosyte-seed/models/ner_model.onnx`
2. **Uncomment the line** in `protosyte-seed/src/ai_filtering.rs`:

```rust
fn embedded_model() -> Vec<u8> {
    include_bytes!("../models/ner_model.onnx").to_vec()
}
```

3. **Rebuild** the project:

```bash
cargo build --features ai-filtering
```

## Training Your Own Model

### Step 1: Prepare Dataset

Create a dataset with labeled examples:

```json
{
  "examples": [
    {
      "text": "password=secret123",
      "entities": [
        {"text": "password=secret123", "label": "CREDENTIAL", "start": 0, "end": 17}
      ]
    },
    {
      "text": "-----BEGIN PRIVATE KEY-----",
      "entities": [
        {"text": "-----BEGIN PRIVATE KEY-----", "label": "PRIVATE_KEY", "start": 0, "end": 28}
      ]
    }
  ]
}
```

### Step 2: Choose Model Architecture

**Recommended: Lightweight models for embedded use**

1. **DistilBERT** (67M parameters, ~260MB)
   - Good balance of accuracy and size
   - Can be quantized to ~65MB

2. **MobileBERT** (25M parameters, ~100MB)
   - Designed for mobile/embedded
   - Can be quantized to ~25MB

3. **TinyBERT** (14M parameters, ~55MB)
   - Very small, still accurate
   - Can be quantized to ~15MB

### Step 3: Train with Transformers

```python
from transformers import AutoTokenizer, AutoModelForTokenClassification
from transformers import TrainingArguments, Trainer

# Load model and tokenizer
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(
    model_name,
    num_labels=5  # O, B-CREDENTIAL, I-CREDENTIAL, B-PRIVATE_KEY, I-PRIVATE_KEY
)

# Training arguments
training_args = TrainingArguments(
    output_dir="./results",
    num_train_epochs=3,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    warmup_steps=500,
    weight_decay=0.01,
    logging_dir="./logs",
)

# Train
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
)
trainer.train()
```

### Step 4: Export to ONNX

```python
from transformers import pipeline
import torch

# Create pipeline
ner_pipeline = pipeline(
    "token-classification",
    model=model,
    tokenizer=tokenizer
)

# Export to ONNX (using optimum library)
from optimum.onnxruntime import ORTModelForTokenClassification

onnx_model = ORTModelForTokenClassification.from_pretrained(
    "./results",
    export=True
)
onnx_model.save_pretrained("./onnx_model")
```

### Step 5: Quantize Model

Quantize to int8 for size reduction:

```python
from optimum.onnxruntime import ORTQuantizer
from optimum.onnxruntime.configuration import AutoQuantizationConfig

# Load ONNX model
quantizer = ORTQuantizer.from_pretrained("./onnx_model")

# Configure quantization
qconfig = AutoQuantizationConfig.avx512_vnni(is_static=False, per_channel=False)

# Quantize
quantizer.quantize(
    save_dir="./onnx_model_quantized",
    quantization_config=qconfig
)
```

### Step 6: Test ONNX Model

```python
import onnxruntime as ort

# Load quantized model
session = ort.InferenceSession("./onnx_model_quantized/model.onnx")

# Test inference
inputs = tokenizer("password=secret123", return_tensors="np")
outputs = session.run(None, dict(inputs))
```

## Model Requirements

### Input Format
- **Format**: Tokenized input IDs (int64 array)
- **Shape**: `[batch_size, sequence_length]`
- **Max length**: 512 tokens (recommended: 128-256 for embedded use)

### Output Format
- **Format**: Logits or probabilities (float32 array)
- **Shape**: `[batch_size, sequence_length, num_labels]`
- **Labels**: BIO tagging scheme
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

## Example Training Script

See `scripts/train-ner-model.sh` for a complete example:

```bash
#!/bin/bash
# Train NER model for Protosyte AI filtering

python3 <<EOF
from transformers import (
    AutoTokenizer, AutoModelForTokenClassification,
    TrainingArguments, Trainer, DataCollatorForTokenClassification
)
from datasets import load_dataset
import torch

# 1. Load base model
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(
    model_name,
    num_labels=5
)

# 2. Prepare dataset
# (Load your labeled dataset here)

# 3. Train
trainer = Trainer(
    model=model,
    args=TrainingArguments(output_dir="./ner_model", num_train_epochs=3),
    train_dataset=train_dataset,
    data_collator=DataCollatorForTokenClassification(tokenizer)
)
trainer.train()

# 4. Export to ONNX
from optimum.onnxruntime import ORTModelForTokenClassification
onnx_model = ORTModelForTokenClassification.from_pretrained(
    "./ner_model",
    export=True
)
onnx_model.save_pretrained("./protosyte-seed/models/ner_model.onnx")
EOF
```

## Pre-trained Models

**Note**: We do not provide pre-trained models due to:
1. Model size (even quantized, ~15-65MB)
2. Custom training requirements (domain-specific data)
3. Security considerations (models could be reverse-engineered)

**Recommendation**: Train your own model on domain-specific data for best results.

## Performance Considerations

### Model Size
- **DistilBERT (int8)**: ~65MB
- **MobileBERT (int8)**: ~25MB
- **TinyBERT (int8)**: ~15MB

### Inference Speed
- **CPU**: 1-5ms per text sample (optimized)
- **Memory**: ~10-50MB runtime usage

### Optimization Tips
1. **Quantize to int8**: 4x size reduction
2. **Limit sequence length**: 128 tokens vs 512
3. **Use smaller models**: MobileBERT/TinyBERT
4. **Batch inference**: Process multiple samples together

## Troubleshooting

### "Model file not found"
- Ensure model path is correct
- Check file permissions
- Verify ONNX format: `python -c "import onnx; onnx.load('model.onnx')"`

### "Input shape mismatch"
- Verify tokenizer matches training
- Check sequence length matches model expectations
- Review model input/output schema

### "Poor accuracy"
- Retrain with more domain-specific data
- Increase training epochs
- Use larger model (if size allows)
- Fine-tune on your specific data types

## Architecture

### Components

1. **ONNX Runtime Integration** (`src/ai_filtering.rs`)
   - Loads and runs ONNX models
   - Tokenizes input text
   - Performs inference
   - Extracts entities with confidence scores

2. **Model Requirements**
   - NER model trained for credential/PII detection
   - Quantized for minimal binary size
   - Supports tokenization vocabulary

3. **Integration Points**
   - Hook manager uses AI filter as primary method
   - Falls back to regex if AI unavailable
   - Configurable confidence threshold

## Requirements

- `ort` crate (ONNX Runtime)
- `ndarray` for tensor operations
- Trained ONNX model file (optional, can be embedded)

## Building

Enable AI filtering with the feature flag:

```bash
cargo build --features ai-filtering
```

## Usage

```rust
use protosyte_seed::ai_filtering::AIDataFilter;

// Create filter (loads default model)
let filter = AIDataFilter::new(Some("models/ner_model.onnx"))?;

// Filter data
if let Some(result) = filter.filter(data) {
    if result.should_capture {
        // High-value data detected
        println!("Detected: {:?}", result.entities);
        println!("Confidence: {}", result.confidence);
    }
}
```

## Entity Types

- `Credential`: Passwords, usernames, authentication tokens
- `PrivateKey`: SSH keys, SSL certificates, private keys
- `ApiKey`: API keys, access tokens, bearer tokens
- `Token`: OAuth tokens, session tokens
- `Pii`: Personal identifiable information

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

## Performance

- **Inference Time**: ~1-5ms per text sample
- **Memory**: ~10-50MB for quantized model
- **CPU Usage**: Minimal with ONNX Runtime optimization
- **Binary Size**: +2-5MB for embedded model

## Limitations

1. **Text Only**: Currently supports text data only
2. **Model Size**: Embedded models increase binary size
3. **Accuracy**: Depends on training data quality
4. **Language**: Default model optimized for English

## Future Enhancements

- [ ] Binary data analysis
- [ ] Multi-language support
- [ ] Real-time model updates
- [ ] Custom entity types
- [ ] Federated learning integration
