# AI-Driven Data Filtering Implementation

## Overview

The AI filtering module uses ONNX Runtime to perform Named Entity Recognition (NER) for identifying high-value data such as credentials, private keys, API keys, and PII. This replaces brittle regex-based filtering with context-aware machine learning.

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
let filter = AIDataFilter::new(None)?;

// Filter data
if let Some(result) = filter.filter(data) {
    if result.should_capture {
        // High-value data detected
        println!("Detected: {:?}", result.entities);
        println!("Confidence: {}", result.confidence);
    }
}
```

## Model Training

To create a custom model:

1. **Dataset**: Collect labeled text samples (credentials, keys, PII, normal text)
2. **Format**: Use BIO tagging scheme (B-Credential, I-Credential, O)
3. **Training**: Train using Transformers (BERT, RoBERTa) or lightweight models
4. **Export**: Export to ONNX format
5. **Quantize**: Quantize model to reduce size

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

