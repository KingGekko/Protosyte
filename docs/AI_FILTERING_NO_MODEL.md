# Using AI Filtering Without a Model

## What Happens If You Don't Have a Model?

**Short answer**: The framework gracefully falls back to regex-based filtering. AI filtering is **optional**, not required.

## Behavior Without a Model

### When Building with `--features ai-filtering`

If you enable the AI filtering feature but don't provide a model:

1. **Build succeeds** - No errors during compilation
2. **Runtime initialization** - `AIDataFilter::new(None)` returns an error (expected)
3. **Graceful degradation** - `HookManager` detects no AI model and uses regex filtering instead
4. **Fully functional** - All filtering still works via regex patterns

### Code Flow

```rust
// In HookManager::new()
let ai_filter = match AIDataFilter::new(None) {
    Ok(filter) => Some(filter),  // Model available - use it!
    Err(_) => None,              // No model - this is OK, use regex instead
};

// In filter_data()
if let Some(ref filter) = self.ai_filter {
    // Use AI filtering if available
} else {
    // No AI model - use regex (default behavior)
}
```

## Filtering Methods

The framework uses a **hierarchical approach**:

1. **AI Filtering** (if model available)
   - Context-aware Named Entity Recognition
   - Lower false positives
   - Better at complex patterns

2. **Regex Filtering** (always available)
   - Pattern-based detection
   - Always works (no model needed)
   - Fast and reliable

3. **Both** (when model is available)
   - AI filter runs first
   - Regex acts as backup/secondary check
   - Best of both worlds

## When You Don't Have a Model

### Option 1: Use Regex Only (Default)

Just **don't enable** the `ai-filtering` feature:

```bash
# Build without AI filtering
cargo build --release

# Uses regex filtering only (fully functional)
```

### Option 2: Enable Feature, No Model (Graceful Degradation)

Build with AI filtering feature enabled, but don't provide a model:

```bash
# Build with feature enabled
cargo build --release --features ai-filtering

# No model available - automatically uses regex filtering
# No errors, no warnings, fully functional
```

### Option 3: Provide Model Later

Build with feature enabled, add model later:

```bash
# Initial build (no model)
cargo build --release --features ai-filtering
# Uses regex filtering

# Later: Add model and rebuild with embedding
cp your_model.onnx protosyte-seed/models/ner_model.onnx
PROTOSYTE_EMBED_MODEL=1 cargo build --release --features ai-filtering
# Now uses AI filtering!
```

## Regex Filtering (Always Available)

Even without an AI model, the framework filters data using regex patterns for:

- **Private Keys**: `-----BEGIN.*PRIVATE KEY-----`
- **Passwords**: `password|passwd|pwd\s*[=:]\s*...`
- **API Keys**: `api[_-]?key\s*[=:]\s*...`
- **Session Tokens**: Pattern matching for tokens
- **Network Flows**: IP addresses, ports, connections
- **File Metadata**: Sensitive file paths and names

## Error Messages

### If Model Expected But Not Found

When you explicitly request a model path but it's missing:

```rust
AIDataFilter::new(Some("path/to/model.onnx"))
// Error: Failed to read model file 'path/to/model.onnx': No such file or directory
```

### If No Model Provided

When building with `--features ai-filtering` but no model:

```bash
# Build output (informational only):
cargo:warning=No ONNX model found. AI filtering will require runtime model path.
cargo:warning=Place model at: models/ner_model.onnx
cargo:warning=Or provide model path: AIDataFilter::new(Some("path/to/model.onnx"))
```

**Note**: These are warnings, not errors. Build succeeds and framework works with regex.

## Configuration Options

### Enable/Disable AI Filtering

```rust
// In your code, you can check if AI filtering is available:
#[cfg(feature = "ai-filtering")]
{
    if let Ok(filter) = AIDataFilter::new(None) {
        // AI filtering available
    } else {
        // No model - use regex
    }
}
```

### Mission Configuration

```yaml
# mission.yaml
target:
  filters:
    use_ai: true    # Try AI filtering if available
    use_regex: true # Always use regex (default: true)
```

## Benefits of Regex-Only Mode

Even without AI filtering, the framework is fully functional:

✅ **Fast**: Regex is very fast  
✅ **Reliable**: Well-tested patterns  
✅ **No dependencies**: No ONNX runtime needed  
✅ **Small binary**: No model embedded  
✅ **Always works**: No model required

## When to Use AI Filtering

Use AI filtering when:

- ✅ You have a trained model
- ✅ You need better accuracy
- ✅ You want context awareness
- ✅ You can handle larger binary size

Use regex-only when:

- ✅ No model available yet
- ✅ Want smaller binary
- ✅ Need fast startup
- ✅ Regex patterns are sufficient

## Summary

**You don't need a model to use the framework!**

- ✅ Build without `--features ai-filtering`: Uses regex only
- ✅ Build with `--features ai-filtering` but no model: Uses regex only (graceful degradation)
- ✅ Add model later: Just embed and rebuild
- ✅ Regex filtering is always available and fully functional

The framework is designed to work **with or without** an AI model.

