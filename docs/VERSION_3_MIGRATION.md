# Version 3.0 Migration Guide

This guide helps you migrate from Protosyte 2.x to Protosyte 3.0.

## ⚠️ Breaking Changes

### 1. PROTOSYTE_PASSPHRASE Now Required

**Previous Behavior (v2.x)**:
- `PROTOSYTE_PASSPHRASE` had a default value: `"default-passphrase-change-in-production"`
- Application would continue with insecure default if not set

**New Behavior (v3.0+)**:
- `PROTOSYTE_PASSPHRASE` is **REQUIRED** - no default value
- Application will **panic** if environment variable is not set
- This is a security requirement to prevent accidental deployment with weak keys

**Migration Steps**:
```bash
# Before running any component, ensure passphrase is set:
export PROTOSYTE_PASSPHRASE="your_secure_passphrase_here"

# Add to your shell profile:
echo 'export PROTOSYTE_PASSPHRASE="your_secure_passphrase_here"' >> ~/.bashrc
source ~/.bashrc

# Or use a secure passphrase manager
```

### 2. Enhanced Key Derivation

**Previous Behavior (v2.x)**:
- Key derivation used SHA256 hashing with static salt
- Less secure key derivation process

**New Behavior (v3.0+)**:
- Uses PBKDF2-HMAC-SHA256 with 100,000 iterations (OWASP recommended)
- Random salt generated per instance
- 32-byte key for AES-256 encryption

**Impact**:
- **Existing encrypted data from v2.x cannot be decrypted with v3.0** unless you:
  1. Decrypt using v2.x first
  2. Re-encrypt with v3.0 using the same passphrase
  3. Or use the `derive_key_from_passphrase()` method with compatible salt

### 3. Updated Dependencies

**Rust Dependencies**:
- `tokio`: 1.40 → 1.48
- `prost`: 0.13 → 0.14
- `rand`: 0.8 → 0.9
- New dependency: `pbkdf2` crate

**Action Required**:
```bash
# Update Rust toolchain (if needed)
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

### 4. New Module Structure

Many new modules were added. If you were using private APIs or internal modules, check:

- `tor_client.rs` → `tor_client/mod.rs` (restructured)
- New error handling with `ProtosyteError` enum
- Thread-safe buffer implementation (breaking API change)

**Migration**:
- Review any custom code that imports internal modules
- Update error handling to use `ProtosyteError` instead of generic errors
- Review buffer usage (now uses `Arc<Mutex<>>`)

## ✅ New Features to Leverage

### 1. Multiple Exfiltration Channels

**New Channels**:
- DNS Tunneling
- ICMP Tunneling
- WebSocket Exfiltration
- QUIC/HTTP3 Exfiltration
- Domain Fronting via CDN

**Configuration**:
```yaml
# mission.yaml
exfiltration:
  channels:
    - tor          # Default
    - dns          # DNS tunneling
    - icmp         # ICMP tunneling
    - websocket    # WebSocket
    - quic         # QUIC/HTTP3
  adaptive: true   # Automatic channel selection
```

### 2. Advanced Evasion Techniques

**New Capabilities**:
- Anti-debugging and anti-VM detection
- Indirect syscalls (beyond Hell's Gate)
- Polymorphic code generation
- Certificate pinning detection
- Timing randomization

**Usage**:
```rust
// Automatic evasion enabled by default
// Configure in mission.yaml for fine-tuning
```

### 3. Enhanced Security

- Forward secrecy support (optional feature)
- Key rotation and expiration
- Secure memory wiping
- Certificate pinning

**Enable Forward Secrecy**:
```toml
# Cargo.toml
[features]
forward-secrecy = ["x25519-dalek", "curve25519-dalek", "hkdf"]
```

### 4. Performance Improvements

- Adaptive compression (automatic algorithm selection)
- Optimized ring buffers
- Batch processing
- Lazy filtering (filter before encryption)

**Benefits**:
- Faster processing
- Lower CPU usage
- Better memory management

## 🔧 Configuration Updates

### mission.yaml Changes

```yaml
# New optional sections in v3.0
exfiltration:
  channels: ["tor", "dns", "icmp"]  # New: multiple channels
  adaptive: true                     # New: adaptive selection

stealth:
  anti_debug: true                   # New: anti-debugging
  timing_randomization: true         # New: human-like timing
  certificate_pinning: true          # New: TLS inspection detection

intelligence:
  screenshots: false                 # New: screenshot capture
  clipboard: true                    # New: clipboard monitoring
  database: true                     # New: database interception
```

## 📝 Testing Checklist

Before deploying v3.0 in production:

- [ ] Set `PROTOSYTE_PASSPHRASE` environment variable
- [ ] Test encryption/decryption with new key derivation
- [ ] Verify exfiltration channels work correctly
- [ ] Test all components build successfully
- [ ] Validate mission.yaml configuration
- [ ] Test on target platforms (Linux/Windows/macOS)
- [ ] Verify backward compatibility with existing data (if needed)
- [ ] Review and update operational procedures

## 🐛 Troubleshooting

### Application Panics on Startup

**Error**: `PROTOSYTE_PASSPHRASE environment variable must be set for security`

**Solution**: Set the environment variable:
```bash
export PROTOSYTE_PASSPHRASE="your_passphrase"
```

### Cannot Decrypt Old Data

**Issue**: Data encrypted with v2.x cannot be decrypted with v3.0

**Solution**: 
1. Use v2.x to decrypt existing data
2. Re-encrypt with v3.0
3. Or implement custom key derivation compatibility layer

### Build Errors

**Issue**: Dependency conflicts or compilation errors

**Solution**:
```bash
# Update Rust
rustup update

# Clean build
cargo clean

# Rebuild
cargo build --release
```

## 📚 Additional Resources

- [CHANGELOG.md](../CHANGELOG.md) - Complete list of changes
- [README.md](../README.md) - Updated usage examples
- [docs/OPERATIONS.md](OPERATIONS.md) - Operational procedures
- [docs/CLI_COMMANDS.md](CLI_COMMANDS.md) - CLI reference

## Support

If you encounter issues during migration:
1. Check the [CHANGELOG.md](../CHANGELOG.md) for detailed changes
2. Review component-specific README files
3. Check GitHub issues for known problems
4. Ensure all environment variables are set correctly

---

**Last Updated**: 2025-12-06  
**For**: Protosyte Framework v3.0.0
