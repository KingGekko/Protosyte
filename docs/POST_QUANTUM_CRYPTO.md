# Post-Quantum Cryptography Implementation

## Overview

The post-quantum cryptography module implements NIST-standardized algorithms: **Kyber-768 (ML-KEM)** for key exchange and **Dilithium-3 (ML-DSA)** for digital signatures. These algorithms are resistant to attacks from quantum computers.

## Architecture

### Algorithms

1. **Kyber-768 (ML-KEM)**
   - Key encapsulation mechanism
   - NIST PQC Standard (selected 2024)
   - 768-bit security level
   - Used for key exchange

2. **Dilithium-3 (ML-DSA)**
   - Digital signature algorithm
   - NIST PQC Standard (selected 2024)
   - Level 3 security
   - Used for authentication

3. **Hybrid Approach**
   - Kyber for key establishment
   - AES-GCM for bulk encryption (derived from Kyber shared secret)
   - Dilithium for signatures
   - Best of both worlds: PQC security + classical efficiency

## Requirements

- `pqcrypto-kyber` crate (Kyber-768)
- `pqcrypto-dilithium` crate (Dilithium-3)
- Feature flag: `--features post-quantum`

## Building

```bash
cargo build --features post-quantum
```

## Usage

### Key Exchange (Kyber)

```rust
use protosyte_seed::pqc::KyberKeyExchange;

// Generate keypair
let alice = KyberKeyExchange::new();
let bob = KyberKeyExchange::new();

// Alice encapsulates using Bob's public key
let (ciphertext, shared_secret_alice) = 
    KyberKeyExchange::encapsulate(bob.public_key())?;

// Bob decapsulates to get shared secret
let shared_secret_bob = bob.decapsulate(&ciphertext)?;

// Both now have the same shared secret
assert_eq!(shared_secret_alice, shared_secret_bob);

// Derive AES key from shared secret
let aes_key = KyberKeyExchange::derive_aes_key(&shared_secret_alice);
```

### Digital Signatures (Dilithium)

```rust
use protosyte_seed::pqc::DilithiumSigner;

// Generate keypair
let signer = DilithiumSigner::new();

// Sign message
let message = b"Important data";
let signature = signer.sign(message)?;

// Verify signature
let is_valid = DilithiumSigner::verify(
    signer.public_key(),
    message,
    &signature,
)?;

assert!(is_valid);
```

### Hybrid Encryption

```rust
use protosyte_seed::pqc::HybridPQCEncryption;

// Alice creates encryption context
let alice = HybridPQCEncryption::new();

// Bob creates encryption context
let bob = HybridPQCEncryption::new();

// Alice encrypts data using Bob's public key
let data = b"Sensitive information";
let encrypted = alice.encrypt(bob.kyber.public_key(), data)?;

// Bob decrypts using his secret key
let decrypted = bob.decrypt(&encrypted)?;

assert_eq!(data, decrypted.as_slice());
```

## Security Properties

### Quantum Resistance
- Resistant to Shor's algorithm (quantum factorization)
- Resistant to Grover's algorithm (quantum search)
- Secure against future quantum computers

### Security Levels
- **Kyber-768**: NIST Level 3 (equivalent to AES-192)
- **Dilithium-3**: NIST Level 3 (equivalent to ECDSA-384)

### Hybrid Security
- Combines PQC with classical crypto
- Maintains compatibility with existing systems
- Gradual migration path

## Performance

### Key Sizes
- Kyber-768 public key: 1,184 bytes
- Kyber-768 secret key: 2,400 bytes
- Kyber-768 ciphertext: 1,088 bytes
- Dilithium-3 public key: 1,952 bytes
- Dilithium-3 secret key: 4,000 bytes
- Dilithium-3 signature: 3,293 bytes

### Operation Times (typical)
- Kyber key generation: ~50-100μs
- Kyber encapsulation: ~100-200μs
- Kyber decapsulation: ~100-200μs
- Dilithium signing: ~200-500μs
- Dilithium verification: ~200-500μs

## Integration with Existing Crypto

The PQC module can be used alongside existing AES-GCM encryption:

```rust
// Option 1: Use hybrid PQC (recommended)
let encrypted = hybrid_pqc.encrypt(peer_pubkey, data)?;

// Option 2: Use PQC for key exchange, AES-GCM for bulk
let (ct, shared_secret) = KyberKeyExchange::encapsulate(peer_pubkey)?;
let aes_key = KyberKeyExchange::derive_aes_key(&shared_secret);
let encrypted = aes_gcm_encrypt(&aes_key, data)?;
```

## Migration Strategy

1. **Phase 1**: Deploy hybrid approach (PQC + classical)
2. **Phase 2**: Gradually increase PQC usage
3. **Phase 3**: Full PQC migration when standardized

## Standards Compliance

- NIST SP 800-208 (Post-Quantum Cryptography)
- FIPS 203 (ML-KEM Standard)
- FIPS 204 (ML-DSA Standard)

## Limitations

1. **Key Sizes**: Larger than classical crypto
2. **Performance**: Slightly slower than ECDH/RSA
3. **Compatibility**: Requires both parties support PQC
4. **Standardization**: Still in standardization process

## Future Enhancements

- [ ] Additional NIST algorithms (SPHINCS+, Falcon)
- [ ] Optimized implementations
- [ ] Hardware acceleration support
- [ ] Post-quantum TLS integration

