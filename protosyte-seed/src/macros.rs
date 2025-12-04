// Compile-Time String Encryption Procedural Macro
// Encrypts strings at compile time, decrypts at runtime

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};

/// Encrypts a string literal at compile time
/// 
/// Usage: `encrypted_str!("sensitive_string")`
/// 
/// The string is XOR-encrypted with a compile-time key derived from the string itself.
/// This makes static analysis harder while keeping runtime overhead minimal.
#[proc_macro]
pub fn encrypted_str(input: TokenStream) -> TokenStream {
    let input_str = parse_macro_input!(input as LitStr);
    let plaintext = input_str.value();
    
    // Derive encryption key from string (compile-time)
    // In production, use a more sophisticated key derivation
    let key = derive_key(&plaintext);
    
    // Encrypt the string
    let encrypted: Vec<u8> = plaintext
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    
    // Generate code that decrypts at runtime
    let expanded = quote! {
        {
            const ENCRYPTED: &[u8] = &[#(#encrypted),*];
            const KEY: &[u8] = &[#(#key),*];
            
            fn decrypt() -> String {
                ENCRYPTED
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| (b ^ KEY[i % KEY.len()]) as char)
                    .collect()
            }
            
            decrypt()
        }
    };
    
    TokenStream::from(expanded)
}

/// Derives an encryption key from the plaintext
/// In production, use a more sophisticated KDF
fn derive_key(plaintext: &str) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    plaintext.hash(&mut hasher);
    let hash = hasher.finish();
    
    // Convert hash to key bytes
    hash.to_le_bytes().to_vec()
}

/// Obfuscates a string using a simple encoding scheme
/// 
/// Usage: `obfuscated_str!("sensitive_string")`
#[proc_macro]
pub fn obfuscated_str(input: TokenStream) -> TokenStream {
    let input_str = parse_macro_input!(input as LitStr);
    let plaintext = input_str.value();
    
    // Simple ROT13 + base64-like obfuscation
    let obfuscated: Vec<u8> = plaintext
        .bytes()
        .map(|b| {
            match b {
                b'A'..=b'Z' => ((b - b'A' + 13) % 26) + b'A',
                b'a'..=b'z' => ((b - b'a' + 13) % 26) + b'a',
                _ => b,
            }
        })
        .collect();
    
    let expanded = quote! {
        {
            const OBFUSCATED: &[u8] = &[#(#obfuscated),*];
            
            fn deobfuscate() -> String {
                OBFUSCATED
                    .iter()
                    .map(|&b| {
                        match b {
                            b'A'..=b'Z' => ((b.wrapping_sub(b'A').wrapping_sub(13)) % 26) + b'A',
                            b'a'..=b'z' => ((b.wrapping_sub(b'a').wrapping_sub(13)) % 26) + b'a',
                            _ => b,
                        } as char
                    })
                    .collect()
            }
            
            deobfuscate()
        }
    };
    
    TokenStream::from(expanded)
}

