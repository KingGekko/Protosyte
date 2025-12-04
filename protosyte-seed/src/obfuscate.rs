// Compile-time string obfuscation utilities
// In production, this would use build.rs to obfuscate strings at compile time

pub struct ObfuscatedString {
    data: Vec<u8>,
    key: u8,
}

impl ObfuscatedString {
    pub fn new(plaintext: &str, key: u8) -> Self {
        let data: Vec<u8> = plaintext.bytes()
            .map(|b| b ^ key)
            .collect();
        Self { data, key }
    }
    
    pub fn reveal(&self) -> String {
        self.data.iter()
            .map(|&b| (b ^ self.key) as char)
            .collect()
    }
}

// Macro for compile-time obfuscation
#[macro_export]
macro_rules! obfuscate {
    ($s:expr) => {{
        // In production, this would be expanded at compile time
        // For now, return the string as-is (security through environment variables)
        $s
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_obfuscated_string_new() {
        let obf = ObfuscatedString::new("test", 0x42);
        assert_eq!(obf.data.len(), 4);
        assert_eq!(obf.key, 0x42);
    }
    
    #[test]
    fn test_obfuscated_string_reveal() {
        let obf = ObfuscatedString::new("hello", 0x42);
        let revealed = obf.reveal();
        assert_eq!(revealed, "hello");
    }
    
    #[test]
    fn test_obfuscated_string_different_keys() {
        let obf1 = ObfuscatedString::new("test", 0x42);
        let obf2 = ObfuscatedString::new("test", 0x99);
        
        // Different keys should produce different obfuscated data
        assert_ne!(obf1.data, obf2.data);
        
        // But both should reveal to the same string
        assert_eq!(obf1.reveal(), obf2.reveal());
    }
    
    #[test]
    fn test_obfuscated_string_empty() {
        let obf = ObfuscatedString::new("", 0x42);
        assert_eq!(obf.reveal(), "");
    }
    
    #[test]
    fn test_obfuscated_string_unicode() {
        let obf = ObfuscatedString::new("test 🚀", 0x42);
        let revealed = obf.reveal();
        assert_eq!(revealed, "test 🚀");
    }
    
    #[test]
    fn test_obfuscate_macro() {
        let result = obfuscate!("test");
        assert_eq!(result, "test");
    }
}
