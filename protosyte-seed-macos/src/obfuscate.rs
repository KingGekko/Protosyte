// macOS compile-time string obfuscation
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

#[macro_export]
macro_rules! obfuscate {
    ($s:expr) => {{
        $s
    }};
}

