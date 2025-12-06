// Intelligent Hook Selection
// Dynamically enables/disables hooks based on observed data

use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};
use std::collections::HashMap;

pub struct HookStatistics {
    pub hook_name: String,
    pub total_calls: u64,
    pub matches: u64,
    pub bytes_captured: u64,
    pub last_match: Option<Instant>,
    pub enabled: bool,
}

impl HookStatistics {
    fn match_rate(&self) -> f32 {
        if self.total_calls == 0 {
            return 0.0;
        }
        self.matches as f32 / self.total_calls as f32
    }
}

pub struct IntelligentHookManager {
    hooks: Arc<Mutex<HashMap<String, HookStatistics>>>,
    analysis_interval: Duration,
    min_match_rate: f32, // Minimum match rate to keep hook enabled
}

impl IntelligentHookManager {
    pub fn new() -> Self {
        Self {
            hooks: Arc::new(Mutex::new(HashMap::new())),
            analysis_interval: Duration::from_secs(3600), // 1 hour
            min_match_rate: 0.01, // 1% minimum
        }
    }
    
    /// Register hook
    pub async fn register_hook(&self, hook_name: String) {
        let mut hooks = self.hooks.lock().await;
        hooks.insert(hook_name.clone(), HookStatistics {
            hook_name: hook_name.clone(),
            total_calls: 0,
            matches: 0,
            bytes_captured: 0,
            last_match: None,
            enabled: true,
        });
    }
    
    /// Record hook call
    pub async fn record_call(&self, hook_name: &str, matched: bool, bytes: usize) {
        let mut hooks = self.hooks.lock().await;
        if let Some(stat) = hooks.get_mut(hook_name) {
            stat.total_calls += 1;
            if matched {
                stat.matches += 1;
                stat.bytes_captured += bytes as u64;
                stat.last_match = Some(Instant::now());
            }
        }
    }
    
    /// Analyze and optimize hooks
    pub async fn analyze_and_optimize(&self) -> Vec<String> {
        let mut hooks = self.hooks.lock().await;
        let mut disabled = Vec::new();
        
        for (name, stat) in hooks.iter_mut() {
            let match_rate = stat.match_rate();
            
            if match_rate < self.min_match_rate && stat.enabled {
                // Disable unproductive hook
                stat.enabled = false;
                disabled.push(name.clone());
            } else if match_rate >= self.min_match_rate && !stat.enabled {
                // Re-enable if match rate improved
                stat.enabled = true;
            }
        }
        
        disabled
    }
    
    /// Check if hook is enabled
    pub async fn is_enabled(&self, hook_name: &str) -> bool {
        let hooks = self.hooks.lock().await;
        hooks.get(hook_name)
            .map(|s| s.enabled)
            .unwrap_or(false)
    }
    
    /// Get hook statistics
    pub async fn get_statistics(&self) -> Vec<HookStatistics> {
        let hooks = self.hooks.lock().await;
        hooks.values().cloned().collect()
    }
    
    /// Start periodic analysis
    pub async fn start_analysis_loop(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(manager.analysis_interval).await;
                let disabled = manager.analyze_and_optimize().await;
                if !disabled.is_empty() {
                    eprintln!("[HOOKS] Disabled unproductive hooks: {:?}", disabled);
                }
            }
        });
    }
}

impl Clone for IntelligentHookManager {
    fn clone(&self) -> Self {
        Self {
            hooks: self.hooks.clone(),
            analysis_interval: self.analysis_interval,
            min_match_rate: self.min_match_rate,
        }
    }
}

impl Clone for HookStatistics {
    fn clone(&self) -> Self {
        Self {
            hook_name: self.hook_name.clone(),
            total_calls: self.total_calls,
            matches: self.matches,
            bytes_captured: self.bytes_captured,
            last_match: self.last_match,
            enabled: self.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_intelligent_hooks() {
        let manager = IntelligentHookManager::new();
        
        manager.register_hook("fwrite".to_string()).await;
        manager.register_hook("send".to_string()).await;
        
        // Record calls
        for _ in 0..1000 {
            manager.record_call("fwrite", false, 0).await;
        }
        
        for _ in 0..100 {
            manager.record_call("send", true, 100).await;
        }
        
        let disabled = manager.analyze_and_optimize().await;
        assert!(disabled.contains(&"fwrite".to_string()));
        assert!(!disabled.contains(&"send".to_string()));
    }
}


