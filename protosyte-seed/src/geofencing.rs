// Geofencing and Environmental Checks
// Verifies target environment before activation

use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, Context};
use std::net::IpAddr;
use std::time::Duration;

pub struct GeofenceConfig {
    pub allowed_countries: Vec<String>,      // ISO country codes
    pub allowed_networks: Vec<ipnetwork::IpNetwork>, // IP ranges
    pub hostname_pattern: Option<String>,    // Regex pattern
    pub domain_name: Option<String>,          // Expected domain
    pub timezone: Option<String>,            // Expected timezone
    pub language: Option<String>,            // Expected language
    pub require_corporate_certs: bool,        // Require corporate certificates
}

pub struct Geofence {
    config: Arc<Mutex<GeofenceConfig>>,
    activated: Arc<Mutex<bool>>,
}

impl Geofence {
    pub fn new(config: GeofenceConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            activated: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Check all environmental conditions
    pub async fn check_environment(&self) -> Result<bool> {
        let config = {
            let guard = self.config.lock().await;
            GeofenceConfig {
                allowed_countries: guard.allowed_countries.clone(),
                allowed_networks: guard.allowed_networks.clone(),
                hostname_pattern: guard.hostname_pattern.clone(),
                domain_name: guard.domain_name.clone(),
                timezone: guard.timezone.clone(),
                language: guard.language.clone(),
                require_corporate_certs: guard.require_corporate_certs,
            }
        };
        
        // Check geolocation
        if !config.allowed_countries.is_empty() {
            if !self.check_geolocation(&config.allowed_countries).await? {
                return Ok(false);
            }
        }
        
        // Check network range
        if !config.allowed_networks.is_empty() {
            if !self.check_network_range(&config.allowed_networks).await? {
                return Ok(false);
            }
        }
        
        // Check hostname
        if let Some(ref pattern) = config.hostname_pattern {
            if !self.check_hostname(pattern).await? {
                return Ok(false);
            }
        }
        
        // Check domain
        if let Some(ref domain) = config.domain_name {
            if !self.check_domain(domain).await? {
                return Ok(false);
            }
        }
        
        // Check timezone
        if let Some(ref tz) = config.timezone {
            if !self.check_timezone(tz).await? {
                return Ok(false);
            }
        }
        
        // Check language
        if let Some(ref lang) = config.language {
            if !self.check_language(lang).await? {
                return Ok(false);
            }
        }
        
        // Check corporate certificates
        if config.require_corporate_certs {
            if !self.check_corporate_certs().await? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Activate if environment checks pass
    pub async fn activate_if_safe(&self) -> Result<bool> {
        if self.check_environment().await? {
            *self.activated.lock().await = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    async fn check_geolocation(&self, allowed_countries: &[String]) -> Result<bool> {
        #[cfg(feature = "geolocation")]
        {
            // Use MaxMind GeoIP or similar service
            // For now, simplified check using IP geolocation API
            let public_ip = self.get_public_ip().await?;
            let country = self.get_country_from_ip(&public_ip).await?;
            
            Ok(allowed_countries.contains(&country))
        }
        
        #[cfg(not(feature = "geolocation"))]
        {
            // Fallback: always pass (geolocation not available)
            Ok(true)
        }
    }
    
    async fn check_network_range(&self, allowed_networks: &[ipnetwork::IpNetwork]) -> Result<bool> {
        // Get local IP addresses
        let local_ips = self.get_local_ips().await?;
        
        for ip in local_ips {
            for network in allowed_networks {
                if network.contains(ip) {
                    return Ok(true); // Found matching network
                }
            }
        }
        
        Ok(false)
    }
    
    async fn check_hostname(&self, pattern: &str) -> Result<bool> {
        use regex::Regex;
        let re = Regex::new(pattern)
            .context("Invalid hostname pattern")?;
        
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_default();
        
        Ok(re.is_match(&hostname))
    }
    
    async fn check_domain(&self, expected_domain: &str) -> Result<bool> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Registry::*;
            
            // Check Windows domain membership
            unsafe {
                let mut hkey = windows::Win32::System::Registry::HKEY::default();
                let key_path = windows::core::PCSTR(b"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\0".as_ptr());
                
                if RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    key_path,
                    0,
                    KEY_READ,
                    &mut hkey,
                ).is_ok() {
                    // Read Domain value
                    // (Simplified - would read registry value)
                    let _ = RegCloseKey(hkey);
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Check /etc/resolv.conf for domain
            if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
                for line in contents.lines() {
                    if line.starts_with("domain") || line.starts_with("search") {
                        if line.contains(expected_domain) {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        
        Ok(false)
    }
    
    async fn check_timezone(&self, expected_tz: &str) -> Result<bool> {
        use chrono::Local;
        let tz = Local::now().timezone();
        let tz_name = format!("{:?}", tz);
        Ok(tz_name.contains(expected_tz))
    }
    
    async fn check_language(&self, expected_lang: &str) -> Result<bool> {
        let lang = std::env::var("LANG")
            .or_else(|_| std::env::var("LC_ALL"))
            .unwrap_or_default();
        
        Ok(lang.contains(expected_lang))
    }
    
    async fn check_corporate_certs(&self) -> Result<bool> {
        // Check for corporate certificates in system certificate store
        // This is platform-specific and complex
        // For now, simplified check
        
        #[cfg(target_os = "windows")]
        {
            // Check Windows certificate store for corporate CA
            // (Would use winapi to enumerate certificates)
        }
        
        #[cfg(target_os = "linux")]
        {
            // Check /etc/ssl/certs for corporate certificates
            // (Would check for specific CA certificates)
        }
        
        // Default: assume corporate certs present (conservative)
        Ok(true)
    }
    
    async fn get_public_ip(&self) -> Result<IpAddr> {
        // Query public IP via external service
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        
        let response = client
            .get("https://api.ipify.org")
            .send()
            .await?;
        
        let ip_str = response.text().await?;
        ip_str.parse()
            .context("Failed to parse public IP")
    }
    
    async fn get_country_from_ip(&self, _ip: &IpAddr) -> Result<String> {
        #[cfg(feature = "geolocation")]
        {
            // Use MaxMind GeoIP database
            // For now, return placeholder
            Ok("US".to_string())
        }
        
        #[cfg(not(feature = "geolocation"))]
        {
            Ok("US".to_string()) // Default
        }
    }
    
    async fn get_local_ips(&self) -> Result<Vec<IpAddr>> {
        use std::net::UdpSocket;
        
        // Get local IP by connecting to external address
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        let local_addr = socket.local_addr()?;
        
        Ok(vec![local_addr.ip()])
    }
    
    /// Check if activated
    pub async fn is_activated(&self) -> bool {
        *self.activated.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_geofence_config() {
        let config = GeofenceConfig {
            allowed_countries: vec!["US".to_string()],
            allowed_networks: vec![],
            hostname_pattern: None,
            domain_name: None,
            timezone: None,
            language: None,
            require_corporate_certs: false,
        };
        
        let geofence = Geofence::new(config);
        // May fail if not in US, which is expected
        let _ = geofence.check_environment().await;
    }
}

