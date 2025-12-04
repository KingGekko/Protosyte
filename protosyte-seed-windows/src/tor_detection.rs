// Automatic Tor Port Detection and Fallback
use std::net::TcpStream;
use std::time::Duration;

pub struct TorManager;

impl TorManager {
    // Automatically detect which Tor port is available
    pub fn detect_tor_port() -> String {
        // Try Tor service port first (9050)
        if Self::test_port("127.0.0.1:9050") {
            return "socks5://127.0.0.1:9050".to_string();
        }
        
        // Fallback to Tor Browser port (9150)
        if Self::test_port("127.0.0.1:9150") {
            return "socks5://127.0.0.1:9150".to_string();
        }
        
        // Try alternative ports
        for port in &[9051, 9052, 9151, 9152] {
            if Self::test_port(&format!("127.0.0.1:{}", port)) {
                return format!("socks5://127.0.0.1:{}", port);
            }
        }
        
        // Default fallback
        "socks5://127.0.0.1:9050".to_string()
    }
    
    fn test_port(addr: &str) -> bool {
        TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_secs(1),
        ).is_ok()
    }
    
    // Check if Tor is running and accessible
    pub fn verify_tor_connection() -> bool {
        use reqwest::blocking::Client;
        use reqwest::Proxy;
        
        let proxy_url = Self::detect_tor_port();
        if let Ok(proxy) = Proxy::all(&proxy_url) {
            if let Ok(client) = Client::builder()
                .proxy(proxy)
                .timeout(Duration::from_secs(5))
                .build()
            {
                // Try to connect through Tor
                if client.get("https://check.torproject.org/api/ip")
                    .send()
                    .is_ok()
                {
                    return true;
                }
            }
        }
        false
    }
    
    // Start Tor if not running (requires Tor executable)
    pub fn ensure_tor_running() -> Result<(), String> {
        if !Self::verify_tor_connection() {
            // Try to start Tor service
            use std::process::Command;
            
            // Check if Tor service exists
            let output = Command::new("sc")
                .args(&["query", "Tor"])
                .output();
            
            if let Ok(output) = output {
                if output.status.success() {
                    // Start service
                    Command::new("sc")
                        .args(&["start", "Tor"])
                        .output()
                        .map_err(|e| format!("Failed to start Tor: {}", e))?;
                }
            }
            
            // Alternative: Check for Tor Browser
            let tor_browser_paths = vec![
                r"C:\Users\%USERNAME%\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
                r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
            ];
            
            for path in tor_browser_paths {
                let expanded = std::env::var("USERPROFILE")
                    .map(|u| path.replace("%USERNAME%", &u))
                    .unwrap_or_else(|_| path.to_string());
                
                if std::path::Path::new(&expanded).exists() {
                    // Start Tor Browser's Tor
                    Command::new(&expanded)
                        .spawn()
                        .map_err(|e| format!("Failed to start Tor: {}", e))?;
                    
                    // Wait for it to start
                    std::thread::sleep(Duration::from_secs(5));
                    return Ok(());
                }
            }
            
            return Err("Tor not found and cannot be started".to_string());
        }
        
        Ok(())
    }
}

