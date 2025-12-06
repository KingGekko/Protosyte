// Screenshot Capture Module
// Captures screenshots at configurable intervals

#[cfg(feature = "screenshot")]
use screenshots::Screen;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;
use std::time::Duration;

pub struct ScreenshotConfig {
    pub interval: Duration,
    pub trigger_keywords: Vec<String>,
    pub enabled: bool,
}

pub struct ScreenshotCapture {
    config: Arc<Mutex<ScreenshotConfig>>,
}

impl ScreenshotCapture {
    pub fn new(config: ScreenshotConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
        }
    }
    
    /// Capture screenshot
    #[cfg(feature = "screenshot")]
    pub async fn capture(&self) -> Result<Vec<u8>> {
        let screens = Screen::all()?;
        if screens.is_empty() {
            return Err(anyhow::anyhow!("No screens available"));
        }
        
        let screen = &screens[0];
        let image = screen.capture()?;
        
        // Convert to JPEG
        let mut jpeg_data = Vec::new();
        {
            let mut cursor = std::io::Cursor::new(&mut jpeg_data);
            image.write_to(&mut cursor, image::ImageOutputFormat::Jpeg(85))?;
        }
        
        Ok(jpeg_data)
    }
    
    #[cfg(not(feature = "screenshot"))]
    pub async fn capture(&self) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("Screenshot capture requires 'screenshot' feature"))
    }
    
    /// Start periodic screenshot capture
    pub async fn start_capture_loop(&self, callback: impl Fn(Vec<u8>) -> tokio::task::JoinHandle<()>) {
        let config = self.config.clone();
        let capture = self.clone();
        
        tokio::spawn(async move {
            loop {
                let interval = {
                    let cfg = config.lock().await;
                    if !cfg.enabled {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        continue;
                    }
                    cfg.interval
                };
                
                tokio::time::sleep(interval).await;
                
                if let Ok(screenshot) = capture.capture().await {
                    callback(screenshot);
                }
            }
        });
    }
}

impl Clone for ScreenshotCapture {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[ignore] // Requires display
    async fn test_screenshot_capture() {
        let config = ScreenshotConfig {
            interval: Duration::from_secs(30),
            trigger_keywords: vec![],
            enabled: true,
        };
        
        let capture = ScreenshotCapture::new(config);
        let _ = capture.capture().await;
    }
}


