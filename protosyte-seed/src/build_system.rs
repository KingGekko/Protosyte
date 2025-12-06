// Cross-Platform Build System
// Unified build system for all platforms

use std::process::Command;
use anyhow::{Result, Context};
use std::path::PathBuf;

pub struct BuildSystem {
    target_dir: PathBuf,
}

impl BuildSystem {
    pub fn new() -> Self {
        Self {
            target_dir: PathBuf::from("target"),
        }
    }
    
    /// Build all platforms
    pub fn build_all(&self) -> Result<()> {
        println!("Building all platforms...");
        
        self.build_linux()?;
        self.build_windows()?;
        self.build_macos()?;
        
        println!("All platforms built successfully!");
        Ok(())
    }
    
    /// Build Linux
    pub fn build_linux(&self) -> Result<()> {
        println!("Building Linux...");
        
        Command::new("cargo")
            .args(&["build", "--release", "--target", "x86_64-unknown-linux-gnu"])
            .status()
            .context("Failed to build Linux")?;
        
        Ok(())
    }
    
    /// Build Windows
    pub fn build_windows(&self) -> Result<()> {
        println!("Building Windows...");
        
        Command::new("cargo")
            .args(&["build", "--release", "--target", "x86_64-pc-windows-msvc"])
            .status()
            .context("Failed to build Windows")?;
        
        Ok(())
    }
    
    /// Build macOS
    pub fn build_macos(&self) -> Result<()> {
        println!("Building macOS...");
        
        Command::new("cargo")
            .args(&["build", "--release", "--target", "x86_64-apple-darwin"])
            .status()
            .context("Failed to build macOS")?;
        
        Ok(())
    }
    
    /// Clean build artifacts
    pub fn clean(&self) -> Result<()> {
        println!("Cleaning build artifacts...");
        
        Command::new("cargo")
            .args(&["clean"])
            .status()
            .context("Failed to clean")?;
        
        Ok(())
    }
    
    /// Run tests for all platforms
    pub fn test_all(&self) -> Result<()> {
        println!("Running tests...");
        
        Command::new("cargo")
            .args(&["test", "--all-features"])
            .status()
            .context("Failed to run tests")?;
        
        Ok(())
    }
    
    /// Build with specific features
    pub fn build_with_features(&self, features: &[&str], target: Option<&str>) -> Result<()> {
        let mut args: Vec<String> = vec!["build".to_string(), "--release".to_string()];
        
        if !features.is_empty() {
            let features_str = features.join(",");
            args.push("--features".to_string());
            args.push(features_str);
        }
        
        if let Some(tgt) = target {
            args.push("--target".to_string());
            args.push(tgt.to_string());
        }
        
        Command::new("cargo")
            .args(&args)
            .status()
            .context("Failed to build with features")?;
        
        Ok(())
    }
    
    /// Package artifacts
    pub fn package(&self, platform: &str) -> Result<PathBuf> {
        println!("Packaging {}...", platform);
        
        let target = match platform {
            "linux" => "x86_64-unknown-linux-gnu",
            "windows" => "x86_64-pc-windows-msvc",
            "macos" => "x86_64-apple-darwin",
            _ => return Err(anyhow::anyhow!("Unknown platform: {}", platform)),
        };
        
        let binary_name = if platform == "windows" {
            "protosyte-seed.exe"
        } else {
            "protosyte-seed"
        };
        
        let binary_path = self.target_dir
            .join("release")
            .join(binary_name);
        
        if !binary_path.exists() {
            return Err(anyhow::anyhow!("Binary not found: {:?}", binary_path));
        }
        
        // Create package directory
        let package_dir = self.target_dir.join("package").join(platform);
        std::fs::create_dir_all(&package_dir)?;
        
        // Copy binary
        let package_binary = package_dir.join(binary_name);
        std::fs::copy(&binary_path, &package_binary)?;
        
        // Create README
        let readme = package_dir.join("README.txt");
        std::fs::write(&readme, format!(
            "Protosyte Seed - {}\n\
            Binary: {}\n\
            Build date: {}\n",
            platform,
            binary_name,
            chrono::Utc::now().to_rfc3339()
        ))?;
        
        Ok(package_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_system() {
        let build = BuildSystem::new();
        // Test structure
        let _ = build;
    }
}

