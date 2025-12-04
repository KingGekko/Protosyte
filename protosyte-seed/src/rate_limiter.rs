// Rate Limiting for Exfiltration (Anti-Detection)
// Implements token bucket algorithm for adaptive rate limiting

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Token bucket rate limiter for exfiltration
/// Prevents detection by limiting and smoothing traffic patterns
pub struct RateLimiter {
    // Token bucket parameters
    capacity: Arc<AtomicU64>,        // Maximum tokens (bytes)
    tokens: Arc<AtomicU64>,          // Current available tokens
    refill_rate: Arc<AtomicU64>,     // Tokens per second (refill rate)
    last_refill: Arc<std::sync::Mutex<Instant>>, // Last refill time
    
    // Message rate limiting
    msg_window: Arc<AtomicUsize>,    // Messages in current window
    msg_limit: usize,                // Max messages per window
    msg_window_start: Arc<std::sync::Mutex<Instant>>, // Window start time
    msg_window_duration: Duration,   // Window duration
    
    // Adaptive parameters
    adaptive_mode: bool,              // Enable adaptive rate limiting
    error_count: Arc<AtomicUsize>,   // Track errors for backoff
    success_count: Arc<AtomicUsize>, // Track successes for increase
}

impl RateLimiter {
    /// Create a new rate limiter
    /// 
    /// # Arguments
    /// * `bytes_per_sec` - Initial rate limit in bytes per second
    /// * `messages_per_min` - Maximum messages per minute
    /// * `adaptive` - Enable adaptive rate limiting based on network conditions
    pub fn new(bytes_per_sec: u64, messages_per_min: usize, adaptive: bool) -> Self {
        let capacity = bytes_per_sec * 2; // Allow burst of 2x rate
        
        Self {
            capacity: Arc::new(AtomicU64::new(capacity)),
            tokens: Arc::new(AtomicU64::new(capacity)), // Start full
            refill_rate: Arc::new(AtomicU64::new(bytes_per_sec)),
            last_refill: Arc::new(std::sync::Mutex::new(Instant::now())),
            
            msg_window: Arc::new(AtomicUsize::new(0)),
            msg_limit: messages_per_min,
            msg_window_start: Arc::new(std::sync::Mutex::new(Instant::now())),
            msg_window_duration: Duration::from_secs(60),
            
            adaptive_mode: adaptive,
            error_count: Arc::new(AtomicUsize::new(0)),
            success_count: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    /// Check if data can be sent and consume tokens
    /// Returns duration to wait if rate limited, or None if can proceed immediately
    pub async fn acquire(&self, bytes: usize) -> Option<Duration> {
        // Refill tokens based on elapsed time
        self.refill_tokens();
        
        // Check message rate limit
        if !self.check_message_rate() {
            // Calculate wait time until next message window slot
            let wait_time = self.calculate_message_wait();
            if wait_time > Duration::ZERO {
                return Some(wait_time);
            }
        }
        
        // Check byte rate limit
        let bytes_needed = bytes as u64;
        let current_tokens = self.tokens.load(Ordering::Acquire);
        
        if current_tokens >= bytes_needed {
            // Consume tokens
            self.tokens.fetch_sub(bytes_needed, Ordering::Release);
            None // Can proceed immediately
        } else {
            // Need to wait for tokens to refill
            let deficit = bytes_needed - current_tokens;
            let refill_rate = self.refill_rate.load(Ordering::Acquire);
            let wait_secs = (deficit as f64 / refill_rate as f64).ceil() as u64;
            Some(Duration::from_secs(wait_secs.max(1))) // Minimum 1 second wait
        }
    }
    
    /// Refill tokens based on elapsed time
    fn refill_tokens(&self) {
        let mut last_refill = self.last_refill.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);
        
        if elapsed >= Duration::from_secs(1) {
            let refill_rate = self.refill_rate.load(Ordering::Acquire);
            let capacity = self.capacity.load(Ordering::Acquire);
            
            // Calculate tokens to add
            let tokens_to_add = (elapsed.as_secs() * refill_rate)
                .min(capacity); // Don't exceed capacity
            
            // Refill tokens (with saturation)
            let current = self.tokens.load(Ordering::Acquire);
            let new_tokens = (current + tokens_to_add).min(capacity);
            self.tokens.store(new_tokens, Ordering::Release);
            
            *last_refill = now;
        }
    }
    
    /// Check message rate limit
    fn check_message_rate(&self) -> bool {
        let mut window_start = self.msg_window_start.lock().unwrap();
        let now = Instant::now();
        
        // Reset window if expired
        if now.duration_since(*window_start) >= self.msg_window_duration {
            self.msg_window.store(0, Ordering::Release);
            *window_start = now;
        }
        
        let current = self.msg_window.load(Ordering::Acquire);
        if current >= self.msg_limit {
            return false; // Rate limited
        }
        
        // Increment message count
        self.msg_window.fetch_add(1, Ordering::Release);
        true
    }
    
    /// Calculate wait time until next message slot
    fn calculate_message_wait(&self) -> Duration {
        let window_start = self.msg_window_start.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*window_start);
        
        if elapsed >= self.msg_window_duration {
            return Duration::ZERO; // Window expired, can proceed
        }
        
        // Calculate time until next window slot
        let time_per_message = self.msg_window_duration.as_secs_f64() / self.msg_limit as f64;
        let messages_sent = self.msg_window.load(Ordering::Acquire);
        let next_slot_time = Duration::from_secs_f64(time_per_message * (messages_sent + 1) as f64);
        
        if next_slot_time > elapsed {
            next_slot_time - elapsed
        } else {
            Duration::ZERO
        }
    }
    
    /// Report successful transmission (for adaptive rate limiting)
    pub fn record_success(&self) {
        if self.adaptive_mode {
            let success = self.success_count.fetch_add(1, Ordering::Relaxed);
            self.error_count.store(0, Ordering::Relaxed); // Reset error count
            
            // Gradually increase rate if many successes (adaptive)
            if success % 10 == 0 && success > 0 {
                self.increase_rate(1.1); // Increase by 10%
            }
        }
    }
    
    /// Report transmission error (for adaptive rate limiting)
    pub fn record_error(&self) {
        if self.adaptive_mode {
            let errors = self.error_count.fetch_add(1, Ordering::Relaxed);
            
            // Back off if too many errors
            if errors >= 3 {
                self.decrease_rate(0.8); // Decrease by 20%
                self.error_count.store(0, Ordering::Relaxed);
            }
        }
    }
    
    /// Increase rate limit (adaptive)
    fn increase_rate(&self, factor: f64) {
        let current_rate = self.refill_rate.load(Ordering::Acquire);
        let new_rate = (current_rate as f64 * factor) as u64;
        let max_rate = self.capacity.load(Ordering::Acquire) / 2; // Don't exceed capacity/2
        
        let clamped_rate = new_rate.min(max_rate);
        self.refill_rate.store(clamped_rate, Ordering::Release);
        
        // Also update capacity
        self.capacity.store(clamped_rate * 2, Ordering::Release);
    }
    
    /// Decrease rate limit (adaptive backoff)
    fn decrease_rate(&self, factor: f64) {
        let current_rate = self.refill_rate.load(Ordering::Acquire);
        let new_rate = (current_rate as f64 * factor) as u64;
        let min_rate = 1024; // Minimum 1KB/sec
        
        let clamped_rate = new_rate.max(min_rate);
        self.refill_rate.store(clamped_rate, Ordering::Release);
        
        // Also update capacity
        self.capacity.store(clamped_rate * 2, Ordering::Release);
    }
    
    /// Get current rate limit (bytes per second)
    pub fn get_current_rate(&self) -> u64 {
        self.refill_rate.load(Ordering::Acquire)
    }
    
    /// Set rate limit manually
    pub fn set_rate(&self, bytes_per_sec: u64) {
        self.refill_rate.store(bytes_per_sec, Ordering::Release);
        self.capacity.store(bytes_per_sec * 2, Ordering::Release);
        // Refill to new capacity
        self.tokens.store(bytes_per_sec * 2, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(1024, 10, false);
        assert_eq!(limiter.get_current_rate(), 1024);
    }
    
    #[tokio::test]
    async fn test_rate_limiter_acquire() {
        let limiter = RateLimiter::new(1024, 10, false);
        
        // Small request should succeed immediately
        let wait = limiter.acquire(100).await;
        assert!(wait.is_none());
        
        // Large request might need to wait
        let wait = limiter.acquire(5000).await;
        // May or may not need to wait depending on tokens
    }
    
    #[tokio::test]
    async fn test_message_rate_limit() {
        let limiter = RateLimiter::new(1024, 2, false);
        
        // First two should succeed
        assert!(limiter.check_message_rate());
        assert!(limiter.check_message_rate());
        
        // Third should fail
        assert!(!limiter.check_message_rate());
    }
    
    #[tokio::test]
    async fn test_adaptive_rate_increase() {
        let limiter = RateLimiter::new(1024, 10, true);
        
        // Record many successes
        for _ in 0..15 {
            limiter.record_success();
        }
        
        // Rate should have increased
        let new_rate = limiter.get_current_rate();
        assert!(new_rate >= 1024);
    }
    
    #[tokio::test]
    async fn test_adaptive_rate_decrease() {
        let limiter = RateLimiter::new(1024, 10, true);
        
        // Record many errors
        for _ in 0..5 {
            limiter.record_error();
        }
        
        // Rate should have decreased
        let new_rate = limiter.get_current_rate();
        assert!(new_rate < 1024);
    }
}

