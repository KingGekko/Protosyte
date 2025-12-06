// Constants for Protosyte Framework
// Centralized configuration values to replace magic numbers

use std::time::Duration;

// Polling intervals (milliseconds)
pub const POLL_INTERVAL_FAST_MS: u64 = 50;
pub const POLL_INTERVAL_NORMAL_MS: u64 = 100;
pub const POLL_INTERVAL_SLOW_MS: u64 = 200;
pub const POLL_INTERVAL_VERY_SLOW_MS: u64 = 500;

// Duration constants
pub const POLL_INTERVAL_FAST: Duration = Duration::from_millis(POLL_INTERVAL_FAST_MS);
pub const POLL_INTERVAL_NORMAL: Duration = Duration::from_millis(POLL_INTERVAL_NORMAL_MS);
pub const POLL_INTERVAL_SLOW: Duration = Duration::from_millis(POLL_INTERVAL_SLOW_MS);
pub const POLL_INTERVAL_VERY_SLOW: Duration = Duration::from_millis(POLL_INTERVAL_VERY_SLOW_MS);

// Buffer sizes (bytes)
pub const BUFFER_SIZE_SMALL: usize = 512;
pub const BUFFER_SIZE_DEFAULT: usize = 1024;
pub const BUFFER_SIZE_MEDIUM: usize = 2048;
pub const BUFFER_SIZE_LARGE: usize = 4096;
pub const BUFFER_SIZE_XLARGE: usize = 8192;
pub const BUFFER_SIZE_XXLARGE: usize = 16384;
pub const BUFFER_SIZE_XXXLARGE: usize = 32768;

// Timeout values (milliseconds)
pub const TIMEOUT_SHORT_MS: u64 = 1000;
pub const TIMEOUT_NORMAL_MS: u64 = 5000;
pub const TIMEOUT_LONG_MS: u64 = 30000;
pub const TIMEOUT_VERY_LONG_MS: u64 = 60000;

pub const TIMEOUT_SHORT: Duration = Duration::from_millis(TIMEOUT_SHORT_MS);
pub const TIMEOUT_NORMAL: Duration = Duration::from_millis(TIMEOUT_NORMAL_MS);
pub const TIMEOUT_LONG: Duration = Duration::from_millis(TIMEOUT_LONG_MS);
pub const TIMEOUT_VERY_LONG: Duration = Duration::from_millis(TIMEOUT_VERY_LONG_MS);

// Circuit breaker thresholds
pub const CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
pub const CIRCUIT_BREAKER_SUCCESS_THRESHOLD: u32 = 2;
pub const CIRCUIT_BREAKER_TIMEOUT_MS: u64 = 60000;

// Rate limiting
pub const RATE_LIMIT_DEFAULT_KBPS: u64 = 64;
pub const RATE_LIMIT_DEFAULT_MSG_PER_MIN: usize = 10;

// Retry configuration
pub const RETRY_MAX_ATTEMPTS: u32 = 3;
pub const RETRY_INITIAL_DELAY_MS: u64 = 1000;
pub const RETRY_MAX_DELAY_MS: u64 = 30000;
pub const RETRY_BACKOFF_MULTIPLIER: f64 = 2.0;

// Clipboard monitoring
pub const CLIPBOARD_CHECK_INTERVAL_SECS: u64 = 5;

// Network configuration
pub const NETWORK_CONNECT_TIMEOUT_MS: u64 = 10000;
pub const NETWORK_READ_TIMEOUT_MS: u64 = 30000;

// Exfiltration configuration
pub const EXFIL_DEFAULT_INTERVAL_SECS: u64 = 347;
pub const EXFIL_DEFAULT_JITTER: f32 = 0.25;

