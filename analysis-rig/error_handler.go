package main

import (
	"fmt"
	"time"
)

// RetryConfig holds configuration for retry operations
type RetryConfig struct {
	MaxAttempts     int
	InitialDelay   time.Duration
	MaxDelay       time.Duration
	BackoffMultiplier float64
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      time.Second,
		MaxDelay:          time.Second * 30,
		BackoffMultiplier: 2.0,
	}
}

// RetryWithBackoff executes an operation with exponential backoff retry
func RetryWithBackoff(config RetryConfig, operation func() error) error {
	delay := config.InitialDelay
	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err

		if attempt < config.MaxAttempts {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * config.BackoffMultiplier)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Network errors are usually retryable
	errStr := err.Error()
	retryablePatterns := []string{
		"network",
		"timeout",
		"connection",
		"temporary",
		"unavailable",
	}

	for _, pattern := range retryablePatterns {
		if findSubstring(errStr, pattern) {
			return true
		}
	}

	return false
}

// RecoverFromError attempts to recover from an error
func RecoverFromError(err error) error {
	if err == nil {
		return nil
	}

	// Some errors are recoverable, others are not
	if IsRetryableError(err) {
		return nil // Can retry
	}

	// Non-retryable errors
	return fmt.Errorf("non-retryable error: %w", err)
}

// findSubstring checks if a string contains a substring (case-sensitive)
func findSubstring(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ProtosyteError represents a framework-specific error
type ProtosyteError struct {
	Component string
	Operation string
	Message   string
	Err       error
}

func (e *ProtosyteError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %s: %v", e.Component, e.Operation, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Component, e.Operation, e.Message)
}

func (e *ProtosyteError) Unwrap() error {
	return e.Err
}

// NewProtosyteError creates a new ProtosyteError
func NewProtosyteError(component, operation, message string, err error) *ProtosyteError {
	return &ProtosyteError{
		Component: component,
		Operation: operation,
		Message:   message,
		Err:       err,
	}
}

