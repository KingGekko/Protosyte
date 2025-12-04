package main

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()
	
	if config.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts=3, got %d", config.MaxAttempts)
	}
	
	if config.InitialDelay != time.Second {
		t.Errorf("Expected InitialDelay=1s, got %v", config.InitialDelay)
	}
	
	if config.MaxDelay != 30*time.Second {
		t.Errorf("Expected MaxDelay=30s, got %v", config.MaxDelay)
	}
	
	if config.BackoffMultiplier != 2.0 {
		t.Errorf("Expected BackoffMultiplier=2.0, got %f", config.BackoffMultiplier)
	}
}

func TestRetryWithBackoffSuccess(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      time.Millisecond * 10,
		MaxDelay:          time.Second,
		BackoffMultiplier: 2.0,
	}
	
	attempt := 0
	err := RetryWithBackoff(config, func() error {
		attempt++
		if attempt == 1 {
			return nil // Success on first attempt
		}
		return errors.New("should not reach here")
	})
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if attempt != 1 {
		t.Errorf("Expected 1 attempt, got %d", attempt)
	}
}

func TestRetryWithBackoffFailure(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      time.Millisecond * 10,
		MaxDelay:          time.Second,
		BackoffMultiplier: 2.0,
	}
	
	attempt := 0
	err := RetryWithBackoff(config, func() error {
		attempt++
		return errors.New("persistent error")
	})
	
	if err == nil {
		t.Error("Expected error, got nil")
	}
	
	if attempt != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempt)
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"network error", errors.New("network connection failed"), true},
		{"timeout error", errors.New("request timeout"), true},
		{"connection error", errors.New("connection refused"), true},
		{"temporary error", errors.New("temporary failure"), true},
		{"unavailable error", errors.New("service unavailable"), true},
		{"other error", errors.New("some other error"), false},
		{"nil error", nil, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryableError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRecoverFromError(t *testing.T) {
	// Retryable error should be recoverable
	retryableErr := errors.New("network error")
	if RecoverFromError(retryableErr) != nil {
		t.Error("Expected nil (recoverable), got error")
	}
	
	// Non-retryable error should not be recoverable
	nonRetryableErr := errors.New("invalid configuration")
	if RecoverFromError(nonRetryableErr) == nil {
		t.Error("Expected error (non-recoverable), got nil")
	}
}

func TestProtosyteError(t *testing.T) {
	err := NewProtosyteError("TEST", "operation", "test message", nil)
	
	if err.Error() == "" {
		t.Error("Expected error message, got empty string")
	}
	
	if err.Component != "TEST" {
		t.Errorf("Expected Component=TEST, got %s", err.Component)
	}
	
	if err.Operation != "operation" {
		t.Errorf("Expected Operation=operation, got %s", err.Operation)
	}
	
	if err.Message != "test message" {
		t.Errorf("Expected Message=test message, got %s", err.Message)
	}
}

func TestProtosyteErrorWithWrappedError(t *testing.T) {
	wrappedErr := errors.New("wrapped error")
	err := NewProtosyteError("TEST", "operation", "test message", wrappedErr)
	
	if err.Unwrap() != wrappedErr {
		t.Error("Expected wrapped error to be unwrappable")
	}
	
	if err.Error() == "" {
		t.Error("Expected error message, got empty string")
	}
}

