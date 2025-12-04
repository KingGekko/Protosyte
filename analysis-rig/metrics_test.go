package main

import (
	"testing"
	"time"
)

func TestMetricsInitialization(t *testing.T) {
	ResetMetrics()
	metrics := GetMetrics()
	
	if metrics.PayloadsRetrieved != 0 {
		t.Errorf("Expected PayloadsRetrieved=0, got %d", metrics.PayloadsRetrieved)
	}
	
	if metrics.PayloadsAnalyzed != 0 {
		t.Errorf("Expected PayloadsAnalyzed=0, got %d", metrics.PayloadsAnalyzed)
	}
	
	if metrics.PayloadsFailed != 0 {
		t.Errorf("Expected PayloadsFailed=0, got %d", metrics.PayloadsFailed)
	}
	
	if metrics.BytesProcessed != 0 {
		t.Errorf("Expected BytesProcessed=0, got %d", metrics.BytesProcessed)
	}
	
	if metrics.RecordsStored != 0 {
		t.Errorf("Expected RecordsStored=0, got %d", metrics.RecordsStored)
	}
	
	if metrics.Uptime < 0 {
		t.Error("Expected Uptime >= 0")
	}
}

func TestIncrementPayloadsRetrieved(t *testing.T) {
	ResetMetrics()
	
	IncrementPayloadsRetrieved()
	IncrementPayloadsRetrieved()
	
	metrics := GetMetrics()
	if metrics.PayloadsRetrieved != 2 {
		t.Errorf("Expected PayloadsRetrieved=2, got %d", metrics.PayloadsRetrieved)
	}
}

func TestIncrementPayloadsAnalyzed(t *testing.T) {
	ResetMetrics()
	
	IncrementPayloadsAnalyzed()
	IncrementPayloadsAnalyzed()
	IncrementPayloadsAnalyzed()
	
	metrics := GetMetrics()
	if metrics.PayloadsAnalyzed != 3 {
		t.Errorf("Expected PayloadsAnalyzed=3, got %d", metrics.PayloadsAnalyzed)
	}
}

func TestIncrementPayloadsFailed(t *testing.T) {
	ResetMetrics()
	
	IncrementPayloadsFailed()
	
	metrics := GetMetrics()
	if metrics.PayloadsFailed != 1 {
		t.Errorf("Expected PayloadsFailed=1, got %d", metrics.PayloadsFailed)
	}
}

func TestAddBytesProcessed(t *testing.T) {
	ResetMetrics()
	
	AddBytesProcessed(1024)
	AddBytesProcessed(2048)
	
	metrics := GetMetrics()
	if metrics.BytesProcessed != 3072 {
		t.Errorf("Expected BytesProcessed=3072, got %d", metrics.BytesProcessed)
	}
}

func TestIncrementRecordsStored(t *testing.T) {
	ResetMetrics()
	
	IncrementRecordsStored()
	IncrementRecordsStored()
	IncrementRecordsStored()
	IncrementRecordsStored()
	
	metrics := GetMetrics()
	if metrics.RecordsStored != 4 {
		t.Errorf("Expected RecordsStored=4, got %d", metrics.RecordsStored)
	}
}

func TestMetricsConcurrency(t *testing.T) {
	ResetMetrics()
	
	// Simulate concurrent access
	done := make(chan bool)
	
	go func() {
		for i := 0; i < 100; i++ {
			IncrementPayloadsRetrieved()
			AddBytesProcessed(100)
		}
		done <- true
	}()
	
	go func() {
		for i := 0; i < 100; i++ {
			IncrementPayloadsAnalyzed()
			IncrementRecordsStored()
		}
		done <- true
	}()
	
	<-done
	<-done
	
	metrics := GetMetrics()
	if metrics.PayloadsRetrieved != 100 {
		t.Errorf("Expected PayloadsRetrieved=100, got %d", metrics.PayloadsRetrieved)
	}
	
	if metrics.PayloadsAnalyzed != 100 {
		t.Errorf("Expected PayloadsAnalyzed=100, got %d", metrics.PayloadsAnalyzed)
	}
	
	if metrics.BytesProcessed != 10000 {
		t.Errorf("Expected BytesProcessed=10000, got %d", metrics.BytesProcessed)
	}
	
	if metrics.RecordsStored != 100 {
		t.Errorf("Expected RecordsStored=100, got %d", metrics.RecordsStored)
	}
}

func TestMetricsUptime(t *testing.T) {
	ResetMetrics()
	
	// Wait a bit
	time.Sleep(10 * time.Millisecond)
	
	metrics := GetMetrics()
	if metrics.Uptime < 10*time.Millisecond {
		t.Errorf("Expected Uptime >= 10ms, got %v", metrics.Uptime)
	}
}

func TestResetMetrics(t *testing.T) {
	IncrementPayloadsRetrieved()
	IncrementPayloadsAnalyzed()
	AddBytesProcessed(1024)
	
	ResetMetrics()
	
	metrics := GetMetrics()
	if metrics.PayloadsRetrieved != 0 {
		t.Errorf("Expected PayloadsRetrieved=0 after reset, got %d", metrics.PayloadsRetrieved)
	}
	
	if metrics.PayloadsAnalyzed != 0 {
		t.Errorf("Expected PayloadsAnalyzed=0 after reset, got %d", metrics.PayloadsAnalyzed)
	}
	
	if metrics.BytesProcessed != 0 {
		t.Errorf("Expected BytesProcessed=0 after reset, got %d", metrics.BytesProcessed)
	}
}

