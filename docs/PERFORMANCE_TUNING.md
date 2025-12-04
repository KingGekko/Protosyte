# Performance Tuning Guide

## Overview

This guide covers performance optimization strategies for the Protosyte framework components, focusing on the Analysis Rig and database operations.

## Analysis Rig Performance

### Database Performance

#### SQLite Optimization

**Index Management:**

```bash
# Check existing indices
sqlite3 /tmp/rig_intel.db "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index';"

# Create additional indices for common queries
sqlite3 /tmp/rig_intel.db "
CREATE INDEX IF NOT EXISTS idx_data_type ON intelligence_records(data_type);
CREATE INDEX IF NOT EXISTS idx_host_fingerprint ON intelligence_records(host_fingerprint);
CREATE INDEX IF NOT EXISTS idx_collected_at ON intelligence_records(collected_at);
CREATE INDEX IF NOT EXISTS idx_mission_id ON intelligence_records(mission_id);
"
```

**Database Settings:**

```sql
-- Enable WAL mode for better concurrency
PRAGMA journal_mode = WAL;

-- Increase cache size (in KB)
PRAGMA cache_size = 10000;  -- 10MB cache

-- Increase page size (requires database recreation)
-- Note: Must be set before database creation
PRAGMA page_size = 4096;

-- Synchronous writes (trade-off between safety and speed)
PRAGMA synchronous = NORMAL;  -- or FULL for maximum safety
```

**Query Optimization:**

```bash
# Analyze query plans
sqlite3 /tmp/rig_intel.db "EXPLAIN QUERY PLAN SELECT * FROM intelligence_records WHERE data_type = 'CREDENTIAL_BLOB';"

# Use LIMIT to avoid large result sets
# Good:
SELECT * FROM intelligence_records LIMIT 100;
# Avoid:
SELECT * FROM intelligence_records;  -- Without limit
```

#### Large Dataset Handling

**Pagination:**

```bash
# Process records in batches
./protosyte-rig --mode records --limit 1000 | process_batch.sh
./protosyte-rig --mode records --limit 1000 --offset 1000 | process_batch.sh
```

**Streaming Results:**

```bash
# Stream large JSON exports
./protosyte-rig --mode records --limit 10000 --format json | \
  jq -c '.records[]' | \
  while read record; do
    # Process each record individually
    echo "$record"
  done
```

### Memory Management

**Large Record Processing:**

```go
// Process records in batches to avoid memory exhaustion
// Example pattern:
const batchSize = 1000
for offset := 0; ; offset += batchSize {
    var records []IntelligenceRecord
    db.Offset(offset).Limit(batchSize).Find(&records)
    if len(records) == 0 {
        break
    }
    // Process batch
}
```

### Concurrent Operations

**Parallel Processing:**

```bash
# Process multiple queries in parallel
(
  ./protosyte-rig --mode stats --format json > stats.json &
  ./protosyte-rig --mode hosts --format json > hosts.json &
  ./protosyte-rig --mode records --limit 1000 --format json > records.json &
  wait
)
```

## Database Performance

### Query Performance

**Optimize Common Queries:**

```sql
-- Count by type (optimized)
SELECT data_type, COUNT(*) 
FROM intelligence_records 
GROUP BY data_type;
-- Ensure index on data_type exists

-- Latest records (optimized)
SELECT * 
FROM intelligence_records 
ORDER BY collected_at DESC 
LIMIT 100;
-- Ensure index on collected_at exists

-- Host aggregation (optimized)
SELECT host_fingerprint, COUNT(*), MAX(collected_at) 
FROM intelligence_records 
GROUP BY host_fingerprint 
ORDER BY COUNT(*) DESC;
-- Ensure index on host_fingerprint exists
```

### Maintenance Tasks

**Regular Maintenance:**

```bash
#!/bin/bash
# performance-maintenance.sh

DB_PATH="/tmp/rig_intel.db"

# Vacuum (reclaim space, optimize)
sqlite3 "$DB_PATH" "VACUUM;"

# Analyze (update query optimizer statistics)
sqlite3 "$DB_PATH" "ANALYZE;"

# Reindex (rebuild indices)
sqlite3 "$DB_PATH" "REINDEX;"

# Check statistics
sqlite3 "$DB_PATH" "
SELECT 
    name,
    (SELECT COUNT(*) FROM intelligence_records) as total_rows,
    (SELECT pgcnt FROM dbstat WHERE name='intelligence_records') as pages
FROM sqlite_master 
WHERE type='table' AND name='intelligence_records';
"
```

**Schedule Maintenance:**

```bash
# Add to crontab (weekly)
0 2 * * 0 /path/to/performance-maintenance.sh
```

## Payload Processing Performance

### Decryption Performance

**Batch Processing:**

```go
// Process multiple payloads in parallel
// Example:
func (a *Analyzer) AnalyzeParallel() error {
    files := getPayloadFiles()
    
    // Process in parallel (limit concurrency)
    sem := make(chan struct{}, 4) // Max 4 concurrent
    var wg sync.WaitGroup
    
    for _, file := range files {
        wg.Add(1)
        go func(f string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            
            // Process file
            a.processFile(f)
        }(file)
    }
    
    wg.Wait()
    return nil
}
```

### Compression Performance

**LZ4 Settings:**

```go
// Use faster compression levels for analysis
// Balance between speed and size
lz4.CompressBlock(src, dst, nil)
```

## Network Performance

### Tor Performance

**Connection Pooling:**

```bash
# Use persistent Tor connections when possible
# Configure Tor to allow multiple connections

# /etc/tor/torrc
MaxCircuitDirtiness 600  # Reuse circuits for 10 minutes
```

**Circuit Reuse:**

```bash
# Reuse Tor circuits for multiple requests
# Rather than creating new circuits for each request
```

### Telegram API Performance

**Rate Limiting:**

```bash
# Telegram API has rate limits
# - 30 messages per second per bot
# - 1 message per second per group

# Implement rate limiting in Broadcast Engine
# Use exponential backoff on errors
```

## Storage Performance

### Filesystem Optimization

**Use Fast Storage:**

```bash
# Use SSD for database storage (if available)
# /tmp is often tmpfs (RAM disk) on Linux - good for speed

# For large databases, consider:
# - Separate database partition on fast storage
# - Use database location other than /tmp
```

**Disk I/O Optimization:**

```bash
# Use filesystem with good performance
# ext4 or xfs recommended

# Mount options:
# - noatime: Don't update access times
# - data=writeback: Faster writes (trade-off)
```

### Database File Location

```go
// Consider using faster storage
db, err := gorm.Open(sqlite.Open("/fast/ssd/path/rig_intel.db"), &gorm.Config{})
```

## System Resource Management

### CPU Optimization

**Query Complexity:**

```bash
# Simplify complex queries
# Use database indices
# Avoid full table scans
```

**Parallel Processing:**

```bash
# Use multiple CPU cores
# Process payloads in parallel (with limits)
```

### Memory Optimization

**Batch Size Tuning:**

```go
// Adjust batch sizes based on available memory
const (
    SmallBatch  = 100   // For limited memory
    MediumBatch = 1000  // Default
    LargeBatch  = 10000 // For large memory systems
)
```

**Memory Limits:**

```bash
# Set memory limits for processes
ulimit -v 2097152  # 2GB virtual memory limit
```

## Monitoring and Profiling

### Performance Monitoring

**Query Timing:**

```bash
# Enable query timing in SQLite
sqlite3 /tmp/rig_intel.db ".timer ON"

# Measure query performance
time sqlite3 /tmp/rig_intel.db "SELECT COUNT(*) FROM intelligence_records;"
```

**Database Size Monitoring:**

```bash
# Monitor database growth
watch -n 60 'du -h /tmp/rig_intel.db'

# Track growth over time
echo "$(date): $(du -h /tmp/rig_intel.db | cut -f1)" >> db_size.log
```

### Profiling

**Go Profiling:**

```bash
# Enable CPU profiling
go run -cpuprofile=cpu.prof main.go

# Analyze profile
go tool pprof cpu.prof

# Memory profiling
go run -memprofile=mem.prof main.go
go tool pprof mem.prof
```

## Benchmarking

### Performance Benchmarks

**Database Benchmarks:**

```bash
# Benchmark query performance
time sqlite3 /tmp/rig_intel.db "
SELECT COUNT(*) FROM intelligence_records;
SELECT data_type, COUNT(*) FROM intelligence_records GROUP BY data_type;
SELECT * FROM intelligence_records ORDER BY collected_at DESC LIMIT 100;
"

# Benchmark insert performance
time sqlite3 /tmp/rig_intel.db "
BEGIN TRANSACTION;
INSERT INTO intelligence_records (mission_id, host_fingerprint, data_type, collected_at, processed_at) 
VALUES (1, 'test', 'CREDENTIAL_BLOB', 1234567890, 1234567890);
-- Repeat many times
COMMIT;
"
```

### Load Testing

**Simulate Load:**

```bash
# Generate test data
for i in {1..10000}; do
  sqlite3 /tmp/rig_intel.db "
    INSERT INTO intelligence_records (mission_id, host_fingerprint, data_type, collected_at, processed_at)
    VALUES ($i, 'host$i', 'CREDENTIAL_BLOB', $(date +%s), $(date +%s));
  "
done

# Test query performance under load
time ./protosyte-rig --mode stats
time ./protosyte-rig --mode records --limit 1000
```

## Best Practices

### General Performance Tips

1. **Use Indices**: Create indices on frequently queried columns
2. **Batch Operations**: Process data in batches, not all at once
3. **Limit Result Sets**: Always use LIMIT on large queries
4. **Optimize Queries**: Analyze query plans and optimize
5. **Regular Maintenance**: Vacuum, analyze, and reindex regularly
6. **Monitor Growth**: Track database size and query performance
7. **Use Appropriate Data Types**: Choose efficient data types
8. **Parallel Processing**: Use parallel processing where safe

### Database-Specific Tips

1. **WAL Mode**: Use WAL mode for better concurrency
2. **Appropriate Cache Size**: Set cache size based on available RAM
3. **Connection Pooling**: Reuse database connections
4. **Transaction Batching**: Batch multiple operations in transactions
5. **Avoid N+1 Queries**: Use joins or batch loading

### System-Specific Tips

1. **Fast Storage**: Use SSD for database storage
2. **Adequate RAM**: Ensure sufficient RAM for database cache
3. **CPU Cores**: Use multiple cores for parallel processing
4. **Network Optimization**: Optimize Tor and network settings
5. **Resource Limits**: Set appropriate resource limits

## Performance Tuning Checklist

- [ ] Database indices created on frequently queried columns
- [ ] WAL mode enabled
- [ ] Appropriate cache size configured
- [ ] Regular maintenance scheduled
- [ ] Query plans analyzed and optimized
- [ ] Batch sizes tuned for available memory
- [ ] Parallel processing implemented where appropriate
- [ ] Fast storage used for database
- [ ] Performance monitoring in place
- [ ] Resource limits configured

## See Also

- `analysis-rig/DATABASE_MANAGEMENT.md` - Database management details
- `OPERATIONAL_WORKFLOW.md` - Operational procedures
- SQLite Performance Tuning: https://www.sqlite.org/performance.html
