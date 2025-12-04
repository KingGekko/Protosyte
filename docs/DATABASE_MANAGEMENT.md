# Database Management Guide

## Overview

The Analysis Rig uses SQLite to store intelligence records. This document covers database management, maintenance, and best practices.

## Database Location

**Default Location**: `/tmp/rig_intel.db`

The database is created automatically on first use. The location can be configured by modifying the `NewAnalyzer()` function in `analyzer.go`.

## Database Schema

### IntelligenceRecord Table

```sql
CREATE TABLE intelligence_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id INTEGER,
    host_fingerprint TEXT,
    data_type TEXT,
    collected_at INTEGER,
    processed_at INTEGER,
    iocs TEXT
);

CREATE INDEX idx_mission_id ON intelligence_records(mission_id);
```

### AI Analysis Table

The database also contains an `ai_analysis` table for storing AI-generated analysis results (if AI integration is enabled).

## Database Operations

### Viewing Database Info

```bash
# Using SQLite CLI
sqlite3 /tmp/rig_intel.db ".tables"
sqlite3 /tmp/rig_intel.db ".schema"

# Count records
sqlite3 /tmp/rig_intel.db "SELECT COUNT(*) FROM intelligence_records;"
```

### Querying Data

```bash
# View all records
sqlite3 /tmp/rig_intel.db "SELECT * FROM intelligence_records LIMIT 10;"

# Count by data type
sqlite3 /tmp/rig_intel.db "SELECT data_type, COUNT(*) FROM intelligence_records GROUP BY data_type;"

# Records by mission
sqlite3 /tmp/rig_intel.db "SELECT mission_id, COUNT(*) FROM intelligence_records GROUP BY mission_id;"
```

### Using CLI Commands (Recommended)

The Analysis Rig provides CLI commands for querying data:

```bash
# Statistics
./protosyte-rig --mode stats

# Records with limit
./protosyte-rig --mode records --limit 100

# Hosts
./protosyte-rig --mode hosts

# JSON output for processing
./protosyte-rig --mode records --limit 1000 --format json | jq '.records[]'
```

## Database Backup

### Manual Backup

```bash
# Backup database
cp /tmp/rig_intel.db /path/to/backup/rig_intel_$(date +%Y%m%d_%H%M%S).db

# Compressed backup
sqlite3 /tmp/rig_intel.db ".backup 'backup.db'"
gzip backup.db
```

### Automated Backup Script

```bash
#!/bin/bash
# backup-db.sh

BACKUP_DIR="/path/to/backups"
DB_PATH="/tmp/rig_intel.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/rig_intel_$TIMESTAMP.db'"
gzip "$BACKUP_DIR/rig_intel_$TIMESTAMP.db"

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "rig_intel_*.db.gz" -mtime +30 -delete

echo "Backup completed: rig_intel_$TIMESTAMP.db.gz"
```

## Multi-Mission Database Management

### Mission Isolation

Records are tagged with `mission_id` for isolation. To query specific missions:

```bash
# Using CLI (requires mission ID parsing)
./protosyte-rig --mode records --format json | jq '.records[] | select(.mission_id == 16095879279323875865)'

# Using SQL
sqlite3 /tmp/rig_intel.db "SELECT * FROM intelligence_records WHERE mission_id = 16095879279323875865;"
```

### Mission-Based Queries

```bash
# Count records per mission
sqlite3 /tmp/rig_intel.db "
SELECT 
    mission_id,
    COUNT(*) as record_count,
    MIN(collected_at) as first_seen,
    MAX(collected_at) as last_seen
FROM intelligence_records
GROUP BY mission_id;
"
```

## Database Maintenance

### Vacuum (Reclaim Space)

```bash
# SQLite vacuum
sqlite3 /tmp/rig_intel.db "VACUUM;"

# Analyze tables for optimization
sqlite3 /tmp/rig_intel.db "ANALYZE;"
```

### Integrity Check

```bash
# Check database integrity
sqlite3 /tmp/rig_intel.db "PRAGMA integrity_check;"

# Quick integrity check
sqlite3 /tmp/rig_intel.db "PRAGMA quick_check;"
```

### Reindex

```bash
# Rebuild all indices
sqlite3 /tmp/rig_intel.db "REINDEX;"
```

## Data Retention

### Archive Old Records

```bash
# Archive records older than 90 days
sqlite3 /tmp/rig_intel.db "
ATTACH DATABASE '/path/to/archive.db' AS archive;
CREATE TABLE IF NOT EXISTS archive.intelligence_records AS 
    SELECT * FROM intelligence_records 
    WHERE collected_at < $(date -d '90 days ago' +%s);
DELETE FROM intelligence_records 
    WHERE collected_at < $(date -d '90 days ago' +%s);
DETACH archive;
"
```

### Purge Records

```bash
# Delete records older than 1 year
sqlite3 /tmp/rig_intel.db "
DELETE FROM intelligence_records 
WHERE collected_at < $(date -d '1 year ago' +%s);
VACUUM;
"
```

## Database Migration

### Schema Changes

The database schema is managed via GORM's `AutoMigrate()` feature. Schema changes are applied automatically when the Analysis Rig starts.

**Note**: Always backup the database before running migrations in production.

### Manual Migration

```bash
# Export data before migration
sqlite3 /tmp/rig_intel.db ".dump" > backup.sql

# Apply migration (would require code changes)
# Run analyzer to trigger AutoMigrate
./protosyte-rig --mode stats
```

## Data Export

### Export to CSV

```bash
# Export all records to CSV
sqlite3 -header -csv /tmp/rig_intel.db "
SELECT * FROM intelligence_records;
" > intelligence_records.csv

# Export specific fields
sqlite3 -header -csv /tmp/rig_intel.db "
SELECT id, data_type, host_fingerprint, datetime(collected_at, 'unixepoch') as collected_at
FROM intelligence_records;
" > intelligence_summary.csv
```

### Export to JSON (Recommended)

```bash
# Using CLI (recommended)
./protosyte-rig --mode records --limit 10000 --format json > all_records.json

# Using SQLite with jq
sqlite3 /tmp/rig_intel.db -json "SELECT * FROM intelligence_records;" | jq '.'
```

### Export via FIP

The recommended method for exporting all intelligence:

```bash
./protosyte-rig --mode fip
# Creates: /tmp/rig_out/forensic_intel_packet.json.gz
```

## Performance Optimization

### Index Management

Ensure indices exist for frequently queried fields:

```sql
-- Check existing indices
SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index';

-- Create additional indices if needed
CREATE INDEX IF NOT EXISTS idx_data_type ON intelligence_records(data_type);
CREATE INDEX IF NOT EXISTS idx_host_fingerprint ON intelligence_records(host_fingerprint);
CREATE INDEX IF NOT EXISTS idx_collected_at ON intelligence_records(collected_at);
```

### Query Optimization

```bash
# Enable query plan display
sqlite3 /tmp/rig_intel.db "EXPLAIN QUERY PLAN SELECT * FROM intelligence_records WHERE data_type = 'CREDENTIAL_BLOB';"
```

### Database Settings

```sql
-- Increase page size (requires database recreation)
PRAGMA page_size = 4096;

-- Enable WAL mode for better concurrency
PRAGMA journal_mode = WAL;

-- Increase cache size (in KB)
PRAGMA cache_size = 10000;

-- Enable foreign keys (if applicable)
PRAGMA foreign_keys = ON;
```

## Security Considerations

### Database Permissions

```bash
# Secure database file
chmod 600 /tmp/rig_intel.db
chown $USER:$USER /tmp/rig_intel.db
```

### Encryption at Rest

SQLite does not provide built-in encryption. For encrypted storage:

1. **Use encrypted filesystem**: Encrypt the filesystem where the database is stored
2. **Use SQLCipher**: Compile SQLite with SQLCipher extension
3. **Application-level encryption**: Encrypt sensitive fields before storage

### Secure Deletion

```bash
# Secure deletion of database (Linux)
shred -u /tmp/rig_intel.db

# Or use secure deletion tool
srm /tmp/rig_intel.db
```

## Troubleshooting

### Database Locked

If you encounter "database is locked" errors:

```bash
# Check for running processes
lsof /tmp/rig_intel.db

# Kill processes if needed
kill -9 <PID>

# Or close database connections
sqlite3 /tmp/rig_intel.db ".timeout 5000"
```

### Database Corruption

```bash
# Check for corruption
sqlite3 /tmp/rig_intel.db "PRAGMA integrity_check;"

# If corrupted, attempt recovery
sqlite3 /tmp/rig_intel.db ".recover" | sqlite3 recovered.db
```

### Disk Space

```bash
# Check database size
du -h /tmp/rig_intel.db

# Check disk space
df -h /tmp

# Vacuum to reclaim space
sqlite3 /tmp/rig_intel.db "VACUUM;"
```

## Best Practices

1. **Regular Backups**: Schedule automated backups daily or weekly
2. **Monitor Size**: Track database growth and archive old data
3. **Integrity Checks**: Run periodic integrity checks
4. **Performance Monitoring**: Monitor query performance and optimize indices
5. **Secure Storage**: Use encrypted filesystems for sensitive databases
6. **Access Control**: Restrict file permissions on database files
7. **Version Control**: Document schema changes and migration procedures
8. **Testing**: Test backup and recovery procedures regularly

## Examples

### Complete Backup and Archive Workflow

```bash
#!/bin/bash
# complete-db-maintenance.sh

DB_PATH="/tmp/rig_intel.db"
BACKUP_DIR="/path/to/backups"
ARCHIVE_DIR="/path/to/archive"
DAYS_TO_ARCHIVE=90

# Create directories
mkdir -p "$BACKUP_DIR" "$ARCHIVE_DIR"

# Backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/rig_intel_$TIMESTAMP.db'"
gzip "$BACKUP_DIR/rig_intel_$TIMESTAMP.db"

# Integrity check
if sqlite3 "$DB_PATH" "PRAGMA integrity_check;" | grep -q "ok"; then
    echo "Database integrity: OK"
else
    echo "WARNING: Database integrity check failed!"
    exit 1
fi

# Archive old records
ARCHIVE_TIME=$(date -d "$DAYS_TO_ARCHIVE days ago" +%s)
sqlite3 "$DB_PATH" "
ATTACH DATABASE '$ARCHIVE_DIR/archive_$TIMESTAMP.db' AS archive;
CREATE TABLE IF NOT EXISTS archive.intelligence_records AS 
    SELECT * FROM intelligence_records 
    WHERE collected_at < $ARCHIVE_TIME;
DELETE FROM intelligence_records 
    WHERE collected_at < $ARCHIVE_TIME;
DETACH archive;
"

# Vacuum
sqlite3 "$DB_PATH" "VACUUM; ANALYZE;"

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.db.gz" -mtime +30 -delete

echo "Maintenance complete"
```

## See Also

- `analysis-rig/README.md` - Analysis Rig documentation
- SQLite Documentation: https://www.sqlite.org/docs.html
