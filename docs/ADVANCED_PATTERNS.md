# Advanced Patterns and Techniques

## Overview

This document covers advanced usage patterns, techniques, and integration strategies for the Protosyte framework.

## Advanced Query Patterns

### Complex Data Analysis

**Time-Series Analysis:**

```bash
# Records collected over time
./protosyte-rig --mode records --format json | \
  jq -r '.records[] | [.id, .data_type, .collected_at] | @csv' | \
  awk -F',' '{print strftime("%Y-%m-%d %H:00:00", $3), $2}' | \
  sort | uniq -c

# Hourly collection patterns
./protosyte-rig --mode records --format json | \
  jq -r '.records[] | .collected_at' | \
  xargs -I {} date -d @{} +"%Y-%m-%d %H:00" | \
  sort | uniq -c | sort -rn
```

**Host Activity Correlation:**

```bash
# Hosts with multiple data types
./protosyte-rig --mode records --format json | \
  jq -r '.records[] | [.host_fingerprint, .data_type] | @csv' | \
  sort | uniq | \
  awk -F',' '{hosts[$1]++; types[$1] = types[$1] "," $2} END {for (h in hosts) if (hosts[h] > 1) print h, types[h]}'

# Most active hosts by time period
./protosyte-rig --mode hosts --format json | \
  jq -r '.hosts[] | [.fingerprint, .count, .latest] | @csv' | \
  awk -F',' '{print $1, $2, strftime("%Y-%m-%d %H:%M", $3)}'
```

**Data Type Distribution:**

```bash
# Distribution analysis
./protosyte-rig --mode stats --format json | \
  jq '.by_type | to_entries | sort_by(.value) | reverse | .[] | "\(.key): \(.value)"'

# Percentage distribution
./protosyte-rig --mode stats --format json | \
  jq -r '
    .total as $total |
    .by_type | to_entries[] |
    "\(.key): \(.value) (\((100 * .value / $total | floor))%))"
  '
```

### Pattern Matching and Filtering

**Credential Patterns:**

```bash
# Extract all credential records
./protosyte-rig --mode records --format json | \
  jq '.records[] | select(.data_type == "CREDENTIAL_BLOB")'

# Credentials by host
./protosyte-rig --mode records --format json | \
  jq -r '.records[] | select(.data_type == "CREDENTIAL_BLOB") | [.host_fingerprint, .id] | @csv' | \
  sort | uniq -c | sort -rn
```

**Session Token Analysis:**

```bash
# All session tokens
./protosyte-rig --mode records --format json | \
  jq '.records[] | select(.data_type == "SESSION_TOKEN")'

# Session token frequency
./protosyte-rig --mode records --format json | \
  jq -r '.records[] | select(.data_type == "SESSION_TOKEN") | .host_fingerprint' | \
  sort | uniq -c | sort -rn
```

**Network Flow Analysis:**

```bash
# Network flows by host
./protosyte-rig --mode records --format json | \
  jq '.records[] | select(.data_type == "NETWORK_FLOW") | .host_fingerprint' | \
  sort | uniq -c | sort -rn

# Flow timing patterns
./protosyte-rig --mode records --format json | \
  jq -r '.records[] | select(.data_type == "NETWORK_FLOW") | .collected_at' | \
  xargs -I {} date -d @{} +"%H:%M" | \
  sort | uniq -c | sort -rn | head -20
```

## Integration Patterns

### Scripting Integration

**Bash Scripts:**

```bash
#!/bin/bash
# analyze_intelligence.sh

# Collect statistics
STATS=$(./protosyte-rig --mode stats --format json)

# Extract metrics
TOTAL=$(echo "$STATS" | jq '.total')
CREDS=$(echo "$STATS" | jq '.by_type.CREDENTIAL_BLOB // 0')

# Generate report
cat <<EOF
Intelligence Summary
====================
Total Records: $TOTAL
Credentials: $CREDS
EOF

# Alert if threshold exceeded
if [ "$CREDS" -gt 100 ]; then
    echo "ALERT: High credential count detected!"
fi
```

**Python Integration:**

```python
#!/usr/bin/env python3
# analyze_intelligence.py

import subprocess
import json
import sys

def get_stats():
    result = subprocess.run(
        ['./protosyte-rig', '--mode', 'stats', '--format', 'json'],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

def get_records(limit=100):
    result = subprocess.run(
        ['./protosyte-rig', '--mode', 'records', '--limit', str(limit), '--format', 'json'],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)['records']

# Usage
stats = get_stats()
print(f"Total records: {stats['total']}")

records = get_records(100)
cred_records = [r for r in records if r['data_type'] == 'CREDENTIAL_BLOB']
print(f"Credential records: {len(cred_records)}")
```

**PowerShell Integration (Windows):**

```powershell
# analyze_intelligence.ps1

$stats = & .\protosyte-rig.exe --mode stats --format json | ConvertFrom-Json
Write-Host "Total records: $($stats.total)"

$records = & .\protosyte-rig.exe --mode records --limit 100 --format json | ConvertFrom-Json
$credRecords = $records.records | Where-Object { $_.data_type -eq 'CREDENTIAL_BLOB' }
Write-Host "Credential records: $($credRecords.Count)"
```

### Database Direct Access Patterns

**SQLite Direct Queries:**

```bash
# Complex queries via SQLite
sqlite3 /tmp/rig_intel.db "
SELECT 
    data_type,
    COUNT(*) as count,
    MIN(collected_at) as first_seen,
    MAX(collected_at) as last_seen,
    (MAX(collected_at) - MIN(collected_at)) / 3600.0 as duration_hours
FROM intelligence_records
GROUP BY data_type;
"

# Host activity timeline
sqlite3 /tmp/rig_intel.db "
SELECT 
    host_fingerprint,
    DATE(datetime(collected_at, 'unixepoch')) as date,
    COUNT(*) as records
FROM intelligence_records
GROUP BY host_fingerprint, date
ORDER BY date DESC, records DESC;
"
```

**Advanced SQL Patterns:**

```sql
-- Top 10 most active hosts
SELECT 
    host_fingerprint,
    COUNT(*) as record_count,
    COUNT(DISTINCT data_type) as data_types,
    MIN(collected_at) as first_seen,
    MAX(collected_at) as last_seen
FROM intelligence_records
GROUP BY host_fingerprint
ORDER BY record_count DESC
LIMIT 10;

-- Data collection rate over time
SELECT 
    DATE(datetime(collected_at, 'unixepoch')) as date,
    COUNT(*) as records_per_day,
    COUNT(DISTINCT host_fingerprint) as unique_hosts
FROM intelligence_records
GROUP BY date
ORDER BY date DESC;

-- Credential density by host
SELECT 
    host_fingerprint,
    COUNT(*) as total_records,
    SUM(CASE WHEN data_type = 'CREDENTIAL_BLOB' THEN 1 ELSE 0 END) as credential_count,
    ROUND(100.0 * SUM(CASE WHEN data_type = 'CREDENTIAL_BLOB' THEN 1 ELSE 0 END) / COUNT(*), 2) as credential_percentage
FROM intelligence_records
GROUP BY host_fingerprint
HAVING credential_count > 0
ORDER BY credential_percentage DESC;
```

## Automation Patterns

### Automated Analysis Workflow

```bash
#!/bin/bash
# automated_analysis.sh

# Configuration
DB_PATH="/tmp/rig_intel.db"
BACKUP_DIR="/path/to/backups"
ALERT_THRESHOLD=100

# Function: Send alert
send_alert() {
    local message="$1"
    # Implement notification mechanism
    # e.g., email, Slack, webhook
    echo "ALERT: $message"
}

# Function: Backup database
backup_database() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/backup_$timestamp.db'"
    gzip "$BACKUP_DIR/backup_$timestamp.db"
}

# Main workflow
main() {
    # 1. Retrieve payloads
    echo "Retrieving payloads..."
    torsocks ./protosyte-rig --mode retrieve
    
    # 2. Analyze
    echo "Analyzing intelligence..."
    ./protosyte-rig --mode analyze
    
    # 3. Check statistics
    echo "Checking statistics..."
    STATS=$(./protosyte-rig --mode stats --format json)
    TOTAL=$(echo "$STATS" | jq '.total')
    CREDS=$(echo "$STATS" | jq '.by_type.CREDENTIAL_BLOB // 0')
    
    # 4. Alert if threshold exceeded
    if [ "$CREDS" -gt "$ALERT_THRESHOLD" ]; then
        send_alert "Credential count exceeded threshold: $CREDS"
    fi
    
    # 5. Backup
    echo "Backing up database..."
    backup_database
    
    # 6. Generate daily report
    echo "Generating daily report..."
    ./protosyte-rig --mode fip
    
    echo "Analysis complete"
}

main
```

### Scheduled Tasks

**Cron Configuration:**

```bash
# /etc/cron.d/protosyte-analysis

# Hourly payload retrieval
0 * * * * user cd /path/to/protosyte && torsocks ./analysis-rig/protosyte-rig --mode retrieve

# Daily analysis
0 2 * * * user cd /path/to/protosyte && export PROTOSYTE_PASSPHRASE="..." && ./analysis-rig/protosyte-rig --mode analyze

# Weekly reporting
0 3 * * 0 user cd /path/to/protosyte && export PROTOSYTE_PASSPHRASE="..." && ./analysis-rig/protosyte-rig --mode fip

# Monthly database maintenance
0 4 1 * * user /path/to/database-maintenance.sh
```

### Event-Driven Patterns

**Watch for New Records:**

```bash
#!/bin/bash
# watch_intelligence.sh

LAST_COUNT=0

while true; do
    CURRENT_COUNT=$(./protosyte-rig --mode stats --format json | jq '.total')
    
    if [ "$CURRENT_COUNT" -gt "$LAST_COUNT" ]; then
        NEW_RECORDS=$((CURRENT_COUNT - LAST_COUNT))
        echo "[$(date)] New records detected: $NEW_RECORDS"
        
        # Trigger analysis
        ./protosyte-rig --mode analyze
        
        LAST_COUNT=$CURRENT_COUNT
    fi
    
    sleep 60  # Check every minute
done
```

## Reporting Patterns

### Custom Report Generation

```bash
#!/bin/bash
# generate_custom_report.sh

OUTPUT_FILE="custom_report_$(date +%Y%m%d).md"

cat > "$OUTPUT_FILE" <<EOF
# Intelligence Report
Generated: $(date)

## Summary Statistics
EOF

# Add statistics
./protosyte-rig --mode stats --format json | \
  jq -r '
    "Total Records: \(.total)",
    "",
    "By Type:",
    (.by_type | to_entries[] | "- \(.key): \(.value)"),
    "",
    "Latest Record: \(.latest)"
  ' >> "$OUTPUT_FILE"

# Add top hosts
cat >> "$OUTPUT_FILE" <<EOF

## Top 10 Hosts
EOF

./protosyte-rig --mode hosts --format json | \
  jq -r '.hosts[0:10][] | "- \(.fingerprint): \(.count) records"' >> "$OUTPUT_FILE"

echo "Report generated: $OUTPUT_FILE"
```

### HTML Report Generation

```bash
#!/bin/bash
# generate_html_report.sh

STATS=$(./protosyte-rig --mode stats --format json)

cat > report.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Intelligence Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>Intelligence Report</h1>
    <p>Generated: $(date)</p>
    
    <h2>Statistics</h2>
    <p>Total Records: $(echo "$STATS" | jq '.total')</p>
    
    <h3>By Type</h3>
    <table>
        <tr><th>Type</th><th>Count</th></tr>
        $(echo "$STATS" | jq -r '.by_type | to_entries[] | "<tr><td>\(.key)</td><td>\(.value)</td></tr>")
    </table>
</body>
</html>
EOF

echo "HTML report generated: report.html"
```

## See Also

- `OPERATIONAL_WORKFLOW.md` - Operational procedures
- `PERFORMANCE_TUNING.md` - Performance optimization
- `analysis-rig/README.md` - CLI command reference
- `analysis-rig/DATABASE_MANAGEMENT.md` - Database operations
