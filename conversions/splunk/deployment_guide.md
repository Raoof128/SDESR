# Splunk Deployment Guide for Sigma Rules

This guide explains how to deploy the converted Sigma rules to Splunk Enterprise or Splunk Cloud.

---

## Prerequisites

- Splunk Enterprise 9.0+ or Splunk Cloud
- Administrator access
- Indexes created: `sysmon`, `windows`, `dns`, `proxy`
- Universal Forwarder installed on monitored systems

---

## Deployment Methods

### Method 1: Manual Deployment via UI (Recommended for < 10 rules)

**Step-by-Step:**

1. **Navigate to Searches and Reports:**
   - Settings → Searches, reports, and alerts

2. **Create New Alert for Each Rule:**
   - Click "New Alert"
   - Title: Use rule title from Sigma (e.g., "Mimikatz Execution Detection")
   - Search: Copy SPL query from `all_rules.spl`
   - Time range: `Last 60 minutes` (adjust based on needs)

3. **Configure Alert Trigger:**
   - Trigger condition: `Number of Results`
   - is greater than: `0`
   - Throttle: `Suppress triggering for 5 minutes`

4. **Set Alert Actions:**
   - Add to Triggered Alerts
   - Send email (optional)
   - Run a script (optional - for SOAR integration)

5. **Set Permissions:**
   - Private (for testing)
   - App → All apps (for production)

6. **Schedule:**
   - Schedule: `Run on Cron Schedule`
   - Cron expression: `*/5 * * * *` (every 5 minutes)
   - OR Real-time (higher resource usage)

---

### Method 2: CLI Deployment (Recommended for 10+ rules)

**Prepare Alert Configuration File:**

Create `savedsearches.conf`:

```ini
[Mimikatz Execution Detection]
search = index=sysmon (CommandLine="*sekurlsa::logonpasswords*" OR CommandLine="*lsadump::sam*" OR Image="*mimikatz.exe*") | stats count by _time, host, User, Image, CommandLine | sort -count
dispatch.earliest_time = -60m@m
dispatch.latest_time = now
enableSched = 1
cron_schedule = */5 * * * *
alert.track = 1
alert.suppress = 1
alert.suppress.period = 5m
alert.severity = 5
alert.expires = 24h
alert_condition = search count > 0
action.email = 1
action.email.to = soc@company.com
action.email.subject = ALERT: Mimikatz Execution Detected on $result.host$
description = Detects Mimikatz credential dumping tool execution
```

**Deploy Configuration:**

```bash
# Copy to Splunk app directory
sudo cp savedsearches.conf /opt/splunk/etc/apps/search/local/

# Reload Splunk
sudo /opt/splunk/bin/splunk reload config

# Verify
/opt/splunk/bin/splunk list search-server
```

---

### Method 3: App-Based Deployment (Recommended for Enterprise)

**Create Custom Splunk App:**

```bash
# Create app structure
mkdir -p siem-detection-rules/{default,metadata}

# Create app.conf
cat > siem-detection-rules/default/app.conf << 'EOF'
[ui]
is_visible = 1
label = SIEM Detection Rules

[launcher]
author = Detection Engineering Team
description = Sigma-based detection rules
version = 1.0.0
EOF

# Copy all savedsearches to default/
cp savedsearches.conf siem-detection-rules/default/

# Create metadata
cat > siem-detection-rules/metadata/default.meta << 'EOF'
[]
access = read : [ * ], write : [ admin ]
export = system
EOF

# Package app
cd ..
tar -czf siem-detection-rules.tar.gz siem-detection-rules/

# Install via UI
# Settings → Apps → Install app from file → Upload .tar.gz
```

---

## Splunk Rule Conversion Examples

### Example 1: Simple Process Creation Rule

**Sigma Rule (001_mimikatz_execution.yml):**
```yaml
detection:
  selection_cmd_line:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
```

**Converted SPL:**
```spl
index=sysmon EventCode=1
(CommandLine="*sekurlsa::logonpasswords*" OR CommandLine="*lsadump::sam*")
| stats count by _time, host, User, Image, CommandLine, ParentImage
| where count > 0
```

### Example 2: Process Access with Filters

**Sigma Rule (002_lsass_memory_access.yml):**
```yaml
detection:
  selection_target:
    TargetImage|endswith: '\lsass.exe'
  selection_access_rights:
    GrantedAccess:
      - '0x1410'
      - '0x0410'
  filter_legitimate:
    SourceImage|startswith: 'C:\Windows\System32\'
  condition: selection_target and selection_access_rights and not filter_legitimate
```

**Converted SPL:**
```spl
index=sysmon EventCode=10
TargetImage="*\\lsass.exe"
(GrantedAccess="0x1410" OR GrantedAccess="0x0410")
NOT (SourceImage="C:\\Windows\\System32\\*")
| stats count by _time, host, SourceImage, TargetImage, GrantedAccess, User
```

---

## Alert Tuning Best Practices

### 1. Throttling

Prevent alert fatigue with suppression:

```spl
... your detection query ...
| search NOT [| inputlookup suppressed_hosts.csv]
```

**Create suppression lookup:**
```csv
host,reason,suppressed_until
LABSERVER01,Authorized pen test,2025-11-20
```

### 2. Whitelisting

Filter known-good activity:

```spl
... detection query ...
| lookup known_good_processes.csv process_hash OUTPUT is_legitimate
| where isnull(is_legitimate) OR is_legitimate != "true"
```

### 3. Dynamic Thresholds

Alert on anomalies:

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| stats count by SourceImage
| eventstats avg(count) as avg, stdev(count) as stdev
| eval threshold=avg+(2*stdev)
| where count > threshold
```

---

## Notable Events Integration

### Create Notable Event

**Enterprise Security Users:**

1. Navigate to Content Management
2. Create Correlation Search
3. Map to MITRE ATT&CK framework
4. Set urgency: Critical/High/Medium/Low

**Example Correlation Search:**

```spl
| savedsearch "Mimikatz Execution Detection"
| eval urgency="critical"
| eval owner="unassigned"
| eval status="new"
| sendalert notable param.rule_title="Mimikatz Detected" param.rule_description="Credential dumping tool detected"
```

---

## Dashboard Creation

### Detection Overview Dashboard

```xml
<dashboard>
  <label>Detection Engineering Overview</label>
  <row>
    <panel>
      <title>Alerts Triggered (Last 24h)</title>
      <single>
        <search>
          <query>
            `notable`
          | search rule_name="Mimikatz*" OR rule_name="LSASS*"
          | stats count
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <title>Top Triggered Rules</title>
      <chart>
        <search>
          <query>
            `notable`
          | stats count by rule_name
          | sort -count
          | head 10
          </query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>
</dashboard>
```

---

## Testing Deployed Rules

### Test Each Rule

```spl
# Run the search manually
index=sysmon EventCode=1 Image="*mimikatz.exe"

# Check for results
| table _time, host, Image, CommandLine, User

# Verify alert fired
index=_audit action="alert_fired" search_name="Mimikatz Execution Detection"
```

### Validate Alert Actions

```spl
# Check email delivery
index=_internal source=*email*
| search "Mimikatz Execution"

# Check triggered alerts
index=_audit action="alert_fired"
| stats count by search_name
| sort -count
```

---

## Performance Optimization

### 1. Use Accelerated Data Models

```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes
where Processes.process="*mimikatz*"
by Processes.dest, Processes.user, Processes.process_name
```

### 2. Summary Indexing

Create scheduled search that summarizes to reduce search time:

```spl
# Summary search (runs every 5 min)
index=sysmon
| stats count by host, EventCode, Image
| collect index=summary_sysmon
```

### 3. Field Extractions

Create field extractions for faster filtering:

```
Settings → Fields → Field extractions → New
Source type: sysmon
Regex: CommandLine="(?<cmdline_arg>[^"]+)"
```

---

## Monitoring Rule Health

### Check Rule Performance

```spl
index=_audit action=search search_name="Mimikatz*"
| stats avg(exec_time) as avg_exec_time, max(exec_time) as max_exec_time by search_name
| where avg_exec_time > 60
```

### Alert on Failed Searches

```spl
index=_internal source=*scheduler.log* status=failed
| stats count by savedsearch_name
| where count > 0
```

---

## Troubleshooting

### Rule Not Firing

1. **Check search syntax:**
   ```spl
   index=sysmon | head 10
   ```

2. **Verify data is being indexed:**
   ```spl
   | metadata type=hosts index=sysmon
   ```

3. **Check alert trigger condition:**
   - Ensure `count > 0` is correct
   - Verify time range covers expected event time

4. **Review scheduler log:**
   ```spl
   index=_internal source=*scheduler.log* savedsearch_name="Mimikatz*"
   ```

### High False Positive Rate

1. **Add filters:**
   ```spl
   ... detection query ...
   | where NOT match(Image, "(?i)C:\\Program Files\\")
   ```

2. **Create baseline:**
   ```spl
   # Collect 7 days of "normal" activity
   index=sysmon earliest=-7d
   | stats count by Image, CommandLine
   | where count > 100
   | outputlookup baseline_processes.csv
   ```

3. **Apply baseline filtering:**
   ```spl
   ... detection query ...
   | lookup baseline_processes.csv Image, CommandLine OUTPUT count as baseline_count
   | where isnull(baseline_count)
   ```

---

## Maintenance

### Regular Tasks

| Task | Frequency | Command |
|------|-----------|---------|
| Review false positives | Weekly | Update whitelists |
| Check rule performance | Weekly | Monitor `_audit` logs |
| Update rules | Monthly | Re-convert from Sigma |
| Tune thresholds | Quarterly | Adjust based on FP rate |

---

## Additional Resources

- [Splunk Alerts Manual](https://docs.splunk.com/Documentation/Splunk/latest/Alert/)
- [SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)
- [Splunk ES Content Update](https://splunkbase.splunk.com/app/3449/)
