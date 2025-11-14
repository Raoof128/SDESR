# Elastic Kibana Deployment Guide for Sigma Rules

This guide explains how to deploy converted Sigma rules to Elastic Security (Kibana).

---

## Prerequisites

- Elastic Stack 8.0+ (Elasticsearch + Kibana)
- Elastic Security app enabled
- Beats configured (Winlogbeat, Filebeat)
- Appropriate user role: `kibana_admin` or `detection_admin`

---

## Deployment Methods

### Method 1: UI Import (Recommended)

**Step-by-Step:**

1. **Navigate to Security App:**
   - Click "Security" in left sidebar
   - Select "Detections" → "Manage Rules"

2. **Import Rules:**
   - Click "Import rules" button (top right)
   - Select `all_rules.json` file
   - Choose import option:
     - **Overwrite:** Replace existing rules with same rule_id
     - **Skip:** Keep existing, only add new
   - Click "Import"

3. **Verify Import:**
   - Check "Imported X rules successfully"
   - Review any import errors

4. **Enable Rules:**
   - Select imported rules
   - Click "Bulk actions" → "Enable"

---

### Method 2: API Import (Recommended for CI/CD)

**Using Curl:**

```bash
# Set variables
KIBANA_URL="http://localhost:5601"
ELASTIC_USER="elastic"
ELASTIC_PASS="Changeme123!"

# Import rules via API
curl -X POST "${KIBANA_URL}/api/detection_engine/rules/_import?overwrite=true" \
  -u "${ELASTIC_USER}:${ELASTIC_PASS}" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@conversions/elastic/all_rules.json"
```

**Using Python:**

```python
import requests
import json

KIBANA_URL = "http://localhost:5601"
ELASTIC_USER = "elastic"
ELASTIC_PASS = "Changeme123!"

# Read rules file
with open('all_rules.json', 'r') as f:
    rules = json.load(f)['rules']

# Import each rule
for rule in rules:
    response = requests.post(
        f"{KIBANA_URL}/api/detection_engine/rules",
        auth=(ELASTIC_USER, ELASTIC_PASS),
        headers={
            "kbn-xsrf": "true",
            "Content-Type": "application/json"
        },
        json=rule
    )

    if response.status_code == 200:
        print(f"✓ Imported: {rule['name']}")
    else:
        print(f"✗ Failed: {rule['name']} - {response.text}")
```

---

## Rule Configuration Examples

### Example 1: Query-Based Detection Rule

**Sigma Rule (001_mimikatz_execution.yml) → Elastic:**

```json
{
  "name": "Mimikatz Execution Detection",
  "description": "Detects Mimikatz credential dumping tool execution",
  "risk_score": 99,
  "severity": "critical",
  "type": "query",
  "query": "process.command_line:(*sekurlsa::logonpasswords* OR *lsadump::sam*) OR process.executable:*mimikatz.exe",
  "language": "kuery",
  "index": [
    "winlogbeat-*",
    "logs-endpoint.events.*"
  ],
  "from": "now-360s",
  "interval": "5m",
  "max_signals": 100,
  "enabled": true,
  "tags": [
    "attack.credential_access",
    "attack.t1003.001"
  ],
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0006",
        "name": "Credential Access",
        "reference": "https://attack.mitre.org/tactics/TA0006/"
      },
      "technique": [
        {
          "id": "T1003",
          "name": "OS Credential Dumping",
          "reference": "https://attack.mitre.org/techniques/T1003/",
          "subtechnique": [
            {
              "id": "T1003.001",
              "name": "LSASS Memory",
              "reference": "https://attack.mitre.org/techniques/T1003/001/"
            }
          ]
        }
      ]
    }
  ]
}
```

---

## Alert Actions Configuration

### 1. Email Notifications

**Navigate to Stack Management → Connectors:**

```
1. Click "Create connector"
2. Select "Email"
3. Configure:
   - Name: SOC Email Alerts
   - Sender: splunk@company.com
   - Service: SMTP
   - Host: smtp.gmail.com
   - Port: 587
4. Test connector
```

**Add to Rule:**

```json
{
  "actions": [
    {
      "group": "default",
      "id": "email-connector-id",
      "params": {
        "to": ["soc@company.com"],
        "subject": "ALERT: {{context.rule.name}}",
        "message": "Alert triggered:\n\nRule: {{context.rule.name}}\nSeverity: {{context.rule.severity}}\nHost: {{context.hits.0.host.name}}\n\nDetails: {{context.hits.0}}"
      }
    }
  ]
}
```

### 2. Slack Notifications

**Create Slack Webhook:**

```
1. Go to https://api.slack.com/apps
2. Create New App → From scratch
3. Add "Incoming Webhooks"
4. Activate → Add New Webhook
5. Select channel → Copy Webhook URL
```

**Configure in Kibana:**

```
Stack Management → Connectors → Create connector
Type: Slack
Webhook URL: https://hooks.slack.com/services/XXX/YYY/ZZZ
```

**Add to Rule:**

```json
{
  "actions": [
    {
      "group": "default",
      "id": "slack-connector-id",
      "params": {
        "message": ":rotating_light: *Detection Alert*\n*Rule:* {{context.rule.name}}\n*Severity:* {{context.rule.severity}}\n*Host:* {{context.hits.0.host.name}}"
      }
    }
  ]
}
```

### 3. SOAR Integration (PagerDuty, TheHive, MISP)

**Webhook Connector:**

```json
{
  "connector_type_id": ".webhook",
  "name": "SOAR Webhook",
  "config": {
    "url": "https://soar-platform.com/api/alerts",
    "method": "post",
    "headers": {
      "Content-Type": "application/json",
      "Authorization": "Bearer API_TOKEN"
    }
  },
  "secrets": {}
}
```

---

## Exception Management

### Create Exceptions for False Positives

**Via UI:**

1. Navigate to detection alert
2. Click "Add Exception"
3. Configure:
   - Field: `process.executable`
   - Operator: `is`
   - Value: `C:\Program Files\LegitSoftware\app.exe`
4. Save

**Via API:**

```bash
curl -X POST "${KIBANA_URL}/api/exception_lists/items" \
  -u "${ELASTIC_USER}:${ELASTIC_PASS}" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "list_id": "mimikatz-exceptions",
    "item_id": "exception-1",
    "name": "Legitimate Admin Tool",
    "type": "simple",
    "description": "Whitelist authorized security tools",
    "entries": [
      {
        "field": "process.executable",
        "operator": "included",
        "type": "match",
        "value": "C:\\IT\\Tools\\AdminTool.exe"
      }
    ]
  }'
```

---

## Detection Rule Tuning

### 1. Adjust Risk Score Dynamically

```json
{
  "risk_score_mapping": [
    {
      "field": "user.name",
      "operator": "equals",
      "value": "Administrator",
      "risk_score": 95
    },
    {
      "field": "host.name",
      "operator": "equals",
      "value": "DC01",
      "risk_score": 99
    }
  ]
}
```

### 2. Threshold-Based Detection

**Convert count-based Sigma rule:**

```json
{
  "type": "threshold",
  "query": "event.code:4625",
  "threshold": {
    "field": ["source.ip", "user.name"],
    "value": 5,
    "cardinality": [
      {
        "field": "user.name",
        "value": 3
      }
    ]
  }
}
```

**Example: 5 failed logins from same IP to 3+ different accounts**

### 3. Machine Learning Jobs

**Anomaly detection for rare processes:**

```json
{
  "type": "machine_learning",
  "anomaly_threshold": 50,
  "machine_learning_job_id": "rare_process_execution"
}
```

---

## Dashboard Creation

### Detection Overview Dashboard

**Create Dashboard:**

```
Analytics → Dashboard → Create dashboard → Add panel
```

**Example Panels:**

**1. Alerts Over Time:**
```
Lens visualization
Index pattern: .alerts-security.alerts-*
Aggregation: Count
Date histogram: @timestamp (per hour)
```

**2. Top Triggered Rules:**
```
Aggregation-based
Terms aggregation: kibana.alert.rule.name
Order by: Count (descending)
Top 10
```

**3. Severity Distribution:**
```
Pie chart
Terms: kibana.alert.severity
```

**4. MITRE ATT&CK Coverage:**
```
Tag cloud
Field: kibana.alert.rule.threat.tactic.name
```

---

## Testing Deployed Rules

### Test Individual Rule

**Navigate to Rule:**
```
Security → Detections → Manage Rules → [Select Rule] → Edit
```

**Run Test Query:**
```kql
# Preview results
process.command_line:*mimikatz* AND event.code:1

# Check recent alerts
kibana.alert.rule.name:"Mimikatz Execution Detection" AND @timestamp >= now-1h
```

**Simulate Attack:**

```powershell
# On Windows system with Winlogbeat
notepad.exe  # Replace with actual attack simulation
```

**Verify Alert:**

```
Security → Alerts
Filter by rule name
Check alert details
```

---

## Performance Optimization

### 1. Index Lifecycle Management

**Reduce index size:**

```
Stack Management → Index Lifecycle Policies
Create policy:
  - Hot phase: 7 days
  - Warm phase: 30 days (move to cheaper storage)
  - Cold phase: 90 days
  - Delete: 365 days
```

### 2. Runtime Fields

**Extract fields at query time:**

```json
{
  "runtime_mappings": {
    "process.parent.cmd_short": {
      "type": "keyword",
      "script": {
        "source": "if (doc['process.parent.command_line'].size() > 0) { emit(doc['process.parent.command_line'].value.substring(0, 50)) }"
      }
    }
  }
}
```

### 3. Query Optimization

**Use filters instead of queries when possible:**

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.code": "1" }},
        { "wildcard": { "process.command_line": "*mimikatz*" }}
      ]
    }
  }
}
```

---

## Monitoring Rule Health

### Check Rule Execution

```
GET .kibana/_search
{
  "query": {
    "term": {
      "type": "alert"
    }
  }
}
```

### Alert on Failed Rules

**Create monitoring rule:**

```json
{
  "name": "Detection Rule Failures",
  "query": "event.module:kibana AND event.action:execute-rule AND event.outcome:failure",
  "threshold": {
    "field": ["kibana.alert.rule.name"],
    "value": 1
  }
}
```

---

## Troubleshooting

### Rule Not Generating Alerts

1. **Check query syntax in Discover:**
   ```
   Analytics → Discover
   Paste rule query
   Verify results
   ```

2. **Verify index patterns:**
   ```
   Stack Management → Index Patterns
   Ensure winlogbeat-* exists
   Check field mappings
   ```

3. **Check rule execution:**
   ```
   Security → Detections → Rule Monitoring
   View execution log
   ```

4. **Review Elasticsearch logs:**
   ```bash
   docker logs siem-lab-elasticsearch | grep ERROR
   ```

### High False Positive Rate

1. **Add exceptions (see above)**

2. **Tune query specificity:**
   ```kql
   # Too broad
   process.name:powershell.exe

   # More specific
   process.name:powershell.exe AND process.command_line:*-enc* AND NOT user.name:*admin*
   ```

3. **Use ML for baseline:**
   ```
   Machine Learning → Anomaly Detection → Create job
   Detector: rare by process.command_line
   ```

---

## Maintenance Tasks

| Task | Frequency | Action |
|------|-----------|--------|
| Review alerts | Daily | Triage and close |
| Update exceptions | Weekly | Add FP whitelists |
| Check rule performance | Weekly | Review execution times |
| Update rules | Monthly | Re-import from Sigma |
| Tune thresholds | Quarterly | Adjust based on FP rate |
| Review threat intel | Monthly | Update IOCs in rules |

---

## Additional Resources

- [Elastic Security Docs](https://www.elastic.co/guide/en/security/current/index.html)
- [Detection Rules](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html)
- [KQL Reference](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
