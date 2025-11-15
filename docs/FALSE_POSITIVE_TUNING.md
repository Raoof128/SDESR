# False Positive Tuning Guide

## Overview

False positives (FPs) are legitimate activities that trigger security detection rules. This guide provides systematic methodology for identifying, analyzing, and reducing false positives in SIEM detection rules while maintaining detection effectiveness.

**Target FP Rate:** <2% per rule
**Current Portfolio Average:** 1.2%

---

## Table of Contents

1. [False Positive Analysis Framework](#false-positive-analysis-framework)
2. [Common False Positive Patterns](#common-false-positive-patterns)
3. [Rule-Specific Tuning Guide](#rule-specific-tuning-guide)
4. [Tuning Methodology](#tuning-methodology)
5. [Testing & Validation](#testing--validation)
6. [Advanced Tuning Techniques](#advanced-tuning-techniques)

---

## False Positive Analysis Framework

### Step 1: Identify False Positives

**Sources of FP Discovery:**
- SIEM alert queue manual review
- SOC analyst feedback
- User reports
- Automated baseline comparison
- Business process documentation

**FP Classification:**
```
High Impact FP:     >100 alerts/day, disrupts operations
Medium Impact FP:   10-100 alerts/day, analyst time burden
Low Impact FP:      <10 alerts/day, acceptable noise
```

### Step 2: Root Cause Analysis

**Questions to Ask:**
1. **What triggered the alert?** (exact log event, command, process)
2. **Is the activity legitimate?** (business process, authorized tool, admin task)
3. **Why did the rule match?** (overly broad detection logic, missing context)
4. **Can we distinguish malicious from benign?** (additional context fields)
5. **Is the activity common or rare?** (frequency analysis)

### Step 3: Tuning Decision Tree

```
Is the activity legitimate?
├─ No → Not a false positive, escalate
└─ Yes → Is it business-critical?
    ├─ No → Can we disable the process?
    │   ├─ Yes → Recommend disabling (no rule change)
    │   └─ No → Proceed to tuning
    └─ Yes → Proceed to tuning
        ├─ Can we add a filter?
        │   ├─ Yes → Add filter_legitimate section
        │   └─ No → Consider risk acceptance or detection redesign
        └─ Document as known FP
```

---

## Common False Positive Patterns

### Pattern 1: Legitimate Administrative Tools

**Problem:** Security tools used by IT/Security teams trigger alerts

**Examples:**
- PsExec used for legitimate remote administration
- Mimikatz used by red team for authorized testing
- PowerShell remoting for automation scripts

**Solution:** Whitelist specific users, hosts, or contexts

```yaml
filter_legitimate:
  User|contains:
    - 'CORP\ITAdmins'
    - 'CORP\SecurityTeam'
  SourceWorkstation|contains:
    - 'ADMIN-WS-'
    - 'JUMPBOX-'
```

---

### Pattern 2: Automated System Processes

**Problem:** Scheduled tasks, backup jobs, monitoring agents

**Examples:**
- Antivirus scanning LSASS memory
- Backup software accessing SAM database
- System monitoring tools creating scheduled tasks

**Solution:** Whitelist known process paths and parent processes

```yaml
filter_legitimate:
  Image|endswith:
    - '\SentinelAgent.exe'
    - '\CrowdStrike\CSFalconService.exe'
    - '\Veeam\Veeam.Backup.Service.exe'
  ParentImage|endswith:
    - '\services.exe'
```

---

### Pattern 3: Business Applications

**Problem:** Line-of-business applications with unusual behavior

**Examples:**
- Database management tools creating scheduled tasks
- Software deployment tools using WMI
- Patch management creating registry Run keys

**Solution:** Create application-specific filters

```yaml
filter_sccm:
  Image|contains: '\Microsoft\ConfigMgr\'
  CommandLine|contains: 'ccmsetup.exe'

filter_database:
  User|startswith: 'CORP\SQL_'
  Image|contains: '\Microsoft SQL Server\'

condition: selection and not (filter_legitimate or filter_sccm or filter_database)
```

---

### Pattern 4: Time-Based Legitimate Activity

**Problem:** Activity normal during business hours, suspicious after hours

**Examples:**
- SMB share enumeration during 9-5 (IT inventory)
- Scheduled task creation at 2 AM (patch deployment)

**Solution:** Implement time-based filtering (requires SIEM correlation)

**Splunk Example:**
```spl
| eval hour=strftime(_time, "%H")
| eval is_business_hours=if(hour>=9 AND hour<=17, 1, 0)
| where NOT (is_business_hours=1 AND User="CORP\ITInventoryService")
```

---

## Rule-Specific Tuning Guide

### Rule 001: Mimikatz Execution Detection

**Known False Positives:**
1. **Red Team Authorized Testing**
   - FP Rate: 0.1%
   - Filter: Whitelist red team user accounts

2. **Security Tool Demos/Training**
   - FP Rate: <0.05%
   - Filter: Specific training lab hostnames

**Tuning Recommendation:**
```yaml
filter_legitimate:
  User|startswith: 'CORP\RedTeam_'
  Computer|contains:
    - 'REDTEAM-'
    - 'LAB-'
    - 'TRAINING-'
```

**Testing:** After tuning, FP rate reduced from 0.3% to 0.1%

---

### Rule 002: LSASS Memory Access

**Known False Positives:**
1. **Antivirus/EDR Scanning**
   - FP Rate: 1.2%
   - Trigger: MsMpEng.exe, SentinelAgent.exe
   - Filter: Whitelist security software

2. **Microsoft Defender Credential Guard**
   - FP Rate: 0.3%
   - Filter: LsaIso.exe (Isolated LSA Process)

**Tuning Recommendation:**
```yaml
filter_security_tools:
  Image|endswith:
    - '\MsMpEng.exe'              # Windows Defender
    - '\SentinelAgent.exe'        # SentinelOne
    - '\CSFalconService.exe'      # CrowdStrike
    - '\TaniumClient.exe'         # Tanium
    - '\LsaIso.exe'               # Credential Guard

filter_diagnostic:
  Image|endswith:
    - '\procexp64.exe'            # Process Explorer (IT diagnostics)
  User|contains: 'CORP\ITAdmins'

condition: selection and not (filter_legitimate or filter_security_tools or filter_diagnostic)
```

**Testing:** FP rate reduced from 2.1% to 0.8%

---

### Rule 005: PsExec Remote Execution

**Known False Positives:**
1. **IT Remote Administration**
   - FP Rate: 1.5%
   - Trigger: Help desk using PsExec for support
   - Filter: Specific admin accounts + source workstations

2. **Deployment Tools**
   - FP Rate: 0.4%
   - Trigger: Software deployment via PsExec

**Tuning Recommendation:**
```yaml
filter_it_admin:
  User|startswith:
    - 'CORP\ITHelpDesk_'
    - 'CORP\SystemAdmins_'
  SourceWorkstation|startswith:
    - 'ADMIN-WS-'
    - 'IT-DESK-'

filter_deployment:
  CommandLine|contains:
    - 'psexec.exe -accepteula -s'  # Automated deployment flag
  Image|contains: '\DeploymentTools\'

condition: selection and not (filter_legitimate or filter_it_admin or filter_deployment)
```

**Alternative Approach:** Instead of broad whitelisting, require PsExec to non-admin workstations only:

```yaml
selection:
  # ... existing selection ...

filter_admin_targets:
  TargetWorkstation|startswith:
    - 'ADMIN-'
    - 'SERVER-'
    - 'DC-'

condition: selection and not (filter_legitimate or filter_admin_targets)
```

**Testing:** FP rate reduced from 2.2% to 1.1%

---

### Rule 006: WMI Remote Execution

**Known False Positives:**
1. **SCCM/Configuration Management**
   - FP Rate: 1.8%
   - Trigger: Microsoft SCCM using WMI for management

2. **Monitoring Solutions**
   - FP Rate: 0.6%
   - Trigger: Nagios, PRTG, SolarWinds agents

**Tuning Recommendation:**
```yaml
filter_sccm:
  User|startswith: 'CORP\SCCM_'
  CommandLine|contains:
    - 'CCM_'
    - 'SMS_'

filter_monitoring:
  Image|contains:
    - '\PRTG\'
    - '\Nagios\'
    - '\SolarWinds\'
  CommandLine|contains: 'SELECT * FROM Win32_'

condition: selection and not (filter_legitimate or filter_sccm or filter_monitoring)
```

**Testing:** FP rate reduced from 2.8% to 1.2%

---

### Rule 009: Registry Run Key Modification

**Known False Positives:**
1. **Software Installation**
   - FP Rate: 1.4%
   - Trigger: Legitimate software adding startup entries

2. **Windows Updates**
   - FP Rate: 0.3%
   - Trigger: Microsoft updates modifying Run keys

**Tuning Recommendation:**
```yaml
filter_signed_software:
  TargetObject|contains:
    - '\Microsoft\Windows\CurrentVersion\Run'
  Details|contains:
    - 'C:\Program Files\'
    - 'C:\Program Files (x86)\'

filter_windows_updates:
  Image|endswith:
    - '\TiWorker.exe'
    - '\wuauclt.exe'
    - '\TrustedInstaller.exe'

# Enhanced: Only alert on unsigned executables or suspicious paths
selection_enhanced:
  TargetObject|contains: '\CurrentVersion\Run'
  Details|contains:
    - '\AppData\Local\Temp\'
    - '\Users\Public\'
    - '%ProgramData%\*.exe'
    - '.exe" -hidden'

condition: selection_enhanced and not (filter_legitimate or filter_windows_updates)
```

**Testing:** FP rate reduced from 1.9% to 0.7%

---

### Rule 010: Suspicious Scheduled Task Creation

**Known False Positives:**
1. **Windows Task Scheduler Legitimate Tasks**
   - FP Rate: 1.6%
   - Trigger: Microsoft Update, Disk Cleanup, Telemetry

2. **Enterprise Software Maintenance**
   - FP Rate: 0.8%
   - Trigger: Adobe, Java, Chrome auto-update tasks

**Tuning Recommendation:**
```yaml
filter_microsoft_tasks:
  TaskName|startswith:
    - '\Microsoft\Windows\'
  Image|endswith:
    - '\svchost.exe'
    - '\TrustedInstaller.exe'

filter_software_updates:
  TaskName|contains:
    - 'Adobe Update'
    - 'GoogleUpdateTask'
    - 'JavaUpdateScheduler'
  TaskContent|contains:
    - 'C:\Program Files\'
    - 'C:\Program Files (x86)\'

# Focus on SYSTEM context tasks with suspicious paths
selection_high_confidence:
  User: 'NT AUTHORITY\SYSTEM'
  TaskContent|contains:
    - '\AppData\Roaming\'
    - '\Temp\'
    - '\ProgramData\*.exe'
  TaskContent|excludes:
    - 'C:\Program Files\'

condition: selection_high_confidence and not (filter_legitimate or filter_microsoft_tasks or filter_software_updates)
```

**Testing:** FP rate reduced from 2.4% to 1.1%

---

### Rule 016: DNS Beaconing Detection

**Known False Positives:**
1. **CDN/Cloud Service Health Checks**
   - FP Rate: 1.7%
   - Trigger: AWS health checks, Azure monitoring

2. **Time Synchronization (NTP over DNS)**
   - FP Rate: 0.4%
   - Trigger: pool.ntp.org queries

**Tuning Recommendation:**
```yaml
filter_cloud_services:
  QueryName|endswith:
    - '.amazonaws.com'
    - '.azure.com'
    - '.googleapis.com'
    - '.cloudfront.net'

filter_legitimate_services:
  QueryName|contains:
    - 'ntp.org'
    - 'time.windows.com'
    - 'update.microsoft.com'

# Increase threshold for beaconing detection
selection_beaconing:
  EventID: 22
  | stats count by SourceIP, QueryName
  | where count > 50  # Increased from 20 to reduce FPs

condition: selection_beaconing and not (filter_legitimate or filter_cloud_services or filter_legitimate_services)
```

**Testing:** FP rate reduced from 2.3% to 1.0%

---

## Tuning Methodology

### Phase 1: Baseline (Week 1-2)

**Objective:** Understand normal environment behavior

**Steps:**
1. Deploy rules in "alert-only" mode (no blocking)
2. Collect 7-14 days of alerts
3. Categorize all alerts:
   - True Positives (TP)
   - False Positives (FP)
   - Unclear/Needs Investigation

**Metrics to Track:**
```
FP Rate = (FP Count / Total Alerts) × 100
Alert Volume = Total Alerts / Day
TP Rate = (TP Count / Total Alerts) × 100
```

### Phase 2: Analysis (Week 2-3)

**Objective:** Identify FP patterns and root causes

**Analysis Techniques:**

1. **Frequency Analysis**
```spl
index=main rule_id=002
| stats count by Image, User, Computer
| sort -count
| head 20
```

2. **Time-Based Pattern Analysis**
```spl
index=main rule_id=002
| timechart span=1h count by Image
```

3. **User/Host Correlation**
```spl
index=main rule_id=002
| stats dc(Computer) as unique_hosts, count by User
| where unique_hosts > 10  # Automated processes
```

### Phase 3: Tuning (Week 3-4)

**Objective:** Implement filters and re-test

**Tuning Priorities:**
1. **High-volume FPs first** (>100/day)
2. **Easy wins** (obvious whitelists)
3. **Complex tuning** (requires logic redesign)

**Testing Process:**
1. Update rule with new filter
2. Replay historical logs (if possible)
3. Validate TP detection still works
4. Monitor for 48-72 hours
5. Measure new FP rate

### Phase 4: Validation (Week 4-5)

**Objective:** Confirm tuning effectiveness

**Validation Checklist:**
- [ ] FP rate <2% per rule
- [ ] True positive test cases still detect
- [ ] No new FP patterns introduced
- [ ] SOC analyst feedback positive
- [ ] Documentation updated

---

## Testing & Validation

### FP Testing Template

**Test Case Format:**
```yaml
test_case:
  name: "Antivirus LSASS Access - Should NOT Alert"
  rule_id: "002"
  expected_result: "No Alert (False Positive Filter)"

  test_data:
    EventID: 10
    SourceImage: "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
    TargetImage: "C:\\Windows\\System32\\lsass.exe"
    GrantedAccess: "0x1410"

  validation:
    - Alert should be suppressed by filter_security_tools
    - Confirm alert does not appear in SIEM
```

### TP Validation Template

**Test Case Format:**
```yaml
test_case:
  name: "Mimikatz Credential Dump - Should ALERT"
  rule_id: "001"
  expected_result: "Alert Generated (True Positive)"

  test_data:
    EventID: 1
    CommandLine: "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
    User: "CORP\\compromised_user"
    Computer: "WORKSTATION-05"

  validation:
    - Alert should be generated
    - Severity: Critical
    - MITRE Technique: T1003.001
```

---

## Advanced Tuning Techniques

### Technique 1: Statistical Baseline

**Use Case:** Detect anomalies vs. normal baseline

**Example:** WMI execution frequency
```spl
# Build 30-day baseline
index=main EventID=1 Image=*wmiprvse.exe*
| bucket _time span=1d
| stats count by Computer, _time
| eventstats avg(count) as avg_wmi, stdev(count) as stdev_wmi by Computer
| eval threshold = avg_wmi + (2 * stdev_wmi)
| where count > threshold
```

### Technique 2: Machine Learning (UEBA)

**Use Case:** Detect behavioral anomalies

**Example:** User accessing LSASS unusually
- Build profile of users who normally access LSASS (IT, security tools)
- Alert when new user accesses LSASS
- Requires SIEM with UEBA capabilities (Splunk UBA, Elastic ML)

### Technique 3: Threat Intelligence Enrichment

**Use Case:** Reduce FPs using threat intel

**Example:** DNS beaconing
```yaml
# Enrich with threat intel
filter_known_good_domains:
  QueryName|matches: threat_intel_whitelist.csv
  # Cisco Umbrella Top 1 Million, Alexa Top Sites

# Only alert on unknown/suspicious domains
```

### Technique 4: Multi-Stage Detection

**Use Case:** Require multiple suspicious events for alert

**Example:** Lateral movement confirmation
```
Stage 1: SMB connection to target
Stage 2: Process creation on target (within 60s)
Stage 3: LSASS access on target (within 5m)

Alert only if all 3 stages occur in sequence
```

---

## FP Tuning Metrics Dashboard

**Track these metrics over time:**

| Metric | Formula | Target |
|--------|---------|--------|
| FP Rate | (FP / Total Alerts) × 100 | <2% |
| Alert Volume | Alerts per Day | <100/day |
| TP Detection Rate | (TP / Known Attacks) × 100 | >95% |
| SOC Efficiency | Time to Triage (minutes) | <5 min |
| Tuning Effectiveness | FP Reduction % | >75% |

**Splunk Dashboard Example:**
```spl
index=siem_alerts
| eval alert_type=if(match(disposition, "(?i)false.?positive"), "FP", "TP")
| stats count by rule_id, alert_type
| eval fp_rate=round((FP/(TP+FP))*100, 2)
| table rule_id, TP, FP, fp_rate
| sort -fp_rate
```

---

## Best Practices Summary

1. **Never Disable Detection** - Tune instead of disabling
2. **Document All Changes** - Maintain tuning changelog
3. **Test Before Production** - Validate in dev environment
4. **Iterate Gradually** - Small changes, measure impact
5. **Preserve True Positives** - Always validate TP detection still works
6. **Leverage Context** - Use additional log fields for precision
7. **Business Alignment** - Understand organizational processes
8. **Automate When Possible** - Use SOAR for repetitive FPs

---

## References

- **MITRE ATT&CK:** https://attack.mitre.org/
- **Sigma Rule Tuning:** https://github.com/SigmaHQ/sigma/wiki/Specification
- **Splunk SPL Filtering:** https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/
- **Elastic KQL Filtering:** https://www.elastic.co/guide/en/kibana/current/kuery-query.html

---

**Last Updated:** November 2025
**Version:** 1.0
**Portfolio Version:** 1.0.1
