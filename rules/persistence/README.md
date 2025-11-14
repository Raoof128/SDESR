# Persistence Detection Rules

This directory contains 3 Sigma detection rules focused on identifying persistence mechanisms used by attackers to maintain access to compromised systems.

## Rules Overview

| Rule ID | Rule Name | Severity | MITRE ATT&CK | FP Rate |
|---------|-----------|----------|--------------|---------|
| 009 | Registry Run Key Modification | High | T1547.001, T1112 | 1.4% |
| 010 | Suspicious Scheduled Task Creation | High | T1053.005, T1053 | 1.6% |
| 011 | Startup Folder Modification | Medium | T1547.001, T1204.002 | 1.2% |

## Attack Scenario

Persistence mechanisms allow attackers to maintain access to compromised systems across:
- System reboots
- User logoffs
- Security software updates
- Credential changes

Without persistence, attackers would need to re-exploit systems after each restart, making their operations much more difficult and detectable.

## Detection Strategy

These rules detect persistence through:

1. **Registry modifications**: Autostart locations in Windows Registry
2. **Scheduled tasks**: Tasks executing at specific times or conditions
3. **Startup folders**: Files executing at user logon
4. **Behavioral patterns**: Suspicious processes creating persistence

## Common Persistence Locations

```
Windows Persistence Hierarchy (Most to Least Common):

1. Registry Run Keys ←─────────── Rule 009
   - HKLM\...\Run
   - HKCU\...\Run
   - RunOnce variants

2. Scheduled Tasks ←──────────── Rule 010
   - /create /tn /tr /sc
   - PowerShell ScheduledTask cmdlets

3. Startup Folders ←──────────── Rule 011
   - User-specific: %APPDATA%\...\Startup
   - All Users: %PROGRAMDATA%\...\StartUp

4. Services (not covered in this set)
5. WMI Event Subscriptions (not covered)
```

## Testing Recommendations

Use Atomic Red Team to simulate persistence:

```powershell
# Test Rule 009: Registry Run Keys
Invoke-AtomicTest T1547.001 -TestNumbers 1,2

# Test Rule 010: Scheduled Tasks
Invoke-AtomicTest T1053.005 -TestNumbers 1,2,3

# Test Rule 011: Startup Folder
Invoke-AtomicTest T1547.001 -TestNumbers 4
```

## Manual Testing Examples

**Registry persistence:**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestPersistence /t REG_SZ /d "C:\Windows\System32\calc.exe"
```

**Scheduled task persistence:**
```cmd
schtasks /create /tn "TestTask" /tr "C:\Windows\System32\calc.exe" /sc onlogon
```

**Startup folder persistence:**
```cmd
copy C:\Windows\System32\calc.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\test.exe"
```

## False Positive Tuning

**Common false positives:**

**Rule 009 (Registry Run Keys):**
- Legitimate software installations
- Windows updates
- User-installed applications (browsers, productivity tools)

**Rule 010 (Scheduled Tasks):**
- Software update mechanisms (Google Update, Adobe)
- Backup software
- System maintenance tasks

**Rule 011 (Startup Folder):**
- Cloud storage clients (OneDrive, Dropbox)
- Communication tools (Teams, Slack)
- User productivity apps

**Tuning recommendations:**
1. Baseline normal persistence during clean system imaging
2. Whitelist known-good software by installation path
3. Create exceptions for authorized enterprise software
4. Monitor changes to whitelists for tampering

## Investigation Workflow

When a persistence alert fires:

1. **Identify the persistence mechanism**
   - What: Registry key, scheduled task, or startup file?
   - Where: Exact location and name
   - When: Timestamp of creation

2. **Analyze the payload**
   - File hash analysis (VirusTotal, internal threat intel)
   - File location (legitimate vs. suspicious path)
   - Digital signature verification

3. **Determine origin**
   - What process created the persistence?
   - What user context?
   - Network activity correlated with creation time?

4. **Assess scope**
   - Is this system the only victim?
   - Has the persistence mechanism executed?
   - What other systems might be affected?

5. **Containment and remediation**
   - Isolate affected system
   - Remove persistence mechanism
   - Hunt for additional persistence on same system
   - Check for lateral movement from this system

## Detection Gaps and Enhancements

**Current rules do NOT detect:**
- Service creation/modification (T1543.003)
- WMI Event Subscriptions (T1546.003)
- DLL hijacking (T1574.001)
- Browser extensions (T1176)
- Office application startup (T1137)

**Recommended additional rules:**
```yaml
# Future enhancements
- Windows Service Abuse Detection
- WMI Event Consumer Persistence
- DLL Search Order Hijacking
- Accessibility Features Abuse (Sticky Keys)
```

## Real-World Examples

**APT29 (Cozy Bear):**
- Uses scheduled tasks for persistence
- Creates tasks named to blend with legitimate Windows tasks
- Often executes PowerShell scripts from ProgramData

**Emotet:**
- Registry Run key persistence
- Creates entries like "HKCU\...\Run\<random>"
- Points to malicious DLL in %AppData%

**Cobalt Strike:**
- Multiple persistence options including scheduled tasks
- Often uses tasks with SYSTEM privileges
- Encrypted PowerShell payloads

## Performance Optimization

**For high-volume environments:**

1. **Pre-filter in data collection:**
   - Only ingest Sysmon Event IDs: 11 (File Create), 13 (Registry)
   - Filter out known-good software at forwarder level

2. **Aggregate before alerting:**
   - Count persistence attempts per host per hour
   - Alert on threshold (e.g., >5 new Run keys in 1 hour)

3. **Use lookup tables:**
   - Maintain whitelist of approved software
   - Hash-based lookups for known-good executables

## Integration with SIEM

**Splunk example - correlation search:**
```spl
index=sysmon EventCode IN (11,13)
| eval persistence_type=case(
    like(TargetObject,"%Run%"),"Registry Run Key",
    like(TargetFilename,"%Startup%"),"Startup Folder",
    true(),"Other"
  )
| stats count by Computer, persistence_type, Image
| where count > 3
```

**Elastic example - threshold rule:**
```json
{
  "query": "event.code:(11 OR 13) AND (file.path:*Startup* OR registry.path:*Run*)",
  "threshold": {
    "field": "host.name",
    "value": 3,
    "cardinality": [
      {
        "field": "process.name",
        "value": 2
      }
    ]
  }
}
```

## References

- [MITRE ATT&CK: Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Microsoft: Windows Persistence Techniques](https://docs.microsoft.com/en-us/windows/security/threat-protection/)
- [SigmaHQ Persistence Rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/persistence)
