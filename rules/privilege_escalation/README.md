# Privilege Escalation Detection Rules

This directory contains 4 Sigma detection rules focused on identifying privilege escalation techniques used by attackers to gain higher-level permissions on compromised systems.

## Rules Overview

| Rule ID | Rule Name | Severity | MITRE ATT&CK | FP Rate |
|---------|-----------|----------|--------------|---------|
| 012 | Token Impersonation Detection | Critical | T1134, T1134.001, T1134.002 | 0.7% |
| 013 | UAC Bypass Attempt Detection | High | T1548.002, T1548 | 1.3% |
| 014 | SeDebug Privilege Enabled | High | T1134.001, T1055, T1003.001 | 0.9% |
| 015 | Process Injection Detection | Critical | T1055, T1055.001, T1055.002 | 1.1% |

## Attack Scenario

Privilege escalation allows attackers to move from:
- **Standard User → Administrator** (horizontal escalation)
- **Administrator → SYSTEM** (vertical escalation)
- **User Context → Another User** (lateral privilege movement)

This is critical because it enables:
- Access to protected system resources
- Credential dumping from privileged processes
- Disabling security controls
- Installing persistent backdoors
- Full system compromise

## Attack Chain Context

```
Initial Access → Execution → Persistence → [Privilege Escalation] → Defense Evasion
                                                    ↓
                                              These Rules
                                                    ↓
                        Token Theft | UAC Bypass | SeDebug | Injection
```

## Detection Strategy

These rules detect privilege escalation through:

1. **Access Token Manipulation**: Stealing or creating elevated tokens (Rule 012)
2. **UAC Bypass**: Circumventing User Account Control prompts (Rule 013)
3. **Dangerous Privileges**: Enabling SeDebugPrivilege for memory access (Rule 014)
4. **Code Injection**: Injecting into privileged processes (Rule 015)

## Common Privilege Escalation Techniques

### Windows Privilege Levels

```
┌─────────────────────────────────────────┐
│  SYSTEM (NT AUTHORITY\SYSTEM)           │ ← Highest
├─────────────────────────────────────────┤
│  Administrator (High Integrity)          │
├─────────────────────────────────────────┤
│  Administrator (Medium Integrity + UAC)  │ ← Rules 012, 013
├─────────────────────────────────────────┤
│  Standard User (Medium Integrity)        │ ← Starting point
├─────────────────────────────────────────┤
│  Low Integrity (Sandboxed)               │
└─────────────────────────────────────────┘
```

## Testing Recommendations

Use Atomic Red Team to simulate privilege escalation:

```powershell
# Test Rule 012: Token Impersonation
Invoke-AtomicTest T1134.001 -TestNumbers 1,2

# Test Rule 013: UAC Bypass
Invoke-AtomicTest T1548.002 -TestNumbers 1,2,3

# Test Rule 014: SeDebugPrivilege
# Requires administrative privileges
Get-Process | Select-Object -First 1 | Debug-Process

# Test Rule 015: Process Injection
Invoke-AtomicTest T1055 -TestNumbers 1,2
```

## Manual Testing Examples

**Token impersonation (requires admin):**
```powershell
# Enable SeDebugPrivilege
$process = Get-Process lsass
$handle = [YourNamespace.Win32]::OpenProcess(0x1F0FFF, $false, $process.Id)
```

**UAC bypass - Fodhelper method:**
```powershell
# Create registry key for UAC bypass
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe"
Start-Process "C:\Windows\System32\fodhelper.exe"
```

**Process injection - CreateRemoteThread:**
```powershell
# Inject DLL into target process (requires elevation)
Start-Process mavinject.exe -ArgumentList "$targetPID /INJECTRUNNING $dllPath"
```

## False Positive Tuning

**Common false positives:**

**Rule 012 (Token Impersonation):**
- Security software (AV, EDR) using SeImpersonatePrivilege
- Backup software impersonating users
- Service accounts with impersonation rights

**Rule 013 (UAC Bypass):**
- Legitimate auto-elevated Windows binaries
- Software installers using approved elevation methods
- Windows Update using TrustedInstaller

**Rule 014 (SeDebugPrivilege):**
- Debuggers (Visual Studio, WinDbg)
- Sysinternals tools (Process Explorer, Process Monitor)
- VMware Tools
- Monitoring software

**Rule 015 (Process Injection):**
- Antivirus behavioral analysis
- Application performance monitoring (APM) tools
- Game anti-cheat systems
- DRM software

**Tuning recommendations:**
1. Whitelist known security tools by path and signature
2. Filter SYSTEM account for specific legitimate processes
3. Baseline administrative activities during business hours
4. Create separate alert severity for known-good tools vs. unknowns

## Investigation Workflow

When a privilege escalation alert fires:

### Phase 1: Initial Assessment
1. **What privilege was escalated?**
   - Standard user → Admin?
   - Admin → SYSTEM?
   - Token impersonation?

2. **What method was used?**
   - UAC bypass technique
   - Token manipulation
   - Process injection
   - SeDebug abuse

3. **Context analysis:**
   - Time of day (business hours vs. off-hours)
   - User account type (standard vs. admin vs. service)
   - Host type (workstation vs. server vs. domain controller)

### Phase 2: Scope Determination
4. **Check for preceding credential theft:**
   ```spl
   index=sysmon host=$affected_host EventCode=10 TargetImage="*lsass.exe"
   | eval time_diff=_time-$escalation_time
   | where time_diff BETWEEN -300 AND 0
   ```

5. **Look for lateral movement attempts:**
   - Network connections to other hosts
   - SMB/RPC activity
   - Credential use on other systems

6. **Identify post-exploitation activity:**
   - Persistence mechanisms installed
   - Data access or exfiltration
   - Additional tools downloaded

### Phase 3: Containment
7. **Immediate actions:**
   - Isolate affected system from network
   - Disable compromised user account
   - Reset credentials for affected account
   - Check for scheduled tasks or services created

8. **Forensic collection:**
   - Memory dump of affected process
   - Registry export of Run keys
   - Event log export (Security, System, Sysmon)
   - Network connection logs

## Detection Enhancements

### Correlation Rules

**Multi-stage attack detection:**
```spl
index=sysmon
| transaction host maxspan=5m
| where (EventCode=4672 AND PrivilegeList="SeDebugPrivilege")
    AND (EventCode=10 AND TargetImage="*lsass.exe")
    AND (EventCode=3 AND DestinationPort=445)
| table _time, host, User, ProcessName, DestinationIP
```

This correlates:
1. SeDebugPrivilege enabled
2. LSASS access (credential theft)
3. SMB connection (lateral movement)

### Behavioral Baselines

Create baselines for:
- Normal privilege usage per user/system
- Expected processes using SeDebugPrivilege
- Typical UAC-prompted applications
- Standard injection behaviors (AV/EDR)

**Example baseline query:**
```spl
index=windows EventCode=4672
| stats count by SubjectUserName, PrivilegeList, ProcessName
| where count > 10
| outputlookup baseline_privileges.csv
```

## Real-World Attack Examples

**Cobalt Strike Beacon:**
- Uses token impersonation (steal_token command)
- Injects into explorer.exe or other long-running processes
- Enables SeDebugPrivilege before credential dumping
- Often uses UAC bypass for initial elevation

**Mimikatz:**
- Requires SeDebugPrivilege for credential dumping
- Uses token impersonation (token::elevate)
- Can be loaded reflectively to avoid disk artifacts
- Often injected into lsass.exe process space

**PowerSploit:**
- Invoke-TokenManipulation for token theft
- Invoke-ReflectivePEInjection for stealth
- UAC bypass modules (Invoke-EventVwrBypass)

## Advanced Evasion Techniques

Attackers may attempt to evade these rules by:

1. **Living off the land**: Using signed Windows binaries
2. **Parent PID spoofing**: Making malicious processes appear legitimate
3. **Direct syscalls**: Bypassing API hooking by EDR
4. **Process doppelgänging**: Advanced injection technique
5. **Token manipulation timing**: Brief elevation followed by de-elevation

**Enhanced detection for evasion:**
- Monitor for PID recycling attacks
- Detect syscall sequences via ETW
- Track process genealogy anomalies
- Analyze handle operations

## Performance Considerations

**High-volume event types:**
- EventID 4673 (Sensitive Privilege Use): Can generate 1000s/hour
- EventID 10 (Process Access): Very high volume in enterprise

**Optimization strategies:**

1. **Pre-filtering at collection:**
   ```xml
   <!-- Sysmon config: Only monitor specific target processes -->
   <ProcessAccess onmatch="include">
     <TargetImage condition="end with">lsass.exe</TargetImage>
     <TargetImage condition="end with">csrss.exe</TargetImage>
   </ProcessAccess>
   ```

2. **Aggregation before alerting:**
   ```spl
   | stats count by host, User, ProcessName
   | where count > 5  # Alert on repeated attempts
   ```

3. **Use cached lookups for whitelisting:**
   ```spl
   | lookup known_good_processes.csv ProcessName OUTPUT is_legitimate
   | where is_legitimate != "true"
   ```

## Integration with SIEM

**Splunk - Privilege Escalation Summary:**
```spl
index=windows OR index=sysmon (EventCode=4672 OR EventCode=4673 OR EventCode=8 OR EventCode=10)
| eval escalation_type=case(
    EventCode=4672 AND PrivilegeList="SeDebugPrivilege", "SeDebug Enabled",
    EventCode=8, "Remote Thread Injection",
    EventCode=10 AND GrantedAccess IN ("0x1F3FFF","0x1438"), "Suspicious Process Access",
    true(), "Other"
  )
| stats count by host, User, escalation_type, ProcessName
| sort -count
```

**Elastic - Multi-technique detection:**
```json
{
  "query": {
    "bool": {
      "should": [
        { "match": { "event.code": "4672" }},
        { "match": { "event.code": "4673" }},
        { "match": { "sysmon.event_id": "8" }},
        { "match": { "sysmon.event_id": "10" }}
      ],
      "minimum_should_match": 1,
      "filter": [
        { "range": { "@timestamp": { "gte": "now-15m" }}}
      ]
    }
  }
}
```

## References

- [MITRE ATT&CK: Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [Windows Privilege Escalation Guide](https://github.com/frizb/Windows-Privilege-Escalation)
- [Token Manipulation Techniques](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [UAC Bypass Methods (UACME)](https://github.com/hfiref0x/UACME)
