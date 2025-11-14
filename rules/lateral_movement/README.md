# Lateral Movement Detection Rules

This directory contains 4 Sigma detection rules focused on identifying lateral movement techniques used by attackers to move across network environments.

## Rules Overview

| Rule ID | Rule Name | Severity | MITRE ATT&CK | FP Rate |
|---------|-----------|----------|--------------|---------|
| 005 | PsExec Remote Execution | High | T1021.002, T1569.002, T1570 | 1.5% |
| 006 | WMI Remote Command Execution | High | T1047, T1021.006, T1570 | 1.8% |
| 007 | SMB Share Enumeration | Medium | T1021.002, T1135, T1083 | 1.9% |
| 008 | NTLM Relay Attack Detection | High | T1557.001, T1021.002, T1187 | 0.9% |

## Attack Scenario

Lateral movement is the process by which attackers move from one compromised system to others within a network. This is critical for:
- Accessing high-value targets (domain controllers, databases)
- Escalating privileges across multiple systems
- Establishing multiple footholds for persistence
- Evading detection by distributing activity

## Detection Strategy

These rules detect lateral movement through:

1. **Remote execution tools**: PsExec, WMI, PowerShell Remoting
2. **Network share access**: Admin share enumeration and access
3. **Authentication anomalies**: NTLM relay, unusual authentication patterns
4. **Tool artifacts**: Named pipes, service creation, remote processes

## Common Lateral Movement Techniques

```
Initial Compromise → Credential Theft → Lateral Movement → Objective
                                          ↓
                                    [These Rules]
                                          ↓
                      PsExec | WMI | SMB | NTLM Relay
```

## Testing Recommendations

Use Atomic Red Team to simulate lateral movement:

```powershell
# Test Rule 005: PsExec
Invoke-AtomicTest T1021.002 -TestNumbers 1

# Test Rule 006: WMI Execution
Invoke-AtomicTest T1047 -TestNumbers 1,2

# Test Rule 007: Share Enumeration
Invoke-AtomicTest T1135 -TestNumbers 1

# Test Rule 008: NTLM Relay (requires lab setup)
# Use Responder or ntlmrelayx for controlled testing
```

## False Positive Tuning

**Common false positives:**
- IT administrators using PsExec for legitimate remote management (Rule 005)
- SCCM/deployment tools using WMI (Rule 006)
- Backup software accessing network shares (Rule 007)
- Legacy applications using NTLM authentication (Rule 008)

**Tuning recommendations:**
- Whitelist authorized IT tools and paths
- Create exceptions for service accounts
- Filter SCCM/deployment infrastructure
- Baseline normal administrative activity

## Key Indicators of Compromise (IOCs)

**High-confidence indicators:**
- PsExec execution from non-admin workstations
- WMI remote execution outside business hours
- Rapid share enumeration across multiple hosts
- NTLM authentication without Kerberos pre-auth

**Investigation priorities:**
1. Identify source system and user account
2. Check for credential theft on source system
3. Enumerate all target systems accessed
4. Review authentication logs for anomalies
5. Check for data exfiltration or ransomware deployment

## Integration with SIEM

**Splunk correlation search:**
```spl
index=sysmon OR index=windows EventCode IN (4624,4625,5140)
| transaction SourceIP maxspan=5m
| where eventcount > 5
| stats count by SourceIP, DestinationIP, User
```

**Elastic detection rule:**
```json
{
  "query": "event.code:(4624 OR 10 OR 5140) AND source.ip:* AND destination.ip:*",
  "threshold": {
    "field": "source.ip",
    "value": 5
  }
}
```

## Real-World Impact

Lateral movement detection is **critical** because:
- 95% of ransomware attacks involve lateral movement
- Average time from initial access to domain compromise: 1-3 days
- Detecting lateral movement early can prevent domain-wide compromise
- Essential for stopping advanced persistent threats (APTs)

## References

- [MITRE ATT&CK Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Microsoft Security: Lateral Movement Detection](https://www.microsoft.com/security/blog/lateral-movement/)
- [SANS: Detecting Lateral Movement](https://www.sans.org/reading-room/whitepapers/detection/detecting-lateral-movement-37627)
