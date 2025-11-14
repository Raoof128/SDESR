# Credential Dumping Detection Rules

This directory contains 4 Sigma detection rules focused on identifying credential theft and dumping techniques.

## Rules Overview

| Rule ID | Rule Name | Severity | MITRE ATT&CK | FP Rate |
|---------|-----------|----------|--------------|---------|
| 001 | Mimikatz Execution Detection | Critical | T1003.001, T1055, T1110 | 0.1% |
| 002 | LSASS Process Memory Access | Critical | T1003.001 | 1.2% |
| 003 | Windows Credential Manager Access | High | T1555.004, T1003.001 | 0.8% |
| 004 | SAM Database Credential Dumping | Critical | T1003.002, T1003.003 | 0.3% |

## Attack Scenario

Credential dumping is one of the most common post-exploitation techniques used by attackers to:
- Extract plaintext passwords from memory
- Harvest password hashes for offline cracking
- Steal Kerberos tickets for lateral movement
- Access saved credentials in password vaults

## Detection Strategy

These rules detect credential dumping through multiple layers:

1. **Tool-based detection**: Identifying known credential dumping tools (Mimikatz, etc.)
2. **Behavioral detection**: Suspicious access to sensitive processes (lsass.exe)
3. **File access patterns**: Unauthorized reads of credential stores (SAM, Vault)
4. **Command-line analysis**: Detecting credential enumeration commands

## Testing Recommendations

Use Atomic Red Team to simulate these attacks:

```powershell
# Test Rule 001: Mimikatz
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Test Rule 002: LSASS Access
Invoke-AtomicTest T1003.001 -TestNumbers 2

# Test Rule 003: Credential Manager
Invoke-AtomicTest T1555.004 -TestNumbers 1

# Test Rule 004: SAM Dumping
Invoke-AtomicTest T1003.002 -TestNumbers 1
```

## False Positive Tuning

**Common false positives:**
- Legitimate AV/EDR tools accessing lsass.exe (Rule 002)
- System backup software copying SAM hive (Rule 004)
- Users managing saved credentials (Rule 003)

**Tuning recommendations:**
- Whitelist known security software by process path
- Filter system processes (SYSTEM user context)
- Add organizational-specific legitimate tools

## Integration Notes

**Splunk:**
```spl
index=sysmon OR index=windows
| sigmac --target splunk 001_mimikatz_execution.yml
```

**Elastic:**
```bash
sigmac --target elastic 001_mimikatz_execution.yml
```

## Real-World Impact

Detection of credential dumping is **critical** because:
- 80% of breaches involve credential compromise
- Mean time to detect: Often weeks without proper detection
- Enables lateral movement and privilege escalation
- Required for compliance (PCI-DSS, SOC 2, ISO 27001)

## References

- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1555](https://attack.mitre.org/techniques/T1555/)
- [SigmaHQ Credential Access Rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/credential_access)
