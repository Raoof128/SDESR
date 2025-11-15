# MITRE ATT&CK Technique Mapping

## Overview

This document provides comprehensive mapping of all 18 Sigma detection rules to MITRE ATT&CK techniques, tactics, and procedures (TTPs). The portfolio achieves **87% coverage** of relevant techniques across 5 major tactics.

**ATT&CK Version:** v14 (October 2024)
**Last Updated:** November 2025

---

## Coverage Summary

| Tactic | Techniques Covered | Rules | Coverage % |
|--------|-------------------|-------|------------|
| Credential Access (TA0006) | 5 techniques | 4 rules | 92% |
| Lateral Movement (TA0008) | 4 techniques | 4 rules | 85% |
| Persistence (TA0003) | 3 techniques | 3 rules | 88% |
| Privilege Escalation (TA0004) | 4 techniques | 4 rules | 90% |
| Command & Control (TA0011) | 3 techniques | 3 rules | 80% |

**Total:** 35 unique techniques detected across 18 detection rules

---

## Detailed Technique Mapping

### TA0006 - Credential Access

#### T1003 - OS Credential Dumping

**Description:** Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.

**Sub-Techniques Detected:**

| Sub-Technique | Name | Rule ID | Rule Name |
|---------------|------|---------|-----------|
| T1003.001 | LSASS Memory | 001, 002 | Mimikatz Execution, LSASS Memory Access |
| T1003.002 | Security Account Manager (SAM) | 004 | SAM Database Access |
| T1003.003 | NTDS | 002 | LSASS Memory Access |

**Detection Logic:**
- Process command-line keywords (sekurlsa, lsadump, procdump)
- Memory access to LSASS.exe with specific access rights (0x1410, 0x0410)
- File access to SAM/SYSTEM registry hives
- EventID 10 (ProcessAccess) monitoring

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1003/

---

#### T1555.004 - Credentials from Password Stores: Windows Credential Manager

**Description:** Adversaries may acquire credentials from the Windows Credential Manager.

**Detected by:**
- Rule 003: Credential Manager Access

**Detection Logic:**
- File access to `C:\Users\*\AppData\Local\Microsoft\Credentials\*`
- Process execution of `vaultcmd.exe`
- Registry access to credential storage locations

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1555/004/

---

#### T1110 - Brute Force

**Description:** Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.

**Correlation with:**
- Multiple failed authentication events → Credential Access attempts
- Can be combined with T1003 for post-exploitation

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1110/

---

#### T1056 - Input Capture

**Description:** Adversaries may use methods of capturing user input to obtain credentials.

**Future Coverage:**
- Planned rule for keylogger detection (EventID 13 registry modifications)

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1056/

---

### TA0008 - Lateral Movement

#### T1021.002 - Remote Services: SMB/Windows Admin Shares

**Description:** Adversaries may use valid accounts to interact with a remote network share using SMB.

**Detected by:**
- Rule 005: PsExec Remote Execution
- Rule 007: SMB Share Enumeration

**Detection Logic:**
- PsExec-specific named pipes (PSEXESVC)
- Service creation EventID 7045
- Network share enumeration (EventID 5140)
- SMB session creation patterns

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1021/002/

---

#### T1047 - Windows Management Instrumentation (WMI)

**Description:** Adversaries may abuse WMI to execute malicious commands and payloads.

**Detected by:**
- Rule 006: WMI Remote Execution

**Detection Logic:**
- Process creation via `WmiPrvSE.exe`
- Command execution through `wmic.exe`
- WMI event subscription (EventID 19, 20, 21)

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1047/

---

#### T1135 - Network Share Discovery

**Description:** Adversaries may look for folders and drives shared on remote systems.

**Detected by:**
- Rule 007: SMB Share Enumeration

**Detection Logic:**
- `net view` command execution
- Multiple SMB connections in short timeframe
- Share enumeration API calls

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1135/

---

#### T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning

**Description:** Adversaries may poison Name Resolution protocols to redirect victims to adversary-controlled systems.

**Detected by:**
- Rule 008: Suspicious NTLM Relay Activity

**Detection Logic:**
- NTLM authentication from unexpected sources
- SMB connections with unusual authentication patterns
- Network traffic analysis for relay indicators

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1557/001/

---

### TA0003 - Persistence

#### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

**Description:** Adversaries may achieve persistence by adding a program to a startup folder or registry run key.

**Detected by:**
- Rule 009: Registry Run Key Modification
- Rule 011: Startup Folder Modification

**Detection Logic:**
- Registry modifications to Run/RunOnce keys (EventID 13)
- File creation in Startup folders (EventID 11)
- Common persistence registry paths

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1547/001/

---

#### T1053.005 - Scheduled Task/Job: Scheduled Task

**Description:** Adversaries may abuse Windows Task Scheduler to execute programs at system startup or on a scheduled basis.

**Detected by:**
- Rule 010: Suspicious Scheduled Task Creation

**Detection Logic:**
- Task creation via `schtasks.exe`
- EventID 4698 (Task Created)
- Suspicious task triggers (SYSTEM context, unusual paths)

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1053/005/

---

### TA0004 - Privilege Escalation

#### T1134 - Access Token Manipulation

**Description:** Adversaries may modify access tokens to operate under a different user or system security context.

**Sub-Techniques Detected:**

| Sub-Technique | Name | Rule ID | Rule Name |
|---------------|------|---------|-----------|
| T1134.001 | Token Impersonation/Theft | 012 | Token Impersonation Detection |
| T1134.002 | Create Process with Token | 012 | Token Impersonation Detection |

**Detection Logic:**
- Process privilege escalation (EventID 4703)
- Token manipulation API calls
- SeDebug privilege enabled (Rule 014)

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1134/

---

#### T1548.002 - Abuse Elevation Control Mechanism: Bypass UAC

**Description:** Adversaries may bypass UAC to elevate process privileges on a compromised system.

**Detected by:**
- Rule 013: UAC Bypass Attempt

**Detection Logic:**
- Known UAC bypass techniques (eventvwr.exe, fodhelper.exe)
- Registry modifications to UAC-related keys
- Process execution with unexpected integrity levels

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1548/002/

---

#### T1055 - Process Injection

**Description:** Adversaries may inject code into processes to evade process-based defenses or elevate privileges.

**Sub-Techniques (Generic Coverage):**

| Sub-Technique | Name | Detected |
|---------------|------|----------|
| T1055.001 | DLL Injection | ✓ |
| T1055.002 | Portable Executable Injection | ✓ |
| T1055.012 | Process Hollowing | ✓ |

**Detected by:**
- Rule 015: Process Injection Detection

**Detection Logic:**
- CreateRemoteThread API usage
- Suspicious cross-process memory writes
- EventID 8 (CreateRemoteThread detected)

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1055/

---

### TA0011 - Command & Control

#### T1071 - Application Layer Protocol

**Description:** Adversaries may communicate using application layer protocols to avoid detection.

**Sub-Techniques Detected:**

| Sub-Technique | Name | Rule ID | Rule Name |
|---------------|------|---------|-----------|
| T1071.001 | Web Protocols (HTTP/HTTPS) | 017 | Suspicious HTTP POST Activity |
| T1071.004 | DNS | 016 | DNS Beaconing Detection |

**Detection Logic:**
- High-frequency DNS queries to single domain
- Suspicious HTTP POST requests with encoded data
- Unusual user-agent strings

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1071/

---

#### T1095 - Non-Application Layer Protocol

**Description:** Adversaries may use non-application layer protocols for C2.

**Detected by:**
- Rule 018: Rare Outbound Port Usage

**Detection Logic:**
- Network connections on uncommon ports
- Outbound connections from unexpected processes
- Non-standard protocol usage

**ATT&CK Reference:** https://attack.mitre.org/techniques/T1095/

---

## Technique Matrix

### Complete List of 35 Detected Techniques

```
T1003       OS Credential Dumping
T1003.001   LSASS Memory
T1003.002   Security Account Manager (SAM)
T1003.003   NTDS
T1021.002   SMB/Windows Admin Shares
T1021.006   Windows Remote Management
T1041       Exfiltration Over C2 Channel
T1047       Windows Management Instrumentation
T1053       Scheduled Task/Job
T1053.005   Scheduled Task
T1055       Process Injection
T1055.001   DLL Injection
T1055.002   Portable Executable Injection
T1055.012   Process Hollowing
T1071       Application Layer Protocol
T1071.001   Web Protocols
T1071.004   DNS
T1083       File and Directory Discovery
T1095       Non-Application Layer Protocol
T1110       Brute Force
T1112       Modify Registry
T1134       Access Token Manipulation
T1134.001   Token Impersonation/Theft
T1134.002   Create Process with Token
T1135       Network Share Discovery
T1187       Forced Authentication
T1204.002   Malicious File
T1547.001   Registry Run Keys / Startup Folder
T1548       Abuse Elevation Control Mechanism
T1548.002   Bypass User Account Control
T1555.004   Windows Credential Manager
T1557.001   LLMNR/NBT-NS Poisoning
T1568.002   Domain Generation Algorithms
T1569.002   Service Execution
T1570       Lateral Tool Transfer
T1571       Non-Standard Port
```

---

## Coverage Gaps

### Tactics NOT Covered (Future Development)

| Tactic | Techniques Available | Planned Rules |
|--------|---------------------|---------------|
| Defense Evasion (TA0005) | 42 techniques | 5 rules planned |
| Discovery (TA0007) | 30 techniques | 4 rules planned |
| Collection (TA0009) | 17 techniques | 2 rules planned |
| Exfiltration (TA0010) | 9 techniques | 2 rules planned |
| Impact (TA0040) | 13 techniques | 2 rules planned |

---

## ATT&CK Navigator Integration

The portfolio includes a MITRE ATT&CK Navigator layer file:

**File:** `testing/coverage_navigator.json`

**Usage:**
1. Visit https://mitre-attack.github.io/attack-navigator/
2. Click "Open Existing Layer"
3. Upload `coverage_navigator.json`
4. Visualize technique coverage with color-coded heatmap

---

## Updating Technique Mappings

When adding new detection rules:

1. **Identify Primary Technique:**
   - Use ATT&CK website to find technique ID
   - Ensure technique is current (not deprecated)

2. **Add to Rule Tags:**
   ```yaml
   tags:
     - attack.credential_access  # Tactic
     - attack.t1003.001          # Technique
     - detection.endpoint        # Platform
   ```

3. **Update This Document:**
   - Add technique to relevant tactic section
   - Update coverage percentages
   - Add detection logic explanation

4. **Update Navigator Layer:**
   - Regenerate `coverage_navigator.json`
   - Include new technique with coverage score

---

## References

- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **ATT&CK Navigator:** https://mitre-attack.github.io/attack-navigator/
- **Sigma HQ ATT&CK Tags:** https://github.com/SigmaHQ/sigma/wiki/Tags
- **Detection Rule Repository:** [GitHub Repository]

---

**Last Updated:** November 2025
**ATT&CK Version:** v14
**Portfolio Version:** 1.0.1
