# SIEM Detection Lab - Setup Guide

This guide walks through setting up a complete SIEM detection engineering lab environment using Docker and virtualization.

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 16GB | 32GB |
| **CPU** | 4 cores | 8 cores |
| **Disk Space** | 50GB | 100GB |
| **OS** | Linux/macOS/Windows with WSL2 | Ubuntu 22.04 LTS |

### Software Requirements

- Docker 20.10+ with Docker Compose
- VirtualBox or VMware (for Windows VMs)
- Git

---

## Part 1: SIEM Stack Deployment (Docker)

### Step 1: Clone Repository

```bash
git clone https://github.com/yourname/siem-detection-engineering.git
cd siem-detection-engineering/lab
```

### Step 2: Start SIEM Stack

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Step 3: Verify Services

**Splunk:**
- URL: http://localhost:8000
- Username: `admin`
- Password: `Changeme123!`

**Kibana:**
- URL: http://localhost:5601
- Username: `elastic`
- Password: `Changeme123!`

**Elasticsearch:**
- URL: http://localhost:9200
- Health check: `curl http://localhost:9200/_cluster/health`

### Step 4: Initial Configuration

**Configure Splunk HEC (HTTP Event Collector):**

1. Navigate to Settings → Data Inputs → HTTP Event Collector
2. Click "New Token"
3. Name: `sysmon-events`
4. Source type: `sysmon`
5. Index: `sysmon` (create if needed)
6. Token: Use the one from docker-compose.yml

**Create Splunk Indexes:**

```bash
# Create indexes via CLI
docker exec siem-lab-splunk /opt/splunk/bin/splunk add index sysmon -auth admin:Changeme123!
docker exec siem-lab-splunk /opt/splunk/bin/splunk add index windows -auth admin:Changeme123!
docker exec siem-lab-splunk /opt/splunk/bin/splunk add index dns -auth admin:Changeme123!
```

**Configure Elastic:**

```bash
# Set up Filebeat index pattern in Kibana
# Navigate to Management → Index Patterns → Create Index Pattern
# Pattern: filebeat-*
# Time field: @timestamp
```

---

## Part 2: Windows VM Setup

### Option A: VirtualBox Setup

**Download Windows:**
- Windows 10 Evaluation: https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise
- Windows Server 2019: https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019

**VM Configuration:**
```
Name: SIEM-Lab-Win10
Type: Microsoft Windows
Version: Windows 10 (64-bit)
Memory: 4096 MB
Processors: 2 CPUs
Disk: 40GB (dynamically allocated)
Network: Bridge Adapter (or Host-only with Docker network access)
```

### Option B: Azure/AWS VM (Cloud Option)

**Azure:**
```bash
az vm create \
  --resource-group siem-lab-rg \
  --name siem-lab-win10 \
  --image Win10 \
  --size Standard_D2s_v3 \
  --admin-username labadmin \
  --admin-password 'ComplexPassword123!'
```

**AWS:**
```bash
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.medium \
  --key-name siem-lab-key \
  --security-group-ids sg-xxxxxxxx
```

---

## Part 3: Sysmon Installation on Windows

### Step 1: Download Sysmon

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Temp\Sysmon.zip"
Expand-Archive "C:\Temp\Sysmon.zip" -DestinationPath "C:\Temp\Sysmon"

# Copy Sysmon config from lab repository
# (Transfer sysmon-config.xml to C:\Temp\)
```

### Step 2: Install Sysmon

```powershell
# Run as Administrator
cd C:\Temp\Sysmon
.\Sysmon64.exe -accepteula -i C:\Temp\sysmon-config.xml

# Verify installation
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### Step 3: Configure Windows Event Logging

```powershell
# Enable Security audit logging
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable

# Verify
auditpol /get /category:*
```

---

## Part 4: Log Forwarding Setup

### Option A: Splunk Universal Forwarder

**Install Splunk Universal Forwarder on Windows:**

```powershell
# Download Universal Forwarder
Invoke-WebRequest -Uri "https://download.splunk.com/products/universalforwarder/releases/9.1.0/windows/splunkforwarder-9.1.0-x64-release.msi" -OutFile "C:\Temp\splunkforwarder.msi"

# Install
msiexec.exe /i C:\Temp\splunkforwarder.msi RECEIVING_INDEXER="<SPLUNK_IP>:9997" AGREETOLICENSE=Yes /quiet

# Configure inputs
cd "C:\Program Files\SplunkUniversalForwarder\bin"

# Add Sysmon monitoring
.\splunk.exe add monitor "Microsoft-Windows-Sysmon/Operational" -index sysmon -sourcetype sysmon

# Add Windows Security log
.\splunk.exe add monitor "Security" -index windows -sourcetype WinEventLog:Security

# Add Windows System log
.\splunk.exe add monitor "System" -index windows -sourcetype WinEventLog:System

# Restart forwarder
.\splunk.exe restart
```

**Verify in Splunk:**
```spl
index=sysmon earliest=-5m
| stats count by host, source
```

### Option B: Winlogbeat (for Elastic)

**Install Winlogbeat:**

```powershell
# Download Winlogbeat
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.0-windows-x86_64.zip" -OutFile "C:\Temp\winlogbeat.zip"
Expand-Archive "C:\Temp\winlogbeat.zip" -DestinationPath "C:\Program Files"
Rename-Item "C:\Program Files\winlogbeat-8.11.0-windows-x86_64" "Winlogbeat"

# Configure
cd "C:\Program Files\Winlogbeat"
```

**Edit `winlogbeat.yml`:**
```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 1, 3, 7, 8, 10, 11, 13, 22
  - name: Security
    event_id: 4624, 4625, 4672, 4673, 4688, 5140
  - name: System

output.elasticsearch:
  hosts: ["<ELASTIC_IP>:9200"]
  username: "elastic"
  password: "Changeme123!"

setup.kibana:
  host: "<KIBANA_IP>:5601"
```

**Install and start:**
```powershell
.\install-service-winlogbeat.ps1
Start-Service winlogbeat

# Verify
Get-Service winlogbeat
Get-EventLog -LogName Application -Source winlogbeat -Newest 10
```

---

## Part 5: Attack Simulation Setup (Kali Linux)

### Option 1: Kali Docker Container

```bash
# Run Kali container
docker run -it --network siem-network --name kali-attacker kalilinux/kali-rolling /bin/bash

# Inside container, install tools
apt update
apt install -y metasploit-framework responder impacket-scripts nmap netcat-openbsd
```

### Option 2: Kali VM

**Download:**
- Kali Linux VMware/VirtualBox: https://www.kali.org/get-kali/#kali-virtual-machines

**Network Configuration:**
- Bridged or same network as Windows VM
- Ensure connectivity: `ping <WINDOWS_VM_IP>`

---

## Part 6: Testing the Setup

### Test 1: Verify Sysmon Logging

**On Windows:**
```powershell
# Generate test event
notepad.exe
Get-Process notepad | Stop-Process

# Check Sysmon log
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List
```

**In Splunk:**
```spl
index=sysmon EventCode=1 Image="*notepad.exe"
| table _time, Computer, Image, CommandLine
```

**In Kibana:**
```
event.code: 1 AND process.name: "notepad.exe"
```

### Test 2: Verify Network Logging

**On Windows:**
```powershell
# Make HTTP request
Invoke-WebRequest -Uri "http://example.com"
```

**Check for Sysmon Event ID 3:**
```spl
index=sysmon EventCode=3 DestinationHostname="example.com"
```

### Test 3: Test a Sigma Rule

**Run a simple persistence test:**
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Test /t REG_SZ /d "C:\Windows\System32\calc.exe"
```

**Expected detection in Splunk:**
```spl
index=sysmon EventCode=13 TargetObject="*CurrentVersion\\Run*"
```

---

## Part 7: Import Sigma Rules

### Splunk Deployment

```bash
# Convert Sigma rules to SPL
cd /path/to/siem-detection-engineering
python3 scripts/convert_sigma_to_splunk.py rules/ conversions/splunk/all_rules.spl

# Copy to Splunk container
docker cp conversions/splunk/all_rules.spl siem-lab-splunk:/tmp/

# Import rules (manually via UI or Splunk CLI)
```

**Manual Import:**
1. Navigate to Settings → Searches, reports, and alerts
2. Create new saved search for each rule
3. Set alert conditions
4. Configure alert actions

### Elastic Deployment

```bash
# Convert Sigma rules to Elastic
python3 scripts/convert_sigma_to_elastic.py rules/ conversions/elastic/all_rules.json

# Import via Kibana UI:
# Security → Detections → Manage Rules → Import Rules
# Upload all_rules.json
```

---

## Part 8: Baseline Collection

Before testing attacks, collect baseline "clean" data:

```powershell
# Run normal activities for 1 hour
# - Open/close applications
# - Browse websites
# - Access network shares
# - Normal administrative tasks

# This helps tune false positive rates
```

**Export baseline:**
```spl
# Splunk: Export search results for each rule
index=sysmon earliest=-1h
| export format=csv filename=baseline.csv
```

---

## Troubleshooting

### Splunk Not Starting

```bash
# Check logs
docker logs siem-lab-splunk

# Restart
docker-compose restart splunk

# Check port conflicts
sudo lsof -i :8000
```

### Elasticsearch Not Healthy

```bash
# Check cluster health
curl http://localhost:9200/_cluster/health?pretty

# Increase heap size in docker-compose.yml
# ES_JAVA_OPTS=-Xms4g -Xmx4g
```

### Logs Not Appearing

**Splunk:**
```bash
# Check forwarder status on Windows
"C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server

# Check HEC endpoint
curl -k https://localhost:8088/services/collector/health
```

**Elastic:**
```bash
# Check Winlogbeat status
Get-Service winlogbeat
Test-NetConnection -ComputerName <ELASTIC_IP> -Port 9200
```

---

## Network Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    SIEM Detection Lab                         │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐         ┌─────────────┐                    │
│  │ Windows VM  │────────▶│   Docker    │                    │
│  │  + Sysmon   │  Logs   │   Network   │                    │
│  │  + Forwarder│         └──────┬──────┘                    │
│  └─────────────┘                │                            │
│                                  │                            │
│  ┌─────────────┐                │                            │
│  │  Kali Linux │                │                            │
│  │  (Attacker) │────────────────┤                            │
│  └─────────────┘   Attacks      │                            │
│                                  │                            │
│                   ┌──────────────▼───────────────┐           │
│                   │    ┌─────────────────────┐   │           │
│                   │    │  Splunk :8000       │   │           │
│                   │    └─────────────────────┘   │           │
│                   │    ┌─────────────────────┐   │           │
│                   │    │  Elasticsearch:9200 │   │           │
│                   │    └─────────────────────┘   │           │
│                   │    ┌─────────────────────┐   │           │
│                   │    │  Kibana :5601       │   │           │
│                   │    └─────────────────────┘   │           │
│                   │                               │           │
│                   │     Docker Compose Stack      │           │
│                   └───────────────────────────────┘           │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Next Steps

1. ✅ Verify all services are running
2. ✅ Confirm log ingestion from Windows VM
3. ✅ Import converted Sigma rules
4. ✅ Run attack simulations from testing/attack_scenarios.md
5. ✅ Tune false positives
6. ✅ Document results in testing/test_results.csv

---

## Additional Resources

- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Docs](https://docs.splunk.com/)
- [Elastic Docs](https://www.elastic.co/guide/index.html)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
