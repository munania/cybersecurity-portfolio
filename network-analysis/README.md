
# Network Traffic Analysis & IDS

![Wireshark](https://img.shields.io/badge/Wireshark-Packet%20Analysis-blue)
![Snort](https://img.shields.io/badge/Snort-IDS-red)
![PCAP](https://img.shields.io/badge/PCAP-50%2B%20hours-green)

> Network packet analysis and intrusion detection system development for identifying malicious traffic patterns.

[← Back to Portfolio](../README.md)

---

## 📋 Project Overview

Analyzed 50+ hours of network traffic to identify attack patterns, created custom IDS rules, and developed expertise in packet-level analysis for threat detection.

---

## 🎯 Objectives

- ✅ Capture and analyze malicious network traffic
- ✅ Identify attack signatures (port scans, brute force, exfiltration)
- ✅ Create custom Snort/Suricata detection rules
- ✅ Extract IOCs from packet captures
- ✅ Document network forensics methodology

---

## 🛠️ Tools Used

**Packet Capture:**
- Wireshark
- tcpdump
- NetworkMiner

**Analysis:**
- Snort (IDS/IPS)
- Suricata
- Zeek (Bro)

**Utilities:**
- tshark (CLI analysis)
- Capinfos (statistics)
- Editcap (PCAP editing)

---

## 📊 Traffic Analyzed

### Attack Scenarios Captured

| Attack Type | Duration | Packets | IOCs Found |
|-------------|----------|---------|------------|
| Port Scanning | 5 hours | 45,000 | 3 IPs |
| Brute Force SSH | 8 hours | 120,000 | 5 IPs |
| Data Exfiltration | 3 hours | 28,000 | 2 domains |
| DDoS Simulation | 2 hours | 500,000 | 15 IPs |
| SQL Injection | 4 hours | 8,500 | 1 payload |

---

## 🔍 Key Findings

### 1. Port Scan Detection

**Traffic Pattern:**
```
Source: 192.168.198.1
Destination: 192.168.198.20
Ports: 1-65535 (SYN scan)
Time: 120 seconds
Packets: 65,535 SYN packets
```

**Wireshark Filter:**
```
tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.198.1
```

**Custom Snort Rule:**
```
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; \
  flags:S; threshold:type threshold, track by_src, count 20, seconds 60; \
  sid:1000001;)
```

---

### 2. SSH Brute Force

**Traffic Pattern:**
```
Multiple SSH connection attempts
Failed authentication
Same source IP
Different usernames/passwords
```

**Detection Rule:**
```
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; \
  flow:to_server,established; content:"SSH"; \
  threshold:type threshold, track by_src, count 5, seconds 60; \
  sid:1000002;)
```

---

## 📁 Repository Contents

### `/pcap-files/`
Captured traffic samples:
- `port-scan.pcap` - Nmap aggressive scan
- `brute-force-ssh.pcap` - Hydra attack
- `sql-injection.pcap` - SQLmap traffic
- `data-exfiltration.pcap` - FTP data transfer
- `ddos-syn-flood.pcap` - SYN flood attack

### `/snort-rules/`
Custom detection rules:
- `reconnaissance.rules` - Port scans, enumeration
- `brute-force.rules` - Authentication attacks
- `exfiltration.rules` - Data theft detection
- `malware.rules` - C2 communication

---

## 🎓 Skills Demonstrated

- ✅ Packet analysis with Wireshark
- ✅ Protocol understanding (TCP/IP, HTTP, DNS, SSH)
- ✅ IDS rule development
- ✅ Network forensics
- ✅ IOC extraction

---

## 📧 Contact

**Questions about this project?**

- 📧 Email: munaniadeno@gmail.com
- 💼 LinkedIn: [Your Profile](https://www.linkedin.com/in/dennis-munania/)
- 💻 GitHub: [Your Profile](https://github.com/munania/)

[← Back to Portfolio](../README.md)
