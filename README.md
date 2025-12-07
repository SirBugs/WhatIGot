# WhatIGot 🔍

```
 ██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗ ██████╗  ██████╗ ████████╗
 ██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║██╔════╝ ██╔═══██╗╚══██╔══╝
 ██║ █╗ ██║███████║███████║   ██║   ██║██║  ███╗██║   ██║   ██║   
 ██║███╗██║██╔══██║██╔══██║   ██║   ██║██║   ██║██║   ██║   ██║   
 ╚███╔███╔╝██║  ██║██║  ██║   ██║   ██║╚██████╔╝╚██████╔╝   ██║   
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   
```

> **Multi-Method Host Discovery Tool** - When ping fails, WhatIGot prevails! 🚀

A fast, reliable host discovery tool designed for **internal network penetration testing**. Unlike simple ping sweeps that get blocked by firewalls and WAFs, WhatIGot uses **multiple probe methods** to determine if a host is alive.

---

## 🎯 The Problem

During internal pentests, you need to know which hosts are up. But:
- ❌ **ICMP Ping** is often blocked by firewalls
- ❌ **nmap -Pn** scans ports (slow, noisy)
- ❌ Single-method tools give false negatives

## ✅ The Solution

WhatIGot uses **20 different probes** simultaneously:
- If **ANY** probe succeeds → Host is **UP**
- Shows confidence score (e.g., `5/20`)
- Live streaming results as they come in

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🔥 **Multi-Method** | ARP + ICMP + 18 TCP ports |
| ⚡ **Fast** | Concurrent scanning with configurable threads |
| 🎯 **Accurate** | Connection refused = Host is UP (smart detection) |
| 📊 **Live Output** | Results stream as hosts are scanned |
| 🎨 **Beautiful** | Colored table output |
| 📁 **Export** | Save results to file |

---

## 📦 Installation

### From Source
```bash
git clone https://github.com/yourusername/whatigot.git
cd whatigot
go build -o whatigot
```

### Quick Install
```bash
go install github.com/yourusername/whatigot@latest
```

---

## 🛠️ Usage

### Basic Commands

```bash
# Scan single IP
./whatigot -i 192.168.1.1

# Scan CIDR range
./whatigot -r 192.168.1.0/24

# Scan from file
./whatigot -l targets.txt

# Fast scan with 50 threads
./whatigot -r 10.0.0.0/24 -t 50

# Verbose mode (show which probes succeeded)
./whatigot -r 192.168.1.0/24 -v

# Save results to file
./whatigot -r 192.168.1.0/24 -o results.txt

# Custom timeout (5 seconds)
./whatigot -r 192.168.1.0/24 -to 5
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Single IP address | - |
| `-r` | CIDR range (e.g., 192.168.1.0/24) | - |
| `-l` | File containing IPs (one per line) | - |
| `-t` | Number of concurrent threads | 1 |
| `-to` | Timeout in seconds | 2 |
| `-v` | Verbose mode (show probe details) | false |
| `-o` | Output file path | - |

---

## 📊 Output Example

### Normal Mode
```
┌─────────────────┬────────┬───────┐
│ IP              │ STATUS │ SCORE │
├─────────────────┼────────┼───────┤
│ 192.168.1.1     │ UP     │ 15/20 │
│ 192.168.1.2     │ DOWN   │ 0/20  │
│ 192.168.1.5     │ UP     │ 1/20  │
│ 192.168.1.10    │ UP     │ 3/20  │
└─────────────────┴────────┴───────┘

● UP: 3
● DOWN: 1
```

### Verbose Mode (`-v`)
```
┌─────────────────┬────────┬───────┬──────────────────────────────────────────────┐
│ IP              │ STATUS │ SCORE │ METHODS                                      │
├─────────────────┼────────┼───────┼──────────────────────────────────────────────┤
│ 192.168.1.1     │ UP     │ 15/20 │ ARP,PING,TCP:22,TCP:80,TCP:443,TCP:445,...   │
│ 192.168.1.5     │ UP     │ 1/20  │ ARP                                          │
│ 192.168.1.10    │ UP     │ 3/20  │ ARP,PING,TCP:3389                            │
└─────────────────┴────────┴───────┴──────────────────────────────────────────────┘
```

---

## 🔍 Probe Methods (20 Total)

### Layer 2 - Data Link
| Probe | Description | Bypasses Firewall? |
|-------|-------------|-------------------|
| **ARP** | ARP table lookup | ✅ YES (local LAN only) |

### Layer 3 - Network
| Probe | Description | Bypasses Firewall? |
|-------|-------------|-------------------|
| **PING** | ICMP Echo Request | ❌ Often blocked |

### Layer 4 - Transport (TCP)
| Port | Service | Common On |
|------|---------|-----------|
| 22 | SSH | Linux servers |
| 80 | HTTP | Web servers |
| 443 | HTTPS | Web servers |
| 445 | SMB | Windows |
| 3389 | RDP | Windows |
| 21 | FTP | File servers |
| 25 | SMTP | Mail servers |
| 53 | DNS | DNS servers |
| 88 | Kerberos | Domain Controllers |
| 135 | RPC | Windows |
| 139 | NetBIOS | Windows |
| 389 | LDAP | Domain Controllers |
| 1433 | MSSQL | Database servers |
| 3306 | MySQL | Database servers |
| 5432 | PostgreSQL | Database servers |
| 5985 | WinRM | Windows |
| 6379 | Redis | Cache servers |
| 8080 | HTTP-Alt | Web servers |

---

## 🧠 How It Works

### Smart Detection Logic

```
┌─────────────────────────────────────────────────────────────┐
│                    TCP Connection Attempt                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  You ──► SYN ──────────────────────────► Host               │
│                                                             │
│  Response:                                                  │
│                                                             │
│  1. SYN+ACK  ◄── Port OPEN      → Host is UP ✅             │
│  2. RST      ◄── Port CLOSED    → Host is UP ✅ (replied!)  │
│  3. Nothing  ◄── Filtered/DROP  → Unknown ❓                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Insight**: Even if a port is **CLOSED**, the host sends a RST (Reset) packet back. This means the host is alive! Only when packets are **DROPped** (no response) do we not know.

### Scoring System

```
Score = Successful Probes / Total Probes

Examples:
- 20/20 = All ports open/closed (very active host)
- 1/20  = Only ARP worked (host behind strict firewall, but on LAN)
- 0/20  = No response at all (host is truly down or heavily filtered)
```

---

## 🎯 Use Cases

### 1. Internal Network Pentest
```bash
# Quick sweep of internal network
./whatigot -r 10.0.0.0/8 -t 100 -o internal_hosts.txt
```

### 2. Verify Hosts Before Scanning
```bash
# Find live hosts, then scan with nmap
./whatigot -r 192.168.1.0/24 -t 50 -o alive.txt
nmap -iL alive.txt -sV
```

### 3. Bypass Ping-Blocking Firewalls
```bash
# When ping fails, WhatIGot uses ARP + TCP
./whatigot -i 192.168.1.100 -v
```

### 4. Quick Host Check
```bash
# Is this host up?
./whatigot -i 10.10.10.5
```

---

## 📝 Target File Format

Create a file with IPs or CIDR ranges:

```text
# targets.txt
192.168.1.1
192.168.1.10
10.0.0.0/24
172.16.0.1
# Comments are ignored
192.168.2.0/28
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**. 

- ✅ Use on networks you own
- ✅ Use with written permission
- ❌ Do NOT use on networks without authorization

**The author is not responsible for any misuse of this tool.**

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- 🐛 Report bugs
- 💡 Suggest features
- 🔧 Submit pull requests

---

## 📄 License

MIT License - feel free to use, modify, and distribute.

---

## 🌟 Star History

If this tool helped you, give it a ⭐!

---

**Made with ❤️ for the infosec community**

