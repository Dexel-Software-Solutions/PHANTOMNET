<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:00d4ff,100:ff4757&height=200&section=header&text=PHANTOMNET&fontSize=70&fontColor=ffffff&fontAlignY=35&desc=Autonomous%20Deceptive%20Network%20Topology%20Morphing%20Framework&descAlignY=58&descSize=16&animation=fadeIn" width="100%"/>

<br/>

[![Version](https://img.shields.io/badge/Version-1.3-00d4ff?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Dexel-Software-Solutions/PHANTOMNET)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![C](https://img.shields.io/badge/C-eBPF%2FXDP-A8B9CC?style=for-the-badge&logo=c&logoColor=black)](https://ebpf.io)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Ubuntu%20%7C%20Debian-557C94?style=for-the-badge&logo=linux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-2ed573?style=for-the-badge)](LICENSE)
[![Research](https://img.shields.io/badge/Level-PhD%20Research-c084fc?style=for-the-badge&logo=academia&logoColor=white)](https://github.com/Dexel-Software-Solutions)
[![Tests](https://img.shields.io/badge/Tests-11%2F11%20PASSED-2ed573?style=for-the-badge&logo=pytest&logoColor=white)](tests/)

<br/>

```
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗███╗   ██╗███████╗████████╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║████╗  ██║██╔════╝╚══██╔══╝
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██╔██╗ ██║█████╗     ██║   
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██║╚██╗██║██╔══╝     ██║   
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║ ╚████║███████╗   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
```

<br/>

> **"Attackers scan your network. Traditional tools block them. PHANTOMNET makes every attacker see a completely different network — one that doesn't exist."**

<br/>

</div>

---

## 📌 Table of Contents

- [What is PHANTOMNET?](#-what-is-phantomnet)
- [Live Demo — Real Output](#-live-demo--real-output-from-kali-linux)
- [How It Works](#-how-it-works)
- [Architecture](#-architecture)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#%EF%B8%8F-configuration)
- [Dashboard](#-dashboard)
- [Module Reference](#-module-reference)
- [Research Publications](#-research-publications)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [Developer](#-developer)

---

## 🔬 What is PHANTOMNET?

PHANTOMNET is a **first-of-its-kind** autonomous cyber deception framework that combines **Moving Target Defense (MTD)** with **AI-driven behavioral fingerprinting** to permanently invalidate attacker reconnaissance.

Unlike static honeypots or traditional IDS/IPS tools, PHANTOMNET:

- 🎭 **Actively deceives** — serves each attacker a personalized fake network topology
- 🔄 **Continuously morphs** — the moment an attacker moves laterally, the topology changes
- 🪤 **Deploys forensic traps** — SSH/HTTP honeypots capture credentials and attack tools
- 📊 **Generates threat intel** — SIEM-ready JSON reports with attacker TTPs and threat scores
- 🧠 **Classifies attackers** — AI engine identifies APTs, ransomware, scanners, lateral movers in real-time

```
Without PHANTOMNET:
  Attacker scans → Sees REAL network → Attacks REAL servers → DATA BREACH ❌

With PHANTOMNET:
  Attacker scans → Sees FAKE network → Attacks FAKE servers → TRAPPED in honeypot ✅
                                     → Topology morphs   → Recon invalidated ✅
                                     → Intel captured    → Real network safe ✅
```

---

## 🖥️ Live Demo — Real Output from Kali Linux

> The following is **actual terminal output** from PHANTOMNET v1.3 running on Kali Linux 6.18.12:

```
┌──(kali㉿kali)-[~/Downloads/PHANTOMNET]
└─$ sudo python3 phantomnet.py --config config/phantomnet.yaml

2026-05-03 11:48:19 [INFO] PHANTOMNET — ══════════════════════════════════════════
2026-05-03 11:48:19 [INFO] PHANTOMNET —   PHANTOMNET — Deceptive Topology Morphing Framework v1.3
2026-05-03 11:48:19 [INFO] PHANTOMNET —   Author   : Demiyan Dissanayake
2026-05-03 11:48:19 [INFO] PHANTOMNET —   Company  : Dexel Software Solutions | Sri Lanka
2026-05-03 11:48:19 [INFO] PHANTOMNET — ══════════════════════════════════════════
2026-05-03 11:48:19 [INFO] PHANTOMNET — [*] Platform  : Linux 6.18.12+kali-amd64
2026-05-03 11:48:19 [INFO] PHANTOMNET — [*] Interface : eth0
2026-05-03 11:48:19 [INFO] GraphManager — Discovery complete: 1 real hosts found.
2026-05-03 11:48:19 [INFO] PHANTOMNET — [*] Dashboard : https://localhost:8443
2026-05-03 11:48:19 [INFO] PHANTOMNET — [*] PHANTOMNET is ACTIVE — Network deception engaged.
2026-05-03 11:48:19 [INFO] ProtocolSpoofer — Raw ARP socket opened on eth0.

2026-05-03 11:48:27 [WARN] Fingerprinter — Attacker classified: 172.16.0.200 → lateral_mover (confidence=0.80)
2026-05-03 11:48:27 [WARN] PHANTOMNET — [!] Attacker detected: 172.16.0.200 | TTP: lateral_mover | Confidence: 0.80
2026-05-03 11:48:27 [INFO] TopologyGen — Generated topology for 172.16.0.200: 15 hosts | TTP=lateral_mover
2026-05-03 11:48:27 [INFO] ProtocolSpoofer — Topology applied → 172.16.0.200: 15 fake hosts.

2026-05-03 11:48:29 [INFO] TrapManager — SSHHoneypot deployed on 172.16.10.7:22   id=6b6eb6bcfc69
2026-05-03 11:48:29 [INFO] TrapManager — HTTPHoneypot deployed on 172.16.10.7:80  id=c0500da12d1d
2026-05-03 11:48:29 [INFO] TrapManager — SSHHoneypot deployed on 172.16.10.21:22  id=62c4345d3fd3
```

**Threat Intel Output** (`logs/threat_intel.json`):
```json
{
  "attacker_ip": "10.10.10.5",
  "ttp_class": "lateral_mover",
  "confidence": 0.80,
  "topology_morphs": 388,
  "threat_score": 100,
  "movements": [
    { "from": "10.10.10.5", "to": "192.168.1.48", "port": 22 },
    { "from": "10.10.10.5", "to": "192.168.1.37", "port": 445 }
  ]
}
```

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  STEP 1 │ Attacker begins network scan                                  │
│         └─► Go packet engine captures traffic at kernel level           │
│                                                                         │
│  STEP 2 │ Behavioral fingerprinting classifies attacker TTP             │
│         └─► port_scanner / lateral_mover / apt / ransomware / recon     │
│                                                                         │
│  STEP 3 │ AI Topology Engine generates personalized fake network        │
│         └─► 15–50 fake hosts with real OS fingerprints, banners, MACs   │
│                                                                         │
│  STEP 4 │ ARP-level deception applied via raw socket                    │
│         └─► Attacker's ARP cache poisoned with fake host entries        │
│                                                                         │
│  STEP 5 │ Attacker attempts lateral movement                            │
│         └─► TOPOLOGY MORPHS INSTANTLY → entire recon is now invalid     │
│                                                                         │
│  STEP 6 │ Attacker walks into forensic trap                             │
│         └─► SSH/HTTP honeypots capture tools, credentials, behavior      │
│                                                                         │
│  STEP 7 │ Threat intelligence report generated                          │
│         └─► JSON: attacker IP, TTPs, movements, threat score 0–100      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ Architecture

```
╔═════════════════════════════════════════════════════════════════════════╗
║                         PHANTOMNET v1.3                                 ║
╠═════════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║   ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐  ║
║   │  BEHAVIORAL      │───►│  AI TOPOLOGY     │───►│   MORPHING       │  ║
║   │  FINGERPRINTER   │    │    ENGINE        │    │   TRIGGER        │  ║
║   │  6 TTP Classes   │    │  OS Profiles     │    │  Real-time       │  ║
║   │  (Python)        │    │  (Python)        │    │  (Python)        │  ║
║   └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘  ║
║            │                       │                       │            ║
║            ▼                       ▼                       ▼            ║
║   ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐  ║
║   │  PACKET ENGINE   │    │    PROTOCOL      │    │   FORENSIC       │  ║
║   │    (Go)          │    │   DECEPTION      │    │  TRAP LAYER      │  ║
║   │  libpcap / XDP   │    │  ARP / DNS       │    │  SSH + HTTP      │  ║
║   │  JSON streaming  │    │  (C + Python)    │    │  Honeypots       │  ║
║   └──────────────────┘    └──────────────────┘    └────────┬─────────┘  ║
║                                                            │            ║
║                                    ┌───────────────────────┘            ║
║                                    ▼                                    ║
║              ┌──────────────────────────┐   ┌──────────────────────┐    ║
║              │    THREAT INTEL ENGINE   │   │   LIVE DASHBOARD     │    ║
║              │    SIEM-ready JSON       │   │   HTTPS :8443        │    ║
║              │    Threat Score 0–100    │   │   Real-time canvas   │    ║
║              │    (Python)              │   │   (JavaScript)       │    ║
║              └──────────────────────────┘   └──────────────────────┘    ║
╚═════════════════════════════════════════════════════════════════════════╝
```

---

## ✨ Features

| Feature | Description | Status |
|---------|-------------|--------|
| 🧠 AI Topology Generation | Contextually convincing fake networks per attacker | ✅ Active |
| 🎭 ARP-Level Deception | Raw socket ARP injection for fake host realization | ✅ Active |
| 🔍 Behavioral Fingerprinting | 6-class TTP classifier (APT, Ransomware, Scanner...) | ✅ Active |
| 🔄 Real-time Topology Morphing | Network changes instantly on lateral movement | ✅ Active |
| 🪤 SSH Honeypot Traps | Capture client banners, key exchange data | ✅ Active |
| 🕸️ HTTP Honeypot Traps | Capture request lines, User-Agents, paths | ✅ Active |
| 📊 Threat Intelligence | SIEM-ready JSON with 0–100 threat score | ✅ Active |
| 🖥️ Live Dashboard | HTTPS real-time visualization at :8443 | ✅ Active |
| ⚡ eBPF/XDP Support | Kernel-level packet filtering (Linux 5.15+) | ✅ Optional |
| 🚀 Go Packet Engine | High-performance capture via libpcap | ✅ Optional |
| 🔁 Simulation Mode | Full functionality without Go binary | ✅ Built-in |
| 🛡️ Auto Interface Detect | Finds eth0/wlan0/ens33 automatically | ✅ Active |

---

## 🛠️ Tech Stack

```
┌─────────────────────────────────────────────────────┐
│  Language        │  Module                          │
├─────────────────────────────────────────────────────┤
│  Python 3.11+    │  Core engine, AI, fingerprinter  │
│  Go 1.21+        │  High-performance packet capture  │
│  C (eBPF/XDP)    │  Kernel-level packet hooks        │
│  JavaScript      │  Real-time dashboard UI           │
│  YAML            │  Configuration                    │
│  Bash            │  Universal installer              │
└─────────────────────────────────────────────────────┘
```

**Dependencies:** `pyyaml` · `cryptography` · `libpcap-dev` · `libbpf-dev` · `openssl`

---

## 🚀 Quick Start

```bash
# 1. Clone or extract
git clone https://github.com/Dexel-Software-Solutions/PHANTOMNET
cd PHANTOMNET

# 2. One-command install (Kali / Ubuntu / Debian)
sudo bash scripts/install.sh

# 3. Run
sudo python3 phantomnet.py --config config/phantomnet.yaml

# 4. Open Dashboard
# https://localhost:8443
```

---

## 🔧 Installation

### Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Linux Kernel | 5.15+ | For eBPF support |
| Python | 3.11+ | Core runtime |
| Go | 1.21+ | Packet engine (optional) |
| clang | 12+ | eBPF compilation (optional) |
| RAM | 512MB+ | Recommended 1GB |
| Privileges | root | Required for raw sockets |

### Supported Distributions

![Kali](https://img.shields.io/badge/Kali_Linux-✅_Tested-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu_22.04+-✅_Supported-E95420?style=flat-square&logo=ubuntu&logoColor=white)
![Debian](https://img.shields.io/badge/Debian_11%2F12-✅_Supported-A81D33?style=flat-square&logo=debian&logoColor=white)
![Parrot](https://img.shields.io/badge/ParrotOS-✅_Supported-00AAFF?style=flat-square)
![Arch](https://img.shields.io/badge/Arch_Linux-✅_Supported-1793D1?style=flat-square&logo=archlinux&logoColor=white)

### Step-by-Step

```bash
# Step 1 — Extract
cd ~/Downloads
unzip PHANTOMNET_v1.3_linux.zip
cd PHANTOMNET

# Step 2 — Install (auto-detects distro, interface, CIDR)
sudo bash scripts/install.sh

# Step 3 — Check your interface
ip a
# Look for: eth0 / wlan0 / ens33

# Step 4 — Edit config
nano config/phantomnet.yaml
# Set: interface and network_cidr

# Step 5 — Run
sudo python3 phantomnet.py --config config/phantomnet.yaml

# Step 6 — Access Dashboard
# Open browser: https://localhost:8443
```

### Build Go Engine (for real packet capture)

```bash
cd network/packet_engine
go mod tidy
go build -o bin/pktengine main.go
cd ../..
sudo python3 phantomnet.py --config config/phantomnet.yaml
```

### Build eBPF Module

```bash
sudo apt install linux-headers-$(uname -r) clang libbpf-dev
make build-ebpf
make attach-ebpf
```

---

## ⚙️ Configuration

Edit `config/phantomnet.yaml`:

```yaml
# ── Network ─────────────────────────────────────────
# Find with: ip a
interface: eth0              # eth0 | wlan0 | ens33
network_cidr: 10.0.2.0/24   # Your actual network CIDR

# ── Deception Settings ──────────────────────────────
max_fake_hosts: 50           # Fake hosts per attacker (1–500)
topology_complexity: medium  # low | medium | high
morphing_interval_seconds: 30

# ── Protocol Deception ──────────────────────────────
arp_deception: true          # ARP-level fake host injection
dns_deception: true          # DNS fake hostname responses

# ── Forensics ───────────────────────────────────────
forensic_traps_enabled: true
threat_intel_output: logs/threat_intel.json

# ── Dashboard ───────────────────────────────────────
dashboard_port: 8443
dashboard_tls_cert: config/certs/server.crt
dashboard_tls_key: config/certs/server.key

# ── Logging ─────────────────────────────────────────
log_level: INFO              # DEBUG | INFO | WARNING | ERROR
```

> **Find your interface and CIDR:**
> ```bash
> ip a                        # shows interface names and IPs
> ip route get 1.1.1.1        # shows primary interface
> ```

---

## 📊 Dashboard

Access the live dashboard at **`https://localhost:8443`**

The dashboard displays:

- 🔴 **Active threat actors** — IP, TTP class, confidence, threat score
- 🟢 **Fake hosts active** — count of injected deceptive nodes
- 🟡 **Topology morphs** — number of times the network shifted
- 🔵 **Packets analyzed** — total intercepted traffic count
- 🟣 **Traps triggered** — forensic honeypot captures
- 📡 **Live topology map** — animated network visualization

### API Endpoints

```bash
curl -k https://localhost:8443/api/status    # System status
curl -k https://localhost:8443/api/topology  # Real network topology
curl -k https://localhost:8443/api/threats   # All attacker records
curl -k https://localhost:8443/api/attackers # Active threat actors
```

---

## 📦 Module Reference

| Module | Language | File | Purpose |
|--------|----------|------|---------|
| Main Orchestrator | Python | `phantomnet.py` | Coordinates all modules |
| AI Topology Engine | Python | `core/ai_engine/topology_generator.py` | Generates fake topologies |
| Graph Manager | Python | `core/topology/graph_manager.py` | Tracks real network |
| Behavioral Fingerprinter | Python | `core/behavioral/fingerprinter.py` | Classifies attacker TTPs |
| Packet Interceptor | Python + Go | `network/packet_engine/` | High-speed packet capture |
| Protocol Spoofer | Python + C | `network/protocol_deception/spoofer.py` | ARP injection |
| eBPF Filter | C | `network/ebpf/phantomnet_filter.c` | Kernel XDP hooks |
| Trap Manager | Python | `forensics/trap_layer/trap_manager.py` | Honeypot orchestration |
| Threat Intel Engine | Python | `forensics/threat_intel/intel_engine.py` | Report generation |
| Dashboard API | Python | `dashboard/api/server.py` | HTTPS REST API |
| Dashboard UI | JavaScript | `dashboard/frontend/index.html` | Live visualization |
| Config Loader | Python | `config/loader.py` | YAML validation |

---

## 🧪 Tests

```bash
python3 tests/test_fingerprinter.py
python3 tests/test_topology_generator.py
```

```
=== PHANTOMNET Fingerprinter Tests ===
  [PASS] loopback packets correctly ignored
  [PASS] port_scanner: ttp=port_scanner conf=1.00
  [PASS] lateral_mover: ttp=ransomware smb=57
  [PASS] web_attacker: ttp=web_attacker http_reqs=180
  [PASS] all_profiles(): 20 dicts returned
[ALL TESTS PASSED]

=== PHANTOMNET Topology Generator Tests ===
  [PASS] Basic generation: 18 hosts, subnet=192.168.200.0/24
  [PASS] No overlap with 5 real IPs
  [PASS] Morph changed topology: 58c83cf0e919 -> e5b1296decb0
  [PASS] All 27 hosts have required fields
  [PASS] 3 trap hosts in topology
  [PASS] to_dict() is JSON-serializable (4557 bytes)
[ALL TESTS PASSED]
```

---

## 🔬 Research Publications

This framework supports the following original research contributions:

1. **"Adaptive Topology Deception Against APT Reconnaissance Using Behavioral Fingerprinting"**
2. **"AI-Driven Moving Target Defense at the Protocol Layer"**
3. **"Real-Time Network Morphing: A New Paradigm in Cyber Deception"**

PHANTOMNET addresses a gap identified in current defensive security research — no existing commercial or open-source tool dynamically invalidates attacker reconnaissance maps in real-time at the protocol level.

---

## ⚠️ Legal Disclaimer

> PHANTOMNET is designed **exclusively for authorized network defense**.
>
> - ✅ Deploy on networks you **own**
> - ✅ Deploy with **explicit written permission**
> - ✅ Use in **authorized penetration testing labs**
> - ❌ Unauthorized use is **illegal** under computer crime laws worldwide
>
> The developer and Dexel Software Solutions accept no liability for misuse.

---

## 👨‍💻 Developer

<div align="center">

<table>
<tr>
<td align="center" width="200">
<br/>
<b style="font-size:20px">DD</b>
<br/><br/>
<b>Demiyan Dissanayake</b><br/>
<i>Dexel Software Solutions</i><br/>
🇱🇰 Dankotuwa, Sri Lanka
</td>
<td>

| Contact | Details |
|---------|---------|
| 📧 **Email** | dexelsoftwaresolutions@gmail.com |
| 🐙 **GitHub** | [github.com/Dexel-Software-Solutions](https://github.com/Dexel-Software-Solutions) |
| 💬 **WhatsApp** | [+94 72 950 4289](https://wa.me/+94729504289) |
| 👤 **Username** | demiyan.dissanayake |
| 🌐 **Website** | [Dexel Software Solutions](https://share.google/sD7T5HaZHK314SOyR) |

</td>
</tr>
</table>

### 🏆 GitHub Achievements

![YOLO](https://img.shields.io/badge/Achievement-YOLO-ffa502?style=for-the-badge)
![Pull Shark](https://img.shields.io/badge/Achievement-Pull%20Shark-00d4ff?style=for-the-badge)
![Quickdraw](https://img.shields.io/badge/Achievement-Quickdraw-2ed573?style=for-the-badge)

### 🗂️ Other Projects

[![MIRAGE](https://img.shields.io/badge/MIRAGE-Deception%20First%20Security%20Framework-ff4757?style=for-the-badge)](https://github.com/Dexel-Software-Solutions/MIRAGE)
[![GHOSTWRITER](https://img.shields.io/badge/GHOSTWRITER-IP%20Rotation%20Defense-00d4ff?style=for-the-badge)](https://github.com/Dexel-Software-Solutions/GHOSTWRITER)
[![Phantom Framework](https://img.shields.io/badge/Phantom--Framework-Pentesting%20Framework-c084fc?style=for-the-badge)](https://github.com/Dexel-Software-Solutions/Phantom-Framework)
[![Subdomain Hunter](https://img.shields.io/badge/Subdomain--Hunter-Recon%20Tool-2ed573?style=for-the-badge)](https://github.com/Dexel-Software-Solutions/Subdomain-hunter)

</div>

---

## 📄 License

```
MIT License — Copyright (c) 2026 Demiyan Dissanayake | Dexel Software Solutions

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish, distribute, and/or sell
copies, subject to the above copyright notice appearing in all copies.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:ff4757,50:00d4ff,100:0d1117&height=120&section=footer&animation=fadeIn" width="100%"/>

**PHANTOMNET v1.3** · Built with ❤️ by **Demiyan Dissanayake** · Dexel Software Solutions · Sri Lanka 🇱🇰

*For authorized defensive use only · MIT License · 2025*

</div>
