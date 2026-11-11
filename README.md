# 🛡️ mini-firewall — Stateful Linux Kernel Netfilter Packet Filter & Security Monitor

[![Language](https://img.shields.io/badge/Language-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Kernel](https://img.shields.io/badge/Linux_Kernel-5.x%20%2F%206.x-orange.svg)](https://kernel.org)
[![Subsystem](https://img.shields.io/badge/Subsystem-Netfilter%20LKM-brightgreen.svg)](https://netfilter.org)
[![Testing](https://img.shields.io/badge/Tests-5%2F5%20Passed-success.svg)](tests/test_firewall.sh)
[![License](https://img.shields.io/badge/License-GPL--2.0-yellow.svg)](LICENSE)

> **High-performance, loadable Linux Kernel Module (LKM) firewall and network security monitor.**  
> Intercepts raw network packets at the kernel level (`NF_INET_PRE_ROUTING`), inspects IPv4/TCP/UDP/ICMP headers within `sk_buff`, detects port scan anomalies, and provides real-time telemetry with a dedicated User Space CLI utility (`fwctl`).

---

## 🧭 Architecture & Packet Flow

```mermaid
flowchart TD
    A[Raw Network Wire / NIC] --> B[Linux Kernel Network Driver]
    B --> C[Netfilter: NF_INET_PRE_ROUTING]
    C --> D{mini-firewall Hook Inspector}
    
    D -->|TCP Scan Anomaly?| E[ALERT: Drop & Log to dmesg]
    D -->|Rule Matched: IP/Port/Proto| F[RULE HIT: NF_DROP]
    D -->|No Match / Allowed| G[NF_ACCEPT]
    
    F --> H[Increment Dropped Counters in /proc]
    G --> I[Pass to Linux TCP/IP Stack & Sockets]
    
    J[User Space: fwctl CLI] <-->|read/write| K[/proc/mini_firewall]
    K <-->|spin_lock_bh| D
```

### Key Kernel Concepts Applied:
* **Netfilter Hooks:** Deep integration at `NF_INET_PRE_ROUTING` with `NF_IP_PRI_FIRST` priority, dropping malicious traffic before allocating socket buffers in the upper network stack.
* **Socket Buffer (`sk_buff`) Parsing:** Parsing network headers (`struct iphdr`, `struct tcphdr`, `struct udphdr`, `struct icmphdr`) with proper byte-order conversion (`ntohs`, `in4_pton`).
* **Concurrency in Softirq Context:** The Netfilter hook runs inside software interrupt context (`softirq/BH`). All state modifications and rule lookups are protected using bottom-half spinlocks (`spin_lock_bh` / `spin_unlock_bh`).
* **Dynamic Control via Procfs:** Custom `/proc/mini_firewall` entry using modern `proc_ops` (Linux 5.6+ and 6.x compatible) enabling dynamic rule updates without module recompilation or reloading.
* **Zero Overhead Anomaly Detection:** Real-time TCP flag analysis for detecting stealth reconnaissance scans (NULL scans, Xmas tree scans, SYN-FIN scans).

---

## ✨ Features

- [x] **IP Filtering:** Instant dropping of packets from blacklisted IPv4 source/destination addresses.
- [x] **Port Filtering:** Destination TCP/UDP port blocking with zero user-space latency.
- [x] **Protocol Stealth Mode:** Dropping ICMP echo requests (ping requests) to make the host invisible to ping sweeps.
- [x] **Reconnaissance Defense:** Automated detection and dropping of malformed TCP flag combinations (Xmas, NULL, SYN-FIN).
- [x] **Live Kernel Telemetry:** Real-time counters for processed, accepted, dropped packets, and drop causes.
- [x] **User Space Management Utility (`fwctl`):** A standalone CLI with ANSI color support, rule management, and real-time monitoring mode.
- [x] **Automated Test Harness:** Scripted validation suite simulating traffic, connection tests, and verifying kernel counters.

---

## 🚀 Quickstart

### Prerequisites
* Linux OS (Ubuntu 22.04 / 24.04 recommended, kernel 5.x or 6.x)
* Kernel build headers: `sudo apt-get install -y build-essential linux-headers-$(uname -r)`

### 1. Build Kernel Module & CLI
```bash
make
```

### 2. Load Module into the Kernel
```bash
sudo make load
```
Verify via `dmesg`:
```text
mini_firewall: initializing Netfilter LKM Packet Filter v1.0.0...
mini_firewall: Netfilter hook registered at NF_INET_PRE_ROUTING successfully.
mini_firewall: Control interface active at /proc/mini_firewall
```

### 3. Run Automated Tests
```bash
sudo make test
```
Output:
```text
======================================================
   Running mini-firewall Kernel & CLI Test Suite
======================================================
[INFO] Test 1: Baseline ICMP (ping) connectivity...
[PASS] Baseline traffic allowed without rules.
[INFO] Test 2: Blocking ICMP protocol...
[PASS] ICMP packet successfully dropped by kernel hook!
[PASS] Kernel stats verified: Protocol drop counter incremented (1).
[INFO] Test 3: Blocking TCP Destination Port 54321...
[PASS] Rule correctly registered in kernel rule table.
[PASS] TCP connection to port 54321 dropped by Netfilter!
[INFO] Test 4: TCP Anomaly & Port Scan Detector Toggle...
[PASS] Scan detection toggle enabled successfully.
[INFO] Test 5: Resetting rules and checking restoration...
[PASS] Traffic fully restored after clearing rules.

======================================================
   ALL TESTS PASSED! (5/5)
   mini-firewall is operational, verified, and stable.
======================================================
```

---

## 💻 CLI Usage (`fwctl`)

The User Space utility provides an interface similar to modern security tools:

```bash
# Check status and live packet statistics
./cli/fwctl status

# Block an aggressive IP address
sudo ./cli/fwctl block ip 192.168.1.150

# Block incoming TCP port 8080
sudo ./cli/fwctl block port 8080 tcp

# Make host stealthy (drop all ICMP ping requests)
sudo ./cli/fwctl block proto icmp

# Enable TCP Port Scan & Anomaly detection
sudo ./cli/fwctl scan-detect on

# Enter real-time monitoring dashboard
./cli/fwctl monitor

# Clear all firewall rules
sudo ./cli/fwctl clear
```

### Terminal Output Preview:
```text
┌────────────────────────────────────────────────────────┐
│   mini-firewall CLI (v1.0.0) - Linux Kernel Filter     │
│   Author: Albert Adamyan                               │
└────────────────────────────────────────────────────────┘
=== mini-firewall (Stateful Netfilter LKM Firewall) ===
Version: 1.0.0
Hook stage: NF_INET_PRE_ROUTING
Scan detection: ENABLED

--- Statistics ---
Total Processed: 4820
Accepted:        4791
Dropped:         29
Dropped Bytes:   2465 bytes
  - Drops by IP:       14
  - Drops by Port:     11
  - Drops by Protocol: 4
  - Drops by Scan:     0

--- Active Rules (3/64) ---
  [1] BLOCK SRC IP:   192.168.1.150 (Hits: 14)
  [2] BLOCK TCP PORT: 8080 (Hits: 11)
  [3] BLOCK PROTO:    ICMP (ping) (1) (Hits: 4)
==================================================
```

---

## 📂 Project Structure

```text
mini-firewall/
├── Makefile               # Root build & lifecycle orchestration
├── README.md              # Documentation & Architecture breakdown
├── kernel/
│   ├── Kbuild             # Linux kernel build configuration
│   ├── Makefile           # Kernel module Makefile
│   ├── mini_firewall.h    # Rule, stats & header declarations
│   └── mini_firewall.c    # LKM implementation, Netfilter hook, procfs ops
├── cli/
│   ├── Makefile           # CLI Makefile
│   └── fwctl.c            # User space control binary in pure C
├── tests/
│   └── test_firewall.sh   # Automated validation & test suite
└── docs/
    └── INTERVIEW_QA.md    # Kernel networking & Netfilter interview cheat-sheet
```

---

## 👤 Author
* **Albert Adamyan**
* GitHub: [@CreatorShyMoon](https://github.com/CreatorShyMoon)
* Telegram: [@moon_dsdsdsss](https://t.me/moon_dsdsdsss)
* Email: [albertadaman70@gmail.com](mailto:albertadaman70@gmail.com)
