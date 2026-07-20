# 🔍 Advanced Multi-Threaded Network Discovery Scanner

A fast, lightweight, and cross-platform Python CLI tool for local subnet discovery. It combines **ICMP Ping**, **ARP MAC/Vendor detection**, **Reverse DNS lookup**, and **Multi-Port Probing** to map active network hosts inside a rich terminal interface.

---

## ✨ Features

- **🚀 Dual Discovery Engine (ICMP + ARP):** Uses ICMP pings along with Scapy ARP requests to catch stealthy hosts (e.g., Windows machines that drop ICMP echo requests).
- **⚡ Fast Multi-Threading:** Utilizes worker threads to scan an entire `/24` subnet (254 host IPs) in seconds.
- **🏷️ Hostname Resolution:** Automatically resolves local hostnames via reverse DNS lookups.
- **🔌 Service Port Probing:** Checks common administrative and web ports (`21`, `22`, `80`, `443`, `445`, `3389`, `8080`) to identify running services.
- **📊 Rich Terminal UI:** Live progress bar and clean tabular formatting powered by `rich`.
- **🌐 Cross-Platform:** Automatically adapts ping parameters across Linux, macOS, and Windows.

---

## 📋 Prerequisites

Ensure you have Python 3.8+ installed on your system.

### Required Dependencies
Install the required packages using `pip`:

```bash
pip install rich scapy

```
Note: Raw socket operations and ARP packet crafting (via scapy) require administrative/root privileges.

## 🚀 Quick Start
### 1.Clone the repository: 

```
git clone [https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git)
cd YOUR_REPOSITORY_NAME
```
### 2. Give the executable permission:

```
chmod +x host_scanner.py
```
### 3. Run the script;
```
sudo ./host_scanner.py
```

## 🛠️ How It Works
1. Subnet Detection: Dynamically detects your local base IPv4 subnet (e.g., 192.168.1.).

2. Task Queueing: Enqueues IP addresses 1 through 254.

3. Multi-Threaded Execution: 40 worker threads fetch IPs, send cross-platform ICMP pings, and fallback to ARP requests if ICMP fails.

4. Enrichment: Responding hosts undergo reverse DNS lookups and targeted port sweeps.

5. Reporting: Displays results in a real-time, color-coded CLI table.

⚖️ License
This project is open-source and available under the MIT License.
