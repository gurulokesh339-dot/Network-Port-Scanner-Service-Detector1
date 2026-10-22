# Network Port Scanner & Service Detector

A multi-threaded network reconnaissance tool written in Python 3. It discovers active TCP ports on a target host, queries running services to extract software versions (**banner grabbing**), and outputs structured security audit reports.

Built with **zero external dependencies** using purely the Python standard library.

---

## 📌 Project Overview & Cybersecurity Relevance

In the **Cyber Kill Chain** and **MITRE ATT&CK Framework** (`T1046: Network Service Discovery`), network scanning is the primary technique used in the reconnaissance phase:

- **Security Auditors / Penetration Testers** use port scanning to discover exposed attack surfaces, unauthorized services, and outdated, vulnerable software versions.
- **Defenders / System Administrators** use it to verify firewall rules, detect rogue services, and ensure internal systems are not leaking unnecessary ports.

---

## 🚀 Key Features

* **TCP Connect Scanning**: Uses socket connections to perform reliable TCP 3-way handshakes (`SYN` $\rightarrow$ `SYN-ACK` $\rightarrow$ `ACK`).
* **Multi-Threaded Concurrency**: Leverages Python's `ThreadPoolExecutor` to scan hundreds of ports concurrently within seconds.
* **Service Detection & Banner Grabbing**:
  * Passively captures initial greeting banners (e.g., SSH versions, FTP server software).
  * Actively transmits HTTP probe headers to web services to detect server software (e.g., Apache, Nginx, IIS).
* **Flexible Target & Port Syntax**:
  * Accepts IP addresses (`192.168.1.1`) or hostnames (`localhost`, `scanme.nmap.org`).
  * Scans common ports (`common`), specific ranges (`1-1024`), or comma-separated lists (`21,22,80,443,8080`).
* **Structured Output Export**: Generates console output with ANSI color highlights and optional structured JSON export for reporting.
* **Safe Local Test Lab**: Includes an isolated mock multi-service server (`test_server.py`) so you can test locally without scanning external networks.

---

## 🛠️ How It Works Under the Hood

```
+-------------------------------------------------------------+
|                      Target Host (IP)                       |
+-------------------------------------------------------------+
                              ▲
                              │ TCP Handshake (connect_ex)
+─────────────────────────────┴───────────────────────────────+
|               Thread Pool Worker (ThreadPoolExecutor)       |
+─────────────────────────────────────────────────────────────+
         │ Port Closed/Filtered (Non-zero) ──> Ignore
         │
         ▼ Port Open (0 / SYN-ACK)
+─────────────────────────────────────────────────────────────+
|               Service & Banner Grabbing Stage               |
|  1. Passive read: Listen for greeting (FTP / SSH / SMTP)    |
|  2. Active probe: Send HTTP probe request if no greeting    |
|  3. Lookup default IANA service name via getservbyport()    |
+─────────────────────────────────────────────────────────────+
         │
         ▼
+─────────────────────────────────────────────────────────────+
|                    Results Table & JSON Report              |
+─────────────────────────────────────────────────────────────+
```

---

## 📂 Project Structure

```
c:\network_port_scanner/
├── run_app.bat         # One-click Windows launcher for Web & Desktop apps
├── web_app.py          # Interactive cybersecurity Web App (browser-based dashboard)
├── app_gui.py          # Native Windows Desktop GUI App (Tkinter)
├── scanner.py          # Command-line multi-threaded port scanner
├── test_server.py      # Local mock multi-service test lab (FTP, SSH, HTTP)
├── PROJECT_REPORT.pdf  # Technical project evaluation report (PDF)
├── PROJECT_REPORT.html # Styled printable HTML report
├── PROJECT_REPORT.md   # Markdown technical documentation
└── README.md           # Documentation, usage guide, and learning notes
```

---

## 💻 Quickstart & Setup

### 1. Prerequisites
- Python 3.8 or newer. (No `pip install` required!)

> If Python is not yet installed on Windows:
> - Download from [python.org](https://www.python.org/downloads/) (make sure to check **"Add python.exe to PATH"**), or install from the Microsoft Store.

---

## 🖥️ How to Launch the App (Visual Mode)

You have two visual options:

### Option A: Interactive Web Dashboard (Recommended)
Open a terminal and run:
```powershell
python c:\network_port_scanner\web_app.py
```
> *This automatically opens `http://127.0.0.1:5000` in Microsoft Edge/Chrome with live scanning telemetry, visual glowing badges, and built-in one-click mock lab toggle.*

### Option B: Native Windows Desktop App
Open a terminal and run:
```powershell
python c:\network_port_scanner\app_gui.py
```
> *Opens a standalone native Windows desktop application with interactive tables, progress bars, and JSON export.*

### Option C: One-Click Launcher (`run_app.bat`)
Simply double-click [`run_app.bat`](file:///c:/network_port_scanner/run_app.bat) in File Explorer to choose your mode from an interactive menu.

---

## 🧪 Safe Local Testing (Step-by-Step)

To test the scanner without scanning external networks:

### Step 1: Start the local mock server
Open a terminal and run:
```powershell
python c:\network_port_scanner\test_server.py
```
*This starts three mock services on `127.0.0.1`: Port 8021 (FTP), Port 8022 (SSH), and Port 8080 (Web).*

### Step 2: Run the scanner in a second terminal
Open another terminal and scan the test range:
```powershell
python c:\network_port_scanner\scanner.py -t 127.0.0.1 -p 8000-8100 -o results.json
```

---

## 📖 CLI Usage & Options

```text
python scanner.py [-h] [-t TARGET] [-p PORTS] [-w THREADS] [--timeout TIMEOUT] [--no-banner] [-o OUTPUT]
```

| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `-t`, `--target` | `IP / Domain` | Target host to scan | `127.0.0.1` |
| `-p`, `--ports` | `PORTS` | Ports to scan: `'common'`, `'1-1024'`, or `'22,80,443'` | `'common'` |
| `-w`, `--threads` | `INTEGER` | Number of concurrent worker threads | `50` |
| `--timeout` | `FLOAT` | Socket connection timeout in seconds | `1.0` |
| `--no-banner` | *flag* | Disable banner grabbing probe | `False` |
| `-o`, `--output` | `FILE.json` | Save findings into a JSON report file | `None` |

### Example Commands:

```powershell
# 1. Quick scan of common top ports on localhost
python scanner.py -t 127.0.0.1

# 2. Scan specific ports and export results to JSON
python scanner.py -t 127.0.0.1 -p 21,22,80,443,8080 -o report.json

# 3. High-speed scan of the first 1000 ports with 100 threads
python scanner.py -t 127.0.0.1 -p 1-1000 -w 100 --timeout 0.5

# 4. Scan the Nmap authorized testing server
python scanner.py -t scanme.nmap.org -p common
```

---

## 📊 Sample Output

### Console Output:
```text
  ╔═══════════════════════════════════════════════════════════════╗
  ║          NETWORK PORT SCANNER & SERVICE DETECTOR              ║
  ║             [Reconnaissance & Banner Grabbing]                ║
  ╚═══════════════════════════════════════════════════════════════╝
  [!] Disclaimer: Only scan hosts you own or have explicit permission to audit.

[*] Target Host     : 127.0.0.1 (127.0.0.1)
[*] Ports to Scan   : 101 ports
[*] Concurrency     : 50 threads (Timeout: 1.0s)
[*] Banner Grabbing : Enabled
[*] Scan Started    : 2026-10-17 22:15:00
---------------------------------------------------------------------------
PORT       STATE      SERVICE         BANNER / VERSION
---------------------------------------------------------------------------
8021/tcp   OPEN       UNKNOWN         220 (vsFTPd 3.0.3 - Mock Security Lab) Ready.
8022/tcp   OPEN       UNKNOWN         SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
8080/tcp   OPEN       HTTP-PROXY      HTTP/1.1 200 OK Server: Apache/2.4.52 (Ubuntu-Lab)
---------------------------------------------------------------------------
[+] Scan Complete in 0.85 seconds.
[+] Total Ports Scanned: 101 | Open Ports Found: 3
[✓] Results successfully exported to 'results.json'
```

### Exported `results.json`:
```json
{
    "target": "127.0.0.1",
    "ip": "127.0.0.1",
    "scanned_ports_count": 101,
    "open_ports_count": 3,
    "duration_seconds": 0.85,
    "scan_timestamp": "2026-10-17 22:15:01",
    "results": [
        {
            "port": 8021,
            "state": "OPEN",
            "service": "UNKNOWN",
            "banner": "220 (vsFTPd 3.0.3 - Mock Security Lab) Ready."
        },
        {
            "port": 8022,
            "state": "OPEN",
            "service": "UNKNOWN",
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        },
        {
            "port": 8080,
            "state": "OPEN",
            "service": "HTTP-PROXY",
            "banner": "HTTP/1.1 200 OK Server: Apache/2.4.52 (Ubuntu-Lab)"
        }
    ]
}
```

---

## 🎓 Core Cybersecurity Concepts Learned

1. **TCP 3-Way Handshake**:
   - `SYN`: Scanner requests connection.
   - `SYN-ACK`: Host acknowledges; socket `connect_ex()` returns `0` (port is **OPEN**).
   - `RST`: Host actively rejects; port is **CLOSED**.
   - No reply / Timeout: Packet dropped by firewall; port is **FILTERED**.
2. **Banner Grabbing**:
   - Extracting server signature strings to identify unpatched software versions (e.g., finding `vsFTPd 2.3.4` would indicate a well-known backdoor exploit).
3. **Threading & Socket Timeouts**:
   - Why sequential scanning of 65,535 ports is too slow and how worker threads parallelize I/O-bound network calls.

---

## ⚖️ Legal & Ethical Disclaimer

This tool is created for **educational and defensive security purposes only**. Unauthorized scanning of remote servers or networks without explicit written permission is strictly prohibited by law (e.g., Computer Fraud and Abuse Act in the US, Section 43/66 in India, Computer Misuse Act in the UK). 

Always scan your own local environment (`127.0.0.1`, local home lab VMs) or authorized services such as `scanme.nmap.org`.

---

## 👨‍💻 Author & Project Credits

* **Developer:** Yanadi Guru Lokesh
* **Email:** [gurulokesh339@gmail.com](mailto:gurulokesh339@gmail.com)
* **Phone:** [+91 7075390614](tel:+917075390614)
* **Department:** Department of Computer Science & Engineering
