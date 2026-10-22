#!/usr/bin/env python3
"""
=============================================================================
CyberScope - Interactive Web App for Network Port Scanner & Service Detector
=============================================================================
Description:
    A modern, browser-based graphical application for the Port Scanner.
    Provides live scanning, progress tracking, visual open port badges,
    service banner inspection, an integrated one-click mock lab, and JSON export.

Author: Yanadi Guru Lokesh
Email: gurulokesh339@gmail.com
Phone: +91 7075390614
Department: Department of Computer Science & Engineering
Language: Python 3 (Standard Library Only - Zero External Dependencies)
Usage:
    python web_app.py
=============================================================================
"""

from __future__ import annotations
import http.server
import socketserver
import json
import socket
import threading
import time
import webbrowser
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

PORT = 5000

# Global state for scanner and mock server
scan_state = {
    "is_scanning": False,
    "progress": 0,
    "total_ports": 0,
    "scanned_ports": 0,
    "target": "",
    "ip": "",
    "duration": 0,
    "open_ports": [],
    "error": None
}

mock_server_state = {
    "is_running": False,
    "services": [
        {"port": 8021, "name": "Mock FTP Server", "greeting": b"220 (vsFTPd 3.0.3 - Lab Edition) Ready.\r\n"},
        {"port": 8022, "name": "Mock SSH Server", "greeting": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"},
        {"port": 8080, "name": "Mock HTTP Web Server", "greeting": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu-Lab)\r\nContent-Type: text/html\r\n\r\n<h1>Mock Web Server</h1>"}
    ]
}

mock_sockets = []

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8000, 8080, 8443, 8888, 9000
]

BANNER_PROBES = {
    80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: CyberScope/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: CyberScope/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: CyberScope/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: CyberScope/1.0\r\n\r\n",
}


def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        custom = {
            3389: "RDP", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT",
            8000: "HTTP-DEV", 6379: "REDIS", 5432: "POSTGRESQL",
            27017: "MONGODB", 8021: "FTP-CUSTOM", 8022: "SSH-CUSTOM"
        }
        return custom.get(port, "UNKNOWN")


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                raw_data = s.recv(1024)
                if raw_data:
                    banner = raw_data.decode("utf-8", errors="ignore").strip()
            except (socket.timeout, socket.error):
                pass

            if not banner:
                probe = BANNER_PROBES.get(port, b"\r\n\r\n")
                try:
                    s.sendall(probe)
                    raw_data = s.recv(1024)
                    if raw_data:
                        banner = raw_data.decode("utf-8", errors="ignore").strip()
                except (socket.timeout, socket.error):
                    pass
    except Exception:
        pass

    if banner:
        first_line = banner.split("\r\n")[0].split("\n")[0].strip()
        cleaned = "".join(ch for ch in first_line if 32 <= ord(ch) <= 126)
        return cleaned[:80]
    return "No banner returned"


def parse_ports(port_arg: str) -> list[int]:
    if not port_arg or port_arg.lower() == "common":
        return COMMON_PORTS

    ports = set()
    parts = port_arg.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
                if 1 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(list(ports)) if ports else COMMON_PORTS


def perform_scan(target: str, port_spec: str, threads: int, timeout: float):
    global scan_state
    scan_state["is_scanning"] = True
    scan_state["progress"] = 0
    scan_state["scanned_ports"] = 0
    scan_state["open_ports"] = []
    scan_state["error"] = None
    scan_state["target"] = target

    # Resolve IP
    try:
        try:
            ipaddress.ip_address(target)
            resolved_ip = target
        except ValueError:
            resolved_ip = socket.gethostbyname(target)
        scan_state["ip"] = resolved_ip
    except Exception as e:
        scan_state["error"] = f"DNS Resolution failed for '{target}': {e}"
        scan_state["is_scanning"] = False
        return

    ports = parse_ports(port_spec)
    scan_state["total_ports"] = len(ports)
    start_time = time.time()

    def check_port(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((resolved_ip, p))
                if res == 0:
                    service = get_service_name(p)
                    banner = grab_banner(resolved_ip, p, timeout)
                    return {"port": p, "state": "OPEN", "service": service, "banner": banner}
        except Exception:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=min(threads, 100)) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                res = future.result()
                scan_state["scanned_ports"] += 1
                scan_state["progress"] = int((scan_state["scanned_ports"] / scan_state["total_ports"]) * 100)
                if res:
                    scan_state["open_ports"].append(res)
                    scan_state["open_ports"].sort(key=lambda x: x["port"])
    except Exception as e:
        scan_state["error"] = str(e)

    scan_state["duration"] = round(time.time() - start_time, 2)
    scan_state["is_scanning"] = False


# Mock server thread management
def start_mock_services():
    global mock_server_state, mock_sockets
    if mock_server_state["is_running"]:
        return

    mock_sockets = []
    mock_server_state["is_running"] = True

    def run_srv(srv):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", srv["port"]))
            s.listen(5)
            mock_sockets.append(s)
            while mock_server_state["is_running"]:
                try:
                    s.settimeout(1.0)
                    client, _ = s.accept()
                    client.settimeout(2.0)
                    try:
                        client.sendall(srv["greeting"])
                        client.recv(1024)
                    except Exception:
                        pass
                    finally:
                        client.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    for srv in mock_server_state["services"]:
        t = threading.Thread(target=run_srv, args=(srv,), daemon=True)
        t.start()


def stop_mock_services():
    global mock_server_state, mock_sockets
    mock_server_state["is_running"] = False
    for s in mock_sockets:
        try:
            s.close()
        except Exception:
            pass
    mock_sockets = []


# Embedded HTML/CSS/JS Frontend
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberScope - Network Port Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-dark: #090d16;
    --card-bg: #111726;
    --card-border: #1e293b;
    --primary: #3b82f6;
    --primary-hover: #2563eb;
    --accent: #06b6d4;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background-color: var(--bg-dark);
    color: var(--text-main);
    font-family: 'Plus Jakarta Sans', sans-serif;
    min-height: 100vh;
    padding: 24px;
    background-image: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 75%);
  }

  .container { max-width: 1100px; margin: 0 auto; }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 24px;
    border-bottom: 1px solid var(--card-border);
    margin-bottom: 24px;
  }

  .logo-box { display: flex; align-items: center; gap: 12px; }
  .logo-icon {
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    width: 44px; height: 44px; border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; font-weight: bold; color: white;
    box-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
  }

  h1 { font-size: 24px; font-weight: 800; letter-spacing: -0.5px; }
  .subtitle { font-size: 13px; color: var(--text-muted); }

  .mock-lab-bar {
    background: rgba(17, 23, 38, 0.8);
    border: 1px solid var(--card-border);
    padding: 12px 20px;
    border-radius: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
  }

  .mock-info { display: flex; align-items: center; gap: 10px; font-size: 14px; }
  .pulse-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background-color: var(--danger);
    transition: all 0.3s;
  }
  .pulse-dot.active {
    background-color: var(--success);
    box-shadow: 0 0 10px var(--success);
  }

  .btn {
    padding: 8px 16px; border-radius: 8px; font-size: 13px;
    font-weight: 600; cursor: pointer; border: none;
    transition: all 0.2s; display: inline-flex; align-items: center; gap: 6px;
  }
  .btn-outline {
    background: transparent; color: var(--text-main);
    border: 1px solid var(--card-border);
  }
  .btn-outline:hover { background: #1e293b; }
  .btn-primary {
    background: linear-gradient(135deg, #2563eb, #0284c7);
    color: white; font-weight: 700;
  }
  .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
  .btn-success { background: #059669; color: white; }

  .grid { display: grid; grid-template-columns: 350px 1fr; gap: 24px; }

  .card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 14px; padding: 20px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
  }

  .card-title {
    font-size: 16px; font-weight: 700; margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px; color: #e2e8f0;
  }

  .form-group { margin-bottom: 16px; }
  label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }
  input, select {
    width: 100%; padding: 10px 12px; border-radius: 8px;
    background: #0b101c; border: 1px solid var(--card-border);
    color: var(--text-main); font-family: 'JetBrains Mono', monospace; font-size: 13px;
  }
  input:focus { outline: none; border-color: var(--primary); }

  .quick-buttons { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .pill-btn {
    background: #1e293b; color: #94a3b8; border: none;
    padding: 4px 8px; border-radius: 6px; font-size: 11px;
    cursor: pointer; font-family: 'JetBrains Mono', monospace;
  }
  .pill-btn:hover { background: #334155; color: white; }

  /* Stats Grid */
  .stats-row {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 12px; margin-bottom: 20px;
  }
  .stat-card {
    background: #0d1322; border: 1px solid var(--card-border);
    border-radius: 10px; padding: 12px; text-align: center;
  }
  .stat-val { font-size: 22px; font-weight: 800; color: var(--primary); font-family: 'JetBrains Mono', monospace; }
  .stat-lbl { font-size: 11px; color: var(--text-muted); font-weight: 600; }

  /* Progress Bar */
  .progress-wrap {
    height: 8px; background: #0b101c; border-radius: 999px;
    overflow: hidden; margin-bottom: 16px; display: none;
  }
  .progress-bar {
    height: 100%; width: 0%;
    background: linear-gradient(90deg, #3b82f6, #06b6d4);
    transition: width 0.15s;
  }

  /* Results Table */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    text-align: left; padding: 10px; border-bottom: 2px solid var(--card-border);
    color: var(--text-muted); font-size: 11px; font-weight: 700; text-transform: uppercase;
  }
  td { padding: 12px 10px; border-bottom: 1px solid #1a2234; vertical-align: middle; }
  tr:hover td { background: rgba(255, 255, 255, 0.02); }

  .badge-open {
    background: rgba(16, 185, 129, 0.15); color: #34d399;
    padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }
  .port-badge {
    font-family: 'JetBrains Mono', monospace; font-weight: 700;
    color: #60a5fa; background: #1e293b; padding: 3px 6px; border-radius: 4px;
  }
  .banner-box {
    font-family: 'JetBrains Mono', monospace; font-size: 11.5px;
    color: #f59e0b; max-width: 320px; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap;
  }

  .empty-state {
    text-align: center; padding: 40px 20px; color: var(--text-muted);
  }
</style>
</head>
<body>

<div class="container">
  <header>
    <div class="logo-box">
      <div class="logo-icon">🛡️</div>
      <div>
        <h1>CyberScope Scanner</h1>
        <div class="subtitle">Interactive Network Reconnaissance & Service Fingerprinting</div>
      </div>
    </div>
    <div>
      <a href="/api/download-json" target="_blank" class="btn btn-outline">📥 Export JSON</a>
    </div>
  </header>

  <!-- Mock Lab Bar -->
  <div class="mock-lab-bar">
    <div class="mock-info">
      <div id="mockDot" class="pulse-dot"></div>
      <div>
        <strong id="mockStatusText">Mock Test Lab: Inactive</strong>
        <span style="color: var(--text-muted); font-size: 12px; margin-left: 8px;">(Ports 8021 FTP, 8022 SSH, 8080 Web)</span>
      </div>
    </div>
    <button id="mockToggleBtn" onclick="toggleMockLab()" class="btn btn-outline">▶ Start Mock Lab</button>
  </div>

  <div class="grid">
    <!-- Controls Side -->
    <div class="card">
      <div class="card-title">⚙️ Scan Configuration</div>

      <div class="form-group">
        <label>TARGET HOST / IP</label>
        <input type="text" id="targetInput" value="127.0.0.1" placeholder="127.0.0.1 or scanme.nmap.org">
        <div class="quick-buttons">
          <button class="pill-btn" onclick="setPreset('127.0.0.1', '8000-8100')">Mock Lab (8000-8100)</button>
          <button class="pill-btn" onclick="setPreset('127.0.0.1', 'common')">Localhost (Common)</button>
          <button class="pill-btn" onclick="setPreset('scanme.nmap.org', 'common')">Scanme.nmap.org</button>
        </div>
      </div>

      <div class="form-group">
        <label>PORTS TO SCAN</label>
        <input type="text" id="portInput" value="8000-8100" placeholder="e.g. common, 8000-8100, 22,80,443">
      </div>

      <div class="form-group">
        <label>CONCURRENCY (THREADS)</label>
        <select id="threadsInput">
          <option value="25">25 Threads (Stealthy)</option>
          <option value="50" selected>50 Threads (Balanced / Recommended)</option>
          <option value="100">100 Threads (High Speed)</option>
        </select>
      </div>

      <div class="form-group">
        <label>TIMEOUT PER PORT</label>
        <select id="timeoutInput">
          <option value="0.5">0.5 seconds (Fast LAN)</option>
          <option value="1.0" selected>1.0 seconds (Standard)</option>
          <option value="2.0">2.0 seconds (High Latency WAN)</option>
        </select>
      </div>

      <button id="scanBtn" onclick="startScan()" class="btn btn-primary" style="width: 100%; padding: 12px; justify-content: center; font-size: 14px;">
        🔍 Launch Network Scan
      </button>

      <div id="errorBox" style="display: none; margin-top: 12px; background: rgba(239,68,68,0.15); border: 1px solid var(--danger); padding: 10px; border-radius: 8px; color: #fca5a5; font-size: 12px;"></div>
    </div>

    <!-- Results Side -->
    <div class="card">
      <div class="card-title">📊 Live Scan Telemetry</div>

      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-val" id="openCount">0</div>
          <div class="stat-lbl">OPEN PORTS</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="scannedCount">0</div>
          <div class="stat-lbl">SCANNED PORTS</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="totalCount">0</div>
          <div class="stat-lbl">TOTAL PORTS</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="durationVal">0.0s</div>
          <div class="stat-lbl">DURATION</div>
        </div>
      </div>

      <div id="progWrap" class="progress-wrap">
        <div id="progBar" class="progress-bar"></div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Captured Banner / Version</th>
          </tr>
        </thead>
        <tbody id="resultsTableBody">
          <tr>
            <td colspan="4" class="empty-state">
              No scan initiated yet. Click <strong>Launch Network Scan</strong> to begin discovery.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
  let pollInterval = null;

  function setPreset(target, ports) {
    document.getElementById('targetInput').value = target;
    document.getElementById('portInput').value = ports;
  }

  async function checkMockStatus() {
    try {
      const res = await fetch('/api/mock-status');
      const data = await res.json();
      const dot = document.getElementById('mockDot');
      const text = document.getElementById('mockStatusText');
      const btn = document.getElementById('mockToggleBtn');

      if (data.is_running) {
        dot.className = 'pulse-dot active';
        text.innerText = 'Mock Test Lab: Active (127.0.0.1)';
        text.style.color = '#34d399';
        btn.innerText = '⏹ Stop Mock Lab';
      } else {
        dot.className = 'pulse-dot';
        text.innerText = 'Mock Test Lab: Inactive';
        text.style.color = '#f8fafc';
        btn.innerText = '▶ Start Mock Lab';
      }
    } catch(e) {}
  }

  async function toggleMockLab() {
    try {
      await fetch('/api/toggle-mock', { method: 'POST' });
      setTimeout(checkMockStatus, 300);
    } catch(e) {}
  }

  async function startScan() {
    const target = document.getElementById('targetInput').value.trim();
    const ports = document.getElementById('portInput').value.trim();
    const threads = document.getElementById('threadsInput').value;
    const timeout = document.getElementById('timeoutInput').value;
    const errorBox = document.getElementById('errorBox');
    errorBox.style.display = 'none';

    if (!target) {
      errorBox.innerText = 'Please specify a target IP or domain.';
      errorBox.style.display = 'block';
      return;
    }

    document.getElementById('progWrap').style.display = 'block';
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanBtn').innerText = '⏳ Scanning in progress...';

    await fetch('/api/start-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, ports, threads, timeout })
    });

    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollScanStatus, 300);
  }

  async function pollScanStatus() {
    try {
      const res = await fetch('/api/scan-status');
      const data = await res.json();

      document.getElementById('progBar').style.width = data.progress + '%';
      document.getElementById('openCount').innerText = data.open_ports.length;
      document.getElementById('scannedCount').innerText = data.scanned_ports;
      document.getElementById('totalCount').innerText = data.total_ports;
      document.getElementById('durationVal').innerText = data.duration + 's';

      if (data.error) {
        const errorBox = document.getElementById('errorBox');
        errorBox.innerText = data.error;
        errorBox.style.display = 'block';
      }

      // Render table
      const tbody = document.getElementById('resultsTableBody');
      if (data.open_ports.length > 0) {
        tbody.innerHTML = data.open_ports.map(p => `
          <tr>
            <td><span class="port-badge">${p.port}/tcp</span></td>
            <td><span class="badge-open">${p.state}</span></td>
            <td><strong>${p.service}</strong></td>
            <td><div class="banner-box">${p.banner}</div></td>
          </tr>
        `).join('');
      } else if (!data.is_scanning) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Scan finished. No open ports found in specified range.</td></tr>';
      }

      if (!data.is_scanning) {
        clearInterval(pollInterval);
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('scanBtn').innerText = '🔍 Launch Network Scan';
        setTimeout(() => {
          document.getElementById('progWrap').style.display = 'none';
        }, 800);
      }
    } catch(e) {}
  }

  checkMockStatus();
</script>

</body>
</html>
"""


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))

        elif parsed.path == "/api/mock-status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"is_running": mock_server_state["is_running"]}).encode("utf-8"))

        elif parsed.path == "/api/scan-status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(scan_state).encode("utf-8"))

        elif parsed.path == "/api/download-json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="scan_results.json"')
            self.end_headers()
            report = {
                "tool": "CyberScope Scanner",
                "target": scan_state["target"],
                "ip": scan_state["ip"],
                "duration_seconds": scan_state["duration"],
                "open_ports_count": len(scan_state["open_ports"]),
                "results": scan_state["open_ports"]
            }
            self.wfile.write(json.dumps(report, indent=4).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/toggle-mock":
            if mock_server_state["is_running"]:
                stop_mock_services()
            else:
                start_mock_services()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"is_running": mock_server_state["is_running"]}).encode("utf-8"))

        elif parsed.path == "/api/start-scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)

            target = data.get("target", "127.0.0.1")
            ports = data.get("ports", "common")
            threads = int(data.get("threads", 50))
            timeout = float(data.get("timeout", 1.0))

            t = threading.Thread(target=perform_scan, args=(target, ports, threads, timeout), daemon=True)
            t.start()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "started"}).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        # Silence console log noise for clean terminal output
        return


def main():
    print("\n" + "=" * 65)
    print("  🛡️  CYBERSCOPE - INTERACTIVE PORT SCANNER WEB APP")
    print("=" * 65)
    print(f"  [+] Starting Web Server at http://127.0.0.1:{PORT}")
    print("  [+] Launching user interface in your web browser...")
    print("  --> Press Ctrl+C in this terminal to shut down the app.\n")

    # Start mock test server by default so beginner can immediately test
    start_mock_services()

    # Open browser automatically
    def open_browser():
        time.sleep(1.2)
        webbrowser.open(f"http://127.0.0.1:{PORT}")

    threading.Thread(target=open_browser, daemon=True).start()

    with socketserver.TCPServer(("127.0.0.1", PORT), RequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  [!] Shutting down CyberScope App...")
            stop_mock_services()
            httpd.server_close()


if __name__ == "__main__":
    main()
