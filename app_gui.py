#!/usr/bin/env python3
"""
=============================================================================
CyberScope Desktop - Native GUI Port Scanner & Service Detector
=============================================================================
Description:
    A desktop GUI application built with Python's built-in Tkinter framework.
    Provides an intuitive visual interface with live scanning progress,
    interactive results table, one-click mock lab toggle, and JSON report export.

Language: Python 3 (Standard Library Only - Zero External Dependencies)
Usage:
    python app_gui.py
=============================================================================
"""

from __future__ import annotations
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import time
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8000, 8080, 8443, 8888, 9000
]

BANNER_PROBES = {
    80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    8000: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
}


class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberScope - Network Port Scanner & Service Detector")
        self.geometry("860x640")
        self.minsize(780, 520)

        # Apply Modern TTK Style
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=24)

        self.is_scanning = False
        self.mock_running = False
        self.mock_sockets = []
        self.scan_results = []

        self.build_ui()

    def build_ui(self):
        # Header Frame
        header = tk.Frame(self, bg="#1e293b", padx=16, pady=12)
        header.pack(fill="x")

        title = tk.Label(header, text="🛡️ CyberScope Port Scanner", font=("Segoe UI", 14, "bold"), fg="#f8fafc", bg="#1e293b")
        title.pack(side="left")

        self.mock_btn = tk.Button(header, text="▶ Start Mock Lab (8021, 8022, 8080)", command=self.toggle_mock_lab,
                                  font=("Segoe UI", 9, "bold"), bg="#0f766e", fg="white", relief="flat", padx=10, pady=4)
        self.mock_btn.pack(side="right")

        # Configuration Frame
        cfg_frame = ttk.LabelFrame(self, text=" Scan Configuration ", padding=12)
        cfg_frame.pack(fill="x", padx=16, pady=10)

        # Row 0: Target
        ttk.Label(cfg_frame, text="Target IP / Host:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.target_entry = ttk.Entry(cfg_frame, width=28)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        # Quick Preset Buttons
        preset_box = ttk.Frame(cfg_frame)
        preset_box.grid(row=0, column=2, columnspan=2, sticky="w", padx=8)
        ttk.Button(preset_box, text="Mock Lab", command=lambda: self.set_preset("127.0.0.1", "8000-8100")).pack(side="left", padx=2)
        ttk.Button(preset_box, text="Common Ports", command=lambda: self.set_preset("127.0.0.1", "common")).pack(side="left", padx=2)
        ttk.Button(preset_box, text="Scanme.nmap.org", command=lambda: self.set_preset("scanme.nmap.org", "common")).pack(side="left", padx=2)

        # Row 1: Ports
        ttk.Label(cfg_frame, text="Ports (e.g. 8000-8100, common):").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        self.ports_entry = ttk.Entry(cfg_frame, width=28)
        self.ports_entry.insert(0, "8000-8100")
        self.ports_entry.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        # Row 1: Threads & Timeout
        ttk.Label(cfg_frame, text="Threads:").grid(row=1, column=2, sticky="e", padx=4)
        self.threads_box = ttk.Spinbox(cfg_frame, from_=5, to=100, width=5)
        self.threads_box.set(50)
        self.threads_box.grid(row=1, column=3, sticky="w", padx=4)

        # Action Buttons
        btn_frame = ttk.Frame(cfg_frame)
        btn_frame.grid(row=2, column=0, columnspan=4, sticky="we", pady=10)

        self.scan_btn = tk.Button(btn_frame, text="🔍 Start Scan", command=self.start_scan_thread,
                                  font=("Segoe UI", 10, "bold"), bg="#2563eb", fg="white", relief="flat", padx=16, pady=6)
        self.scan_btn.pack(side="left", padx=4)

        self.stop_btn = tk.Button(btn_frame, text="⏹ Stop", command=self.stop_scan,
                                  font=("Segoe UI", 10, "bold"), bg="#ef4444", fg="white", relief="flat", padx=12, pady=6, state="disabled")
        self.stop_btn.pack(side="left", padx=4)

        self.export_btn = ttk.Button(btn_frame, text="📥 Export to JSON", command=self.export_json)
        self.export_btn.pack(side="right", padx=4)

        # Progress bar
        self.prog_bar = ttk.Progressbar(self, mode="determinate")
        self.prog_bar.pack(fill="x", padx=16, pady=4)

        # Results Table (Treeview)
        table_frame = ttk.LabelFrame(self, text=" Discovered Ports & Services ", padding=8)
        table_frame.pack(fill="both", expand=True, padx=16, pady=6)

        columns = ("port", "state", "service", "banner")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("port", text="Port")
        self.tree.heading("state", text="State")
        self.tree.heading("service", text="Service Name")
        self.tree.heading("banner", text="Service Banner / Software Version")

        self.tree.column("port", width=80, anchor="center")
        self.tree.column("state", width=80, anchor="center")
        self.tree.column("service", width=120, anchor="w")
        self.tree.column("banner", width=480, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Status Bar
        self.status_var = tk.StringVar(value="Ready. Configure parameters and click Start Scan.")
        status_bar = tk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", font=("Segoe UI", 9), padx=8, pady=4)
        status_bar.pack(fill="x", side="bottom")

    def set_preset(self, target, ports):
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, target)
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, ports)

    def parse_ports(self, port_str):
        if not port_str or port_str.lower() == "common":
            return COMMON_PORTS
        ports = set()
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                s, e = part.split("-", 1)
                try:
                    ports.update(range(int(s), int(e) + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    pass
        return sorted([p for p in ports if 1 <= p <= 65535]) or COMMON_PORTS

    def grab_banner(self, ip, port, timeout=1.0):
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                try:
                    raw = s.recv(1024)
                    if raw:
                        banner = raw.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass

                if not banner:
                    probe = BANNER_PROBES.get(port, b"\r\n\r\n")
                    try:
                        s.sendall(probe)
                        raw = s.recv(1024)
                        if raw:
                            banner = raw.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
        except Exception:
            pass

        if banner:
            clean = "".join(c for c in banner.split("\n")[0].strip() if 32 <= ord(c) <= 126)
            return clean[:80]
        return "No banner returned"

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port, "tcp").upper()
        except Exception:
            custom = {8021: "FTP-CUSTOM", 8022: "SSH-CUSTOM", 8080: "HTTP-PROXY", 3389: "RDP"}
            return custom.get(port, "UNKNOWN")

    def start_scan_thread(self):
        target = self.target_entry.get().strip()
        port_spec = self.ports_entry.get().strip()
        try:
            threads = int(self.threads_box.get())
        except ValueError:
            threads = 50

        if not target:
            messagebox.showerror("Error", "Please enter a valid target host or IP.")
            return

        self.tree.delete(*self.tree.get_children())
        self.scan_results = []
        self.is_scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        threading.Thread(target=self.run_scan, args=(target, port_spec, threads), daemon=True).start()

    def stop_scan(self):
        self.is_scanning = False
        self.status_var.set("Scan cancelled by user.")

    def run_scan(self, target, port_spec, threads):
        # Resolve target
        try:
            try:
                ipaddress.ip_address(target)
                resolved_ip = target
            except ValueError:
                resolved_ip = socket.gethostbyname(target)
        except Exception as e:
            self.status_var.set(f"DNS Resolution Failed: {e}")
            self.scan_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.is_scanning = False
            return

        ports = self.parse_ports(port_spec)
        total = len(ports)
        self.prog_bar["maximum"] = total
        self.prog_bar["value"] = 0

        self.status_var.set(f"Scanning {target} ({resolved_ip}) - {total} ports across {threads} threads...")
        start_time = time.time()
        scanned_count = 0

        def check(p):
            if not self.is_scanning:
                return None
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    if s.connect_ex((resolved_ip, p)) == 0:
                        srv = self.get_service_name(p)
                        banner = self.grab_banner(resolved_ip, p, 1.0)
                        return (p, "OPEN", srv, banner)
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=min(threads, 100)) as executor:
            futures = {executor.submit(check, p): p for p in ports}
            for f in as_completed(futures):
                if not self.is_scanning:
                    break
                scanned_count += 1
                res = f.result()
                if res:
                    self.scan_results.append(res)
                    self.tree.insert("", "end", values=(f"{res[0]}/tcp", res[1], res[2], res[3]))
                self.prog_bar["value"] = scanned_count

        elapsed = round(time.time() - start_time, 2)
        self.is_scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set(f"Scan complete in {elapsed}s! Found {len(self.scan_results)} open ports out of {total} scanned.")

    def toggle_mock_lab(self):
        if self.mock_running:
            self.mock_running = False
            for s in self.mock_sockets:
                try:
                    s.close()
                except Exception:
                    pass
            self.mock_sockets = []
            self.mock_btn.config(text="▶ Start Mock Lab (8021, 8022, 8080)", bg="#0f766e")
            self.status_var.set("Mock test lab stopped.")
        else:
            self.mock_running = True
            self.mock_btn.config(text="⏹ Stop Mock Lab", bg="#b91c1c")
            self.status_var.set("Mock test lab running on 127.0.0.1 (Ports 8021, 8022, 8080).")

            services = [
                (8021, b"220 (vsFTPd 3.0.3 - Mock Security Lab) Ready.\r\n"),
                (8022, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"),
                (8080, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n<h1>Mock Web Server</h1>")
            ]

            def srv_thread(p, banner):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", p))
                    s.listen(5)
                    self.mock_sockets.append(s)
                    while self.mock_running:
                        s.settimeout(1.0)
                        try:
                            client, _ = s.accept()
                            client.sendall(banner)
                            client.close()
                        except socket.timeout:
                            continue
                        except Exception:
                            break
                except Exception:
                    pass

            for port, banner in services:
                threading.Thread(target=srv_thread, args=(port, banner), daemon=True).start()

    def export_json(self):
        if not self.scan_results:
            messagebox.showinfo("Export", "No open ports found to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if path:
            data = [
                {"port": r[0], "state": r[1], "service": r[2], "banner": r[3]}
                for r in self.scan_results
            ]
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                messagebox.showinfo("Success", f"Results exported to {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")


def main():
    app = PortScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
