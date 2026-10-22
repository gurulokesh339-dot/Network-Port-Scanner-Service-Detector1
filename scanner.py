#!/usr/bin/env python3
"""
=============================================================================
Network Port Scanner & Service Detector
=============================================================================
Description:
    A fast, multi-threaded network reconnaissance tool written in Python.
    Scans a target host for open TCP ports, attempts banner grabbing to identify
    running software/services, and generates structured reports (CLI & JSON).

Author: Yanadi Guru Lokesh
Email: gurulokesh339@gmail.com
Phone: +91 7075390614
Department: Department of Computer Science & Engineering
Language: Python 3 (Standard Library Only - Zero External Dependencies)
=============================================================================
"""

from __future__ import annotations

import socket
import sys
import time
import argparse
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI Color Codes for terminal formatting
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"

# Common well-known and registered ports to scan when none specified
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8000, 8080, 8443, 8888, 9000
]

BANNER_PROBES = {
    80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
}


def print_banner():
    """Prints the application banner and ethical disclaimer."""
    ascii_art = f"""{CYAN}
  ╔═══════════════════════════════════════════════════════════════╗
  ║          NETWORK PORT SCANNER & SERVICE DETECTOR              ║
  ║             [Reconnaissance & Banner Grabbing]                ║
  ╚═══════════════════════════════════════════════════════════════╝{RESET}
  {YELLOW}[!] Disclaimer: Only scan hosts you own or have explicit permission to audit.{RESET}
"""
    print(ascii_art)


def resolve_target(target: str) -> str:
    """
    Resolves a hostname (e.g., 'localhost' or 'scanme.nmap.org') to an IPv4 address.
    Returns the resolved IP string, or exits if invalid.
    """
    try:
        # Check if already a valid IP address
        ipaddress.ip_address(target)
        return target
    except ValueError:
        # If not, resolve DNS hostname
        try:
            resolved_ip = socket.gethostbyname(target)
            return resolved_ip
        except socket.gaierror:
            print(f"{RED}[-] Error: Could not resolve hostname '{target}'. Check your network or target name.{RESET}")
            sys.exit(1)


def parse_ports(port_arg: str) -> list[int]:
    """
    Parses various port input specifications:
      - 'common': list of top standard ports
      - '1-100': inclusive port range
      - '21,22,80,443': comma-separated list of ports
      - '80': single port
    """
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
                if start < 1 or end > 65535 or start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"{RED}[-] Error: Invalid port range '{part}'. Ports must be between 1 and 65535.{RESET}")
                sys.exit(1)
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError
                ports.add(p)
            except ValueError:
                print(f"{RED}[-] Error: Invalid port number '{part}'. Must be an integer between 1 and 65535.{RESET}")
                sys.exit(1)

    return sorted(list(ports))


def get_service_name(port: int) -> str:
    """Returns standard service name for a given port, or 'Unknown'."""
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        # Known common ports not always in the local OS database
        custom_lookup = {
            3389: "RDP",
            8080: "HTTP-PROXY",
            8443: "HTTPS-ALT",
            8000: "HTTP-DEV",
            6379: "REDIS",
            5432: "POSTGRESQL",
            27017: "MONGODB"
        }
        return custom_lookup.get(port, "UNKNOWN")


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempts to connect and grab the service banner from an open port.
    Returns sanitized banner string, or empty string if none returned.
    """
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # 1. Passive listen: Services like SSH, FTP, SMTP send a banner on connection
            try:
                raw_data = s.recv(1024)
                if raw_data:
                    banner = raw_data.decode("utf-8", errors="ignore").strip()
            except (socket.timeout, socket.error):
                pass

            # 2. Active probe: If no initial banner, send a probe (useful for HTTP)
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

    # Clean up multi-line banner to a single readable line (up to 80 chars)
    if banner:
        first_line = banner.split("\r\n")[0].split("\n")[0].strip()
        # Filter out non-printable ASCII characters
        cleaned = "".join(ch for ch in first_line if 32 <= ord(ch) <= 126)
        return cleaned[:80]
    return "No banner returned"


def scan_port(ip: str, port: int, timeout: float, do_banner: bool) -> dict | None:
    """
    Performs a TCP 3-way handshake on a specific port.
    Returns a result dict if open, or None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # connect_ex returns 0 if connection succeeded (SYN-ACK received)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = get_service_name(port)
                banner = grab_banner(ip, port, timeout) if do_banner else "N/A"
                return {
                    "port": port,
                    "state": "OPEN",
                    "service": service,
                    "banner": banner
                }
    except (socket.timeout, socket.error):
        return None
    except Exception:
        return None
    return None


def run_scanner(target: str, ports: list[int], threads: int, timeout: float, do_banner: bool, output_file: str | None):
    """
    Coordinates multi-threaded scanning across target ports.
    """
    resolved_ip = resolve_target(target)
    print(f"{BOLD}[*] Target Host     :{RESET} {target} ({resolved_ip})")
    print(f"{BOLD}[*] Ports to Scan   :{RESET} {len(ports)} ports")
    print(f"{BOLD}[*] Concurrency     :{RESET} {threads} threads (Timeout: {timeout}s)")
    print(f"{BOLD}[*] Banner Grabbing :{RESET} {'Enabled' if do_banner else 'Disabled'}")
    print(f"{BOLD}[*] Scan Started    :{RESET} {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 75)
    print(f"{BOLD}{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER / VERSION':<40}{RESET}")
    print("-" * 75)

    start_time = time.time()
    open_ports = []

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Schedule scan tasks
            future_to_port = {
                executor.submit(scan_port, resolved_ip, port, timeout, do_banner): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                res = future.result()
                if res:
                    open_ports.append(res)
                    port_str = f"{res['port']}/tcp"
                    state_str = f"{GREEN}{res['state']}{RESET}"
                    service_str = f"{CYAN}{res['service']}{RESET}"
                    banner_str = res['banner'] if res['banner'] != "No banner returned" else f"{YELLOW}{res['banner']}{RESET}"
                    print(f"{port_str:<10} {state_str:<19} {service_str:<24} {banner_str}")

    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrupted by user (Ctrl+C). Showing partial results...{RESET}")

    duration = time.time() - start_time
    open_ports.sort(key=lambda x: x["port"])

    print("-" * 75)
    print(f"{BOLD}[+] Scan Complete in {duration:.2f} seconds.{RESET}")
    print(f"{BOLD}[+] Total Ports Scanned: {len(ports)} | Open Ports Found: {GREEN}{len(open_ports)}{RESET}")

    # Export to JSON if requested
    if output_file:
        report = {
            "target": target,
            "ip": resolved_ip,
            "scanned_ports_count": len(ports),
            "open_ports_count": len(open_ports),
            "duration_seconds": round(duration, 2),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": open_ports
        }
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4)
            print(f"{GREEN}[✓] Results successfully exported to '{output_file}'{RESET}")
        except IOError as e:
            print(f"{RED}[-] Failed to write output file: {e}{RESET}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Fast Multi-Threaded Network Port Scanner & Service Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scanner.py -t 127.0.0.1
  python scanner.py -t scanme.nmap.org -p common
  python scanner.py -t 192.168.1.1 -p 1-1000 -w 100 --timeout 0.5
  python scanner.py -t 127.0.0.1 -p 80,443,8080,3306 -o results.json
"""
    )

    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target hostname or IP address (default: 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="common", help="Ports to scan: 'common', range '1-1024', or list '21,22,80' (default: common)")
    parser.add_argument("-w", "--threads", type=int, default=50, help="Number of concurrent worker threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing probe")
    parser.add_argument("-o", "--output", help="Save scan results to a JSON file (e.g., results.json)")

    args = parser.parse_args()
    port_list = parse_ports(args.ports)
    do_banner = not args.no_banner

    run_scanner(
        target=args.target,
        ports=port_list,
        threads=args.threads,
        timeout=args.timeout,
        do_banner=do_banner,
        output_file=args.output
    )


if __name__ == "__main__":
    main()
