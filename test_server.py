#!/usr/bin/env python3
"""
=============================================================================
Safe Local Test Server for Port Scanner
=============================================================================
Description:
    Runs 3 mock network services locally on 127.0.0.1 to safely test
    port scanning and banner grabbing without touching any external networks.

Mock Services:
    - Port 8021: Mock FTP Server (returns '220 vsFTPd 3.0.3 Ready')
    - Port 8022: Mock SSH Server (returns 'SSH-2.0-OpenSSH_8.9p1')
    - Port 8080: Mock HTTP Web Server (returns 'HTTP/1.1 200 OK Server: Apache/2.4.52')
=============================================================================
"""

import socket
import threading
import sys

SERVICES = [
    {
        "port": 8021,
        "name": "Mock FTP Server",
        "greeting": b"220 (vsFTPd 3.0.3 - Mock Security Lab) Ready.\r\n"
    },
    {
        "port": 8022,
        "name": "Mock SSH Server",
        "greeting": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
    },
    {
        "port": 8080,
        "name": "Mock HTTP Web Server",
        "greeting": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu-Lab)\r\nContent-Type: text/html\r\n\r\n<h1>Mock Web Server</h1>"
    }
]

running = True


def handle_client(client_socket, service):
    """Sends mock service response and closes connection."""
    try:
        client_socket.settimeout(2.0)
        # Send greeting / banner
        client_socket.sendall(service["greeting"])
        # Attempt to read any request probe
        try:
            client_socket.recv(1024)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        client_socket.close()


def run_service(service):
    """Listens on a given port and serves incoming connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("127.0.0.1", service["port"]))
        server.listen(5)
        server.settimeout(1.0)
        print(f"  [+] {service['name']} listening on 127.0.0.1:{service['port']}")

        while running:
            try:
                client_sock, _ = server.accept()
                t = threading.Thread(target=handle_client, args=(client_sock, service), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break
    except OSError as e:
        print(f"  [-] Failed to bind port {service['port']}: {e}")
    finally:
        server.close()


def main():
    global running
    print("\n" + "=" * 60)
    print("  MOCK MULTI-SERVICE TEST LAB FOR PORT SCANNER")
    print("=" * 60)
    print("  Starting mock test services on 127.0.0.1 ...\n")

    threads = []
    for service in SERVICES:
        t = threading.Thread(target=run_service, args=(service,), daemon=True)
        t.start()
        threads.append(t)

    print("\n  [✓] All mock services are active!")
    print("  --> In a new terminal, run:")
    print("      python scanner.py -t 127.0.0.1 -p 8000-8100\n")
    print("  Press Ctrl+C to stop the test server.\n")

    try:
        while True:
            threading.Event().wait(1.0)
    except KeyboardInterrupt:
        print("\n  [!] Stopping mock test services...")
        running = False
        sys.exit(0)


if __name__ == "__main__":
    main()
