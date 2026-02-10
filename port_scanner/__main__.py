#!/usr/bin/env python3
"""
Enhanced Port Scanner
Assignment 2: Network Security
"""

import socket
import sys
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# In order to grab banner
def grab_banner(target, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        try:
            # first try http, send a simple http request to get a banner
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except Exception:
            pass

        return ""

    except Exception:
        return ""
    finally:
        sock.close()


def scan_port(target, port, timeout=1.0):
    try:
        # Create a socket and set timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        start = time.time()
        # to see if the target port is open
        result = sock.connect_ex((target, port))
        elapsed = time.time() - start

        if result == 0:
            banner = grab_banner(target, port, timeout)
            return {
                "port": port,
                "state": "OPEN",
                "time": elapsed,
                "banner": banner
            }

    except Exception:
        pass
    finally:
        sock.close()

    return None


def scan_range(target, start_port, end_port, threads=50):
    results = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...\n")

    # using the thread here to speed up
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(scan_port, target, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return sorted(results, key=lambda x: x["port"])


def expand_targets(target):
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        else:
            return [target]
    except ValueError:
        print("[!] Invalid target")
        sys.exit(1)


def main():


    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner/__main__.py <target> [start_port] [end_port]")
        print("Example: python3 port_scanner/__main__.py localhost 1 65535")
        sys.exit(1)

    target_input = sys.argv[1]

    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1024

    targets = expand_targets(target_input)

    for target in targets:
        print(f"[*] Starting port scan on {target}")

        results = scan_range(target, start_port, end_port)

        print("PORT\tSTATE\tTIME\tSERVICE / BANNER")
        print("-" * 30)

        for r in results:
            service = r["banner"].splitlines()[0] if r["banner"] else "-"
            print(f"{r['port']}\t{r['state']}\t{r['time']:.3f}s\t{service}")

        print(f"\n[+] Found {len(results)} open ports\n")


if __name__ == "__main__":
    main()
