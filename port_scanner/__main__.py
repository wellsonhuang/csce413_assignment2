#!/usr/bin/env python3
"""

Assignment 2: Network Security
"""

import socket
import argparse
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# In order to grab banner
def grab_banner(target, port, timeout=2):
    # connect to the port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # situation 1 : listen to the port
        try:
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except:
            pass

        # situation 2 : if their is no return ,send HTTP request
        try:
            request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            sock.sendall(request)
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except:
            pass

        return ""

    except:
        return ""
    finally:
        try:
            sock.close()
        except:
            pass


def scan_port(target, port, timeout=0.1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start_time = time.time()
    result = sock.connect_ex((target, port))
    elapsed = time.time() - start_time

    # if connection successful, go grab banner
    if result == 0:
        banner = grab_banner(target, port, timeout)
        sock.close()
        return {
            "port": port,
            "state": "OPEN",
            "time": elapsed,
            "banner": banner
        }

    sock.close()
    return None


def scan_range(target, start_port, end_port, threads):
    results = []

    print(f"\n[*] Start Scanning on {target} ({start_port}-{end_port})")
    print(f"[*] you are using threads: {threads}\n")

    # Use thread to go faster
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

# to handle CIDR
def expand_targets(target):
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        else:
            return [target]
    except ValueError:
        print("[!] there is no target")
        exit(1)


def parse_ports(port_string):
    try:
        start, end = port_string.split("-")
        return int(start), int(end)
    except:
        print("[!] Invalid port range format. Use format like 1-65535")
        exit(1)


def main():
    parser = argparse.ArgumentParser(description="Simple TCP Port Scanner")

    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", default="1-1024")
    parser.add_argument("--threads", type=int, default=100)

    args = parser.parse_args()

    start_port, end_port = parse_ports(args.ports)
    targets = expand_targets(args.target)

    for target in targets:
        results = scan_range(target, start_port, end_port, args.threads)

        print("PORT\tSTATE\tTIME\tSERVICE / BANNER")
        print("-" * 60)

        for r in results:
            banner_line = r["banner"].splitlines()[0] if r["banner"] else "-"
            print(f"{r['port']}\t{r['state']}\t{r['time']:.3f}s\t{banner_line}")

        print(f"\n[+] Found {len(results)} open ports\n")


if __name__ == "__main__":
    main()