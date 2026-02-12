#!/usr/bin/env python3
import argparse
import logging
import socket
import time
import subprocess
import select
import threading


DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
LISTEN_HOST = "0.0.0.0"

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )

def open_protected_port(protected_port, source_ip, duration=30):
    # Use iptables, allow acsess from source_ip
    subprocess.run([
        "iptables", "-I", "INPUT", "1",
        "-s", source_ip,
        "-p", "tcp",
        "--dport", str(protected_port),
        "-j", "ACCEPT"
    ], check=False)
    logging.info(f"Opened port {protected_port} for {source_ip} temporarily ({duration}s)")

    # use a thread to make sure the port will close after some time
    def revoke():
        time.sleep(duration)
        subprocess.run([
            "iptables", "-D", "INPUT",
            "-s", source_ip,
            "-p", "tcp",
            "--dport", str(protected_port),
            "-j", "ACCEPT"
        ], check=False)
        logging.info(f"Closed port {protected_port} for {source_ip} after {duration}s")

    threading.Thread(target=revoke, daemon=True).start()

def close_protected_port(protected_port):
    # clear all the rules first
    subprocess.run(["iptables", "-F", "INPUT"], check=False) 
    # then add drop rule for the port
    subprocess.run([
        "iptables", "-A", "INPUT", 
        "-p", "tcp", 
        "--dport", str(protected_port), 
        "-j", "DROP"
    ], check=True)
    logging.info("TODO: Close firewall for port %s", protected_port)

def listen_for_knocks(sequence, window_seconds, protected_port):
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)
    # close first
    close_protected_port(protected_port)
    
    sockets = {}
    for port in sequence:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((LISTEN_HOST, port))
        s.setblocking(False)
        sockets[port] = s
        logger.info(f"Listening for knock on UDP {port}")

    clients = {}

    while True:
        readable, _, _ = select.select(sockets.values(), [], [], 1.0)
        now = time.time()

        # clean all the expired clients 
        expired_ips = [ip for ip, state in clients.items() if now - state["start"] > window_seconds]
        for ip in expired_ips:
            del clients[ip]
            logger.info(f"Knock timeout for {ip}")

        # for the comming knock
        for s in readable:
            data, addr = s.recvfrom(1024)
            ip = addr[0]
            port = s.getsockname()[1]

            # if the request is from new client
            if ip not in clients:
                if port == sequence[0]:
                    clients[ip] = {"index": 1, "start": now}
                    logger.info(f"Start knock sequence from {ip} (Port {port})")
            # from already client
            else:
                state = clients[ip]
                if port == sequence[state["index"]]:
                    state["index"] += 1
                    logger.info(f"Correct knock from {ip} (Port {port}, Step {state['index']})")
                    
                    if state["index"] == len(sequence):
                        open_protected_port(protected_port, ip)
                        del clients[ip]
                else:
                    logger.warning(f"Wrong sequence! Need to reset.")
                    del clients[ip]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sequence", default="1234,5678,9012")
    parser.add_argument("--protected-port", type=int, default=2222)
    parser.add_argument("--window", type=float, default=10.0)
    args = parser.parse_args()
    
    setup_logging()
    seq = [int(p) for p in args.sequence.split(",")]
    listen_for_knocks(seq, args.window, args.protected_port)