#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import subprocess
import select

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

# remove firewall rule to open port
def open_protected_port(protected_port):
    subprocess.run(
        [
            "iptables",
            "-D",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            str(protected_port),
            "-j",
            "DROP",
        ],
        check=False,
    )
    logging.info("Opened firewall for port %s", protected_port)


def close_protected_port(protected_port):
# add firewall rule here
    subprocess.run(
        [
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            str(protected_port),
            "-j",
            "DROP",
        ],
        check=False,
    )
    logging.info("Closed firewall for port %s", protected_port)


def listen_for_knocks(sequence, window_seconds, protected_port):
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    sockets = {}
    for port in sequence:
        #using UDP socket to get knock
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((LISTEN_HOST, port))
        s.setblocking(False)
        sockets[port] = s

    # for tracking the IP address
    clients = {}

    while True:
        readable, _, _ = select.select(sockets.values(), [], [], 1.0)
        now = time.time()

        for s in readable:
            data, addr = s.recvfrom(1024)
            ip = addr[0]
            port = s.getsockname()[1]

            if ip not in clients:
                if port == sequence[0]:
                    clients[ip] = {"index": 1, "start": now}
                continue

            state = clients[ip]

            # make sure time 
            if now - state["start"] > window_seconds:
                del clients[ip]
                continue
            # sequence 
            if port == sequence[state["index"]]:
                state["index"] += 1
                if state["index"] == len(sequence):
                    open_protected_port(protected_port)
                    del clients[ip]
            else:
                del clients[ip]


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()