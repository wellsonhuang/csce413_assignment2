#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import socket
import threading
import time
import paramiko
from collections import defaultdict

from logger import setup_logger

HOST_KEY = paramiko.RSAKey.generate(2048)
BANNER = "SSH-2.0-OpenSS_8.9p1 Ubuntu-3ubuntu0.3"

logger = setup_logger()
FAILED_ATTEMPTS = defaultdict(list)
TIME_WINDOW = 60  



class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.start_time = time.time()
        self.username = None
        self.password = None

    def check_auth_password(self, username, password):
        now = time.time()
        self.username = username
        self.password = password

        logger.info(
            f"AUTH_ATTEMPT ip={self.client_ip} "
            f"user={username} password={password}"
        )

        attempts = FAILED_ATTEMPTS[self.client_ip]
        attempts[:] = [t for t in attempts if now - t < TIME_WINDOW]
        attempts.append(now)

        # if you login with the same Ip address more than 3 times in 1 min, I will send a alert
        if len(attempts) >= 3:
            logger.warning(
                f"ALERT Multiple failed login attempts!!! ip={self.client_ip} "
            )

        #make it successful for any username/password
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


def fake_shell(channel, client_ip, server):
    channel.send(b"Ubuntu 22.04.3 LTS\r\n")
    channel.send(b"$ ")

    try:
        while True:
            data = channel.recv(1024)
            if not data:
                break

            command = data.decode(errors="ignore").strip()

            logger.info(
                f"COMMAND ip={client_ip} "
                f"user={server.username} cmd=\"{command}\""
            )

            ATTACK_PATTERNS = [
                "wget ",
                "curl ",
                "/etc/shadow",
            ]
            for pattern in ATTACK_PATTERNS:
                if pattern in command:
                    logger.warning(
                        f"ALERT Known attack pattern!!! ip={client_ip} "
                        f"cmd=\"{command}\""
                    )
                    break

            if command in ["exit", "logout"]:
                channel.send(b"logout\r\n")
                break

            # put some response for serveral attack commend
            if command == "whoami":
                channel.send(f"{server.username}\r\n".encode())
            elif command.startswith("cat"):
                channel.send(b"Permission denied\r\n")
            else:
                channel.send(b"you can't \r\n")

            channel.send(b"$ ")

    finally:
        duration = time.time() - server.start_time
        logger.info(
            f"DISCONNECT ip={client_ip} "
            f"user={server.username} duration={duration:.2f}s"
        )
        channel.close()


def handle_client(client, addr):
    transport = paramiko.Transport(client)
    transport.local_version = BANNER
    transport.add_server_key(HOST_KEY)

    server = HoneypotSSHServer(addr[0])

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)

        if channel is None:
            return

        server.event.wait(10)
        fake_shell(channel, addr[0], server)

    except Exception as e:
        logger.error(f"ERROR ip={addr[0]} err={e}")
    finally:
        transport.close()


def start_honeypot(host="0.0.0.0", port=22):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    logger.info(f"SSH honeypot listening on {host}:{port}")

    while True:
        client, addr = sock.accept()
        logger.info(f"CONNECTION from {addr[0]}:{addr[1]}")

        t = threading.Thread(
            target=handle_client,
            args=(client, addr),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    start_honeypot()