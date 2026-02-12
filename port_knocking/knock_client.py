#!/usr/bin/env python3
import argparse
import socket
import time

def perform_knock_sequence(target, sequence, delay):
    for port in sequence:
        print(f"Knocking on {target}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"\x00", (target, port))
        sock.close()
        time.sleep(delay)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--sequence", default="1234,5678,9012")
    parser.add_argument("--delay", type=float, default=0.2)
    args = parser.parse_args()
    
    seq = [int(p) for p in args.sequence.split(",")]
    perform_knock_sequence(args.target, seq, args.delay)