FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iptables iproute2 netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY knock_server.py knock_client.py ./

USER root

# expose the port to 2223
CMD bash -c "nc -lk -p 2223 & python3 knock_server.py --protected-port 2223"