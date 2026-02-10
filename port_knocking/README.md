## Port Knocking Starter Template

This directory is a starter template for the port knocking portion of the assignment.

### What you need to implement
- Pick a protected service/port (default is 2222).
I selected 2222 tcp port, and set it to close as a default with iptables drop rule.
- Define a knock sequence (e.g., 1234, 5678, 9012).
Using UDP for those sequence
- Implement a server that listens for knocks and validates the sequence.
I use UDP sockets for all knocking port and check all the packets and also have to tell the different for the knock sequence per source IP
- Open the protected port only after a valid sequence.
I will drop out the rule if the sequence is valid and in time
- Add timing constraints and reset on incorrect sequences.
Using time windo
- Implement a client to send the knock sequence.
Send UDP to each port I knock

### Getting started
1. Implement your server logic in `knock_server.py`.
2. Implement your client logic in `knock_client.py`.
3. Update `demo.sh` to demonstrate your flow.
4. Run from the repo root with `docker compose up port_knocking`.

### Example usage
```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
```
