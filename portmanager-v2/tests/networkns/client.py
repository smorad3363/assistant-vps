"""Run inside *client* network namespace: verify NAT TCP and UDP reply."""
import socket

RELAY = "198.18.0.2"
with socket.create_connection((RELAY, 443), timeout=5) as connection:
    connection.sendall(b"example-tcp")
    assert connection.recv(4096) == b"TCP:example-tcp"
print("PASS: TCP 443 -> 8443 and return path")
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.sendto(b"example-udp", (RELAY, 2053))
    payload, sender = sock.recvfrom(4096)
    assert payload == b"UDP:example-udp", payload
    assert sender[0] == RELAY, sender
print("PASS: UDP 2053 -> 2053 and return path")
