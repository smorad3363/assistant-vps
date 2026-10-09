"""Run inside *target* network namespace: TCP/UDP echo test fixture."""
import socket
import threading

TARGET = "198.19.0.2"


def tcp():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((TARGET, 8443))
    s.listen(5)
    while True:
        connection, _ = s.accept()
        try:
            data = connection.recv(4096)
            connection.sendall(b"TCP:" + data)
        finally:
            connection.close()


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((TARGET, 2053))
    while True:
        payload, address = s.recvfrom(4096)
        s.sendto(b"UDP:" + payload, address)


threading.Thread(target=tcp, daemon=True).start()
udp()
