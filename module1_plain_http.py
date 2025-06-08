import socket

HOST = "portquiz.net"
PORT = 80
request = f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"

with socket.create_connection((HOST, PORT)) as sock:
    sock.sendall(request.encode())
    response = b""
    while chunk := sock.recv(4096):
        response += chunk

print(response.split(b"\r\n\r\n", 1)[1].decode()[:200], "…")
