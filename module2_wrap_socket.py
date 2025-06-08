import socket, ssl

HOST, PORT = "tuskvector.com", 443

# Set up a modern TLS client context
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_default_certs()
ctx.check_hostname = True
ctx.verify_mode    = ssl.CERT_REQUIRED

with ctx.wrap_socket(socket.socket(), server_hostname=HOST) as tls_sock:
    tls_sock.connect((HOST, PORT))
    print("Negotiated cipher:", tls_sock.cipher())
    tls_sock.sendall(
        b"GET / HTTP/1.1\r\n"
        b"Host: tuskvector.com\r\n"
        b"Connection: close\r\n\r\n"
    )
    resp = b""
    while chunk := tls_sock.recv(4096):
        resp += chunk

body = resp.split(b"\r\n\r\n", 1)[1].decode(errors="ignore")
print(body[:200], "…")
