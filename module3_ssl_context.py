#!/usr/bin/env python3
import threading
import time
import socket
import ssl
import struct
from scapy.all import sniff, TCP, IP, Raw

HOST, PORT = "tuskvector.com", 443
HOST_IP      = socket.gethostbyname(HOST)

# Map the record-type byte to human names
RECORD_TYPES = {
    20: 'ChangeCipherSpec',
    21: 'Alert',
    22: 'Handshake',
    23: 'ApplicationData'
}

# Map handshake-type byte inside Handshake records
HANDSHAKE_TYPES = {
    0x01: 'ClientHello',
    0x02: 'ServerHello',
    0x0b: 'Certificate',
    0x10: 'ClientKeyExchange',
    0x14: 'Finished'
}

def parse_records(data):
    """Yield (ct, version, length, fragment) for every TLS record in `data`."""
    i = 0
    while i + 5 <= len(data):
        ct  = data[i]
        ver = struct.unpack('!H', data[i+1:i+3])[0]
        ln  = struct.unpack('!H', data[i+3:i+5])[0]
        frag = data[i+5:i+5+ln]
        yield ct, ver, ln, frag
        i += 5 + ln

def tls_packet_callback(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    ip, tcp = pkt[IP], pkt[TCP]
    if not ((ip.src == HOST_IP and tcp.sport == PORT) or
            (ip.dst == HOST_IP and tcp.dport == PORT)):
        return

    for ct, ver, ln, frag in parse_records(bytes(pkt[Raw].load)):
        rec_name = RECORD_TYPES.get(ct, f"Unknown({ct})")
        direction = "Server→Client" if ip.src == HOST_IP else "Client→Server"
        msg = f"{direction} TLS Record [{rec_name}] v0x{ver:04x} len={ln}"
        if ct == 22 and ln >= 1:
            hs = frag[0]
            hs_name = HANDSHAKE_TYPES.get(hs, f"HS(0x{hs:02x})")
            msg += f"  — Handshake[{hs_name}]"
        print(msg)

def sniff_tls():
    sniff(
        filter=f"tcp and host {HOST_IP} and port {PORT}",
        prn=tls_packet_callback,
        store=False,
        timeout=8
    )

# 1. Start the sniffer thread (needs root)
sniffer = threading.Thread(target=sniff_tls, daemon=True)
sniffer.start()

# 2. Give it a moment
time.sleep(0.5)

# 3. Perform the TLS handshake + HTTP GET
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_default_certs()
ctx.check_hostname = True
ctx.verify_mode    = ssl.CERT_REQUIRED

with ctx.wrap_socket(socket.socket(), server_hostname=HOST) as tls_sock:
    tls_sock.connect((HOST, PORT))
    print("\nNegotiated cipher:", tls_sock.cipher(), "\n")

    tls_sock.sendall(
        b"GET / HTTP/1.1\r\n"
        b"Host: " + HOST.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )

    resp = b""
    while chunk := tls_sock.recv(4096):
        resp += chunk

    body = resp.split(b"\r\n\r\n", 1)[1].decode(errors="ignore")
    print("Decrypted HTTP body (first 200 chars):\n", body[:200], "…\n")

# 4. Wait for the sniffer to finish
sniffer.join()
