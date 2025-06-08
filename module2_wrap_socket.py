#!/usr/bin/env python3
import threading
import time
import socket
import ssl
from scapy.all import sniff, TCP, IP, Raw
from cryptography import x509
from cryptography.hazmat.backends import default_backend

HOST = "tuskvector.com"
PORT = 443

# Resolve once
HOST_IP = socket.gethostbyname(HOST)

# TLS record content type → name
RECORD_TYPES = {
    20: 'ChangeCipherSpec',
    21: 'Alert',
    22: 'Handshake',
    23: 'ApplicationData'
}

# TLS handshake message type → name
HANDSHAKE_TYPES = {
    0x01: 'ClientHello',
    0x02: 'ServerHello',
    0x0b: 'Certificate',
    0x10: 'ClientKeyExchange',
    0x14: 'Finished'
}

def tls_packet_callback(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    ip   = pkt[IP]
    tcp  = pkt[TCP]
    data = bytes(pkt[Raw].load)

    if not ((ip.src == HOST_IP and tcp.sport == PORT) or
            (ip.dst == HOST_IP and tcp.dport == PORT)):
        return

    if len(data) < 5:
        return

    content_type = data[0]
    length       = int.from_bytes(data[3:5], 'big')
    rec_name     = RECORD_TYPES.get(content_type, f"Unknown({content_type})")
    direction    = "Server → Client" if ip.src == HOST_IP else "Client → Server"
    msg = f"{direction} TLS Record [{rec_name}] (len={length})"

    if content_type == 22 and len(data) >= 6:
        hs_type = data[5]
        hs_name = HANDSHAKE_TYPES.get(hs_type, f"UnknownHS({hs_type})")
        msg += f"  Handshake Message [{hs_name}]"

    print(msg)

def sniff_tls():
    sniff(
        filter=f"tcp and host {HOST_IP} and port {PORT}",
        prn=tls_packet_callback,
        store=False,
        timeout=8
    )

# 1. Start sniffer thread (needs root)
sniffer = threading.Thread(target=sniff_tls, daemon=True)
sniffer.start()

# 2. Let the sniffer spin up
time.sleep(0.5)

# 3. Perform TLS client handshake + HTTP GET
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_default_certs()
ctx.check_hostname = True
ctx.verify_mode    = ssl.CERT_REQUIRED

with ctx.wrap_socket(socket.socket(), server_hostname=HOST) as tls_sock:
    tls_sock.connect((HOST, PORT))

    # Print the negotiated cipher
    print("Negotiated cipher:", tls_sock.cipher())

    # --- Certificate Inspection ---
    der = tls_sock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der, default_backend())
    print("\nServer leaf certificate:")
    print("  Subject:      ", cert.subject.rfc4514_string())
    print("  Issuer:       ", cert.issuer.rfc4514_string())
    print("  Valid from:   ", cert.not_valid_before)
    print("  Valid until:  ", cert.not_valid_after)
    print("  Serial number:", cert.serial_number)
    print("Certificate validation: PASSED (verified against system CAs)\n")

    # Send HTTP request over the encrypted channel
    tls_sock.sendall(
        b"GET / HTTP/1.1\r\n"
        b"Host: " + HOST.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )

    # Read and print the first 200 chars of the decrypted body
    resp = b""
    while chunk := tls_sock.recv(4096):
        resp += chunk

    body = resp.split(b"\r\n\r\n", 1)[1].decode(errors="ignore")
    print("Response body (first 200 chars):\n", body[:200], "…")

# 4. Wait for the sniffer to finish
sniffer.join()
