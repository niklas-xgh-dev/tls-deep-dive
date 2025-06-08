#!/usr/bin/env python3
import threading
import time
import socket
from scapy.all import sniff, TCP, IP

HOST = "portquiz.net"
PORT = 80

# Resolve once
HOST_IP = socket.gethostbyname(HOST)

# Messages when CLIENT → SERVER
CLIENT_MSGS = {
    'S':  "Hey server! You there?",
    'A':  "I got your hello!",
    'PA': "Here's my GET request—hit me with some data!",
    'FA': "Alright, I'm done — talk later!"
}

# Messages when SERVER → CLIENT
SERVER_MSGS = {
    'SA': "Hey hey! I'm here and I hear you!",
    'A':  "Got your request!",
    'PA': "Here's your HTML payload — enjoy!",
    'FA': "Alright, I'm done — talk later!"
}

def packet_callback(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return

    ip  = pkt[IP]
    tcp = pkt[TCP]
    flags = str(tcp.flags)

    # Identify direction
    if ip.src == HOST_IP and tcp.sport == PORT:
        # Packet from server → client
        msg = SERVER_MSGS.get(flags, f"Server flags={flags}")
    elif ip.dst == HOST_IP and tcp.dport == PORT:
        # Packet from client → server
        msg = CLIENT_MSGS.get(flags, f"Client flags={flags}")
    else:
        return

    print(f"{ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport}  {msg}")

def sniff_handshake():
    sniff(
        filter=f"tcp and host {HOST_IP} and port {PORT}",
        prn=packet_callback,
        store=False,
        count=8,
        timeout=5
    )

# 1. Start sniffer thread (needs root)
sniffer = threading.Thread(target=sniff_handshake, daemon=True)
sniffer.start()

# 2. Give scapy a moment to spin up
time.sleep(0.5)

# 3. Perform your plain-HTTP GET
with socket.create_connection((HOST, PORT)) as sock:
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(request.encode())
    data = sock.recv(4096)
    print("Received (first 100 chars):", data.decode(errors="ignore")[:100], "…")

# 4. Wait for the sniffer to finish
sniffer.join()
