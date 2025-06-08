#!/usr/bin/env python3
import socket, ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

HOST, PORT = "tuskvector.com", 443
ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname=HOST) as s:
    s.connect((HOST,PORT))
    # get_peer_cert_chain isn’t in stdlib; fallback via PyOpenSSL if you like
    leaf = x509.load_der_x509_certificate(s.getpeercert(True), default_backend())
    # If you have pyOpenSSL, you can do:
    #   chain = OpenSSL.SSL.Connection(...).get_peer_cert_chain()
    chain = [leaf]  # plus any intermediates you pulled
    for idx,cert in enumerate(chain):
        print(f"Certificate {idx}:")
        print(" Subject:", cert.subject.rfc4514_string())
        print(" Issuer: ", cert.issuer.rfc4514_string())
        # SANs
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            print(" SAN:", ext.value)
        except x509.ExtensionNotFound:
            pass
        # Key Usage
        try:
            ku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
            print(" KeyUsage:", ku)
        except x509.ExtensionNotFound:
            pass
        # OCSP / AIA
        try:
            aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            print(" AIA:", aia)
        except x509.ExtensionNotFound:
            pass
        print()
