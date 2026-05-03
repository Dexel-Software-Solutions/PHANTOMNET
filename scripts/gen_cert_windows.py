"""
PHANTOMNET — Windows TLS Certificate Generator
Generates a self-signed cert without OpenSSL command line tool.
Run: python scripts/gen_cert_windows.py
"""

import os
import sys
import datetime
from pathlib import Path

def generate():
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress
    except ImportError:
        print("[*] Installing cryptography package...")
        os.system(f"{sys.executable} -m pip install cryptography")
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

    cert_dir = Path("config/certs")
    cert_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Generating RSA private key...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    print("[*] Building self-signed certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PHANTOMNET"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dexel Software Solutions"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "LK"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_path  = cert_dir / "server.key"
    cert_path = cert_dir / "server.crt"

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificate : {cert_path}")
    print(f"[+] Private key : {key_path}")
    print("[+] Done!")

if __name__ == "__main__":
    generate()
