"""Lab TLS target: self-signed certificate server on localhost (no root needed).

Run:  python3 lab/tls_server.py [--port 8443] [--cn lab.local]
Then: sudo vtk tls 127.0.0.1 --port 8443 --sni lab.local

Generates a fresh self-signed certificate at startup with cryptography and
serves a minimal HTTP response over TLS. Loopback caveat: the kernel may RST
raw-socket handshakes it does not know about; see lab/README.md for the
iptables one-liner that fixes it.
"""

from __future__ import annotations

import argparse
import datetime
import socket
import ssl
import threading

HOST = "127.0.0.1"


def make_self_signed_cert(cn: str, days: int = 30):

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .public_key(key.public_key())
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def serve(port: int, cn: str, stop: threading.Event) -> None:
    cert_pem, key_pem = make_self_signed_cert(cn)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pem") as cf, tempfile.NamedTemporaryFile(suffix=".pem") as kf:
        cf.write(cert_pem)
        cf.flush()
        kf.write(key_pem)
        kf.flush()
        ctx.load_cert_chain(cf.name, kf.name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, port))
    sock.listen(16)
    sock.settimeout(0.5)
    print(f"lab TLS target on {HOST}:{port} (CN={cn}) — Ctrl+C to stop")
    while not stop.is_set():
        try:
            conn, _addr = sock.accept()
        except socket.timeout:
            continue
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            tls.recv(4096)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nvtknet-lab\r\n")
            tls.close()
        except Exception as exc:  # noqa: BLE001 — lab server: log and keep serving
            print(f"connection error: {exc}")
    sock.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="vtknet lab TLS target")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cn", default="lab.local")
    args = ap.parse_args()
    stop = threading.Event()
    try:
        serve(args.port, args.cn, stop)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
