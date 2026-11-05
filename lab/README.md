# vtknet lab

Reproducible live targets for verifying the toolkit end to end.

## Option A — Docker (recommended)

```bash
docker compose -f lab/docker-compose.yml up -d
sudo lab/verify.sh 172.20.0.10
docker compose -f lab/docker-compose.yml down
```

The lab gives you three targets on a private bridge (172.20.0.0/24):
`web` (nginx, port 80), `echo` (TCP echo, port 9000) and `tls`
(self-signed TLS server, port 8443, CN=lab.local).

## Option B — bare metal, no Docker

Start the lab TLS target (no root needed to *serve*):

```bash
python3 lab/tls_server.py --port 8443 --cn lab.local
```

And any plain TCP listener, e.g.:

```bash
python3 -m http.server 8000
```

## Verification script

`lab/verify.sh <target-ip>` runs the full live pipeline and prints the JSON
reports: sweep → scan → tls → quic. Requires root (raw sockets).

## Loopback caveat (TLS probe against 127.0.0.1)

Raw-socket TCP handshakes against loopback race with the kernel: the kernel
RSTs handshake states it does not own, which can tear the session down before
our ClientHello lands. Standard fix while testing:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -d 127.0.0.1 -j DROP
sudo vtk tls 127.0.0.1 --port 8443 --sni lab.local
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -d 127.0.0.1 -j DROP
```

Never leave the RST-drop rule installed — it masks real connection errors.
