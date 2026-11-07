#!/usr/bin/env bash
# Live verification of the whole vtknet pipeline against a lab target.
# Usage: sudo lab/verify.sh <target-ip> [tls-port]
set -euo pipefail

TARGET="${1:?usage: sudo lab/verify.sh <target-ip> [tls-port]}"
TLS_PORT="${2:-8443}"
HERE="$(cd "$(dirname "$0")" && pwd)"
VTK="$(cd "$HERE/.." && pwd)/.venv/bin/vtk"
OUT="$(mktemp -d)"

if [ "$(id -u)" != "0" ]; then
    echo "needs root (raw sockets): run with sudo" >&2
    exit 1
fi

echo "== 1/4 ICMP sweep =="
"$VTK" sweep "$TARGET/32" --json --rate 50 > "$OUT/sweep.json" && "$VTK" sweep "$TARGET/32" | tail -2

echo "== 2/4 TCP SYN scan (ports 80,9000) =="
"$VTK" scan "$TARGET" --ports 80,9000 --type syn --rate 50 --json > "$OUT/scan.json" && "$VTK" scan "$TARGET" --ports 80,9000 | tail -2

echo "== 3/4 TLS fingerprint + certificate audit =="
"$VTK" tls "$TARGET" --port "$TLS_PORT" --sni lab.local --json > "$OUT/tls.json" && "$VTK" tls "$TARGET" --port "$TLS_PORT" | tail -2

echo "== 4/4 QUIC version negotiation =="
"$VTK" quic "$TARGET" --json > "$OUT/quic.json" || true

echo "== reports in $OUT =="
ls -1 "$OUT"
echo "done."
