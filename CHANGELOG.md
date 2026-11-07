# Changelog

## 0.7.0 — speed + hostile-input hardening

- **Concurrent engine**: `--workers N` runs sr() batches on a thread pool
  (each call owns its sockets); `rate` is the TOTAL across workers, so
  politeness intent survives parallelism; results merge in batch order —
  output stays deterministic. `workers=1` (default) is the untouched
  sequential path.
- **Hostile-pcap hardening**: `iter_pcap_safe` skips malformed records with a
  bounded error budget; `pcap_summary` reports `malformed`/`junk_suspect`/
  `truncated` and caps unique-key counters (`MAX_UNIQUE_KEYS`) so millions of
  forged conversations cannot exhaust memory; opaque junk frames (scapy
  leniency artifacts) are counted but never pollute stats; unreadable files
  raise a clear `ValueError` (CLI: exit 2 with message).
- `decode_bytes` never raises on garbage — worst case is an opaque Raw packet.
- Stream writer failures (disk full) log and continue instead of killing a capture.

## 0.6.0 — temporal memory

- **SQLite history**: every network-truth run auto-persists to
  `~/.vtknet/history.db` (`--db PATH` to relocate, `--no-save` to opt out);
  dry-runs, synth and inspect never save.
- **`vtk report`**: `--list` recent runs, `--show N` full run JSON,
  `--diff A B` — added/removed/changed findings between runs, keyed by
  finding identity (module|kind|host|port) with volatile detail keys
  (timestamps, capture counters) excluded from change detection.
- **`vtk dns`**: same query to N resolvers → consistent vs divergent answers;
  divergence = suspected spoofing (HIGH).
- **`vtk dhcp`**: broadcast discover with `multi=True` → every offer becomes a
  finding; multiple servers / unknown server vs `--known-server` → rogue
  detection (HIGH). `conf.checkIPaddr` snapshotted and restored.
- Engine: `send_recv(..., multi=True)` support.

## 0.5.0 — integration sprint (guide tricks → code)

- TLS probe rewritten over scapy `TCP_client` automaton (correct seq/ack +
  retransmissions; link factory injectable for offline tests).
- `synth --replay IFACE --pps N` via tcpreplay/sendpfast; new `frag_evasion`
  scenario (shuffled out-of-order IP fragments for reassembly testing).
- Streaming capture: `sniff --out` writes each packet as it arrives (PcapWriter).
- `vtk inspect`: decode evidence hex/file/pcap back into layers + rebuild command.
- `vtk pcap`: streaming pcap statistics (protocols, talkers, conversations).

## 0.4.0 — extensibility + wire formats

- Plugin API (`vtknet.plugins.VtkPlugin`): entry-point group + `--plugin-dir`
  file discovery; plugins become subcommands, builtins win collisions.
- `vtk quic`: RFC 9000 Version Negotiation probe (crypto-free QUIC check).
- Self-contained HTML reports (`--html FILE`).
- Live lab: `lab/docker-compose.yml` + bare-metal `lab/tls_server.py` +
  `lab/verify.sh`; loopback kernel-RST caveat documented.

## 0.3.0 — detection modules

- `vtk fuzz`: seeded boundary-value mutation + ICMP liveness crash detection
  (crashing mutant saved as evidence).
- `vtk wifi`: deauth-storm / evil-twin / rogue-AP detectors (live + offline).
- `vtk mitm`: ARP poisoning with guaranteed restore (3× correct bindings,
  ip_forward reverted) — cleanup discipline as a feature.
- TLS certificate audit: DER extraction + expiry/self-signed findings.

## 0.2.0 — capture + TLS + synthetic traces

- `core/capture.py`: AsyncSniffer wrapper (ring buffer, offline mode, pcap
  I/O, request/reply correlation for TCP/ICMP/ARP).
- `vtk tls`: raw-handshake ServerHello fingerprint (version + cipher).
- `vtk synth`: 5 seeded IDS-test scenarios with JSON metadata sidecars.
- `vtk sniff` command; `--out`/`--report` flag split.

## 0.1.0 — foundation

- Engine (rate + jitter + retry + dry-run, L2/L3), JSON-stable data model
  (Finding/Evidence/ScanResult), recon (ICMP sweep + ARP scan), TCP scanner
  (SYN/NULL/FIN/XMAS/ACK), CLI with exit-code discipline, CI workflow.
