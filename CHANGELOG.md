# Changelog

## 0.9.0 — 2026-11-11 (expansion round: ECH, IDS eval, notarize, watch, deep verify)

- **`vtk ech`** (RFC 9849): first-class Encrypted Client Hello surface —
  ECHConfigList discovery via HTTPS/SVCB DNS records, GREASE-ECH ClientHello
  (framing-preserving splice), and `ech_required` (121) detection;
  kinds `ech.dns.*` / `ech.path.*` / `ech.enforced`.
- **`vtk eval`** (Sprint 2 MVP): `synth --eval` harness — seeded scenario →
  IDS engine (suricata offline / null) → keyword+target scoring matrix →
  `eval.detected`/`eval.missed` (HIGH on gaps). Ground truth from the
  scenario sidecar; CI-ready.
- **`vtk notarize`**: record the report's evidence Merkle root in the
  **Rekor v2 transparency log** (`hashes/entries`, kind=intoto) — hash-only
  disclosure, public timestamp; offline mode emits the manifest.
- **`vtk sign --intoto`**: in-toto Statement v1 attestations
  (`application/vnd.in-toto+json`) with per-host subject digests —
  cosign-compatible shape, verified by the same DSSE pipeline.
- **`vtk verify --deep`**: re-derives claims from evidence bytes — SYN+ACK
  for `port.open`, echo-reply for `host.alive`, certificate expiry re-check;
  `verify.deep.holds` / `.contradicts` (MEDIUM) / `.skipped` (never false-fails).
- **`vtk watch`** (Sprint 3 MVP): profile-driven probe rounds through the
  real CLI, auto-diff against the previous round of the same command+target,
  severity floor, JSON webhook — the one-shot tool learns to live.
- **`fuzz --minimize`**: on a recorded crash, delta-debug the crashing mutant
  field-by-field (live re-fires) → `fuzz.minimized` with the minimal packet
  as evidence — vendor-ready bug report in one command.
- **Taxonomy contract**: `SCHEMA_VERSION` (SemVer, OSV-style additive-only
  evolution) stamped into every ScanResult and the JSON Schema
  (`schema_version` required property); draft-07 retained deliberately
  (SARIF/Semgrep compatibility).
- **`action.yml`**: official GitHub Action — `vtk assert` as a desired-state
  PR gate (exit 1 on violation).
- kinds registry: 82 registered kinds (was 65); new: `eval.*`, `watch.*`,
  `notarize.*`, `fuzz.minimized`, `verify.deep.*`, `ech.*`.

## 0.8.0 — evidence chain, signed reports, desired-state

- **Evidence SHA-256**: every `Evidence` stamps its own SHA-256 at creation
  (`core/models.py`) — the first link of the verify/sign chain; the hash
  travels in JSON, HTML and SARIF output.
- **`vtk kinds`**: central finding-kind registry (`core/kinds.py`) — one
  meaning + default severity + reference per kind; `--schema` emits a
  draft-07 JSON Schema of the findings payload; plugins register via
  `register_kind()` (builtins never shadowed).
- **`report --diff :last`**: diff against the most recent run of the same
  command+target (`:last-N` walks further back) — diff-by-default without
  remembering run ids (`History.find_last_run`).
- **SARIF 2.1.0 export** (`--sarif FILE`): findings land directly in the
  GitHub Security tab; severity → level mapping, evidence hash in result
  properties.
- **`--dry-run --emit out.pcap`**: dry-runs write the packets that *would*
  be sent to a reviewable pcap — L3 probes framed with placeholder MACs so
  no neighbor resolution (no traffic) ever happens during a dry-run.
- **`vtk banner`**: service-first-bytes grabbing over the `TCP_client`
  automaton — banner text + raw bytes as hex evidence; `banner.no-data`
  marks client-speaks-first services (probe those with `tls`).
- **PQ-TLS probe v1** (`tls --pq`, `--force-fragment`): ClientHello
  offering X25519MLKEM768 (hello ~1.4 KB) and a padded past-MTU variant —
  detects servers/paths that break on post-quantum or fragmented
  ClientHellos. v1 uses a deterministic dummy key_share: ServerHello/alert
  detection is valid, no hybrid handshake completes.
- New kinds registered: `banner.*`, `tls.pq.*`, `kinds.*`.
- **Review pass — PQ probe corrected and upgraded**: the MLKEM group constant
  was the decimal 4588 mis-hexed as `0x4588` (an unassigned IANA group that
  made every reply look post-quantum); it is now the real code point
  `0x11EC`. The probe reads the server-SELECTED key_share group back from
  the ServerHello (`parse_serverhello_selected_group`, pure byte walk):
  `tls.pq.negotiated` now means the server genuinely chose X25519MLKEM768,
  while a classical selection lands in the new `tls.pq.fallback` kind —
  both carry `pq_selected_group`/`pq_confirmed` in detail. The ClientHello
  now mirrors the real RFC 10024 / Chrome wire shape: MLKEM768 listed FIRST
  in supported_groups (client preference) and ONE 1216-byte hybrid client
  share (1184B ML-KEM-768 ek, then 32B x25519 — reversed order per RFC
  10024 §3.2) instead of two separate entries.
- **Review pass — bounded link reads**: scapy automaton `recv()` has no
  timeout, so a server that accepts and stays silent could hang a probe
  forever. `core/converse.link_recv_bounded` enforces the deadline from
  the caller's side (helper read + close-underneath unblock); `banner`
  and the PQ probe use it with `engine.cfg.timeout`.
- **`vtk verify REPORT.json`**: the chain of custody closes — every
  evidence hash is re-derived from the bytes as they stand now
  (`verify.tampered`, high, on mismatch), unregistered finding kinds are
  flagged against the kinds registry (`verify.unknown-kind`), and a
  `verify.summary` finding carries the totals. Pre-0.8.0 reports (no
  stored hashes) count as `no_hash` instead of failing. Offline, no root.
- **Out-of-the-box round §11 (IDEAS.md)** — five ideas shipped:
  - **Merkle-ized findings / selective disclosure**: every signed envelope
    carries `vtknetMerkleRoot` (Merkle root over all evidence hashes);
    `vtk verify --prove FINDING_ID` emits a Certificate-Transparency-style
    inclusion proof — share ONE finding with a third party without
    disclosing the rest of the report. No scanner or attestation tool
    offers this.
  - **`vtk replay`**: evidence is executable — re-send the exact bytes a
    finding was proven with (the crashing fuzz mutant, the anomalous
    probe) through the Engine, dry-run aware, DSSE reports verified
    before replay.
  - **`vtk assert`**: the network as desired-state — JSON rules of promises
    ("port 443 present", "no rogue DHCP"), evaluated against any report;
    exit 1 on violation = the CI-gate contract. Compose live mode with
    the Unix pipeline.
  - **blindspots**: every scan/sweep/tls/banner run now declares the
    boundaries of its own knowledge (`blindspot.*` findings — filtered
    ports, silent hosts, unknown cert health). The most honest report in
    the market: quantified ignorance, not manufactured omniscience.
  - **`vtk ledger`**: double-entry bookkeeping for the wire — every packet
    addressed to us is a credit, our probes are the debits; unaccounted
    talkers ("the network spoke first") become findings with packet
    evidence. Offline pcap or live capture; hostile floods capped.
- **SARIF upgraded to GitHub-grade** (research-driven): results now carry
  the stable cross-run fingerprint in `partialFingerprints`
  (`primaryLocationLineHash` — the only key GitHub reads for alert dedup —
  plus a versioned `vtknetFindingHash/v1`) and a deterministic
  `correlationGuid`; a per-run uuid there would close/reopen alerts every
  scan. Locations use deterministic `tcp://host:port` artifact URIs
  (SARIF §3.4.7), rule metadata (descriptions + help +
  `security-severity` CVSS-like buckets) is generated from the kinds
  registry — no other scanner emits all of this (Semgrep/Trivy ship no
  stable fingerprints at all).
- **`vtk keygen` / `vtk sign` — DSSE-signed reports (Ed25519)**: the
  first network scanner with standards-grade tamper-evident output.
  Reports are wrapped in DSSE v1 envelopes (`report.json.dsse`,
  payloadType `application/vnd.vtknet.report.v1+json`), signed over the
  PAE bytes exactly per the DSSE spec; signing is reproducible
  (canonical JSON). `vtk verify` accepts envelopes and fails closed —
  a bad signature is an error, never a warning. Keypairs land in
  `~/.vtknet/keys/<keyid>.key|.pub` (0600 private); keyid = sha256 of
  the DER public key. The chain of custody is now end-to-end:
  evidence stamped at birth → envelope signed → verify re-derives
  signature AND every evidence hash.

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
