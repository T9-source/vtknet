# vtknet (`vtk`)

Evidence-driven network testing toolkit built on **Scapy**.

## The idea

Existing tools are siloed: nmap scans with fixed packet shapes, wireshark
analyzes interactively, hping3 crafts without a pipeline, tcpreplay replays
without generating. `vtknet` is one pipeline where **everything is a Scapy
packet**:

- Modules compose: build → send → capture replies → structured findings.
- Every finding carries **evidence**: the hex bytes of the packet(s) that prove it —
  and `vtk inspect` turns any evidence hex back into readable layers.
- One shared `Engine` controls pacing (rate + jitter), timeouts, retries, dry-run;
  stateful conversations run over scapy's `TCP_client` automaton.
- Output is stable JSON, human summary, or self-contained HTML (`--html`).
- Everything is reproducible: same seed → same mutants, same traces, same bytes.

**What it is not:** not an nmap replacement for raw speed, not a wireshark
replacement for interactive deep analysis. It wins at controlled packet
crafting, structured evidence, automation, detection engineering, and
custom-protocol work.

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
vtk --help
```

Raw-socket commands (sweep/arp/scan/tls/quic/fuzz/mitm, live sniff/wifi) need
root. `synth`, `sniff --offline`, `wifi --offline`, `inspect` and `pcap` never do.

## Commands

| Command | What it does | Root? |
|---|---|---|
| `sweep` | ICMP host discovery on a CIDR | yes |
| `arp` | ARP discovery of the local segment | yes |
| `scan` | TCP SYN/NULL/FIN/XMAS/ACK scan | yes |
| `tls` | TLS fingerprint via `TCP_client` conversation: ServerHello version+cipher **and X.509 certificate audit** (expiry → severity, self-signed); `--pq` = post-quantum hybrid probe | yes |
| `banner` | grab the first bytes a service sends (stateful TCP conversation, evidence hex) | yes |
| `quic` | QUIC reachability via RFC 9000 Version Negotiation (one datagram, no crypto needed) | yes |
| `sniff` | capture live or read a pcap offline; `--out` **streams** to pcap while capturing (never OOM) | live only |
| `synth` | seeded synthetic attack traces (6 scenarios incl. `frag_evasion`) + JSON sidecars; `--replay IFACE` replays via tcpreplay | no |
| `fuzz` | seeded header fuzzer (ip/icmp/udp/tcp) with ICMP liveness crash detection — the crashing mutant is saved as evidence | yes |
| `wifi` | deauth-storm / evil-twin / rogue-AP detection on a monitor iface or offline pcap | live only |
| `mitm` | ARP poisoning kit with **automatic restore**: correct bindings pushed 3× on exit, ip_forward reverted if we changed it | yes |
| `inspect` | decode evidence hex / file / pcap bytes back into layers + the exact rebuild command | no |
| `pcap` | streaming pcap statistics — protocols, top talkers, conversations — without loading the file | no |
| `report` | query the run history: `--list`, `--show N`, `--diff A B` (added/removed/changed; `:last` = newest run of the same command+target) | no |
| `kinds` | the finding-kind registry: meanings + default severities; `--schema` emits the JSON Schema (with `schema_version`) | no |
| `ech` | Encrypted Client Hello surface (RFC 9849): ECHConfigList via HTTPS/SVCB DNS + GREASE probe + `ech_required` (121) detection | yes |
| `eval` | `synth --eval`: generate a seeded attack scenario, run an IDS over it, score detection (`eval.detected` / `eval.missed`) | no |
| `verify` | re-derive every evidence SHA-256 in a saved report — tamper-evident chain of custody (`verify.tampered` on mismatch) | no |
| `keygen` | generate an Ed25519 signing keypair (`~/.vtknet/keys/`) | no |
| `sign` | DSSE-sign a saved report (`report.json.dsse`) — standards-grade tamper evidence | no |
| `replay` | re-send the exact evidence bytes of one finding (evidence is executable) | yes |
| `assert` | desired-state assertions over a report — exit 1 on any broken promise | no |
| `ledger` | double-entry wire audit: unaccounted inbound talkers become findings | live only / `--offline` |
| `verify --prove ID` | Merkle inclusion proof — share one finding without the rest of the report | no |
| `verify --deep` | re-derive claims from evidence bytes (SYN+ACK / ICMP type / cert expiry) — the report proves its own words | no |
| `sign --intoto` | sign as an in-toto Statement v1 (cosign-compatible attestation, per-host subject digests) | no |
| `notarize` | record the report's evidence Merkle root in the Rekor transparency log (hash-only; `--online` submits) | no |
| `watch` | scheduled probe rounds + auto-diff alerts (profile JSON, severity floor, webhook) — MVP daemon | yes |
| `dns` | same query to N resolvers — divergent answers = suspected spoofing (HIGH) | yes |
| `dhcp` | broadcast discover, classify every offer — rogue-server detection (`--known-server`) | yes |
| `plugins` | list discovered plugins (see below) | no |

## Temporal memory (history + diff)

Every network-truth run auto-persists to `~/.vtknet/history.db` (SQLite).
Dry-runs, `synth`, `inspect` and `report` never save. Relocate with the global
`--db PATH`, opt out with `--no-save`.

```bash
sudo vtk scan 10.0.0.5 --ports 1-1024 --type syn      # auto-saved
vtk report --list                                      # recent runs
vtk report --show 3                                    # full JSON of run #3
vtk report --diff 2 3                                  # added/removed/changed
vtk report --diff 4 :last                              # ':last' = newest run of the same command+target
```

Diffing keys findings by identity (`module|kind|host|port`) and ignores
volatile detail (timestamps, capture counters) — re-running the same scan
against the same target yields a clean, empty diff. A newly open port shows
up as `diff.added` (LOW); a changed TLS certificate as `diff.changed`.

## Plugins

A plugin is a `VtkPlugin` subclass that becomes its own subcommand and joins
the standard JSON/HTML reporting pipeline:

```python
# myplugin.py
from scapy.all import IP, TCP
from vtknet.plugins import VtkPlugin

class MyScan(VtkPlugin):
    name = "myscan"
    help = "scan whatever you want your way"

    def add_arguments(self, parser):
        parser.add_argument("target")

    def run(self, engine, args):
        answered, _ = engine.send_recv(
            [IP(dst=args.target) / TCP(dport=p, flags="S") for p in (80, 443)]
        )
        findings = [
            Finding(module="myscan", kind="port.open", host=args.target, port=s[TCP].dport)
            for s, r in answered if r.haslayer(TCP) and int(r[TCP].flags) & 0x12 == 0x12
        ]
        return findings, {"sent": 2}
```

```bash
vtk --plugin-dir . myscan 10.0.0.5 --json --report out.json   # local file plugins
# or ship as a pip package exposing the "vtknet.plugins" entry-point group
vtk plugins                                                   # list everything found
```

Plugins are deduped by name and can never shadow builtin commands. See
`examples/plugins/hello_ports.py` for a working copy-paste example.

## HTML reports

```bash
sudo vtk scan 10.0.0.5 --ports 1-1024 --html report.html
```

Self-contained single file (inline CSS, severity badges, evidence hex
truncated + escaped) — send it by email, it renders anywhere.

## Live lab (reproducible targets)

```bash
docker compose -f lab/docker-compose.yml up -d     # nginx + echo + self-signed TLS
sudo lab/verify.sh 172.20.0.10                     # full pipeline against the lab
python3 lab/tls_server.py                          # or bare-metal, no Docker
```

`lab/README.md` documents the loopback kernel-RST caveat for TLS probing.

## Usage

```bash
# ICMP host discovery on a CIDR
sudo vtk sweep 192.168.1.0/24
sudo vtk scan 10.0.0.5 --ports 1-1024 --type syn --rate 200 --json --report out.json

# TLS: version, cipher AND certificate health in one probe
sudo vtk tls example.com --sni example.com

# post-quantum compatibility: ClientHello offering X25519MLKEM768
# (add --force-fragment to pad it past the MTU — fragmented-CH test)
sudo vtk tls example.com --pq

# what does the service say first? (banner + evidence bytes)
sudo vtk banner 192.168.1.50 --port 22

# rehearse a sweep without sending anything, then review the exact bytes
vtk sweep 192.168.1.0/24 --dry-run --emit plan.pcap

# fuzz a lab device: same seed reproduces the crashing packet byte-for-byte
sudo vtk fuzz 192.168.1.50 --base tcp --port 8080 --count 200 --seed 1337

# wifi detection: live (monitor iface) or offline analysis of a capture
sudo vtk wifi --iface wlan0mon --known-ssid CorpNet --known-bssid aa:bb:cc:dd:ee:ff
vtk wifi --offline suspicious.pcap --deauth-threshold 5

# ARP MITM with guaranteed cleanup (lab only) — auto-restores after --duration
sudo vtk mitm --victim 192.168.1.50 --gateway 192.168.1.1 --duration 60

# detection engineering: generate → replay at wire speed → verify — reproducibly
vtk synth --list
vtk synth --scenario frag_evasion --pcap frags.pcap --count 8 --seed 1337
sudo vtk synth --scenario syn_flood --pcap floods.pcap --count 200 --replay eth0 --pps 1000

# read the evidence back — bytes to layers, both directions
vtk inspect --hex 4545000c000100004011f96bc0a800016322e34900350035
vtk pcap frags.pcap

# prove the report wasn't touched: sign it, then re-derive signature + every evidence hash
vtk keygen && vtk sign out.json
vtk verify out.json.dsse

# prove ONE finding to a third party without the rest of the report
vtk verify out.json --prove <finding-id>

# the network as desired-state: broken promise = exit 1 (CI gate)
vtk assert rules.json --against out.json

# who talked to us unasked?
vtk ledger --offline suspicious.pcap
```

Common flags (after the subcommand): `--json`, `--report FILE`, `--html FILE`,
`--dry-run`, `--rate`, `--jitter`, `--timeout`, `--retry`, `--iface`, `-v/-vv`.
Global: `--plugin-dir DIR` (before the subcommand).

## JSON report shape

```json
{
  "command": "tls",
  "duration_s": 0.4,
  "stats": {"sent": 3, "answered": 2},
  "findings": [
    {
      "module": "tlsprobe", "kind": "tls.serverhello", "host": "203.0.113.9", "port": 443,
      "state": "open", "severity": "info",
      "detail": {"version_int": "0x0303", "cipher": 49199},
      "evidence": [{"kind": "packet_hex", "data": "1603032c02...", "note": "server TLS record",
                    "sha256": "9a1f..."}]
    },
    {
      "module": "tlsprobe", "kind": "tls.cert.expired", "severity": "high",
      "detail": {"subject": "CN=old.example.com", "days_left": -12, "self_signed": false},
      "evidence": [{"kind": "certificate_der", "data": "3082...", "note": "X.509 certificate (DER)"}]
    }
  ]
}
```

## Layout

```
src/vtknet/
├── core/
│   ├── engine.py    # unified sr/srp/send wrapper: rate, jitter, retry, dry-run
│   ├── capture.py   # AsyncSniffer wrapper: ring buffer, offline mode, pcap I/O, reply correlation
│   ├── models.py    # Finding / Evidence / ScanResult — JSON-stable data model
│   ├── plugins.py   # VtkPlugin contract + entry-point/file discovery
│   └── report.py    # human summary + self-contained HTML reports
├── plugins.py       # public plugin API (from vtknet.plugins import VtkPlugin)
├── modules/
│   ├── recon.py     # ICMP sweep + ARP scan
│   ├── scanner.py   # SYN/NULL/FIN/XMAS/ACK TCP scan engine
│   ├── tlsprobe.py  # ClientHello builder + ServerHello/alert/certificate parsing
│   ├── quicprobe.py # RFC 9000 version-negotiation probe (crypto-free QUIC check)
│   ├── synthetic.py # 5 seeded IDS-test scenarios with JSON sidecars
│   ├── fuzz.py      # seeded boundary-value mutation + liveness crash detection
│   ├── wifi.py      # deauth/evil-twin/rogue-AP detectors (live + offline)
│   └── mitm.py      # ARP spoofer with guaranteed restore + ip_forward cleanup
├── utils/net.py     # CIDR expansion, port-spec parsing, host resolution
└── cli.py           # vtk sweep|arp|scan|tls|quic|sniff|synth|fuzz|wifi|mitm|plugins
lab/                 # docker-compose lab + bare-metal TLS target + verify.sh
examples/plugins/    # copy-paste plugin example
```

Adding a module = pure builder/parser functions (unit-testable offline) plus a
`run(engine, targets) -> (list[Finding], stats)` over the shared Engine.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

All 119 tests run offline: pure builders/parsers, dry-run engine, canned TLS
fixtures, duck-typed engines for live flows, real end-to-end runs (synthetic
trace → pcap → AsyncSniffer offline → detectors), plugin loading from
directories, and HTML report rendering. CI needs no root and no hardware.

## Roadmap

- Ideas for later: QUIC Initial crypto probing, IPv6 modules, async engine,
  a `vtk report --merge` for combining runs.

## Authorized use only

Run it against networks and hosts you own or are explicitly authorized to test.
