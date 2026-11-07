"""Command-line interface: ``vtk sweep|arp|scan|tls|quic|sniff|synth|fuzz|wifi|mitm|plugins``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

import vtknet
from vtknet.core import inspect as inspect_mod
from vtknet.core import plugins as plugins_mod
from vtknet.core import report
from vtknet.core.capture import Capture, CaptureConfig
from vtknet.core.engine import Engine, EngineConfig
from vtknet.core.models import Finding, ScanResult, Severity
from vtknet.core.store import DEFAULT_DB, History
from vtknet.modules import (
    dhcpprobe,
    dnsprobe,
    fuzz,
    mitm,
    quicprobe,
    recon,
    scanner,
    synthetic,
    tlsprobe,
    wifi,
)
from vtknet.utils import net

log = logging.getLogger("vtknet.cli")

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2

# commands whose findings are network truth worth persisting
AUTO_SAVE_COMMANDS = {
    "sweep",
    "arp",
    "scan",
    "tls",
    "quic",
    "sniff",
    "fuzz",
    "wifi",
    "mitm",
    "pcap",
    "dns",
    "dhcp",
}

BUILTIN_COMMANDS = {
    "sweep",
    "arp",
    "scan",
    "tls",
    "quic",
    "sniff",
    "synth",
    "fuzz",
    "wifi",
    "mitm",
    "inspect",
    "pcap",
    "report",
    "dns",
    "dhcp",
    "plugins",
}


def _plugin_dirs_from_argv(argv: list[str] | None) -> list[str]:
    """Pre-scan argv for --plugin-dir (needed before plugins can register subcommands)."""
    argv = list(argv or [])
    dirs: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--plugin-dir" and i + 1 < len(argv):
            dirs.append(argv[i + 1])
            i += 2
        elif a.startswith("--plugin-dir="):
            dirs.append(a.split("=", 1)[1])
            i += 1
        else:
            i += 1
    return dirs


def build_parser(plugin_dirs: list[str] | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vtk",
        description="Evidence-driven network testing toolkit (Scapy-based). "
        "Run only against networks you are authorized to test.",
    )
    parser.add_argument("--version", action="version", version=f"vtk {vtknet.__version__}")
    parser.add_argument(
        "--plugin-dir",
        action="append",
        default=None,
        metavar="DIR",
        help="load local plugins (*.py VtkPlugin classes) from DIR (repeatable)",
    )
    parser.add_argument(
        "--db", default=None, metavar="FILE", help=f"history database path (default: {DEFAULT_DB})"
    )
    parser.add_argument(
        "--no-save", action="store_true", help="do not persist this run to the history database"
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--iface", default=None, help="network interface (default: scapy conf.iface)")
    common.add_argument("--timeout", type=float, default=2.0, help="reply timeout in seconds")
    common.add_argument("--retry", type=int, default=1, help="retransmission rounds for unanswered probes")
    common.add_argument("--rate", type=float, default=100.0, help="packets per second (0 = unlimited)")
    common.add_argument(
        "--workers",
        type=int,
        default=1,
        help="parallel sr() workers over batches — rate is the TOTAL across workers",
    )
    common.add_argument("--jitter", type=float, default=0.0, help="random extra delay per batch, seconds")
    common.add_argument("--json", action="store_true", help="emit machine-readable JSON report")
    common.add_argument("--report", metavar="FILE", help="also write the JSON report to FILE")
    common.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report to FILE")
    common.add_argument("--dry-run", action="store_true", help="build packets without sending anything")
    common.add_argument("-v", "--verbose", action="count", default=0, help="verbose logging (-v, -vv)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_sweep = sub.add_parser("sweep", parents=[common], help="ICMP host discovery on a CIDR or host")
    p_sweep.add_argument("target", help="CIDR (e.g. 10.0.0.0/24) or a single host")

    p_arp = sub.add_parser("arp", parents=[common], help="ARP discovery of the local segment")
    p_arp.add_argument("target", help="CIDR of the local segment (e.g. 192.168.1.0/24)")

    p_scan = sub.add_parser("scan", parents=[common], help="TCP scan of a single host")
    p_scan.add_argument("target", help="IP or hostname (single host, not a CIDR)")
    p_scan.add_argument("--ports", default="1-1024", help="port spec: 80 | 80,443 | 1-1024")
    p_scan.add_argument(
        "--type", dest="scan_type", default="syn", choices=[t.value for t in scanner.ScanType]
    )

    p_tls = sub.add_parser("tls", parents=[common], help="TLS ServerHello fingerprint via raw handshake")
    p_tls.add_argument("target", help="IP or hostname (single host)")
    p_tls.add_argument("--port", type=int, default=443, help="TLS port (default 443)")
    p_tls.add_argument("--sni", default=None, help="SNI hostname (default: the target)")

    p_quic = sub.add_parser(
        "quic", parents=[common], help="QUIC reachability via RFC 9000 version negotiation"
    )
    p_quic.add_argument("target", help="IP or hostname (single host)")
    p_quic.add_argument("--port", type=int, default=443, help="QUIC/UDP port (default 443)")

    p_sniff = sub.add_parser("sniff", parents=[common], help="capture packets live (root) or read a pcap offline")
    p_sniff.add_argument(
        "--offline", metavar="PCAP", help="read from a pcap file instead of the wire (no root needed)"
    )
    p_sniff.add_argument("--filter", dest="bpf", default=None, help="BPF filter (needs libpcap)")
    p_sniff.add_argument("--count", type=int, default=50, help="stop after N packets (default 50)")
    p_sniff.add_argument("--out", metavar="PCAP", help="write captured packets to a pcap file")

    p_synth = sub.add_parser(
        "synth", parents=[common], help="generate seeded synthetic attack traces (pcap) for IDS/rule testing"
    )
    p_synth.add_argument("--scenario", help="scenario name (see --list)")
    p_synth.add_argument("--pcap", metavar="FILE", help="output .pcap path")
    p_synth.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducible traces")
    p_synth.add_argument("--count", type=int, default=50, help="packets/events per scenario")
    p_synth.add_argument("--target", default="192.0.2.9", help="address the scenario points at")
    p_synth.add_argument("--domain", default=None, help="base domain for dns_tunnel scenario")
    p_synth.add_argument(
        "--replay", metavar="IFACE", help="replay the generated pcap on IFACE via tcpreplay (root)"
    )
    p_synth.add_argument("--pps", type=int, default=None, help="packets per second for replay")
    p_synth.add_argument("--list", action="store_true", help="list available scenarios and exit")

    p_inspect = sub.add_parser(
        "inspect", parents=[common], help="decode evidence hex / pcap bytes back into layers (offline)"
    )
    p_inspect.add_argument("--hex", dest="hex_data", default=None, help="hex string of the frame")
    p_inspect.add_argument("--file", default=None, help="file containing hex text (or raw bytes)")
    p_inspect.add_argument("--pcap", default=None, help="decode the first packet of a pcap file")

    p_pcap = sub.add_parser(
        "pcap", parents=[common], help="streaming pcap statistics without loading the file (offline)"
    )
    p_pcap.add_argument("pcap_file", help="pcap file to summarize")

    p_report = sub.add_parser(
        "report", parents=[common], help="query the run history: list, show, or diff two runs (offline)"
    )
    p_report.add_argument("--list", action="store_true", help="list recent runs")
    p_report.add_argument("--show", metavar="RUN_ID", type=int, help="print the full JSON of a run")
    p_report.add_argument(
        "--diff", metavar=("RUN_A", "RUN_B"), nargs=2, type=int, help="added/removed/changed between runs"
    )

    p_dns = sub.add_parser(
        "dns", parents=[common], help="ask several resolvers the same question — divergence = suspected spoofing"
    )
    p_dns.add_argument("name", help="domain name to resolve")
    p_dns.add_argument(
        "--resolvers", default=",".join(dnsprobe.DEFAULT_RESOLVERS), help="comma-separated resolver IPs"
    )
    p_dns.add_argument("--qtype", default="A", help="record type: A | AAAA | PTR | TXT (default A)")

    p_dhcp = sub.add_parser(
        "dhcp", parents=[common], help="broadcast a discover and classify every offer — rogue-server detection"
    )
    p_dhcp.add_argument("--known-server", default=None, help="the trusted DHCP server IP (any other offer = rogue)")

    p_fuzz = sub.add_parser(
        "fuzz", parents=[common], help="seeded protocol fuzzer with liveness crash detection"
    )
    p_fuzz.add_argument("target", help="IP or hostname (single host)")
    p_fuzz.add_argument("--count", type=int, default=20, help="mutant packets to send")
    p_fuzz.add_argument("--base", default="tcp", choices=fuzz.BASES, help="base packet to mutate")
    p_fuzz.add_argument("--port", type=int, default=None, help="destination port for tcp/udp bases")
    p_fuzz.add_argument("--seed", type=int, default=1337, help="RNG seed (same seed = same mutants)")

    p_wifi = sub.add_parser(
        "wifi",
        parents=[common],
        help="802.11 detection: deauth storms, evil twins, rogue APs (monitor iface or --offline)",
    )
    p_wifi.add_argument(
        "--offline", metavar="PCAP", help="analyze a captured wifi pcap instead (no root/hardware)"
    )
    p_wifi.add_argument("--known-ssid", default=None, help="legit SSID for rogue-AP detection")
    p_wifi.add_argument(
        "--known-bssid", action="append", default=None, help="legit BSSID (repeatable)"
    )
    p_wifi.add_argument(
        "--deauth-threshold", type=int, default=3, help="deauth frames per sender to trigger a storm finding"
    )

    p_mitm = sub.add_parser(
        "mitm",
        parents=[common],
        help="ARP poisoning with automatic restore on exit (authorized labs only)",
    )
    p_mitm.add_argument("--victim", required=True, help="victim IP (same L2 segment)")
    p_mitm.add_argument("--gateway", required=True, help="gateway IP (same L2 segment)")
    p_mitm.add_argument("--duration", type=float, default=30.0, help="seconds to poison before auto-restore")
    p_mitm.add_argument("--interval", type=float, default=2.0, help="poison refresh interval")
    p_mitm.add_argument("--no-forward", action="store_true", help="do not touch ip_forward")

    sub.add_parser("plugins", parents=[common], help="list discovered plugins")

    found = plugins_mod.discover(plugin_dirs)
    if found:
        plugins_mod.register_subcommands(sub, common, found, BUILTIN_COMMANDS)
        log.debug("plugins registered as subcommands: %s", [p.name for p in found])
    return parser


def _needs_raw_sockets(args: argparse.Namespace) -> bool:
    """Commands that touch raw sockets (offline modes and synth need no privileges)."""
    if args.command in ("inspect", "pcap", "plugins", "report"):
        return False
    if args.command == "synth":
        return bool(getattr(args, "replay", None))  # tcpreplay sends on a real iface
    if args.command in ("sniff", "wifi"):
        return args.offline is None
    return True  # builtins and plugins may send raw packets; warn conservatively


def _warn_privileges(args: argparse.Namespace) -> None:
    if args.dry_run or not _needs_raw_sockets(args):
        return
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        log.warning("raw sockets normally require root; if you get permission errors, re-run with sudo")


def _run_tls(args: argparse.Namespace, engine: Engine, result: ScanResult) -> None:
    if len(args.target.split(",")) > 1:
        raise ValueError("tls expects a single host")
    dst = net.resolve_host(args.target)
    if dst != args.target:
        log.info("resolved %s -> %s", args.target, dst)
    findings, stats = tlsprobe.tls_probe(engine, dst, port=args.port, sni=args.sni)
    result.findings, result.stats = findings, stats


def _run_sniff(args: argparse.Namespace, result: ScanResult) -> None:
    if args.dry_run:
        log.info(
            "dry-run: would capture %s with filter=%r, stopping after %d packets",
            args.offline or args.iface or "default interface",
            args.bpf,
            args.count,
        )
        result.stats = {"received": 0, "kept": 0}
        return
    cfg = CaptureConfig(
        offline=args.offline,
        iface=args.iface,
        filter_bpf=args.bpf,
        count=args.count,
        timeout=args.timeout,
        stream_to=args.out,  # stream to pcap while capturing — never OOM on long runs
    )
    cap = Capture(cfg)
    cap.start()
    cap.wait(timeout=max(args.timeout, 15.0) + 5.0)
    cap.stop()
    st = cap.stats()
    result.findings = [
        Finding(
            module="capture",
            kind="capture.done",
            host=args.offline or args.iface or "default-iface",
            detail={
                "offline": bool(args.offline),
                "bpf": args.bpf or "",
                "pcap_written": args.out or "",
                **st,
            },
        )
    ]
    result.stats = {"received": st["received"], "kept": st["kept"]}


def _run_synth(args: argparse.Namespace, result: ScanResult) -> None:
    if args.list:
        names = synthetic.list_scenarios()
        print("available scenarios: " + ", ".join(names))
        result.stats = {"scenarios": len(names)}
        return
    if not args.scenario:
        raise ValueError("synth requires --scenario (or --list)")
    if not args.pcap:
        raise ValueError("synth requires --pcap FILE for the output trace")
    params: dict = {"seed": args.seed, "count": args.count, "target": args.target}
    if args.domain:
        params["base_domain"] = args.domain
    meta = synthetic.write_trace(args.scenario, args.pcap, **params)
    result.findings = [
        Finding(
            module="synthetic",
            kind="trace.written",
            host="-",
            detail={
                "scenario": meta.name,
                "description": meta.description,
                "packets": meta.count,
                "pcap": args.pcap,
                "iocs": meta.iocs,
                "seed": args.seed,
            },
        )
    ]
    result.stats = {"written": meta.count}
    if args.replay:
        if args.dry_run:
            log.info(
                "dry-run: would replay %s on %s via tcpreplay (pps=%s)",
                args.pcap,
                args.replay,
                args.pps,
            )
            return
        log.info("replaying %s on %s via tcpreplay", args.pcap, args.replay)
        n = synthetic.replay_trace(args.pcap, args.replay, pps=args.pps)
        result.findings.append(
            Finding(module="synthetic", kind="trace.replayed", host="-",
                    detail={"pcap": args.pcap, "iface": args.replay, "packets": n, "pps": args.pps})
        )
        result.stats["replayed"] = n


def _run_inspect(args: argparse.Namespace, result: ScanResult) -> None:
    sources = sum(bool(x) for x in (args.hex_data, args.file, args.pcap))
    if sources != 1:
        raise ValueError("inspect needs exactly one of --hex / --file / --pcap")
    if args.hex_data:
        data = inspect_mod.parse_evidence(args.hex_data)
    elif args.file:
        with open(args.file, "rb") as fh:
            raw = fh.read()
        try:
            data = inspect_mod.parse_evidence(raw.decode("ascii", errors="ignore"))
        except ValueError:
            data = raw  # not hex text — treat as raw wire bytes
    else:
        first = next(iter(vtknet_capture_iter(args.pcap)), None)
        if first is None:
            raise ValueError(f"pcap contains no packets: {args.pcap}")
        data = bytes(first)

    pkt = inspect_mod.decode_bytes(data)
    show_text = pkt.show(dump=True)
    command = pkt.command()
    layers = [l.__name__ for l in pkt.layers()]
    result.findings = [
        Finding(
            module="inspect",
            kind="inspect.done",
            host="-",
            detail={
                "length": len(data),
                "layers": layers,
                "summary": pkt.summary(),
                "command": command,
                "show": show_text,
            },
        )
    ]
    result.stats = {"decoded": len(data)}
    if not args.json:
        print(show_text)
        print("command:", command)


def vtknet_capture_iter(path: str):
    from vtknet.core.capture import iter_pcap

    return iter_pcap(path)


def _run_pcap(args: argparse.Namespace, result: ScanResult) -> None:
    summary = inspect_mod.pcap_summary(args.pcap_file)
    result.findings = [
        Finding(
            module="inspect",
            kind="pcap.summary",
            host=args.pcap_file,
            detail=summary,
        )
    ]
    result.stats = {"packets": summary["packets"]}


def _run_report(args: argparse.Namespace, result: ScanResult) -> None:
    history = History(args.db or DEFAULT_DB)
    try:
        if args.show is not None:
            run = history.get_run(args.show)
            if run is None:
                raise ValueError(f"unknown run id: {args.show}")
            if args.json:
                result.findings = [
                    Finding(module="report", kind="run.show", host=f"run-{run['id']}", detail=run)
                ]
            else:
                print(json.dumps(run, indent=2, ensure_ascii=False))
            result.stats = {"findings": len(run["findings"])}
            return
        if args.diff is not None:
            run_a, run_b = args.diff
            d = history.diff(run_a, run_b)
            result.findings = [
                Finding(
                    module="report",
                    kind=f"diff.{category}",
                    host=item["host"],
                    port=item["port"],
                    severity=(
                        Severity.LOW
                        if category == "added" and item["kind"] == "port.open"
                        else Severity.INFO
                    ),
                    detail=item,
                )
                for category in ("added", "removed", "changed")
                for item in d[category]
            ]
            result.stats = {
                "added": len(d["added"]),
                "removed": len(d["removed"]),
                "changed": len(d["changed"]),
            }
            return
        # default / --list
        runs = history.list_runs()
        if not args.json:
            print(f"{'id':>4}  {'command':<10} {'findings':>8}  started")
            for r in runs:
                print(f"{r['id']:>4}  {r['command']:<10} {r['findings']:>8}  {r['started']}")
        result.stats = {"runs": len(runs)}
    finally:
        history.close()


def _run_dns(args: argparse.Namespace, engine: Engine, result: ScanResult) -> None:
    resolvers = [r.strip() for r in args.resolvers.split(",") if r.strip()]
    if len(resolvers) < 2:
        raise ValueError("dns needs at least 2 resolvers to compare (use --resolvers a,b,c)")
    result.findings, result.stats = dnsprobe.dns_probe(engine, args.name, resolvers, args.qtype)


def _run_dhcp(args: argparse.Namespace, engine: Engine, result: ScanResult) -> None:
    result.findings, result.stats = dhcpprobe.dhcp_probe(engine, known_server=args.known_server)


def _run_fuzz(args: argparse.Namespace, engine: Engine, result: ScanResult) -> None:
    if len(args.target.split(",")) > 1:
        raise ValueError("fuzz expects a single host")
    dst = net.resolve_host(args.target)
    if dst != args.target:
        log.info("resolved %s -> %s", args.target, dst)
    result.findings, result.stats = fuzz.fuzz_target(
        engine, dst, count=args.count, base=args.base, port=args.port, seed=args.seed
    )


def _run_wifi(args: argparse.Namespace, result: ScanResult) -> None:
    if args.dry_run:
        log.info(
            "dry-run: would analyze %s for deauth storms / evil twins / rogue APs "
            "(known_ssid=%r, threshold=%d)",
            args.offline or args.iface or "monitor interface",
            args.known_ssid,
            args.deauth_threshold,
        )
        result.stats = {"frames": 0}
        return
    kwargs = {
        "known_ssid": args.known_ssid,
        "known_bssids": args.known_bssid,
        "deauth_threshold": args.deauth_threshold,
    }
    if args.offline:
        findings, stats = wifi.analyze_offline(args.offline, **kwargs)
    else:
        findings, stats = wifi.monitor(
            args.iface or conf_iface(), timeout=args.timeout, **kwargs
        )
    result.findings = findings
    result.stats = {k: v for k, v in stats.items() if isinstance(v, int)}
    result.args["frames_total"] = stats.get("frames", 0)


def _run_mitm(args: argparse.Namespace, engine: Engine, result: ScanResult) -> None:
    spoof = mitm.ArpSpoofer(
        engine,
        args.victim,
        args.gateway,
        interval=args.interval,
        manage_forward=not args.no_forward,
    )
    spoof.start()  # dry-run: logs the plan and returns; live: resolves MACs
    if engine.cfg.dry_run:
        result.findings = [
            Finding(
                module="mitm",
                kind="mitm.planned",
                host=args.victim,
                detail={
                    "gateway": args.gateway,
                    "duration_s": args.duration,
                    "interval_s": args.interval,
                    "manage_forward": not args.no_forward,
                },
            )
        ]
        result.stats = {"poisons_sent": 0, "restores_sent": 0}
        return
    try:
        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            time.sleep(min(0.5, max(args.duration, 0.1)))
    except KeyboardInterrupt:
        log.info("interrupted — restoring ARP caches")
    finally:
        st = spoof.stop()
    result.findings = [
        Finding(
            module="mitm",
            kind="mitm.session",
            host=args.victim,
            severity=Severity.MEDIUM,
            detail={
                "gateway": args.gateway,
                "victim_mac": st["victim_mac"],
                "gateway_mac": st["gateway_mac"],
                "duration_s": args.duration,
                "forward_restored": st["forward_restored"],
            },
        )
    ]
    result.stats = {"poisons_sent": st["poisons_sent"], "restores_sent": st["restores_sent"]}


def conf_iface() -> str:
    from scapy.all import conf

    return str(conf.iface)


def _run_quic(args: argparse.Namespace, engine: Engine, result: ScanResult) -> None:
    if len(args.target.split(",")) > 1:
        raise ValueError("quic expects a single host")
    dst = net.resolve_host(args.target)
    if dst != args.target:
        log.info("resolved %s -> %s", args.target, dst)
    result.findings, result.stats = quicprobe.quic_probe(engine, dst, port=args.port)


def _run_plugins(args: argparse.Namespace, result: ScanResult) -> None:
    # same filter as register_subcommands: builtin names always win
    found = [pl for pl in plugins_mod.discover(args.plugin_dir) if pl.name not in BUILTIN_COMMANDS]
    for pl in found:
        print(f"  {pl.name:<16} {pl.help}")
    if not found:
        print("  (no plugins found — use --plugin-dir DIR or install vtknet.plugins entry points)")
    result.stats = {"plugins": len(found)}


def _run(args: argparse.Namespace) -> ScanResult:
    cfg = EngineConfig(
        iface=args.iface,
        timeout=args.timeout,
        retry=args.retry,
        rate=args.rate,
        jitter=args.jitter,
        workers=max(1, args.workers),
        dry_run=args.dry_run,
    )
    engine = Engine(cfg)
    result = ScanResult(command=args.command, args=vars(args))
    started = time.monotonic()

    external = getattr(args, "_plugin", None)
    if external is not None:
        result.findings, result.stats = external.run(engine, args)
        result.finish(time.monotonic() - started)
        return result

    if args.command in ("sweep", "arp", "scan"):
        hosts = net.expand_hosts(args.target)
        if args.command == "sweep":
            result.findings, result.stats = recon.ping_sweep(engine, hosts)
        elif args.command == "arp":
            result.findings, result.stats = recon.arp_scan(engine, hosts)
        else:
            if len(hosts) != 1:
                raise ValueError("scan expects a single host (IP or hostname), not a CIDR")
            dst = net.resolve_host(hosts[0])
            if dst != hosts[0]:
                log.info("resolved %s -> %s", hosts[0], dst)
            ports = net.parse_ports(args.ports)
            if len(ports) > 5000:
                log.warning("large port list (%d ports) — consider tuning --rate/--timeout", len(ports))
            result.findings, result.stats = scanner.tcp_scan(
                engine, dst, ports, scanner.ScanType(args.scan_type)
            )
    elif args.command == "tls":
        _run_tls(args, engine, result)
    elif args.command == "quic":
        _run_quic(args, engine, result)
    elif args.command == "plugins":
        _run_plugins(args, result)
    elif args.command == "sniff":
        _run_sniff(args, result)
    elif args.command == "synth":
        _run_synth(args, result)
    elif args.command == "fuzz":
        _run_fuzz(args, engine, result)
    elif args.command == "wifi":
        _run_wifi(args, result)
    elif args.command == "mitm":
        _run_mitm(args, engine, result)
    elif args.command == "inspect":
        _run_inspect(args, result)
    elif args.command == "pcap":
        _run_pcap(args, result)
    elif args.command == "report":
        _run_report(args, result)
    elif args.command == "dns":
        _run_dns(args, engine, result)
    elif args.command == "dhcp":
        _run_dhcp(args, engine, result)
    else:  # pragma: no cover — argparse enforces choices
        raise ValueError(f"unknown command: {args.command}")
    result.finish(time.monotonic() - started)
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser(_plugin_dirs_from_argv(argv)).parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose >= 2 else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    _warn_privileges(args)
    try:
        result = _run(args)
    except ValueError as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except RuntimeError as exc:
        log.error("%s", exc)
        return EXIT_RUNTIME
    except KeyboardInterrupt:
        log.error("interrupted by user")
        return EXIT_RUNTIME

    # temporal memory: persist every network-truth run (never dry-runs/synth/inspect)
    if not args.no_save and not args.dry_run and args.command in AUTO_SAVE_COMMANDS:
        try:
            History(args.db or DEFAULT_DB).save_result(result)
        except Exception as exc:  # noqa: BLE001 — history failure must not kill the run
            log.warning("history save failed: %s", exc)

    if args.report:
        try:
            result.save(args.report)
            log.info("JSON report written to %s", args.report)
        except OSError as exc:
            log.error("cannot write report: %s", exc)
            return EXIT_RUNTIME
    if args.html:
        try:
            report.write_html(result, args.html)
        except OSError as exc:
            log.error("cannot write HTML report: %s", exc)
            return EXIT_RUNTIME

    if args.json:
        print(result.to_json())
    else:
        report.print_summary(result)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
