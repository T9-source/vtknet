"""Example vtknet plugin: a minimal SYN probe over a fixed port list.

Copy this into a directory and run:
    vtk --plugin-dir /path/to/dir hello-ports 127.0.0.1
"""

from scapy.all import IP, TCP

from vtknet.core.engine import Engine
from vtknet.core.models import Finding
from vtknet.plugins import VtkPlugin

PORTS = (80, 443, 8080)


class HelloPorts(VtkPlugin):
    name = "hello-ports"
    help = "example plugin: SYN-probe a fixed port list and report open ports"

    def add_arguments(self, parser):
        parser.add_argument("target", help="single host to probe")
        parser.add_argument("--note", default="", help="free-text note stored in findings")

    def run(self, engine: Engine, args) -> tuple[list[Finding], dict[str, int]]:
        probes = [IP(dst=args.target) / TCP(dport=p, flags="S") for p in PORTS]
        answered, _unanswered = engine.send_recv(probes)
        findings = [
            Finding(
                module="hello-ports",
                kind="port.open",
                host=args.target,
                port=sent[TCP].dport,
                detail={"note": args.note} if args.note else {},
            )
            for sent, reply in answered
            if reply.haslayer(TCP) and int(reply[TCP].flags) & 0x12 == 0x12
        ]
        return findings, {"sent": len(probes)}
