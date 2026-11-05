# Security Policy — vtknet

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x   | ✅ |
| < 0.4   | ❌ |

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Email **ntgi46@proton.me** with:

1. Affected version and command (`vtk scan`, `vtk tls`, …).
2. Reproduction steps or a minimal script/pcap.
3. Expected vs actual behaviour, and (if applicable) the finding/JSON output.

You will receive an acknowledgement within **72 hours**, and a fix or a
documented mitigation target within **14 days** for confirmed
vulnerabilities. Credit is given in the release notes unless you prefer
to stay anonymous.

## Scope

In scope: the `vtknet` package itself — command surface, engine, parsing
of network responses (TLS/QUIC/802.11/ARP), report rendering, plugin
loading, and anything that could turn a *test* into an unintended action.

Out of scope: vulnerabilities in Scapy, Python, or the OS packet stack;
the `lab/` targets (they are intentionally vulnerable by design).

## Responsible use

`vtknet` is an **authorized-testing** toolkit: raw-socket commands assume
you own the target network or have explicit written permission. The
maintainers ship detection and evidence tooling — scanning hosts you do
not control is your responsibility, not ours.
