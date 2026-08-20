"""Optional NVIDIA NIM integration.

The tool is fully **independent** — NIM is never required. When enabled, NIM is
used only to *suggest* strategy parameters (which tool, burst size, timing) for
the adaptive loop.

Anti-hallucination contract (enforced in :mod:`handshaker.nim.client`):

* NIM output is treated as an untrusted *suggestion*, validated against a strict
  schema and clamped to the set of actions the installed tools can actually do.
* NIM is NEVER consulted for verification — handshake verification is always
  the deterministic tshark/aircrack/hcxpcapngtool pipeline.
* All facts given to NIM (BSSID, channel, clients) come from the live scan.
"""
