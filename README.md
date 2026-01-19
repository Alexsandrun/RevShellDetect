# RevShellDetect

Simple Linux-focused reverse shell detector. It scans active TCP/UDP connections
and reports processes running common shells or interpreter/tooling binaries that
have outbound connections to suspicious remote addresses. Both IPv4 and IPv6 are
covered when available in `/proc/net`.

## Usage

```bash
python3 rev_shell_detect.py
```

To treat private (RFC1918) addresses as suspicious too:

```bash
python3 rev_shell_detect.py --include-private
```

## Notes

- Requires access to `/proc` (typical on Linux).
- Looks for outbound TCP sessions in `ESTABLISHED` state and UDP sockets that
  have a remote endpoint, associated with common shell processes or common
  reverse-shell tooling.
