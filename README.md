# RevShellDetect

Simple Linux-focused reverse shell detector. It scans active TCP connections and
reports processes running common shells that have outbound connections to
suspicious remote addresses.

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
- Looks for outbound TCP sessions in `ESTABLISHED` state associated with common
  shell processes.
