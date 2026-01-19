#!/usr/bin/env python3
"""Simple reverse shell detector for Linux systems."""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SHELL_NAMES = {
    "bash",
    "sh",
    "zsh",
    "ksh",
    "dash",
    "ash",
    "tcsh",
    "csh",
    "fish",
}

SUSPICIOUS_COMMANDS = {
    "bash",
    "sh",
    "zsh",
    "ksh",
    "dash",
    "ash",
    "tcsh",
    "csh",
    "fish",
    "busybox",
    "nc",
    "netcat",
    "ncat",
    "socat",
    "telnet",
    "python",
    "python3",
    "perl",
    "php",
    "ruby",
    "irb",
    "node",
    "nodejs",
    "java",
    "lua",
    "go",
    "openssl",
}


@dataclass(frozen=True)
class Connection:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    inode: str


@dataclass(frozen=True)
class Finding:
    pid: int
    process_name: str
    cmdline: str
    connection: Connection


def parse_proc_net(path: Path, protocol: str) -> list[Connection]:
    connections: list[Connection] = []
    if not path.exists():
        return connections

    for line in path.read_text().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local_hex, remote_hex, state, inode = parts[1], parts[2], parts[3], parts[9]
        if protocol == "tcp" and state != "01":
            continue
        local_ip, local_port = decode_address(local_hex)
        remote_ip, remote_port = decode_address(remote_hex)
        if protocol == "udp" and remote_port == 0:
            continue
        connections.append(
            Connection(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                inode=inode,
            )
        )
    return connections


def decode_address(hex_value: str) -> tuple[str, int]:
    address, port = hex_value.split(":")
    ip = decode_ip(address)
    return ip, int(port, 16)


def decode_ip(address: str) -> str:
    if len(address) == 8:
        return socket.inet_ntoa(bytes.fromhex(address)[::-1])
    if len(address) == 32:
        raw = bytes.fromhex(address)
        reordered = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        return str(ipaddress.IPv6Address(reordered))
    return "0.0.0.0"


def is_suspicious_remote(ip: str, allow_private: bool) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if ip_obj.is_loopback or ip_obj.is_link_local:
        return False
    if ip_obj.is_private:
        return allow_private
    return True


def build_inode_map() -> dict[str, list[int]]:
    inode_to_pids: dict[str, list[int]] = {}
    for proc_entry in Path("/proc").iterdir():
        if not proc_entry.is_dir():
            continue
        if not proc_entry.name.isdigit():
            continue
        pid = int(proc_entry.name)
        fd_dir = proc_entry / "fd"
        if not fd_dir.exists():
            continue
        for fd_entry in fd_dir.iterdir():
            try:
                target = os.readlink(fd_entry)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inode = target.removeprefix("socket:[").removesuffix("]")
                inode_to_pids.setdefault(inode, []).append(pid)
    return inode_to_pids


def read_cmdline(pid: int) -> str:
    try:
        data = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return ""
    return " ".join(segment for segment in data.decode(errors="ignore").split("\x00") if segment)


def read_comm(pid: int) -> str:
    try:
        return (Path("/proc") / str(pid) / "comm").read_text().strip()
    except OSError:
        return ""


def find_reverse_shells(
    connections: Iterable[Connection],
    inode_map: dict[str, list[int]],
    allow_private: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    for conn in connections:
        if not is_suspicious_remote(conn.remote_ip, allow_private):
            continue
        for pid in inode_map.get(conn.inode, []):
            comm = read_comm(pid)
            cmdline = read_cmdline(pid)
            if is_suspicious_process(comm, cmdline):
                findings.append(
                    Finding(
                        pid=pid,
                        process_name=comm,
                        cmdline=cmdline,
                        connection=conn,
                    )
                )
    return findings


def is_suspicious_process(comm: str, cmdline: str) -> bool:
    comm_lower = comm.lower()
    cmd_lower = cmdline.lower()
    if comm_lower in SHELL_NAMES or comm_lower in SUSPICIOUS_COMMANDS:
        return True
    return any(token in cmd_lower for token in SUSPICIOUS_COMMANDS) or any(
        marker in cmd_lower for marker in ("/dev/tcp", "/dev/udp", "mkfifo")
    )


def format_finding(finding: Finding) -> str:
    conn = finding.connection
    return (
        f"PID {finding.pid} ({finding.process_name}) -> "
        f"{conn.remote_ip}:{conn.remote_port} "
        f"from {conn.local_ip}:{conn.local_port} "
        f"cmdline=\"{finding.cmdline}\""
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect likely reverse shells on Linux")
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="flag private remote IPs as suspicious",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    connections: list[Connection] = []
    connections.extend(parse_proc_net(Path("/proc/net/tcp"), "tcp"))
    connections.extend(parse_proc_net(Path("/proc/net/tcp6"), "tcp"))
    connections.extend(parse_proc_net(Path("/proc/net/udp"), "udp"))
    connections.extend(parse_proc_net(Path("/proc/net/udp6"), "udp"))
    inode_map = build_inode_map()
    findings = find_reverse_shells(connections, inode_map, args.include_private)

    if not findings:
        print("No reverse shell candidates found.")
        return 0

    print("Potential reverse shell sessions:")
    for finding in findings:
        print(format_finding(finding))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
