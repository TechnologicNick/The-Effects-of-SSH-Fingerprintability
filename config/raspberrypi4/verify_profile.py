#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import paramiko


SCRIPT_DIR = Path(__file__).resolve().parent
NOTES_PATH = SCRIPT_DIR / "notes.md"
VERIFICATION_HEADER = "## Verification"
HEADING_RE = re.compile(r"^##\s+")
BULLET_RE = re.compile(r"^- `(?P<command>.+)`$")
ANSI_ESCAPE_RE = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
PROMPT_RE = re.compile(r"^[^\s@]+@[^\s:]+:.*[$#]\s*$")
PROMPT_SUFFIX_RE = re.compile(r"[^\s@]+@[^\s:]+:.*[$#]\s*$")
VOLATILE_STATUS_KEYS = {
    "Tgid",
    "Pid",
    "PPid",
    "NStgid",
    "NSpid",
    "NSpgid",
    "NSsid",
    "VmPeak",
    "VmSize",
    "VmLck",
    "VmPin",
    "VmHWM",
    "VmRSS",
    "RssAnon",
    "RssFile",
    "RssShmem",
    "VmData",
    "VmStk",
    "VmExe",
    "VmLib",
    "VmPTE",
    "VmSwap",
    "voluntary_ctxt_switches",
    "nonvoluntary_ctxt_switches",
}
ATTACKER_SYNTAX_PROBE = (
    'if [ -r /proc/cpuinfo ] && [ -r /proc/meminfo ] && grep -q "model name" '
    '/proc/cpuinfo 2>/dev/null && grep -q "MemTotal" /proc/meminfo 2>/dev/null; '
    'then; echo "valid"; else; echo "honeypot"; fi'
)


@dataclass
class Target:
    label: str
    destination: str
    port: int | None
    auth_mode: str


@dataclass
class CommandResult:
    returncode: int | None
    output: bytes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run every verification command listed in notes.md against the real Pi "
            "and the local honeypot, then compare the outputs."
        )
    )
    parser.add_argument(
        "--real-target",
        default="pi",
        help="SSH destination for the real Raspberry Pi. Default: %(default)s",
    )
    parser.add_argument(
        "--honeypot-target",
        default="pi@localhost",
        help="SSH destination for the honeypot. Default: %(default)s",
    )
    parser.add_argument(
        "--honeypot-port",
        type=int,
        default=2222,
        help="SSH port for the honeypot. Default: %(default)s",
    )
    parser.add_argument(
        "--real-port",
        type=int,
        default=None,
        help="Optional SSH port override for the real Raspberry Pi.",
    )
    parser.add_argument(
        "--real-auth-mode",
        choices=("default", "none"),
        default="default",
        help="Authentication mode for the real Pi target. Default: %(default)s",
    )
    parser.add_argument(
        "--honeypot-auth-mode",
        choices=("default", "none"),
        default="none",
        help="Authentication mode for the honeypot target. Default: %(default)s",
    )
    parser.add_argument(
        "--honeypot-password",
        default="verification",
        help="Password used for honeypot SSH verification. Default: %(default)s",
    )
    return parser.parse_args()


def extract_verification_commands(notes_path: Path) -> list[str]:
    lines = notes_path.read_text(encoding="utf-8").splitlines()
    commands: list[str] = []
    in_section = False

    for line in lines:
        if not in_section:
            if line.strip() == VERIFICATION_HEADER:
                in_section = True
            continue

        if HEADING_RE.match(line):
            break

        match = BULLET_RE.match(line.strip())
        if match:
            commands.append(match.group("command"))

    if not commands:
        raise RuntimeError(f"No verification commands found under {VERIFICATION_HEADER!r}")

    return commands


def build_ssh_command(target: Target, remote_command: str) -> list[str]:
    ssh_command = [
        "ssh",
        "-T",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
    ]
    if target.auth_mode == "default":
        ssh_command.extend(["-o", "BatchMode=yes"])
    elif target.auth_mode == "none":
        ssh_command.extend(
            [
                "-o",
                "PreferredAuthentications=none",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
            ]
        )
    if target.port is not None:
        ssh_command.extend(["-p", str(target.port)])
    ssh_command.append(target.destination)
    ssh_command.append(f"export LC_ALL=C LANG=C; {remote_command}")
    return ssh_command


def run_remote_command(target: Target, command: str) -> CommandResult:
    completed = subprocess.run(
        build_ssh_command(target, command),
        capture_output=True,
        check=False,
    )
    return CommandResult(
        returncode=completed.returncode,
        output=completed.stdout + completed.stderr,
    )


def decode_output(data: bytes) -> list[str]:
    return data.decode("utf-8", errors="replace").splitlines()


def normalize_output(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n").encode("utf-8")


def normalize_for_command(command: str, data: bytes) -> bytes:
    text = normalize_output(data).decode("utf-8", errors="replace")

    if command == "cat /proc/self/status":
        lines: list[str] = []
        for line in text.splitlines():
            key = line.split(":", 1)[0]
            if key in VOLATILE_STATUS_KEYS:
                lines.append(f"{key}:\t<volatile>")
            else:
                lines.append(line)
        text = "\n".join(lines)

    if command == "cat /proc/cpuinfo":
        text = "\n".join(
            "BogoMIPS\t: <volatile>" if line.startswith("BogoMIPS\t:") else line
            for line in text.splitlines()
        )

    if command == ATTACKER_SYNTAX_PROBE:
        lines = []
        for line in text.splitlines():
            if "syntax error near unexpected token" in line:
                lines.append("syntax error near unexpected token `;`")
                continue
            match = re.search(r"`(?:export LC_ALL=C LANG=C; )?(if .*fi)'$", line)
            if match:
                lines.append(f"`{match.group(1)}'")
        text = "\n".join(lines)

    return text.encode("utf-8")


def render_diff(label: str, left: bytes, right: bytes) -> str:
    diff = difflib.unified_diff(
        decode_output(left),
        decode_output(right),
        fromfile=f"real-{label}",
        tofile=f"honeypot-{label}",
        lineterm="",
    )
    return "\n".join(diff)


def print_result(index: int, total: int, command: str, ok: bool) -> None:
    status = "PASS" if ok else "FAIL"
    print(f"[{index}/{total}] {status} {command}")


def compare_results(command: str, real: CommandResult, honeypot: CommandResult) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if real.returncode is not None and honeypot.returncode is not None and real.returncode != honeypot.returncode:
        issues.append(
            f"Return code mismatch: real={real.returncode}, honeypot={honeypot.returncode}"
        )
    if normalize_for_command(command, real.output) != normalize_for_command(command, honeypot.output):
        issues.append("combined output differs")
    return not issues, issues


def indent_block(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def summarize_failures(
    command: str,
    issues: Iterable[str],
    real: CommandResult,
    honeypot: CommandResult,
) -> None:
    print(f"  Command: {command}")
    for issue in issues:
        print(f"  - {issue}")
    normalized_real = normalize_for_command(command, real.output)
    normalized_honeypot = normalize_for_command(command, honeypot.output)
    if normalized_real != normalized_honeypot:
        diff = render_diff("output", normalized_real, normalized_honeypot)
        print("  output diff:")
        if diff:
            print(indent_block(diff))
        else:
            print(indent_block(f"real={normalized_real!r}\nhoneypot={normalized_honeypot!r}"))


def split_destination(destination: str) -> tuple[str, str]:
    if "@" in destination:
        username, hostname = destination.split("@", 1)
        return username, hostname
    return "pi", destination


class HoneypotShell:
    def __init__(self, destination: str, port: int | None, password: str) -> None:
        username, hostname = split_destination(destination)
        self.username = username
        self.hostname = hostname
        self.prompt_anchor = f"{username}@{hostname}:"
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname,
            port=port or 22,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
        )
        self.channel = self.client.invoke_shell()
        self.channel.settimeout(10)
        time.sleep(0.5)
        initial = self._clean_bytes(self._drain())
        for line in initial.splitlines():
            if PROMPT_RE.match(line):
                self.prompt_anchor = line.split(":", 1)[0] + ":"
                break

    def close(self) -> None:
        self.channel.close()
        self.client.close()

    def _drain(self) -> bytes:
        chunks: list[bytes] = []
        while self.channel.recv_ready():
            chunks.append(self.channel.recv(65535))
        return b"".join(chunks)

    def _clean_bytes(self, data: bytes) -> str:
        cleaned = ANSI_ESCAPE_RE.sub(b"", data).replace(b"\r", b"")
        return cleaned.decode("utf-8", errors="replace")

    def _strip_prompt_suffix(self, text: str) -> str:
        start = text.rfind(self.prompt_anchor)
        if start != -1:
            suffix = text[start:]
            if PROMPT_RE.match(suffix):
                return text[:start]
        match = PROMPT_SUFFIX_RE.search(text)
        if match:
            if match.start() == 0:
                return ""
            return text[:match.start()]
        return text

    def run(self, command: str) -> CommandResult:
        marker = f"__VERIFY_DONE__{uuid.uuid4().hex}"
        self.channel.send(command + "\n")
        self.channel.send(f"echo {marker}\n")

        buffer = b""
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.channel.recv_ready():
                buffer += self.channel.recv(65535)
                if marker.encode("utf-8") in ANSI_ESCAPE_RE.sub(b"", buffer):
                    break
            else:
                time.sleep(0.05)
        else:
            raise RuntimeError(f"Timed out waiting for honeypot output for: {command}")

        text = self._clean_bytes(buffer)
        lines = text.splitlines()

        while lines and lines[0].strip() == command.strip():
            lines.pop(0)

        result_lines: list[str] = []
        for line in lines:
            if f"echo {marker}" in line:
                prefix = self._strip_prompt_suffix(line.split(f"echo {marker}", 1)[0])
                if prefix:
                    result_lines.append(prefix)
                break
            if PROMPT_RE.match(line):
                continue
            result_lines.append(line)

        output = "\n".join(result_lines).strip("\n").encode("utf-8")
        return CommandResult(returncode=None, output=output)


def main() -> int:
    args = parse_args()
    commands = extract_verification_commands(NOTES_PATH)

    real = Target("real", args.real_target, args.real_port, args.real_auth_mode)
    honeypot = Target(
        "honeypot",
        args.honeypot_target,
        args.honeypot_port,
        args.honeypot_auth_mode,
    )

    failures = 0
    total = len(commands)
    honeypot_shell = HoneypotShell(honeypot.destination, honeypot.port, args.honeypot_password)

    try:
        for index, command in enumerate(commands, start=1):
            real_result = run_remote_command(real, command)
            honeypot_result = honeypot_shell.run(command)
            ok, issues = compare_results(command, real_result, honeypot_result)
            print_result(index, total, command, ok)
            if not ok:
                failures += 1
                summarize_failures(command, issues, real_result, honeypot_result)
    finally:
        honeypot_shell.close()

    if failures:
        print(f"\n{failures} of {total} verification commands differed.")
        return 1

    print(f"\nAll {total} verification commands matched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
