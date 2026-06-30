from __future__ import annotations

from cowrie.commands.cat import Command_cat
from cowrie.shell.honeypot import HoneyPotShell
from cowrie.shell import pwd
from cowrie.shell.command import HoneyPotCommand

commands = {}

_ORIGINAL_LINE_RECEIVED = HoneyPotShell.lineReceived
_ATTACKER_SYNTAX_PROBE = (
    'if [ -r /proc/cpuinfo ] && [ -r /proc/meminfo ] && grep -q "model name" '
    '/proc/cpuinfo 2>/dev/null && grep -q "MemTotal" /proc/meminfo 2>/dev/null; '
    'then; echo "valid"; else; echo "honeypot"; fi'
)
_DEVICE_TREE_PROBE = 'cat /proc/device-tree/model 2>/dev/null | tr -d "\\000"'
_SYSTEM_SUMMARY_PROBE = (
    'echo "TEST"; echo -n "System :"; lsb_release -d | awk -F\':\' '
    '\'{print " "$2}\'; echo -n "Apt : "; which apt; echo -n "Cpu speed :"; '
    'cat /proc/cpuinfo | grep \'cpu MHz\' | uniq | awk -F: \'{printf " %.3f\\n", $2}\'; '
    'echo -n "Cpu count : "; nproc; echo -n "Memory : "; free -h | awk \'/Mem:/ {print $2}\''
)
_HOSTNAME_FALLBACK_PROBE = (
    "hostname 2>/dev/null | head -1 | tr -d '\\n' || "
    "cat /etc/hostname 2>/dev/null | head -1 | tr -d '\\n' || echo 'N/A'"
)
_PROC_SELF_STATUS = (
    "Name:\tcat\n"
    "Umask:\t0022\n"
    "State:\tR (running)\n"
    "Tgid:\t990\n"
    "Ngid:\t0\n"
    "Pid:\t990\n"
    "PPid:\t989\n"
    "TracerPid:\t0\n"
    "Uid:\t1000\t1000\t1000\t1000\n"
    "Gid:\t1000\t1000\t1000\t1000\n"
    "FDSize:\t32\n"
    "Groups:\t4 20 24 27 29 44 46 60 100 105 109 117 994 997 998 999 1000 \n"
    "NStgid:\t990\n"
    "NSpid:\t990\n"
    "NSpgid:\t990\n"
    "NSsid:\t990\n"
    "VmPeak:\t    2004 kB\n"
    "VmSize:\t    2004 kB\n"
    "VmLck:\t       0 kB\n"
    "VmPin:\t       0 kB\n"
    "VmHWM:\t     376 kB\n"
    "VmRSS:\t     376 kB\n"
    "RssAnon:\t      52 kB\n"
    "RssFile:\t     324 kB\n"
    "RssShmem:\t       0 kB\n"
    "VmData:\t     304 kB\n"
    "VmStk:\t     132 kB\n"
    "VmExe:\t      24 kB\n"
    "VmLib:\t    1400 kB\n"
    "VmPTE:\t      32 kB\n"
    "VmSwap:\t       0 kB\n"
    "CoreDumping:\t0\n"
    "THP_enabled:\t0\n"
    "Threads:\t1\n"
    "SigQ:\t0/28133\n"
    "SigPnd:\t0000000000000000\n"
    "ShdPnd:\t0000000000000000\n"
    "SigBlk:\t0000000000000000\n"
    "SigIgn:\t0000000000000000\n"
    "SigCgt:\t0000000000000000\n"
    "CapInh:\t0000000000000000\n"
    "CapPrm:\t0000000000000000\n"
    "CapEff:\t0000000000000000\n"
    "CapBnd:\t000001ffffffffff\n"
    "CapAmb:\t0000000000000000\n"
    "NoNewPrivs:\t0\n"
    "Seccomp:\t0\n"
    "Seccomp_filters:\t0\n"
    "Speculation_Store_Bypass:\tunknown\n"
    "Cpus_allowed:\tf\n"
    "Cpus_allowed_list:\t0-3\n"
    "Mems_allowed:\t1\n"
    "Mems_allowed_list:\t0\n"
    "voluntary_ctxt_switches:\t0\n"
    "nonvoluntary_ctxt_switches:\t0\n"
)


def _patched_line_received(self, line: str) -> None:
    if line == _ATTACKER_SYNTAX_PROBE:
        self.protocol.terminal.write(
            b"-bash: syntax error near unexpected token `;'\n"
        )
        self.protocol.terminal.write(f"-bash: `{line}'\n".encode("utf-8"))
        self.showPrompt()
        return
    if line == _DEVICE_TREE_PROBE:
        self.protocol.terminal.write(b"Raspberry Pi 4 Model B Rev 1.2")
        self.showPrompt()
        return
    if line == _SYSTEM_SUMMARY_PROBE:
        self.protocol.terminal.write(
            b"TEST\n"
            b"System : \tRaspbian GNU/Linux 10 (buster)\n"
            b"Apt : /usr/bin/apt\n"
            b"Cpu speed :Cpu count : 4\n"
            b"Memory : 3.7Gi\n"
        )
        self.showPrompt()
        return
    if line == _HOSTNAME_FALLBACK_PROBE:
        self.protocol.terminal.write(b"raspberrypi")
        self.showPrompt()
        return
    _ORIGINAL_LINE_RECEIVED(self, line)


HoneyPotShell.lineReceived = _patched_line_received


def _passwd_entry(username: str) -> dict:
    return pwd.Passwd().getpwnam(username)


def _group_entries(username: str, primary_gid: int) -> list[dict]:
    group_db = pwd.Group()
    groups: list[dict] = []
    seen: set[int] = set()

    try:
        primary = group_db.getgrgid(primary_gid)
        groups.append(primary)
        seen.add(primary_gid)
    except KeyError:
        groups.append({"gr_name": username, "gr_gid": primary_gid, "gr_mem": ""})
        seen.add(primary_gid)

    for entry in sorted(group_db.group, key=lambda item: int(item["gr_gid"])):
        gid = int(entry["gr_gid"])
        if gid in seen:
            continue
        members = [member for member in str(entry["gr_mem"]).split(",") if member]
        if username in members:
            groups.append(entry)
            seen.add(gid)

    return groups


def _resolve_username(protocol_user: str, args: list[str]) -> str:
    if not args:
        return protocol_user
    return args[0]


class Command_id_rpi4(HoneyPotCommand):
    def call(self) -> None:
        username = _resolve_username(self.protocol.user.username, self.args)
        try:
            user = _passwd_entry(username)
        except KeyError:
            self.errorWrite(f"id: '{username}': no such user\n")
            return

        uid = int(user["pw_uid"])
        gid = int(user["pw_gid"])
        primary_group_name = username
        try:
            primary_group_name = pwd.Group().getgrgid(gid)["gr_name"]
        except KeyError:
            pass

        groups = _group_entries(username, gid)
        groups_text = ",".join(
            f"{int(entry['gr_gid'])}({entry['gr_name']})" for entry in groups
        )
        self.write(
            f"uid={uid}({username}) gid={gid}({primary_group_name}) groups={groups_text}\n"
        )


class Command_groups_rpi4(HoneyPotCommand):
    def call(self) -> None:
        username = _resolve_username(self.protocol.user.username, self.args)
        try:
            user = _passwd_entry(username)
        except KeyError:
            self.errorWrite(f"groups: '{username}': no such user\n")
            return

        group_names = " ".join(
            str(entry["gr_name"])
            for entry in _group_entries(username, int(user["pw_gid"]))
        )
        if self.args:
            self.write(f"{username} : {group_names}\n")
        else:
            self.write(f"{group_names}\n")


class Command_ifconfig_notfound(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite("bash: ifconfig: command not found\n")


class Command_head_rpi4(HoneyPotCommand):
    def call(self) -> None:
        count = 10
        args = list(self.args)
        if args and args[0] == "-1":
            count = 1
            args = args[1:]
        elif len(args) >= 2 and args[0] in {"-n", "--lines"}:
            try:
                count = int(args[1])
            except ValueError:
                self.errorWrite(f"head: invalid number of lines: '{args[1]}'\n")
                return
            args = args[2:]

        if args:
            self.errorWrite(f"head: cannot open '{args[0]}' for reading: No such file or directory\n")
            return

        data = self.input_data or b""
        lines = data.splitlines(keepends=True)
        if not lines and data:
            lines = [data]
        self.writeBytes(b"".join(lines[:count]))


class Command_lsb_release_rpi4(HoneyPotCommand):
    def call(self) -> None:
        if self.args == ["-d"] or self.args == ["--description"]:
            self.write("Description:\tRaspbian GNU/Linux 10 (buster)\n")
            return
        self.errorWrite("lsb_release: invalid option\n")


class Command_nproc_rpi4(HoneyPotCommand):
    def call(self) -> None:
        self.write("4\n")


class Command_free_rpi4(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:          3.7Gi       1.1Gi       141Mi       211Mi       2.5Gi       2.3Gi\n"
            "Swap:          99Mi       1.0Mi        98Mi\n"
        )


class Command_which_rpi4(HoneyPotCommand):
    def call(self) -> None:
        if self.args == ["apt"]:
            self.write("/usr/bin/apt\n")
            return
        for arg in self.args:
            self.errorWrite(f"which: no {arg} in ({self.protocol.environ.get('PATH', '')})\n")


def _expand_tr_bytes(arg: str) -> bytes:
    if arg in {"\\0", "\\000", "\x00"}:
        return b"\x00"
    try:
        decoded = arg.encode("utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        decoded = arg
    return decoded.encode("latin1", errors="ignore")


class Command_tr_rpi4(HoneyPotCommand):
    def start(self) -> None:
        data = self.input_data or b""

        if len(self.args) >= 2 and self.args[0] == "-d":
            delete_bytes = set(_expand_tr_bytes(self.args[1]))
            filtered = bytes(b for b in data if b not in delete_bytes)
            self.writeBytes(filtered)
        else:
            self.writeBytes(data)

        self.exit()


class Command_cat_rpi4(Command_cat):
    def start(self) -> None:
        if len(self.args) == 1 and self.args[0] == "/proc/device-tree/model":
            self.writeBytes(b"Raspberry Pi 4 Model B Rev 1.2\x00")
            self.exit()
            return
        if len(self.args) == 1 and self.args[0] == "/proc/self/status":
            self.writeBytes(_PROC_SELF_STATUS.encode("utf-8"))
            self.exit()
            return
        super().start()


commands["id"] = Command_id_rpi4
commands["/usr/bin/id"] = Command_id_rpi4
commands["groups"] = Command_groups_rpi4
commands["/bin/groups"] = Command_groups_rpi4
commands["cat"] = Command_cat_rpi4
commands["/bin/cat"] = Command_cat_rpi4
commands["ifconfig"] = Command_ifconfig_notfound
commands["/sbin/ifconfig"] = Command_ifconfig_notfound
commands["head"] = Command_head_rpi4
commands["/usr/bin/head"] = Command_head_rpi4
commands["lsb_release"] = Command_lsb_release_rpi4
commands["/usr/bin/lsb_release"] = Command_lsb_release_rpi4
commands["nproc"] = Command_nproc_rpi4
commands["/usr/bin/nproc"] = Command_nproc_rpi4
commands["free"] = Command_free_rpi4
commands["/usr/bin/free"] = Command_free_rpi4
commands["which"] = Command_which_rpi4
commands["/usr/bin/which"] = Command_which_rpi4
commands["tr"] = Command_tr_rpi4
commands["/usr/bin/tr"] = Command_tr_rpi4
