# Raspberry Pi 4 config

This config was created to look indistinguishable to a real Raspberry Pi 4. It is also based off of a real Raspberry Pi 4, hence why there are references to Homebridge and OpenVPN.

The key exchange is 1:1 and can be verified, assuming a `pi` host is defined in `~/.ssh/config`, using

```bash
ssh -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=none -o PubkeyAuthentication=no -p 2222 localhost true
ssh -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=none -o PubkeyAuthentication=no pi true
```

To achieve this, some changes to Cowrie were required.

You can test a local version using

```bash
docker compose up --build
```

You can automatically rerun every command in the `## Verification` section with

```bash
python verify_profile.py
```

By default, the verifier uses normal SSH auth for the real Pi target and
Paramiko with a dummy password for the honeypot target, so it does not depend
on a local key being accepted by Cowrie or on OpenSSH's `none` auth behavior.
It also normalizes a small set of inherently volatile fields when comparing
`/proc/self/status` and `BogoMIPS` lines in `/proc/cpuinfo`, since those values
drift between runs on the real device even when the profile is correct.

## Changes/overrides

- Added honeyfs overrides to mirror the real Pi for:
  - `/etc/hostname`
  - `/etc/hosts`
  - `/etc/os-release`
  - `/etc/debian_version`
  - `/etc/issue`
  - `/etc/passwd`
  - `/etc/group`
  - `/proc/version`
  - `/proc/cpuinfo`
  - `/proc/device-tree/model`

- Added command overrides in [./overrides/commands/rpi4_overrides.py](./overrides/commands/rpi4_overrides.py) so `id`, `groups`, `ifconfig`, and similar probes look more like the real device.

- Added a SSH factory override in [./overrides/ssh/factory.py](./overrides/ssh/factory.py) to improve KEXINIT and algorithm offers.

- Added a custom SSH transport in [./overrides/ssh/transport.py](./overrides/ssh/transport.py) to emulate OpenSSH behavior more closely:
  - `kex-strict-s-v00@openssh.com`
  - strict-KEX sequence resets
  - OpenSSH-style `SSH2_MSG_EXT_INFO`
  - `chacha20-poly1305@openssh.com`
  - `aes128-gcm@openssh.com`
  - `aes256-gcm@openssh.com`
  - `*-etm@openssh.com`
  - `umac-64@openssh.com`
  - `umac-64-etm@openssh.com`
  - `umac-128@openssh.com`
  - `umac-128-etm@openssh.com`

- Added copied SSH GEX moduli in [./assets/moduli](./assets/moduli) so diffie-hellman-group-exchange-sha256 works like the Pi.

## Verification

The following commands are the comparison probes used by `python ./verify_profile.py`. The real Pi is queried over your normal `ssh` setup, while the honeypot side is queried through an interactive Paramiko shell session. They are meant to highlight remaining drift as well as successful matches.

- `uname -s -v -n -r -m`
- `uname -a ; echo 'vT'`
- `uname -s -m`
- `uname -a && echo "====" && cat /etc/os-release`
- `id`
  - This needs the custom `id` override because Cowrie's stock account database does not expose the Pi user's real UID/GID and supplementary groups.
- `groups`
  - This needs the custom `groups` override because the stock shell would not return the Raspberry Pi's full group membership layout for `pi`.
- `whoami`
- `ifconfig`
  - This needs the custom `ifconfig` override because for some reason `ifconfig` is not in the `$PATH` when using `ssh pi ifconfig`, even though it is installed.
- `cat /etc/hostname`
- `cat /etc/hosts`
- `cat /etc/issue`
- `cat /etc/debian_version`
- `cat /proc/version`
- `cat /proc/cpuinfo`
- `cat /proc/device-tree/model 2>/dev/null | tr -d "\000"`
  - This needs the custom probe override because Cowrie's normal `cat | tr` path was truncating the NUL-terminated device-tree model string.
- `cat /proc/self/status`
  - This needs the custom `cat` override because Cowrie does not expose a Linux-like per-process `/proc/self/status` view by default.
- `echo -e "\x6F\x6B"`
- `echo 'dGVzdA==' | base64 -d 2>/dev/null`
- `if [ -r /proc/cpuinfo ] && [ -r /proc/meminfo ] && grep -q "model name" /proc/cpuinfo 2>/dev/null && grep -q "MemTotal" /proc/meminfo 2>/dev/null; then; echo "valid"; else; echo "honeypot"; fi`
  - This needs the custom probe override because the attacker is abusing invalid syntax at `then;` and `else;`. Cowrie still executes each command separately, including printing it's a honeypot, while the real Pi just returns ``-bash: syntax error near unexpected token `;'``.
- `echo "TEST"; echo -n "System :"; lsb_release -d | awk -F':' '{print " "$2}'; echo -n "Apt : "; which apt; echo -n "Cpu speed :"; cat /proc/cpuinfo | grep 'cpu MHz' | uniq | awk -F: '{printf " %.3f\n", $2}'; echo -n "Cpu count : "; nproc; echo -n "Memory : "; free -h | awk '/Mem:/ {print $2}'`
  - This needs the custom probe override because Cowrie's stock `awk`/`which`/`nproc`/`free` surface and pipeline behavior do not reproduce the Pi's exact one-liner output.
- `hostname 2>/dev/null | head -1 | tr -d '\n' || cat /etc/hostname 2>/dev/null | head -1 | tr -d '\n' || echo 'N/A'`
  - This needs the custom probe override because Cowrie treats `||` like an unconditional separator, so the fallback branch would otherwise run even when `hostname` succeeds.

## Source provenance for the UMAC additions:

- OpenSSH source files copied into `overrides/ssh/umac_ext/`:
  - `umac.c`: https://github.com/openssh/openssh-portable/blob/master/umac.c
  - `umac.h`: https://github.com/openssh/openssh-portable/blob/master/umac.h
  - `umac128.c`: https://github.com/openssh/openssh-portable/blob/master/umac128.c
- Behavioral reference while patching Cowrie's transport:
  - `mac.c`: https://github.com/openssh/openssh-portable/blob/master/mac.c
  - `sshbuf.h`: https://github.com/openssh/openssh-portable/blob/master/sshbuf.h
- The local wrapper and portability shims are our additions:
  - `overrides/ssh/umac_ext/openssh_umac_module.c`
  - `overrides/ssh/umac_ext/includes.h`
  - `overrides/ssh/umac_ext/misc.h`
  - `overrides/ssh/umac_ext/xmalloc.h`
  - `overrides/ssh/umac_ext/openbsd-compat/openssl-compat.h`
