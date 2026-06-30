# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
OpenSSH-like SSH transport for the Raspberry Pi 4 profile.

This keeps Cowrie's session logging and shell behavior, but patches the wire
protocol to look much closer to the real Raspberry Pi:

- `kex-strict-s-v00@openssh.com` instead of `ext-info-s` in initial KEXINIT
- strict-KEX sequence number resets
- `chacha20-poly1305@openssh.com`
- `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com`
- OpenSSH-style `*-etm@openssh.com` MAC handling
- OpenSSH-style UMAC variants
"""

from __future__ import annotations

import hmac
import re
import struct
import time
import uuid
import zlib
from dataclasses import dataclass
from hashlib import md5, sha1, sha256, sha512
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.poly1305 import Poly1305
from twisted.conch.ssh import transport as twisted_transport
from twisted.conch.ssh.common import getNS
from twisted.internet.protocol import connectionDone
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log, randbytes

from cowrie.core.config import CowrieConfig

try:
    import openssh_umac
except ImportError:  # pragma: no cover - only happens outside the custom image
    openssh_umac = None


_STRICT_KEX_CLIENT = b"kex-strict-c-v00@openssh.com"
_STRICT_KEX_SERVER = b"kex-strict-s-v00@openssh.com"
_EXT_INFO_CLIENT = b"ext-info-c"
_SERVER_SIG_ALGS = (
    b"ssh-ed25519,ssh-rsa,rsa-sha2-256,rsa-sha2-512,"
    b"ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521"
)


def _uint32(value: int) -> bytes:
    return struct.pack(">L", value)


def _uint64_be(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _uint64_le(value: int) -> bytes:
    return value.to_bytes(8, "little")


def _chacha_nonce(sequence: int, counter: int) -> bytes:
    return _uint64_le(counter) + _uint64_be(sequence)


def _chacha_xor(key: bytes, sequence: int, counter: int, data: bytes) -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, _chacha_nonce(sequence, counter)), mode=None)
    return cipher.encryptor().update(data)


def _poly1305_tag(key: bytes, data: bytes) -> bytes:
    return Poly1305.generate_tag(key, data)


def _verify_poly1305(key: bytes, data: bytes, tag: bytes) -> bool:
    try:
        Poly1305.verify_tag(key, data, tag)
        return True
    except Exception:
        return False


def _hash_for_mac(name: bytes) -> Callable[[], Any] | None:
    base = name.replace(b"-etm@openssh.com", b"")
    return {
        b"hmac-sha1": sha1,
        b"hmac-sha2-256": sha256,
        b"hmac-sha2-512": sha512,
        b"hmac-md5": md5,
    }.get(base)


@dataclass
class _MacContext:
    name: bytes
    digest_size: int
    key: bytes
    etm: bool
    mode: str
    hash_factory: Callable[[], Any] | None = None

    def compute(self, seqid: int, data: bytes) -> bytes:
        if self.mode == "none":
            return b""
        if self.mode == "hmac":
            assert self.hash_factory is not None
            return hmac.new(self.key, _uint32(seqid) + data, self.hash_factory).digest()[
                : self.digest_size
            ]
        if self.mode == "umac":
            if openssh_umac is None:
                raise RuntimeError("UMAC support is unavailable in this environment")
            return openssh_umac.compute_tag(
                self.digest_size,
                self.key,
                _uint64_be(seqid),
                data,
            )
        raise RuntimeError(f"Unsupported MAC mode: {self.mode}")

    def verify(self, seqid: int, data: bytes, mac: bytes) -> bool:
        return hmac.compare_digest(self.compute(seqid, data), mac)


def _build_mac(name: bytes, key: bytes) -> _MacContext:
    if name == b"none":
        return _MacContext(name=name, digest_size=0, key=b"", etm=False, mode="none")

    etm = name.endswith(b"-etm@openssh.com")
    if name.startswith(b"umac-64"):
        return _MacContext(name=name, digest_size=8, key=key[:16], etm=etm, mode="umac")
    if name.startswith(b"umac-128"):
        return _MacContext(name=name, digest_size=16, key=key[:16], etm=etm, mode="umac")

    hash_factory = _hash_for_mac(name)
    if hash_factory is None:
        raise RuntimeError(f"Unsupported MAC algorithm: {name!r}")
    digest_size = hash_factory().digest_size
    return _MacContext(
        name=name,
        digest_size=digest_size,
        key=key[:digest_size],
        etm=etm,
        mode="hmac",
        hash_factory=hash_factory,
    )


class _AESCTRState:
    def __init__(self, key: bytes, iv: bytes, decrypt: bool) -> None:
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        self.stream = cipher.decryptor() if decrypt else cipher.encryptor()

    def apply(self, data: bytes) -> bytes:
        return self.stream.update(data)


class _AESGCMState:
    def __init__(self, key: bytes, iv: bytes) -> None:
        self.aead = AESGCM(key)
        self.fixed = iv[:4]
        self.counter = int.from_bytes(iv[4:12], "big")

    def nonce(self) -> bytes:
        return self.fixed + self.counter.to_bytes(8, "big")

    def advance(self) -> None:
        self.counter = (self.counter + 1) % (1 << 64)


@dataclass
class _CipherDirection:
    mode: str
    block_size: int
    cipher_name: bytes
    mac: _MacContext
    ctr: _AESCTRState | None = None
    gcm: _AESGCMState | None = None
    chacha_main_key: bytes | None = None
    chacha_header_key: bytes | None = None

    @property
    def aad_len(self) -> int:
        if self.mode in {"etm", "gcm", "chacha"}:
            return 4
        return 0

    @property
    def tag_len(self) -> int:
        if self.mode in {"gcm", "chacha"}:
            return 16
        return 0


class OpenSSHLikeCiphers:
    def __init__(self, outCip: bytes, inCip: bytes, outMac: bytes, inMac: bytes):
        self.outCipType = outCip
        self.inCipType = inCip
        self.outMACType = outMac
        self.inMACType = inMac
        self.encBlockSize = 8
        self.decBlockSize = 8
        self.verifyDigestSize = 0
        self.outgoing: _CipherDirection | None = None
        self.incoming: _CipherDirection | None = None

    def setKeys(
        self,
        outIV: bytes,
        outKey: bytes,
        inIV: bytes,
        inKey: bytes,
        outInteg: bytes,
        inInteg: bytes,
    ) -> None:
        self.outgoing = self._build_direction(
            self.outCipType, self.outMACType, outIV, outKey, outInteg, decrypt=False
        )
        self.incoming = self._build_direction(
            self.inCipType, self.inMACType, inIV, inKey, inInteg, decrypt=True
        )
        self.encBlockSize = self.outgoing.block_size
        self.decBlockSize = self.incoming.block_size
        self.verifyDigestSize = self.incoming.mac.digest_size

    def _build_direction(
        self,
        cipher_name: bytes,
        mac_name: bytes,
        iv: bytes,
        key: bytes,
        integ: bytes,
        *,
        decrypt: bool,
    ) -> _CipherDirection:
        mac = _build_mac(mac_name, integ)
        if cipher_name == b"none":
            return _CipherDirection("none", 8, cipher_name, mac)
        if cipher_name in {b"aes128-ctr", b"aes192-ctr", b"aes256-ctr"}:
            key_len = {b"aes128-ctr": 16, b"aes192-ctr": 24, b"aes256-ctr": 32}[cipher_name]
            mode = "etm" if mac.etm else "classic"
            return _CipherDirection(
                mode,
                16,
                cipher_name,
                mac,
                ctr=_AESCTRState(key[:key_len], iv[:16], decrypt),
            )
        if cipher_name in {b"aes128-gcm@openssh.com", b"aes256-gcm@openssh.com"}:
            key_len = {b"aes128-gcm@openssh.com": 16, b"aes256-gcm@openssh.com": 32}[cipher_name]
            return _CipherDirection(
                "gcm",
                16,
                cipher_name,
                _MacContext(name=b"none", digest_size=0, key=b"", etm=False, mode="none"),
                gcm=_AESGCMState(key[:key_len], iv[:12]),
            )
        if cipher_name == b"chacha20-poly1305@openssh.com":
            return _CipherDirection(
                "chacha",
                8,
                cipher_name,
                _MacContext(name=b"none", digest_size=0, key=b"", etm=False, mode="none"),
                chacha_main_key=key[:32],
                chacha_header_key=key[32:64],
            )
        raise RuntimeError(f"Unsupported cipher: {cipher_name!r}")

    def encrypt_packet(self, seqid: int, packet: bytes) -> bytes:
        state = self.outgoing
        assert state is not None
        if state.mode == "none":
            return packet
        if state.mode == "classic":
            assert state.ctr is not None
            encrypted = state.ctr.apply(packet)
            mac = state.mac.compute(seqid, packet)
            return encrypted + mac
        if state.mode == "etm":
            assert state.ctr is not None
            header = packet[:4]
            encrypted_body = state.ctr.apply(packet[4:])
            mac = state.mac.compute(seqid, header + encrypted_body)
            return header + encrypted_body + mac
        if state.mode == "gcm":
            assert state.gcm is not None
            header = packet[:4]
            encrypted = state.gcm.aead.encrypt(state.gcm.nonce(), packet[4:], header)
            state.gcm.advance()
            return header + encrypted
        if state.mode == "chacha":
            assert state.chacha_main_key is not None
            assert state.chacha_header_key is not None
            header = packet[:4]
            body = packet[4:]
            encrypted_header = _chacha_xor(state.chacha_header_key, seqid, 0, header)
            poly_key = _chacha_xor(state.chacha_main_key, seqid, 0, b"\x00" * 32)
            encrypted_body = _chacha_xor(state.chacha_main_key, seqid, 1, body)
            tag = _poly1305_tag(poly_key, encrypted_header + encrypted_body)
            return encrypted_header + encrypted_body + tag
        raise RuntimeError(f"Unsupported outgoing mode: {state.mode}")

    def peek_length(self, seqid: int, buf: bytes) -> int | None:
        state = self.incoming
        assert state is not None
        if state.mode in {"etm", "gcm"}:
            if len(buf) < 4:
                return None
            return struct.unpack("!L", buf[:4])[0]
        if state.mode == "chacha":
            if len(buf) < 4:
                return None
            assert state.chacha_header_key is not None
            plain = _chacha_xor(state.chacha_header_key, seqid, 0, buf[:4])
            return struct.unpack("!L", plain)[0]
        return None

    def decrypt_classic_first_block(self, data: bytes) -> bytes:
        state = self.incoming
        assert state is not None and state.ctr is not None
        return state.ctr.apply(data)

    def decrypt_packet(self, seqid: int, packet: bytes, aad_len: int, auth_len: int) -> bytes:
        state = self.incoming
        assert state is not None
        if state.mode == "none":
            return packet
        if state.mode == "classic":
            assert state.ctr is not None
            return state.ctr.apply(packet)
        if state.mode == "etm":
            assert state.ctr is not None
            header = packet[:aad_len]
            encrypted_body = packet[aad_len:]
            return header + state.ctr.apply(encrypted_body)
        if state.mode == "gcm":
            assert state.gcm is not None
            header = packet[:aad_len]
            encrypted = packet[aad_len:] + b""
            plain_body = state.gcm.aead.decrypt(state.gcm.nonce(), encrypted, header)
            state.gcm.advance()
            return header + plain_body
        if state.mode == "chacha":
            assert state.chacha_main_key is not None
            assert state.chacha_header_key is not None
            encrypted_header = packet[:aad_len]
            encrypted_body = packet[aad_len:]
            poly_key = _chacha_xor(state.chacha_main_key, seqid, 0, b"\x00" * 32)
            if len(encrypted_body) < auth_len:
                raise RuntimeError("Incomplete chacha20-poly1305 packet")
            ciphertext = encrypted_body[:-auth_len]
            tag = encrypted_body[-auth_len:]
            if not _verify_poly1305(poly_key, encrypted_header + ciphertext, tag):
                raise ValueError("bad MAC")
            header = _chacha_xor(state.chacha_header_key, seqid, 0, encrypted_header)
            plain_body = _chacha_xor(state.chacha_main_key, seqid, 1, ciphertext)
            return header + plain_body
        raise RuntimeError(f"Unsupported incoming mode: {state.mode}")


class HoneyPotSSHTransport(twisted_transport.SSHServerTransport, TimeoutMixin):
    supportedCiphers = [
        b"chacha20-poly1305@openssh.com",
        b"aes128-ctr",
        b"aes192-ctr",
        b"aes256-ctr",
        b"aes128-gcm@openssh.com",
        b"aes256-gcm@openssh.com",
    ]
    supportedMACs = [
        b"umac-64-etm@openssh.com",
        b"umac-128-etm@openssh.com",
        b"hmac-sha2-256-etm@openssh.com",
        b"hmac-sha2-512-etm@openssh.com",
        b"hmac-sha1-etm@openssh.com",
        b"umac-64@openssh.com",
        b"umac-128@openssh.com",
        b"hmac-sha2-256",
        b"hmac-sha2-512",
        b"hmac-sha1",
    ]
    supportedCompressions = [b"none", b"zlib@openssh.com"]

    startTime: float = 0.0
    gotVersion: bool = False
    buf: bytes
    transportId: str
    ipv4rex = re.compile(r"^::ffff:(\d+\.\d+\.\d+\.\d+)$")
    auth_timeout: int = CowrieConfig.getint(
        "honeypot", "authentication_timeout", fallback=120
    )
    interactive_timeout: int = CowrieConfig.getint(
        "honeypot", "interactive_timeout", fallback=300
    )
    ourVersionString: bytes
    transport: Any
    outgoingCompression: Any
    _blockedByKeyExchange: Any

    def __repr__(self) -> str:
        return f"Cowrie SSH Transport to {self.transport.getPeer().host}"

    def connectionMade(self) -> None:
        self.buf = b""
        self.transportId = uuid.uuid4().hex[:12]
        self._strict_kex_enabled = False
        self._initial_kex_complete = False

        src_ip: str = self.transport.getPeer().host
        ipv4_search = self.ipv4rex.search(src_ip)
        if ipv4_search is not None:
            src_ip = ipv4_search.group(1)

        log.msg(
            eventid="cowrie.session.connect",
            format="New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]",
            src_ip=src_ip,
            src_port=self.transport.getPeer().port,
            dst_ip=self.transport.getHost().host,
            dst_port=self.transport.getHost().port,
            session=self.transportId,
            sessionno=f"S{self.transport.sessionno}",
            protocol="ssh",
        )

        self.transport.write(self.ourVersionString + b"\r\n")
        self.currentEncryptions = twisted_transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        self.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")

        self.startTime = time.time()
        self.setTimeout(self.auth_timeout)

    def sendKexInit(self) -> None:
        if not self.gotVersion:
            return
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            raise RuntimeError(
                "Cannot send KEXINIT while key exchange state is %r"
                % (self._keyExchangeState,)
            )

        supported_key_exchanges = list(self.supportedKeyExchanges)
        if self.sessionID is None:
            supported_key_exchanges.append(_STRICT_KEX_SERVER)

        self.ourKexInitPayload = b"".join(
            [
                bytes((twisted_transport.MSG_KEXINIT,)),
                randbytes.secureRandom(16),
                twisted_transport.NS(b",".join(supported_key_exchanges)),
                twisted_transport.NS(b",".join(self.supportedPublicKeys)),
                twisted_transport.NS(b",".join(self.supportedCiphers)),
                twisted_transport.NS(b",".join(self.supportedCiphers)),
                twisted_transport.NS(b",".join(self.supportedMACs)),
                twisted_transport.NS(b",".join(self.supportedMACs)),
                twisted_transport.NS(b",".join(self.supportedCompressions)),
                twisted_transport.NS(b",".join(self.supportedCompressions)),
                twisted_transport.NS(b",".join(self.supportedLanguages)),
                twisted_transport.NS(b",".join(self.supportedLanguages)),
                b"\000\000\000\000\000",
            ]
        )
        self.sendPacket(twisted_transport.MSG_KEXINIT, self.ourKexInitPayload[1:])
        self._keyExchangeState = self._KEY_EXCHANGE_REQUESTED
        self._blockedByKeyExchange = []

    def _unsupportedVersionReceived(self, remoteVersion: bytes) -> None:
        self.transport.write(b"Protocol major versions differ.\n")
        self.transport.loseConnection()

    def dataReceived(self, data: bytes) -> None:
        self.buf = self.buf + data
        if not self.gotVersion:
            if b"\n" not in self.buf:
                return
            self.otherVersionString = self.buf.split(b"\n")[0].strip()
            log.msg(
                eventid="cowrie.client.version",
                version=self.otherVersionString.decode(
                    "utf-8", errors="backslashreplace"
                ),
                format="Remote SSH version: %(version)s",
            )
            m = re.match(rb"SSH-(\d+\.\d+)-(.*)", self.otherVersionString)
            if m is None:
                log.msg(
                    f"Bad protocol version identification: {self.otherVersionString!r}"
                )
                self.transport.write(b"Invalid SSH identification string.\n")
                self.transport.loseConnection()
                return
            self.gotVersion = True
            remote_version = m.group(1)
            if remote_version not in self.supportedVersions:
                self._unsupportedVersionReceived(self.otherVersionString)
                return
            i = self.buf.index(b"\n")
            self.buf = self.buf[i + 1 :]
            self.sendKexInit()

        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0:1])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

    def dispatchMessage(self, messageNum: int, payload: bytes) -> None:
        if self._strict_kex_enabled and not self._initial_kex_complete:
            if messageNum not in {twisted_transport.MSG_KEXINIT, twisted_transport.MSG_NEWKEYS} and not (
                30 <= messageNum <= 49
            ):
                self.sendDisconnect(
                    twisted_transport.DISCONNECT_PROTOCOL_ERROR,
                    b"strict KEX violation",
                )
                return
        twisted_transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)

    def sendPacket(self, messageType: int, payload: bytes) -> None:
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            if not self._allowedKeyExchangeMessageType(messageType):
                self._blockedByKeyExchange.append((messageType, payload))
                return

        payload = bytes((messageType,)) + payload
        if self.outgoingCompression:
            payload = self.outgoingCompression.compress(
                payload
            ) + self.outgoingCompression.flush(2)

        cipher_state = self.currentEncryptions
        if isinstance(cipher_state, OpenSSHLikeCiphers):
            block_size = cipher_state.encBlockSize
            aad_len = cipher_state.outgoing.aad_len  # type: ignore[union-attr]
        else:
            block_size = cipher_state.encBlockSize
            aad_len = 0

        total_size = 5 + len(payload) - aad_len
        lenPad = block_size - (total_size % block_size)
        if lenPad < 4:
            lenPad += block_size

        if messageType == twisted_transport.MSG_KEXINIT:
            padding = b"\0" * lenPad
        else:
            padding = randbytes.secureRandom(lenPad)

        packet = struct.pack("!LB", len(payload) + lenPad + 1, lenPad) + payload + padding

        if isinstance(cipher_state, OpenSSHLikeCiphers):
            encPacket = cipher_state.encrypt_packet(self.outgoingPacketSequence, packet)
        else:
            encPacket = cipher_state.encrypt(packet) + cipher_state.makeMAC(
                self.outgoingPacketSequence, packet
            )

        self.transport.write(encPacket)
        self.outgoingPacketSequence += 1
        if self._strict_kex_enabled and messageType == twisted_transport.MSG_NEWKEYS:
            self.outgoingPacketSequence = 0

    def getPacket(self) -> bytes | None:
        cipher_state = self.currentEncryptions
        if not isinstance(cipher_state, OpenSSHLikeCiphers):
            return self._getPacketClassic()

        state = cipher_state.incoming
        assert state is not None
        aad_len = state.aad_len
        auth_len = state.tag_len
        mac_len = 0 if auth_len else state.mac.digest_size
        block_size = state.block_size

        if aad_len and not hasattr(self, "_packlen"):
            self._packlen = 0

        if aad_len and self._packlen == 0:
            packlen = cipher_state.peek_length(self.incomingPacketSequence, self.buf)
            if packlen is None:
                return None
            if packlen < 5 or packlen > 1048576:
                self.sendDisconnect(
                    twisted_transport.DISCONNECT_PROTOCOL_ERROR, b"Packet corrupt"
                )
                return None
            self._packlen = packlen
        elif not aad_len:
            return self._getPacketClassicCustom(cipher_state)

        need = self._packlen
        if need % block_size != 0:
            self.sendDisconnect(
                twisted_transport.DISCONNECT_PROTOCOL_ERROR, b"Packet corrupt"
            )
            return None
        total_needed = aad_len + need + auth_len + mac_len
        if len(self.buf) < total_needed:
            return None

        raw_packet = self.buf[: aad_len + need]
        auth_tag = self.buf[aad_len + need : aad_len + need + auth_len]
        mac_data = self.buf[
            aad_len + need + auth_len : aad_len + need + auth_len + mac_len
        ]

        if mac_len and state.mac.etm:
            if not state.mac.verify(self.incomingPacketSequence, raw_packet, mac_data):
                self.sendDisconnect(twisted_transport.DISCONNECT_MAC_ERROR, b"bad MAC")
                return None

        try:
            plain_packet = cipher_state.decrypt_packet(
                self.incomingPacketSequence, raw_packet + auth_tag, aad_len, auth_len
            )
        except ValueError:
            self.sendDisconnect(twisted_transport.DISCONNECT_MAC_ERROR, b"bad MAC")
            return None
        except Exception:
            self.sendDisconnect(
                twisted_transport.DISCONNECT_PROTOCOL_ERROR, b"bad decryption"
            )
            return None

        if mac_len and not state.mac.etm:
            if not state.mac.verify(self.incomingPacketSequence, plain_packet, mac_data):
                self.sendDisconnect(twisted_transport.DISCONNECT_MAC_ERROR, b"bad MAC")
                return None

        self.buf = self.buf[total_needed:]
        self._packlen = 0

        padding_len = plain_packet[4]
        payload = plain_packet[5:-padding_len]
        if self.incomingCompression:
            try:
                payload = self.incomingCompression.decompress(payload)
            except Exception:
                self.sendDisconnect(
                    twisted_transport.DISCONNECT_COMPRESSION_ERROR,
                    b"compression error",
                )
                return None

        self.incomingPacketSequence += 1
        return payload

    def _getPacketClassic(self) -> bytes | None:
        bs = self.currentEncryptions.decBlockSize
        ms = self.currentEncryptions.verifyDigestSize
        if len(self.buf) < bs:
            return None
        if not hasattr(self, "first"):
            first = self.currentEncryptions.decrypt(self.buf[:bs])
        else:
            first = self.first
            del self.first
        packetLen, paddingLen = struct.unpack("!LB", first[:5])
        if packetLen > 1048576:
            self.sendDisconnect(
                twisted_transport.DISCONNECT_PROTOCOL_ERROR,
                twisted_transport.networkString(f"bad packet length {packetLen}"),
            )
            return None
        if len(self.buf) < packetLen + 4 + ms:
            self.first = first
            return None
        if (packetLen + 4) % bs != 0:
            self.sendDisconnect(
                twisted_transport.DISCONNECT_PROTOCOL_ERROR,
                twisted_transport.networkString(
                    f"bad packet mod ({packetLen + 4}%{bs} == {(packetLen + 4) % bs})"
                ),
            )
            return None
        encData, self.buf = self.buf[: 4 + packetLen], self.buf[4 + packetLen :]
        packet = first + self.currentEncryptions.decrypt(encData[bs:])
        if len(packet) != 4 + packetLen:
            self.sendDisconnect(twisted_transport.DISCONNECT_PROTOCOL_ERROR, b"bad decryption")
            return None
        if ms:
            macData, self.buf = self.buf[:ms], self.buf[ms:]
            if not self.currentEncryptions.verify(
                self.incomingPacketSequence, packet, macData
            ):
                self.sendDisconnect(twisted_transport.DISCONNECT_MAC_ERROR, b"bad MAC")
                return None
        payload = packet[5:-paddingLen]
        if self.incomingCompression:
            try:
                payload = self.incomingCompression.decompress(payload)
            except Exception:
                self.sendDisconnect(
                    twisted_transport.DISCONNECT_COMPRESSION_ERROR, b"compression error"
                )
                return None
        self.incomingPacketSequence += 1
        return payload

    def _getPacketClassicCustom(self, cipher_state: OpenSSHLikeCiphers) -> bytes | None:
        state = cipher_state.incoming
        assert state is not None
        bs = state.block_size
        ms = state.mac.digest_size
        if len(self.buf) < bs:
            return None
        if not hasattr(self, "first"):
            first = cipher_state.decrypt_classic_first_block(self.buf[:bs])
        else:
            first = self.first
            del self.first
        packetLen, paddingLen = struct.unpack("!LB", first[:5])
        if packetLen > 1048576:
            self.sendDisconnect(
                twisted_transport.DISCONNECT_PROTOCOL_ERROR,
                twisted_transport.networkString(f"bad packet length {packetLen}"),
            )
            return None
        if len(self.buf) < packetLen + 4 + ms:
            self.first = first
            return None
        if (packetLen + 4) % bs != 0:
            self.sendDisconnect(
                twisted_transport.DISCONNECT_PROTOCOL_ERROR,
                twisted_transport.networkString(
                    f"bad packet mod ({packetLen + 4}%{bs} == {(packetLen + 4) % bs})"
                ),
            )
            return None
        encData = self.buf[: 4 + packetLen]
        macData = self.buf[4 + packetLen : 4 + packetLen + ms]
        packet = first + cipher_state.decrypt_packet(
            self.incomingPacketSequence, encData[bs:], 0, 0
        )
        if len(packet) != 4 + packetLen:
            self.sendDisconnect(twisted_transport.DISCONNECT_PROTOCOL_ERROR, b"bad decryption")
            return None
        if ms and not state.mac.verify(self.incomingPacketSequence, packet, macData):
            self.sendDisconnect(twisted_transport.DISCONNECT_MAC_ERROR, b"bad MAC")
            return None
        self.buf = self.buf[4 + packetLen + ms :]
        payload = packet[5:-paddingLen]
        if self.incomingCompression:
            try:
                payload = self.incomingCompression.decompress(payload)
            except Exception:
                self.sendDisconnect(
                    twisted_transport.DISCONNECT_COMPRESSION_ERROR, b"compression error"
                )
                return None
        self.incomingPacketSequence += 1
        return payload

    def ssh_KEXINIT(self, packet: bytes) -> Any:
        self.otherKexInitPayload = bytes((twisted_transport.MSG_KEXINIT,)) + packet
        k = getNS(packet[16:], 10)
        strings, rest = k[:-1], k[-1]
        (
            kexAlgs,
            keyAlgs,
            encCS,
            encSC,
            macCS,
            macSC,
            compCS,
            compSC,
            langCS,
            langSC,
        ) = (s.split(b",") for s in strings)

        ckexAlgs = ",".join([alg.decode("utf-8") for alg in kexAlgs])
        cencCS = ",".join([alg.decode("utf-8") for alg in encCS])
        cmacCS = ",".join([alg.decode("utf-8") for alg in macCS])
        ccompCS = ",".join([alg.decode("utf-8") for alg in compCS])
        hasshAlgorithms = f"{ckexAlgs};{cencCS};{cmacCS};{ccompCS}"
        hassh = md5(hasshAlgorithms.encode("utf-8")).hexdigest()

        log.msg(
            eventid="cowrie.client.kex",
            format="SSH client hassh fingerprint: %(hassh)s",
            hassh=hassh,
            hasshAlgorithms=hasshAlgorithms,
            kexAlgs=kexAlgs,
            keyAlgs=keyAlgs,
            encCS=encCS,
            macCS=macCS,
            compCS=compCS,
            langCS=langCS,
        )

        outs = [encSC, macSC, compSC]
        ins = [encCS, macCS, compCS]
        server = (
            self.supportedKeyExchanges,
            self.supportedPublicKeys,
            self.supportedCiphers,
            self.supportedCiphers,
            self.supportedMACs,
            self.supportedMACs,
            self.supportedCompressions,
            self.supportedCompressions,
        )
        client = (kexAlgs, keyAlgs, outs[0], ins[0], outs[1], ins[1], outs[2], ins[2])

        self.kexAlg = twisted_transport.ffs(client[0], server[0])
        self.keyAlg = twisted_transport.ffs(client[1], server[1])
        self.nextEncryptions = OpenSSHLikeCiphers(
            twisted_transport.ffs(client[2], server[2]),
            twisted_transport.ffs(client[3], server[3]),
            twisted_transport.ffs(client[4], server[4]),
            twisted_transport.ffs(client[5], server[5]),
        )
        self.outgoingCompressionType = twisted_transport.ffs(client[6], server[6])
        self.incomingCompressionType = twisted_transport.ffs(client[7], server[7])

        if (
            None
            in (
                self.kexAlg,
                self.keyAlg,
                self.outgoingCompressionType,
                self.incomingCompressionType,
            )
            or self.kexAlg in (_EXT_INFO_CLIENT, _STRICT_KEX_CLIENT, _STRICT_KEX_SERVER)
        ):
            log.msg(
                eventid="cowrie.debug.kex_mismatch",
                kexAlg=self.kexAlg,
                keyAlg=self.keyAlg,
                outCipher=self.nextEncryptions.outCipType,
                inCipher=self.nextEncryptions.inCipType,
                outMac=self.nextEncryptions.outMACType,
                inMac=self.nextEncryptions.inMACType,
                outCompression=self.outgoingCompressionType,
                inCompression=self.incomingCompressionType,
                format="KEX mismatch kex=%(kexAlg)r key=%(keyAlg)r outCipher=%(outCipher)r inCipher=%(inCipher)r outMac=%(outMac)r inMac=%(inMac)r outCompression=%(outCompression)r inCompression=%(inCompression)r",
            )
            self.sendDisconnect(
                twisted_transport.DISCONNECT_KEY_EXCHANGE_FAILED,
                b"couldn't match all kex parts",
            )
            return None
        self._peerSupportsExtensions = _EXT_INFO_CLIENT in kexAlgs
        if self.sessionID is None and _STRICT_KEX_CLIENT in kexAlgs:
            self._strict_kex_enabled = True

        if self._keyExchangeState == self._KEY_EXCHANGE_REQUESTED:
            self._keyExchangeState = self._KEY_EXCHANGE_PROGRESSING
        else:
            self.sendKexInit()

        return kexAlgs, keyAlgs, rest

    def _keySetup(self, sharedSecret: bytes, exchangeHash: bytes) -> None:
        firstKey = self.sessionID is None
        twisted_transport.SSHTransportBase._keySetup(self, sharedSecret, exchangeHash)
        if firstKey and self._peerSupportsExtensions:
            self.sendExtInfo([(b"server-sig-algs", _SERVER_SIG_ALGS)])

    def ssh_NEWKEYS(self, packet: bytes) -> None:
        if packet != b"":
            self.sendDisconnect(
                twisted_transport.DISCONNECT_PROTOCOL_ERROR, b"NEWKEYS takes no data"
            )
            return
        if self._strict_kex_enabled:
            self.incomingPacketSequence = 0
        self._newKeys()
        if not self._initial_kex_complete:
            self._initial_kex_complete = True

    def timeoutConnection(self) -> None:
        log.msg("Timeout reached in HoneyPotSSHTransport")
        self.transport.loseConnection()

    def setService(self, service):
        if service.name == b"ssh-connection":
            self.setTimeout(self.interactive_timeout)

        if service.name == b"ssh-connection":
            if self.outgoingCompressionType == b"zlib@openssh.com":
                self.outgoingCompression = zlib.compressobj(6)
            if self.incomingCompressionType == b"zlib@openssh.com":
                self.incomingCompression = zlib.decompressobj()

        twisted_transport.SSHServerTransport.setService(self, service)

    def connectionLost(self, reason: failure.Failure | None = connectionDone) -> None:
        self.setTimeout(None)
        twisted_transport.SSHServerTransport.connectionLost(self, reason)
        self.transport.connectionLost(reason)
        self.transport = None
        duration = f"{time.time() - self.startTime:.1f}"
        log.msg(
            eventid="cowrie.session.closed",
            format="Connection lost after %(duration)s seconds",
            duration=duration,
        )

    def sendDisconnect(self, reason, desc):
        if b"bad packet length" not in desc:
            twisted_transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            log.msg(
                f"[SERVER] - Disconnecting with error, code {reason} reason: {desc}"
            )
            self.transport.loseConnection()

    def receiveError(self, reasonCode, description):
        log.msg(f"Got remote error, code {reasonCode} reason: {description}")
