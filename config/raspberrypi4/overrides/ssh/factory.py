# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import time
from configparser import NoOptionError, NoSectionError
from hashlib import sha256, sha512
from typing import TYPE_CHECKING

from twisted.conch.openssh_compat import primes
from twisted.conch.ssh import _kex
from twisted.conch.ssh import factory, keys, transport
from twisted.python import log
from zope.interface import implementer

from cowrie.core.config import CowrieConfig
from cowrie.ssh import connection
from cowrie.ssh import keys as cowriekeys
from cowrie.ssh import transport as shellTransport
from cowrie.ssh.userauth import HoneyPotSSHUserAuthServer
from cowrie.ssh_proxy import server_transport as proxyTransport
from cowrie.ssh_proxy.userauth import ProxySSHAuthServer

if TYPE_CHECKING:
    from twisted.cred import portal as tp


def _hex_to_int(hex_string: str) -> int:
    return int("".join(hex_string.split()), 16)


@implementer(_kex._IFixedGroupKexAlgorithm)
class _DHGroup14SHA256:
    preference = 8
    hashProcessor = sha256
    prime = _kex._DHGroup14SHA1.prime
    generator = _kex._DHGroup14SHA1.generator


@implementer(_kex._IFixedGroupKexAlgorithm)
class _DHGroup16SHA512:
    preference = 9
    hashProcessor = sha512
    prime = _hex_to_int(
        """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
        ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
        ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
        F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
        43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
        88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
        2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
        287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
        1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
        93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
        FFFFFFFF FFFFFFFF
        """
    )
    generator = 2


@implementer(_kex._IFixedGroupKexAlgorithm)
class _DHGroup18SHA512:
    preference = 10
    hashProcessor = sha512
    prime = _hex_to_int(
        """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
        ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
        ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
        F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
        43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
        88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
        2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
        287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
        1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
        93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
        36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD
        F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831
        179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B
        DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF
        5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6
        D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3
        23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
        CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328
        06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C
        DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE
        12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4
        38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300
        741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568
        3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
        22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B
        4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A
        062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36
        4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1
        B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92
        4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47
        9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
        60C980DD 98EDD3DF FFFFFFFF FFFFFFFF
        """
    )
    generator = 2


def _register_extra_kex_algorithms() -> None:
    extra_algorithms = {
        b"diffie-hellman-group14-sha256": _DHGroup14SHA256(),
        b"diffie-hellman-group16-sha512": _DHGroup16SHA512(),
        b"diffie-hellman-group18-sha512": _DHGroup18SHA512(),
    }
    _kex._kexAlgorithms.update(extra_algorithms)


_register_extra_kex_algorithms()


def _configured_list(option: str) -> list[bytes] | None:
    try:
        return [
            item.encode("utf-8")
            for item in CowrieConfig.get("ssh", option).split(",")
            if item.strip()
        ]
    except (NoOptionError, NoSectionError):
        return None


def _filter_supported(configured: list[bytes] | None, supported: list[bytes]) -> list[bytes]:
    if configured is None:
        return supported[:]

    supported_set = set(supported)
    filtered = [item for item in configured if item in supported_set]
    return filtered or supported[:]


class CowrieSSHFactory(factory.SSHFactory):
    starttime: float | None = None
    privateKeys: dict[bytes, bytes]
    publicKeys: dict[bytes, bytes]
    primes: dict[int, list[tuple[int, int]]] | None = None
    portal: tp.Portal | None = None
    ourVersionString: bytes = CowrieConfig.get(
        "ssh", "version", fallback="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
    ).encode("ascii")

    def __init__(self, backend, pool_handler):
        self.pool_handler = pool_handler
        self.backend: str = backend
        self.privateKeys = {}
        self.publicKeys = {}
        self.services = {
            b"ssh-userauth": (
                ProxySSHAuthServer if self.backend == "proxy" else HoneyPotSSHUserAuthServer
            ),
            b"ssh-connection": connection.CowrieSSHConnection,
        }
        super().__init__()

    def logDispatch(self, **args):
        args["sessionno"] = "S{}".format(args["sessionno"])
        for output in self.tac.output_plugins:
            output.logDispatch(**args)

    def _add_rsa_key_aliases(self, pub: bytes, priv: bytes, requested: list[bytes]) -> None:
        aliases = {b"ssh-rsa", b"rsa-sha2-256", b"rsa-sha2-512"}
        for alias in requested:
            if alias in aliases:
                self.publicKeys[alias] = keys.Key.fromString(data=pub)
                self.privateKeys[alias] = keys.Key.fromString(data=priv)

    def startFactory(self) -> None:
        self.starttime = time.time()

        requested_pubkeys = _configured_list("public_key_auth")
        if requested_pubkeys is None:
            requested_pubkeys = [
                b"rsa-sha2-512",
                b"rsa-sha2-256",
                b"ssh-rsa",
                b"ecdsa-sha2-nistp256",
                b"ssh-ed25519",
            ]

        rsa_requested = any(
            key in requested_pubkeys
            for key in (b"ssh-rsa", b"rsa-sha2-256", b"rsa-sha2-512")
        )
        if rsa_requested:
            rsa_pub, rsa_priv = cowriekeys.getRSAKeys()
            self._add_rsa_key_aliases(rsa_pub, rsa_priv, requested_pubkeys)

        if b"ecdsa-sha2-nistp256" in requested_pubkeys:
            ecdsa_pub, ecdsa_priv = cowriekeys.getECDSAKeys()
            self.publicKeys[b"ecdsa-sha2-nistp256"] = keys.Key.fromString(data=ecdsa_pub)
            self.privateKeys[b"ecdsa-sha2-nistp256"] = keys.Key.fromString(data=ecdsa_priv)

        if b"ssh-ed25519" in requested_pubkeys:
            ed_pub, ed_priv = cowriekeys.geted25519Keys()
            self.publicKeys[b"ssh-ed25519"] = keys.Key.fromString(data=ed_pub)
            self.privateKeys[b"ssh-ed25519"] = keys.Key.fromString(data=ed_priv)

        _modulis = "/etc/ssh/moduli", "/private/etc/moduli"
        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except OSError:
                pass

        self.ourVersionString = CowrieConfig.get(
            "ssh", "version", fallback="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
        ).encode("ascii")

        factory.SSHFactory.startFactory(self)
        log.msg("Ready to accept SSH connections")

    def stopFactory(self) -> None:
        factory.SSHFactory.stopFactory(self)

    def buildProtocol(self, addr):
        t: transport.SSHServerTransport
        if self.backend == "proxy":
            t = proxyTransport.FrontendSSHTransport()
        else:
            t = shellTransport.HoneyPotSSHTransport()

        t.ourVersionString = self.ourVersionString
        t.supportedPublicKeys = list(self.privateKeys.keys())

        supported_kex = _kex.getSupportedKeyExchanges()
        if not self.primes:
            if b"diffie-hellman-group-exchange-sha1" in supported_kex:
                supported_kex.remove(b"diffie-hellman-group-exchange-sha1")
                log.msg("No moduli, no diffie-hellman-group-exchange-sha1")
            if b"diffie-hellman-group-exchange-sha256" in supported_kex:
                supported_kex.remove(b"diffie-hellman-group-exchange-sha256")
                log.msg("No moduli, no diffie-hellman-group-exchange-sha256")
        t.supportedKeyExchanges = _filter_supported(_configured_list("kex"), supported_kex)

        supported_ciphers = t.supportedCiphers[:]
        t.supportedCiphers = _filter_supported(_configured_list("ciphers"), supported_ciphers)

        supported_macs = t.supportedMACs[:]
        t.supportedMACs = _filter_supported(_configured_list("macs"), supported_macs)

        supported_compressions = [b"none", b"zlib@openssh.com", b"zlib"]
        t.supportedCompressions = _filter_supported(
            _configured_list("compression"), supported_compressions
        )

        t.factory = self
        return t
