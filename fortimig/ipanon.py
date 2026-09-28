"""Anonymisation déterministe des adresses IPv4 (SPEC §5.9, décision D9).

Principe (famille Crypto-PAn) : le bit ``i`` de l'adresse est inversé ou non
selon une fonction pseudo-aléatoire (HMAC-SHA256 avec la graine) des ``i``
bits qui le précèdent. Deux adresses qui partagent un préfixe de ``n`` bits
ont donc des images qui partagent exactement ``n`` bits : sous-réseaux,
masques et appartenance d'un hôte à un sous-réseau sont préservés, et la
fonction est bijective (même IP source → même IP de remplacement, sans
collision).

Préservation des classes :
- adresses « spéciales » (``KEEP``) : laissées telles quelles ;
- plages privées (``PRIVATE``) : une adresse privée reste dans la même plage ;
- adresses publiques : restent publiques.
Pour cela, tant que le préfixe courant est un préfixe strict d'une plage
protégée, le bit est conservé ; au-delà, il est permuté. Une adresse hors de
toute plage protégée diverge donc de toutes ces plages avant le premier bit
permuté, et son image reste hors de ces plages.

Les masques de sous-réseau (1 contigus puis 0 contigus, ex. 255.255.255.0)
sont laissés tels quels, où qu'ils apparaissent.

Adresses de réseau : une adresse accompagnée d'un masque (``A/len`` ou
``set subnet A M``) dont les bits d'hôte sont nuls est remplacée par
``f(A) & masque``. Grâce à la préservation des préfixes, c'est exactement le
réseau qui contient l'image de chacun de ses hôtes, et l'image reste
lisible comme une adresse de réseau (ex. ``x.y.z.0/24``).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass, field

DEFAULT_SEED = "fortimig-graine-par-defaut"

# Laissées telles quelles : "ce réseau", loopback, multicast, réservé et
# broadcast limité (240.0.0.0/4 contient 255.255.255.255).
KEEP = tuple(
    ipaddress.IPv4Network(n)
    for n in ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4")
)

# Plages privées ou à usage local : l'image reste dans la même plage.
PRIVATE = tuple(
    ipaddress.IPv4Network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")
)

_PROTECTED = tuple((int(n.network_address), n.prefixlen) for n in KEEP + PRIVATE)

# Adresse IPv4 isolée, avec longueur de préfixe optionnelle : pas précédée
# d'un chiffre ou d'un point, pas suivie d'un chiffre ni d'un ".<chiffre>"
# (évite les OID SNMP et numéros de version).
IPV4_RE = re.compile(
    r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?(?!\d|\.\d)"
)
_FULL_IPV4_RE = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

_ALL_ONES = 0xFFFFFFFF


def is_netmask(addr: int) -> bool:
    inverted = ~addr & _ALL_ONES
    return inverted & (inverted + 1) == 0


def _prefix_mask(plen: int) -> int:
    return (_ALL_ONES << (32 - plen)) & _ALL_ONES if plen else 0


def _to_int(octets: tuple[str, ...]) -> int | None:
    values = [int(o) for o in octets]
    if any(v > 255 for v in values):
        return None
    return (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]


def parse_ipv4(text: str) -> int | None:
    """Adresse si ``text`` est exactement une adresse IPv4, sinon None."""
    match = _FULL_IPV4_RE.fullmatch(text)
    return _to_int(match.groups()) if match else None


def _fmt(addr: int) -> str:
    return str(ipaddress.IPv4Address(addr))


def _top(addr: int, bits: int) -> int:
    return addr >> (32 - bits) if bits else 0


@dataclass(slots=True)
class IPv4Anonymizer:
    seed: str = DEFAULT_SEED
    table: dict[str, str] = field(default_factory=dict)
    _key: bytes = b""
    _cache: dict[tuple[int, int], int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._key = hashlib.sha256(self.seed.encode("utf-8")).digest()

    def _flip(self, length: int, prefix: int) -> int:
        cached = self._cache.get((length, prefix))
        if cached is None:
            digest = hmac.new(self._key, f"{length}/{prefix}".encode(), hashlib.sha256).digest()
            cached = self._cache[(length, prefix)] = digest[0] & 1
        return cached

    def _keep_bit(self, length: int, prefix: int) -> bool:
        """Vrai si le préfixe de ``length`` bits est un préfixe strict d'une plage protégée."""
        return any(
            plen > length and _top(net, length) == prefix for net, plen in _PROTECTED
        )

    def anonymize_int(self, addr: int) -> int:
        for net, plen in _PROTECTED[: len(KEEP)]:
            if _top(addr, plen) == _top(net, plen):
                return addr
        result = 0
        for i in range(32):
            prefix = _top(addr, i)
            bit = (addr >> (31 - i)) & 1
            if not self._keep_bit(i, prefix):
                bit ^= self._flip(i, prefix)
            result = (result << 1) | bit
        return result

    def map_address(self, addr: int, plen: int | None = None) -> str:
        """Image d'une adresse, ou d'une adresse de réseau si ``plen`` est donné.

        L'entrée correspondante est ajoutée à la table (``A`` ou ``A/len``).
        """
        mask = _prefix_mask(plen) if plen is not None else _ALL_ONES
        if plen is not None and plen < 32 and addr & ~mask & _ALL_ONES == 0:
            new = _fmt(self.anonymize_int(addr) & mask)
            original = _fmt(addr)
            if new != original:
                self.table[f"{original}/{plen}"] = f"{new}/{plen}"
            return new
        new = _fmt(self.anonymize_int(addr))
        if new != _fmt(addr):
            self.table[_fmt(addr)] = new
        return new

    def anonymize(self, text: str) -> str:
        """Remplace chaque adresse IPv4 de ``text`` (hors masques)."""

        def repl(match: re.Match[str]) -> str:
            addr = _to_int(match.groups()[:4])
            if addr is None or is_netmask(addr):
                return match.group(0)
            plen_text = match.group(5)
            if plen_text is None:
                return self.map_address(addr)
            plen = int(plen_text)
            if plen > 32:
                return match.group(0)
            return f"{self.map_address(addr, plen)}/{plen_text}"

        return IPV4_RE.sub(repl, text)

    def network_pairs(self, values: list[str]) -> dict[int, str]:
        """Adresses de réseau suivies d'un masque dans une liste de valeurs.

        Ex. ``set subnet 10.1.2.0 255.255.255.0`` : retourne ``{0: image}``.
        Les autres valeurs sont à traiter par ``anonymize``.
        """
        result: dict[int, str] = {}
        for i in range(len(values) - 1):
            addr, mask = parse_ipv4(values[i]), parse_ipv4(values[i + 1])
            if addr is None or mask is None or not is_netmask(mask) or is_netmask(addr):
                continue
            plen = 32 - (~mask & _ALL_ONES).bit_length()
            if plen < 32 and addr & ~mask & _ALL_ONES == 0:
                result[i] = self.map_address(addr, plen)
        return result
