"""Anonymisation IPv4 : déterminisme, préfixes, classes (SPEC §5.9, D9)."""

import ipaddress
import random

import pytest

from fortimig.ipanon import KEEP, PRIVATE, IPv4Anonymizer, is_netmask


def ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def common_prefix(a: int, b: int) -> int:
    x = a ^ b
    return 32 - x.bit_length()


def classify(addr: int) -> str:
    a = ipaddress.IPv4Address(addr)
    for net in KEEP + PRIVATE:
        if a in net:
            return str(net)
    return "public"


@pytest.fixture
def anon() -> IPv4Anonymizer:
    return IPv4Anonymizer("graine-de-test")


def test_deterministic_across_instances() -> None:
    a, b = IPv4Anonymizer("s1"), IPv4Anonymizer("s1")
    text = "set ip 10.1.2.3 255.255.255.0 gw 203.0.113.9"
    assert a.anonymize(text) == b.anonymize(text)
    assert IPv4Anonymizer("s2").anonymize(text) != a.anonymize(text)


def test_prefix_preservation(anon: IPv4Anonymizer) -> None:
    rng = random.Random(1)
    for _ in range(2000):
        x = rng.getrandbits(32)
        y = x ^ (1 << rng.randrange(32)) if rng.random() < 0.5 else rng.getrandbits(32)
        if classify(x).startswith(("0.", "127.", "224.", "240.")) or classify(y).startswith(
            ("0.", "127.", "224.", "240.")
        ):
            continue
        assert common_prefix(anon.anonymize_int(x), anon.anonymize_int(y)) == common_prefix(x, y)


def test_class_preservation(anon: IPv4Anonymizer) -> None:
    rng = random.Random(2)
    samples = [rng.getrandbits(32) for _ in range(3000)]
    for net in PRIVATE:
        base = int(net.network_address)
        samples += [base + rng.randrange(net.num_addresses) for _ in range(300)]
    for x in samples:
        assert classify(anon.anonymize_int(x)) == classify(x)


def test_special_addresses_unchanged(anon: IPv4Anonymizer) -> None:
    for s in ("0.0.0.0", "127.0.0.1", "224.0.0.5", "239.1.1.1", "255.255.255.255"):
        assert anon.anonymize_int(ip(s)) == ip(s)


def test_bijective_on_a_subnet(anon: IPv4Anonymizer) -> None:
    net = ipaddress.IPv4Network("10.20.0.0/20")
    images = {anon.anonymize_int(int(a)) for a in net}
    assert len(images) == net.num_addresses
    # L'image d'un /20 est elle-même un /20.
    first = min(images)
    assert first % net.num_addresses == 0 and max(images) == first + net.num_addresses - 1


def test_network_address_with_mask_token_stays_a_network(anon: IPv4Anonymizer) -> None:
    pairs = anon.network_pairs(["10.1.2.0", "255.255.255.0"])
    assert list(pairs) == [0]
    net = ipaddress.IPv4Network(f"{pairs[0]}/24")  # strict : bits d'hôte nuls
    host = anon.anonymize("10.1.2.77")
    assert ipaddress.IPv4Address(host) in net
    assert anon.table["10.1.2.0/24"] == f"{pairs[0]}/24"


def test_interface_address_with_mask_is_a_host(anon: IPv4Anonymizer) -> None:
    # "set ip 10.1.2.1 255.255.255.0" : adresse d'hôte, pas de réseau.
    assert anon.network_pairs(["10.1.2.1", "255.255.255.0"]) == {}


def test_cidr_network_stays_a_network(anon: IPv4Anonymizer) -> None:
    out = anon.anonymize("192.168.10.0/24 et 192.168.10.5")
    net_s, _, host_s = out.split()
    net = ipaddress.IPv4Network(net_s)
    assert net.subnet_of(ipaddress.IPv4Network("192.168.0.0/16"))
    assert ipaddress.IPv4Address(host_s) in net


@pytest.mark.parametrize("mask", ["255.255.255.0", "255.255.0.0", "255.255.255.252", "255.255.255.255"])
def test_netmasks_unchanged(anon: IPv4Anonymizer, mask: str) -> None:
    assert is_netmask(ip(mask))
    assert anon.anonymize(mask) == mask


@pytest.mark.parametrize(
    "text",
    ["1.3.6.1.4.1.12356", "7.04", "version 7.4.9", "999.1.1.1", "build2829"],
)
def test_non_addresses_unchanged(anon: IPv4Anonymizer, text: str) -> None:
    assert anon.anonymize(text) == text


def test_cidr_range_and_embedded_forms(anon: IPv4Anonymizer) -> None:
    out = anon.anonymize('"10.0.0.0/24" 10.0.0.1-10.0.0.9 "h-192.168.1.10"')
    assert "10.0.0.0/24" not in out and "/24" in out
    assert "10.0.0.1-" not in out
    assert "192.168.1.10" not in out and '"h-192.168.' in out
    assert set(anon.table) == {"10.0.0.0/24", "10.0.0.1", "10.0.0.9", "192.168.1.10"}
