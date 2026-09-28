"""Commande sanitize (SPEC §5.9) et absence de fuite de secrets (SPEC §10)."""

import ipaddress
import json
from pathlib import Path

import pytest

from fortimig.cli import main
from fortimig.model import Command, Edit, format_path, walk
from fortimig.parser import parse
from fortimig.fortios import physical_interfaces
from fortimig.sanitize import MASKED_LINE, reference_names, sanitize
from fortimig.secrets import SECRET_MARKER
from fortimig.serializer import serialize
from tests.helpers import FIXTURES, fixture_bytes

CANARY = "CANARY-SECRET"


def load_fixture(name: str):
    return parse(fixture_bytes(name).decode())


def values_at(text: str) -> dict[str, list[str]]:
    return {
        format_path(p): n.values for p, n in walk(parse(text).children) if isinstance(n, Command)
    }


def edit_names(text: str) -> list[str]:
    return [n.name for _, n in walk(parse(text).children) if isinstance(n, Edit)]


# --- Secrets seuls ----------------------------------------------------------------


def test_default_masks_secrets_only() -> None:
    doc = load_fixture("secrets.conf")
    result = sanitize(doc)
    text = serialize(result.document)
    assert CANARY not in text
    assert result.secrets_masked == 17
    assert result.ip_table == {} and result.name_table == {}
    # Rien d'autre ne change : noms, IP et mots-clés intacts.
    assert '"radius-canari"' in text and "198.51.100.7" in text and "set action accept" in text
    parse(text)


def test_unknown_lines_are_masked() -> None:
    doc = parse("config a\n    frobnicate CANARY-SECRET-X\n\nend\n")
    result = sanitize(doc)
    assert serialize(result.document) == f"config a\n    {MASKED_LINE}\n\nend\n"
    assert result.lines_masked == 1


# --- Noms ---------------------------------------------------------------------


def test_names_replaced_consistently() -> None:
    result = sanitize(load_fixture("simple.conf"), names=True)
    text = serialize(result.document)
    table = result.name_table
    values = values_at(text)

    # Objets renommés, références cohérentes.
    web, lan = table["srv-web"], table["net-lan"]
    assert web == "firewall-address-0001" and lan == "firewall-address-0002"
    assert values['config firewall addrgrp > edit "firewall-addrgrp-0001" > set member'] == [web, lan]
    assert values["config firewall policy > edit 42 > set dstaddr"] == [web]
    assert values["config firewall policy > edit 42 > set name"] == [table["lan-vers-web"]]
    # Interface logique renommée, références suivies.
    assert values["config firewall policy > edit 42 > set dstintf"] == [table["vlan100"]]
    # Commentaires et hostname remplacés.
    assert values['config firewall address > edit "firewall-address-0001" > set comment'] == [
        table["Serveur l'exemple"]
    ]
    assert table["Serveur l'exemple"].startswith("comment-")
    assert values["config system global > set hostname"] == [table["FW-EXEMPLE-01"]]


def test_names_never_touch_physical_interfaces_builtins_keywords() -> None:
    result = sanitize(load_fixture("simple.conf"), names=True)
    text = serialize(result.document)
    values = values_at(text)
    names = edit_names(text)
    assert {"port1", "port2"} <= set(names)
    agg = result.name_table["agg1"]
    assert agg == "system-interface-0001"
    # Membres physiques d'un agrégat : jamais renommés.
    assert values[f'config system interface > edit "{agg}" > set member'] == ["port3", "port4"]
    assert values["config firewall policy > edit 42 > set srcintf"] == ["port1"]
    assert values["config firewall policy > edit 7 > set srcaddr"] == ["all"]
    assert values["config firewall policy > edit 7 > set schedule"] == ["always"]
    assert values["config firewall policy > edit 42 > set action"] == ["accept"]
    # Services non définis dans le fichier (objets d'usine) : pas de clé d'edit, donc inchangés.
    assert values["config firewall policy > edit 42 > set service"] == ["HTTP", "HTTPS"]
    # Identifiants numériques des policies conservés (l'ordre et les ID sont significatifs).
    assert "42" in names and "7" in names


def test_physical_interfaces_detection() -> None:
    assert physical_interfaces(load_fixture("simple.conf")) == ["port1", "port2"]


def test_keep_names_from_reference() -> None:
    reference = parse(
        "config firewall service custom\n    edit \"HTTP\"\n    next\n    edit \"HTTPS\"\n    next\nend\n"
    )
    keep = reference_names(reference)
    result = sanitize(load_fixture("simple.conf"), names=True, keep_names=keep)
    values = values_at(serialize(result.document))
    assert values["config firewall policy > edit 42 > set service"] == ["HTTP", "HTTPS"]
    assert "HTTP" not in result.name_table


def test_vdom_names_replaced_except_root() -> None:
    result = sanitize(load_fixture("multivdom.conf"), names=True)
    text = serialize(result.document)
    dmz = result.name_table["dmz"]
    assert dmz == "vdom-0001"
    assert "edit root\n" in text and f"edit {dmz}\n" in text
    assert values_at(text)['config global > config system interface > edit "port2" > set vdom'] == [dmz]


def test_group_name_and_secrets_in_ha() -> None:
    result = sanitize(load_fixture("multivdom.conf"), names=True)
    values = values_at(serialize(result.document))
    assert values["config global > config system ha > set group-name"] == [result.name_table["HA-EXEMPLE"]]
    assert values["config global > config system ha > set password"] == ["ENC", SECRET_MARKER]
    assert values["config global > config system ha > set hbdev"] == ["ha1", "50", "ha2", "50"]


def test_identifying_options_are_reported_not_changed() -> None:
    result = sanitize(load_fixture("secrets.conf"), names=True)
    assert any("« dn »" in w for w in result.warnings)
    # Les "server" de la fixture sont des adresses IP : relèvent de --ips.
    assert not any("« server »" in w for w in result.warnings)
    doc = parse('config user ldap\n    edit "l"\n        set server "ldap.exemple.invalid"\n    next\nend\n')
    assert any("« server »" in w for w in sanitize(doc, names=True).warnings)


# --- Adresses IP ----------------------------------------------------------------


def test_ips_replaced_masks_kept_subnets_preserved() -> None:
    result = sanitize(load_fixture("simple.conf"), ips=True, seed="graine-test")
    values = values_at(serialize(result.document))
    ip, mask = values['config system interface > edit "port1" > set ip']
    assert mask == "255.255.255.0" and ip != "192.0.2.1"
    net, net_mask = values['config firewall address > edit "net-lan" > set subnet']
    assert net_mask == "255.255.255.0"
    # 192.0.2.1 (interface) appartient toujours au réseau anonymisé de 192.0.2.0/24.
    assert ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(f"{net}/24")
    host, host_mask = values['config firewall address > edit "srv-web" > set subnet']
    assert host_mask == "255.255.255.255" and host != "203.0.113.10"
    # Adresse entre guillemets (health-check) également remplacée.
    server = values['config system sdwan > config health-check > edit "hc-exemple" > set server']
    assert server != ["192.0.2.254"]
    assert ipaddress.IPv4Address(server[0]) in ipaddress.IPv4Network(f"{net}/24")
    assert "192.0.2.0/24" in result.ip_table


# --- Déterminisme -----------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.conf")))
def test_sanitize_is_deterministic(name: str) -> None:
    outputs = []
    for _ in range(2):
        result = sanitize(load_fixture(name), ips=True, names=True, seed="s")
        outputs.append((serialize(result.document), result.ip_table, result.name_table))
    assert outputs[0] == outputs[1]


# --- CLI et fuites -----------------------------------------------------------------


def run_cli(tmp_path: Path, *extra: str) -> tuple[int, Path]:
    src = tmp_path / "source.conf"
    src.write_bytes(fixture_bytes("secrets.conf"))
    out = tmp_path / "extrait.conf"
    code = main(["sanitize", "--config", str(src), "--out", str(out), *extra])
    return code, out


def test_cli_sanitize_writes_output_and_sensitive_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run_cli(tmp_path, "--ips", "--names", "--seed", "s")
    assert code == 0
    table_path = tmp_path / "extrait.conf.SENSIBLE.json"
    table = json.loads(table_path.read_text("utf-8"))
    assert "SENSIBLE" in table["AVERTISSEMENT"]
    assert table["noms"]["radius-canari"].startswith("user-radius-")
    console = capsys.readouterr()
    assert "SENSIBLE" in console.out
    assert "graine par défaut" not in console.err
    parse(out.read_text("utf-8"))


def test_cli_warns_on_default_seed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run_cli(tmp_path, "--ips")
    assert "graine par défaut" in capsys.readouterr().err


def test_cli_without_options_writes_no_table(tmp_path: Path) -> None:
    code, out = run_cli(tmp_path)
    assert code == 0 and out.exists()
    assert not (tmp_path / "extrait.conf.SENSIBLE.json").exists()


@pytest.mark.parametrize("options", [[], ["--ips"], ["--names"], ["--ips", "--names", "--seed", "s"]])
def test_no_secret_leaks_anywhere(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], options: list[str]
) -> None:
    run_cli(tmp_path, *options)
    console = capsys.readouterr()
    assert CANARY not in console.out and CANARY not in console.err
    for produced in tmp_path.iterdir():
        if produced.name == "source.conf":
            continue
        assert CANARY not in produced.read_text("utf-8"), produced.name


def test_cli_parse_error_is_blocking_and_does_not_leak(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "casse.conf"
    src.write_text('config a\n    set password "CANARY-SECRET-UNCLOSED\n', "utf-8")
    out = tmp_path / "out.conf"
    code = main(["sanitize", "--config", str(src), "--out", str(out)])
    assert code == 2
    assert not out.exists()
    err = capsys.readouterr().err
    assert "ligne 2" in err and CANARY not in err


def test_cli_refuses_to_overwrite_source(tmp_path: Path) -> None:
    src = tmp_path / "source.conf"
    src.write_bytes(fixture_bytes("simple.conf"))
    assert main(["sanitize", "--config", str(src), "--out", str(src)]) == 2
    assert src.read_bytes() == fixture_bytes("simple.conf")
