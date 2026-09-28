"""Chargement et validation de mapping.toml (SPEC §6, D2, D6)."""

import tomllib
from pathlib import Path

import pytest

from fortimig.mapping import MappingError, load_mapping, parse_mapping

VALID = """
[device]
hostname = "FW-EXEMPLE-01"
hostname_secondary = "FW-EXEMPLE-02"
ha_priority_primary = 200
ha_priority_secondary = 100

[interfaces]
"port1" = "port3"
"port2" = "x1"
"port30" = "drop"

[header]
from_target = ["platform"]
"""


def parse(text: str):
    return parse_mapping(tomllib.loads(text))


def test_valid_mapping() -> None:
    m = parse(VALID)
    assert m.interfaces == {"port1": "port3", "port2": "x1"}
    assert list(m.interfaces) == ["port1", "port2"]  # ordre du fichier
    assert m.dropped == ("port30",)
    assert m.hostname == "FW-EXEMPLE-01" and m.hostname_secondary == "FW-EXEMPLE-02"
    assert (m.ha_priority_primary, m.ha_priority_secondary) == (200, 100)
    assert m.header_from_target == ("platform",)
    assert m.declares("port30") and m.declares("port1") and not m.declares("port9")


def test_minimal_mapping() -> None:
    m = parse('[interfaces]\n"port1" = "port1"\n')
    assert m.hostname is None and m.header_from_target == ()


def test_load_from_file(tmp_path: Path) -> None:
    path = tmp_path / "mapping.toml"
    path.write_text(VALID, "utf-8")
    assert load_mapping(path).interfaces["port2"] == "x1"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[devices]\n", "section(s) inconnue(s)"),
        ('[device]\nhostnam = "x"\n', "clé(s) inconnue(s) dans [device]"),
        ("[device]\nhostname = 3\n", "chaîne non vide"),
        ('[device]\nha_priority_primary = "200"\n', "entier positif"),
        ("[device]\nha_priority_primary = true\n", "entier positif"),
        ("[device]\nha_priority_primary = 100\nha_priority_secondary = 100\n", "doivent différer"),
        ('[interfaces]\n"port 1" = "port1"\n', "source invalide"),
        ('[interfaces]\n"port1" = 3\n', "cible invalide"),
        ('[interfaces]\n"port1" = "x 1"\n', "cible invalide"),
        ('[header]\nfrom_target = "platform"\n', "liste de clés"),
        ('[header]\nfrom_target = ["#platform"]\n', "liste de clés"),
        ('[header]\nautre = 1\n', "clé(s) inconnue(s) dans [header]"),
        ("interfaces = 1\n", "doit être une table"),
    ],
)
def test_invalid_mappings(text: str, message: str) -> None:
    with pytest.raises(MappingError) as exc:
        parse(text)
    assert message in str(exc.value)


def test_toml_syntax_error(tmp_path: Path) -> None:
    path = tmp_path / "mapping.toml"
    path.write_text('[interfaces]\n"port1" = \n', "utf-8")
    with pytest.raises(MappingError, match="syntaxe TOML invalide"):
        load_mapping(path)
