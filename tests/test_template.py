"""Squelette de mapping.toml (commande mapping-template)."""

import tomllib
from pathlib import Path

import pytest

from fortimig.cli import main
from fortimig.fortios import physical_interfaces
from fortimig.interfaces import validate_mapping
from fortimig.mapping import parse_mapping
from fortimig.parser import parse
from fortimig.report import Category, Report
from fortimig.template import TO_DEFINE, mapping_template
from tests.helpers import FIXTURES, fixture_bytes


def build() -> str:
    source = parse(fixture_bytes("flat.conf").decode())
    target = parse(fixture_bytes("target-default.conf").decode())
    return mapping_template(source, target, "flat.conf", "target-default.conf")


def test_template_lists_every_physical_port_undecided() -> None:
    mapping = parse_mapping(tomllib.loads(build()))
    source = parse(fixture_bytes("flat.conf").decode())
    assert list(mapping.interfaces) == physical_interfaces(source)
    assert set(mapping.interfaces.values()) == {TO_DEFINE}
    assert mapping.hostname is None and mapping.ha_priority_primary is None  # [device] en commentaire


def test_unedited_template_blocks_conversion() -> None:
    source = parse(fixture_bytes("flat.conf").decode())
    target = parse(fixture_bytes("target-default.conf").decode())
    report = Report()
    validate_mapping(source, parse_mapping(tomllib.loads(build())), physical_interfaces(target), report)
    errors = [f for f in report.findings if f.category is Category.ERREUR]
    assert len(errors) >= len(physical_interfaces(source))


def test_template_comments() -> None:
    text = build()
    assert '"port1"       = "A_DEFINIR"  # porte 1 VLAN, 5 référence(s), port de même nom disponible sur la cible' in text
    assert '"port15"      = "A_DEFINIR"  # lien HA (hbdev), 1 référence(s)\n' in text
    assert "# mgmt, ha, port1, port2, port3, port4, port5, port6, x1, x2, modem, npu0_vlink0, npu0_vlink1" in text


def test_cli_never_overwrites(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "mapping.toml"
    args = ["mapping-template", "--source", str(FIXTURES / "flat.conf"),
            "--target-default", str(FIXTURES / "target-default.conf"), "--out", str(out)]
    assert main(args) == 0 and out.read_text("utf-8") == build()
    out.write_text("contenu utilisateur", "utf-8")
    assert main(args) == 2
    assert out.read_text("utf-8") == "contenu utilisateur"
    assert "aucun écrasement" in capsys.readouterr().err


def test_template_shows_roles_of_ports_without_ip() -> None:
    text = build()
    # Ports sans IP mais indispensables : le rôle est affiché pour éviter un « drop » par erreur.
    assert "\"port3\"       = \"A_DEFINIR\"  # membre de l'agrégat « agg-lan »" in text
    assert "membre de la zone « zone-dmz », surveillé par le HA (monitor)" in text
    assert '"npu0_vlink0" = "A_DEFINIR"  # porte 1 VLAN' in text
    assert '"npu0_vlink1" = "A_DEFINIR"  # 0 référence(s)' in text
