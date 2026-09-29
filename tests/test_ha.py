"""Haute disponibilité et secondary-ha.txt (SPEC §5.6, D6, D7)."""

import tomllib

from fortimig.ha import TO_FILL, apply_ha
from fortimig.interfaces import rename_interfaces
from fortimig.mapping import parse_mapping
from fortimig.model import Command, format_path, walk
from fortimig.parser import parse
from fortimig.report import Category, Report
from fortimig.serializer import serialize
from tests.helpers import fixture_bytes

DEVICE = """
[device]
hostname = "FW-NOUVEAU-01"
hostname_secondary = "FW-NOUVEAU-02"
ha_priority_primary = 250
ha_priority_secondary = 100
"""

FLAT_INTERFACES = """
[interfaces]
"ha" = "ha"
"mgmt" = "mgmt"
"port1" = "port3"
"port3" = "port5"
"port4" = "port6"
"port2" = "x1"
"port15" = "port1"
"port30" = "drop"
"npu0_vlink0" = "drop"
"npu0_vlink1" = "drop"
"""


def mapping(text: str):
    return parse_mapping(tomllib.loads(text))


def values(doc) -> dict[str, list[str]]:
    return {format_path(p): n.values for p, n in walk(doc.children) if isinstance(n, Command)}


def run(fixture: str, text: str):
    doc = parse(fixture_bytes(fixture).decode())
    report = Report()
    secondary = apply_ha(doc, mapping(text), report)
    return doc, report, secondary


def test_primary_hostname_and_priority_applied() -> None:
    doc, report, _ = run("multivdom.conf", DEVICE)
    v = values(doc)
    assert v["config global > config system global > set hostname"] == ["FW-NOUVEAU-01"]
    assert v["config global > config system ha > set priority"] == ["250"]
    modified = {(f.path, f.before, f.after) for f in report.findings if f.category is Category.MODIFIE}
    assert (
        "config global > config system ha > set priority",
        "set priority 200",
        "set priority 250",
    ) in modified


def test_secondary_file_multivdom() -> None:
    _, report, secondary = run("multivdom.conf", DEVICE)
    assert secondary == (
        "config global\n"
        "config system global\n"
        '    set hostname "FW-NOUVEAU-02"\n'
        "end\n"
        "config system ha\n"
        "    set group-id 10\n"
        '    set group-name "HA-EXEMPLE"\n'
        "    set mode a-p\n"
        f"    set password {TO_FILL}\n"
        '    set hbdev "ha1" 50 "ha2" 50\n'
        "    set session-pickup enable\n"
        "    set override disable\n"
        "    set priority 100\n"
        '    set monitor "port1" "port2"\n'
        "    set ha-mgmt-status enable\n"
        "    config ha-mgmt-interfaces\n"
        "        edit 1\n"
        '            set interface "mgmt1"\n'
        "            set gateway 192.0.2.254\n"
        "        next\n"
        "    end\n"
        "end\n"
        "end\n"
    )
    messages = [f.message for f in report.findings if f.category is Category.A_REVOIR]
    assert any("passer le second 120G en multi-VDOM" in m for m in messages)
    assert any("mot de passe HA à renseigner" in m for m in messages)
    parse(secondary)  # le fichier est lui-même parsable


def test_secondary_uses_renamed_interfaces_and_flat_style() -> None:
    doc = parse(fixture_bytes("flat.conf").decode())
    report = Report()
    target = parse(fixture_bytes("target-default.conf").decode())
    from fortimig.fortios import physical_interfaces

    rename_interfaces(doc, mapping(FLAT_INTERFACES), physical_interfaces(target), report)
    secondary = apply_ha(doc, mapping(DEVICE), report)
    assert secondary is not None
    assert 'set hbdev "ha" 0 "port1" 0\n' in secondary  # port15 -> port1
    assert 'set monitor "agg-lan" "x1"\n' in secondary  # port2 -> x1
    assert "\n    " not in secondary  # source sans indentation
    assert "set priority 100\n" in secondary and "set priority 250" not in secondary


def test_no_secret_in_secondary_or_report() -> None:
    _, report, secondary = run("multivdom.conf", DEVICE)
    assert secondary is not None and "FAKE-ENC" not in secondary
    assert "FAKE-ENC" not in repr(report)
    # Le primaire, lui, garde son mot de passe chiffré intact.
    doc, _, _ = run("multivdom.conf", DEVICE)
    assert "set password ENC FAKE-ENC-BLOB-HA-0004==" in serialize(doc)


def test_missing_secondary_settings_are_blocking() -> None:
    _, report, secondary = run("multivdom.conf", '[device]\nhostname = "A"\nha_priority_primary = 200\n')
    assert secondary is None
    assert [(f.path, f.message) for f in report.findings if f.category is Category.ERREUR] == [
        ("mapping.toml > [device]", "hostname_secondary, ha_priority_secondary requis pour produire secondary-ha.txt")
    ]


def test_missing_primary_settings_are_flagged_not_invented() -> None:
    doc, report, _ = run(
        "multivdom.conf", '[device]\nhostname_secondary = "B"\nha_priority_secondary = 100\n'
    )
    v = values(doc)
    assert v["config global > config system global > set hostname"] == ["FW-EXEMPLE-01"]
    assert v["config global > config system ha > set priority"] == ["200"]
    review = [f.message for f in report.findings if f.category is Category.A_REVOIR]
    assert any("hostname absent de mapping.toml" in m for m in review)
    assert any("ha_priority_primary absent" in m for m in review)


def test_no_ha_block() -> None:
    _, report, secondary = run("simple.conf", DEVICE)
    assert secondary is None
    assert any("aucun bloc « config system ha »" in f.message for f in report.findings)


def test_mono_vdom_secondary_has_no_global_wrapper() -> None:
    source = (
        "config system global\n    set hostname \"X\"\nend\n"
        "config system ha\n    set group-id 1\n    set password ENC FAKE-ENC-MONO\nend\n"
    )
    doc = parse(source)
    report = Report()
    secondary = apply_ha(doc, mapping(DEVICE), report)
    assert secondary == (
        'config system global\n    set hostname "FW-NOUVEAU-02"\nend\n'
        f"config system ha\n    set group-id 1\n    set password {TO_FILL}\n    set priority 100\nend\n"
    )
    # Priorité absente de la source : ajoutée au primaire, avant tout sous-bloc.
    assert "    set priority 250\nend\n" in serialize(doc)


def test_override_with_inverted_priorities_is_flagged() -> None:
    text = DEVICE.replace("ha_priority_primary = 250", "ha_priority_primary = 50")
    _, report, _ = run("flat.conf", text)  # flat.conf : override enable
    assert any("deviendra primaire" in f.message for f in report.findings)


def test_nested_priority_is_flagged() -> None:
    source = (
        "config system ha\n    set group-id 1\n    config secondary-vcluster\n"
        "        set priority 50\n    end\nend\n"
    )
    doc = parse(source)
    report = Report()
    apply_ha(doc, mapping(DEVICE), report)
    assert any(
        f.path == "config system ha > config secondary-vcluster > set priority" for f in report.findings
    )
