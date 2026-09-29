"""Configuration par défaut du modèle cible (SPEC §5.5, D4, D5)."""

import tomllib

from fortimig.fortios import interface_entries, physical_interfaces
from fortimig.interfaces import rename_interfaces
from fortimig.mapping import parse_mapping
from fortimig.model import Edit, format_path
from fortimig.parser import parse
from fortimig.report import Category, Report
from fortimig.serializer import serialize
from fortimig.target import apply_target_defaults
from tests.helpers import fixture_bytes

MAPPING = """
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

G = "config global > config system interface"


def convert(source: str = "flat.conf"):
    doc = parse(fixture_bytes(source).decode())
    target = parse(fixture_bytes("target-default.conf").decode())
    mapping = parse_mapping(tomllib.loads(MAPPING))
    report = Report()
    rename_interfaces(doc, mapping, physical_interfaces(target), report)
    apply_target_defaults(doc, target, mapping, report)
    return doc, report


def names(doc) -> list[str]:
    return [e.name for _, e in interface_entries(doc)]


def review(report: Report) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in report.findings:
        if f.category is Category.A_REVOIR:
            out.setdefault(f.path, []).append(f.message)
    return out


def test_unused_target_ports_inserted_after_last_physical() -> None:
    doc, report = convert()
    assert names(doc) == [
        "ha", "mgmt", "port3", "x1", "port5", "port6", "port1",
        "port2", "port4", "x2", "modem", "npu0_vlink0", "npu0_vlink1",  # non utilisés, ordre de la cible
        "agg-lan", "vlan-srv", "vlan-p1", "vlan-lacp", "vlan-ivdom",
    ]
    added = [f.after for f in report.findings if f.category is Category.MODIFIE and "non utilisé" in f.message]
    assert added == ["port2", "port4", "x2", "modem", "npu0_vlink0", "npu0_vlink1"]
    assert not any(f.category is Category.ERREUR for f in report.findings)


def test_inserted_blocks_follow_converted_style() -> None:
    doc, _ = convert()
    text = serialize(doc)
    # flat.conf n'est pas indenté : les blocs repris de la cible non plus.
    assert 'edit "x2"\nset vdom "root"\nset type physical\nset mediatype sr\n' in text
    parse(text)


def test_unused_port_with_default_admin_access_is_flagged() -> None:
    _, report = convert()
    r = review(report)
    assert any("accès administratif" in m for m in r[f'{G} > edit "port2"'])
    assert f'{G} > edit "modem"' not in r  # status down : pas d'exposition
    assert f'{G} > edit "port4"' not in r


def test_default_options_not_carried_on_mapped_ports() -> None:
    _, report = convert()
    r = review(report)
    x1 = r['config global > config system interface > edit "x1"']
    assert any(
        "port2 -> x1 : options du bloc par défaut du 120G non reprises" in m
        and "set mediatype sr" in m and "set speed 10000full" in m
        for m in x1
    )
    port1 = r['config global > config system interface > edit "port1"']
    assert any("set mode dhcp" in m for m in port1)
    assert not any("non reprises" in m for m in r.get(f'{G} > edit "ha"', []))


def test_disappearing_default_objects_flagged() -> None:
    _, report = convert()
    r = review(report)
    assert any("« lan » (type hard-switch)" in m for m in r[f'{G} > edit "lan"'])
    assert any("« fortilink » (type aggregate)" in m for m in r[f'{G} > edit "fortilink"'])
    assert 'config global > config system virtual-switch > edit "lan"' in r
    assert 'config global > config system physical-switch > edit "sw0"' in r
    dhcp = r["config vdom > edit root > config system dhcp server > edit 1"]
    assert dhcp == ["entrée par défaut du 120G absente de la configuration convertie : elle disparaîtra à la restauration"]
    before = next(f.before for f in report.findings if f.path.endswith("config system dhcp server > edit 1"))
    assert before == 'set interface "lan"'


def test_default_object_replaced_by_source_entry() -> None:
    source = fixture_bytes("flat.conf").decode().replace(
        "config firewall policy\n",
        'config system dhcp server\nedit 1\nset interface "vlan-srv"\nnext\nend\nconfig firewall policy\n',
        1,
    )
    doc = parse(source)
    target = parse(fixture_bytes("target-default.conf").decode())
    mapping = parse_mapping(tomllib.loads(MAPPING))
    report = Report()
    apply_target_defaults(doc, target, mapping, report)
    assert review(report)["config vdom > edit root > config system dhcp server > edit 1"] == [
        "entrée par défaut du 120G remplacée par l'entrée de même nom de la source"
    ]


def test_name_collision_with_unused_port_is_blocking() -> None:
    doc = parse(fixture_bytes("flat.conf").decode().replace('edit "agg-lan"', 'edit "port4"', 1))
    target = parse(fixture_bytes("target-default.conf").decode())
    mapping = parse_mapping(tomllib.loads(MAPPING))
    report = Report()
    apply_target_defaults(doc, target, mapping, report)
    errors = [(f.path, f.message) for f in report.findings if f.category is Category.ERREUR]
    assert (
        f'{G} > edit "port4"',
        "port « port4 » du 120G non mappé, mais ce nom est déjà porté par une interface "
        "de la configuration convertie",
    ) in errors


def test_no_secret_in_target_findings() -> None:
    _, report = convert()
    assert "FAKE-ENC" not in repr(report)
    assert all(isinstance(e, Edit) for _, e in interface_entries(convert()[0]))
    assert format_path(("a", "b")) == "a > b"


def test_duplicate_snmp_index_flagged() -> None:
    # Source : port2 (index 4) -> x1 ; cible : port2 non utilisé, repris avec son index 4.
    _, report = convert()
    dup = [(f.path, f.message) for f in report.findings if "index SNMP" in f.message]
    assert (
        f'{G} > edit "x1" > set snmp-index',
        "index SNMP 4 porté par plusieurs interfaces (« x1 », « port2 ») : à renuméroter",
    ) in dup
    assert all(f.category is Category.A_REVOIR for f in report.findings if "index SNMP" in f.message)
