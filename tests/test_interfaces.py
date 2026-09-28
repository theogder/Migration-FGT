"""Renommage des interfaces (SPEC §5.3, §10)."""

import tomllib

import pytest

from fortimig.fortios import physical_interfaces
from fortimig.interfaces import rename_interfaces
from fortimig.mapping import Mapping, parse_mapping
from fortimig.model import Command, Edit, format_path, walk
from fortimig.parser import parse
from fortimig.report import Category, Report
from fortimig.serializer import serialize
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
"""

G = "config global > config system interface"
R = "config vdom > edit root"


def mapping(text: str = MAPPING, **replace: str) -> Mapping:
    data = tomllib.loads(text)
    for key, value in replace.items():
        if value is None:
            data["interfaces"].pop(key)
        else:
            data["interfaces"][key] = value
    return parse_mapping(data)


def target_ports() -> list[str]:
    return physical_interfaces(parse(fixture_bytes("target-default.conf").decode()))


def convert(m: Mapping | None = None, source: str | None = None, targets: list[str] | None = None):
    doc = parse(source if source is not None else fixture_bytes("flat.conf").decode())
    report = Report()
    rename_interfaces(doc, m or mapping(), targets if targets is not None else target_ports(), report)
    return doc, report


def values(doc) -> dict[str, list[str]]:
    return {format_path(p): n.values for p, n in walk(doc.children) if isinstance(n, Command)}


def edits(doc, block_path: str) -> list[str]:
    return [
        n.name
        for p, n in walk(doc.children)
        if isinstance(n, Edit) and format_path(p[:-1]) == block_path
    ]


def findings(report: Report, category: Category) -> list[tuple[str, str]]:
    return [(f.path, f.message) for f in report.findings if f.category is category]


# --- Cas nominal sur la fixture au format observé -----------------------------------


def test_nominal_conversion_has_no_error() -> None:
    _, report = convert()
    assert findings(report, Category.ERREUR) == []


def test_physical_keys_renamed_simultaneously() -> None:
    doc, _ = convert()
    # port1 -> port3 et port3 -> port5 : jamais port1 -> port5 ; port15 -> port1.
    assert edits(doc, G) == [
        "ha", "mgmt", "port3", "x1", "port5", "port6", "port1", "agg-lan", "vlan-srv", "vlan-p1",
    ]


def test_references_updated() -> None:
    doc, _ = convert()
    v = values(doc)
    assert v[f'{G} > edit "agg-lan" > set member'] == ["port5", "port6"]
    assert v[f'{G} > edit "vlan-p1" > set interface'] == ["port3"]  # parent du VLAN
    assert v[f'{G} > edit "vlan-srv" > set interface'] == ["agg-lan"]  # logique : inchangé
    assert v["config global > config system ha > set hbdev"] == ["ha", "0", "port1", "0"]
    assert v["config global > config system ha > set monitor"] == ["agg-lan", "x1"]
    assert v[f'{R} > config system zone > edit "zone-dmz" > set interface'] == ["x1", "vlan-p1"]
    assert v[f'{R} > config firewall vip > edit "vip-web" > set extintf'] == ["x1"]
    assert v[f"{R} > config router static > edit 1 > set device"] == ["x1"]
    assert v[f"{R} > config firewall policy > edit 10 > set srcintf"] == ["port3"]
    assert v[f"{R} > config firewall policy > edit 20 > set dstintf"] == ["x1"]
    assert edits(doc, f"{R} > config system dns-server") == ["port3"]
    # "member" d'un groupe d'adresses : jamais traité comme une interface.
    assert v[f'{R} > config firewall addrgrp > edit "grp-exemple" > set member'] == ["net-srv"]


def test_logical_interfaces_keep_their_names() -> None:
    doc, _ = convert()
    assert {"agg-lan", "vlan-srv", "vlan-p1"} <= set(edits(doc, G))


def test_dropped_interface_removed_and_references_flagged() -> None:
    doc, report = convert()
    assert "port30" not in edits(doc, G)
    assert findings(report, Category.SUPPRIME) == [
        (f'{G} > edit "port30"', "interface physique « port30 » supprimée")
    ]
    review = findings(report, Category.A_REVOIR)
    # Référence dans un attribut couvert : non modifiée, signalée.
    assert (
        f"{R} > config firewall policy > edit 20 > set srcintf",
        "référence vers « port30 » (interface abandonnée : drop)",
    ) in review
    assert values(doc)[f"{R} > config firewall policy > edit 20 > set srcintf"] == ["port30"]


def test_uncovered_references_flagged_not_modified() -> None:
    doc, report = convert()
    v = values(doc)
    vwp = f'{R} > config system virtual-wire-pair > edit "vwp-exemple" > set member'
    comments = f"{R} > config firewall policy > edit 10 > set comments"
    assert v[vwp] == ["port30", "port1"]
    assert v[comments] == ["port1"]
    uncovered = [f for f in report.findings if "référence non couverte" in f.message]
    assert sorted(f.path for f in uncovered) == sorted([vwp, vwp, comments])
    assert all(f.category is Category.A_REVOIR for f in uncovered)
    assert any("renommée en « port3 »" in f.message for f in uncovered if f.path == comments)


def test_port_specific_options_flagged() -> None:
    _, report = convert()
    review = findings(report, Category.A_REVOIR)
    speed = [r for r in review if r[0].endswith("set speed")]
    assert speed == [(f'{G} > edit "port1" > set speed', "port1 -> port3 : vitesse / duplex "
                      "dépendant du type de port cible (RJ45, SFP, SFP+)")]
    snmp = [r for r in review if r[0].endswith("set snmp-index")]
    # Tous les ports mappés, y compris à l'identique (ha, mgmt) ; pas le port abandonné.
    assert len(snmp) == 7
    assert not any("port30" in r[0] for r in snmp)


def test_modifications_are_reported_with_before_after() -> None:
    _, report = convert()
    renamed = [f for f in report.findings if f.message == "interface renommée"]
    assert [(f.before, f.after) for f in renamed] == [
        ("port1", "port3"), ("port2", "x1"), ("port3", "port5"), ("port4", "port6"), ("port15", "port1"),
    ]
    hbdev = next(f for f in report.findings if f.path.endswith("set hbdev"))
    assert hbdev.before == 'set hbdev "ha" 0 "port15" 0'
    assert hbdev.after == 'set hbdev "ha" 0 "port1" 0'


def test_report_never_contains_secrets() -> None:
    _, report = convert()
    dump = repr(report)
    assert "FAKE-ENC" not in dump


def test_flat_output_stays_flat_and_parsable() -> None:
    doc, _ = convert()
    text = serialize(doc)
    assert 'edit "port3"\nset vdom "root"\n' in text
    assert "\n    " not in text
    parse(text)


def test_identity_mapping_changes_nothing() -> None:
    identity = "[interfaces]\n" + "".join(
        f'"{p}" = "{p}"\n' for p in ["ha", "mgmt", "port1", "port2", "port3", "port4", "port15", "port30"]
    )
    targets = ["ha", "mgmt", "port1", "port2", "port3", "port4", "port15", "port30"]
    doc, report = convert(mapping(identity), targets=targets)
    assert serialize(doc) == fixture_bytes("flat.conf").decode()
    assert findings(report, Category.MODIFIE) == []
    assert not any("non couverte" in f.message for f in report.findings)


# --- Renommages croisés et circulaires ------------------------------------------


CYCLE_SOURCE = """config system interface
    edit "a"
        set type physical
    next
    edit "b"
        set type physical
    next
    edit "c"
        set type physical
    next
end
config firewall policy
    edit 1
        set srcintf "a" "b" "c"
        set dstintf "c"
    next
end
"""


@pytest.mark.parametrize(
    ("table", "expected_keys", "expected_src"),
    [
        ({"a": "b", "b": "c", "c": "a"}, ["b", "c", "a"], ["b", "c", "a"]),  # circulaire
        ({"a": "b", "b": "a", "c": "c"}, ["b", "a", "c"], ["b", "a", "c"]),  # échange
        ({"a": "b", "b": "c", "c": "d"}, ["b", "c", "d"], ["b", "c", "d"]),  # chaîne
    ],
)
def test_simultaneous_rename(table: dict[str, str], expected_keys: list[str], expected_src: list[str]) -> None:
    m = parse_mapping({"interfaces": table})
    doc, report = convert(m, CYCLE_SOURCE, targets=["a", "b", "c", "d"])
    assert findings(report, Category.ERREUR) == []
    assert edits(doc, "config system interface") == expected_keys
    v = values(doc)
    assert v["config firewall policy > edit 1 > set srcintf"] == expected_src
    assert v["config firewall policy > edit 1 > set dstintf"] == [table["c"]]


# --- Erreurs bloquantes -----------------------------------------------------------


def test_unmapped_physical_interface_is_blocking() -> None:
    _, report = convert(mapping(port4=None))
    assert findings(report, Category.ERREUR) == [
        (f'{G} > edit "port4"', "interface physique « port4 » absente du mapping "
         '(la mapper vers un port du 120G ou la déclarer "drop")')
    ]
    assert report.exit_code() == 2


def test_missing_target_is_blocking() -> None:
    _, report = convert(mapping(port2="x9"))
    assert findings(report, Category.ERREUR) == [
        ("mapping.toml > [interfaces] > port2",
         "interface cible « x9 » absente des ports physiques de target-default.conf")
    ]


def test_duplicate_target_is_blocking() -> None:
    _, report = convert(mapping(port4="x1"))
    errors = findings(report, Category.ERREUR)
    assert [p for p, _ in errors] == [
        "mapping.toml > [interfaces] > port4",
        "mapping.toml > [interfaces] > port2",
    ]
    assert all("attribuée plusieurs fois" in m for _, m in errors)


def test_logical_interface_in_mapping_is_blocking() -> None:
    _, report = convert(mapping(**{"vlan-srv": "x2"}))
    assert any(
        p == "mapping.toml > [interfaces] > vlan-srv" and "interface logique" in m
        for p, m in findings(report, Category.ERREUR)
    )


def test_target_clashing_with_logical_name_is_blocking() -> None:
    targets = target_ports() + ["vlan-p1"]
    _, report = convert(mapping(port2="vlan-p1"), targets=targets)
    assert any("déjà porté par une interface logique" in m for _, m in findings(report, Category.ERREUR))


def test_mapping_entry_without_source_interface_is_flagged() -> None:
    _, report = convert(mapping(port99="drop"))
    assert ("mapping.toml > [interfaces] > port99", "« port99 » n'existe pas dans la configuration source") in findings(
        report, Category.A_REVOIR
    )
    assert findings(report, Category.ERREUR) == []


def test_vlan_without_type_is_not_physical() -> None:
    # vlan-p1 n'a pas de "set type" mais a un vlanid (hypothèse U2) : pas besoin de mapping.
    assert "vlan-p1" not in physical_interfaces(parse(fixture_bytes("flat.conf").decode()))


def test_uncovered_edit_key_is_flagged() -> None:
    source = CYCLE_SOURCE + 'config router multicast\n    config interface\n        edit "a"\n        next\n    end\nend\n'
    m = parse_mapping({"interfaces": {"a": "b", "b": "a", "c": "c"}})
    doc, report = convert(m, source, targets=["a", "b", "c"])
    path = 'config router multicast > config interface > edit "a"'
    assert (path, "référence non couverte : clé d'edit égale à « a » (renommée en « b »), non modifiée") in findings(
        report, Category.A_REVOIR
    )
    assert edits(doc, "config router multicast > config interface") == ["a"]
