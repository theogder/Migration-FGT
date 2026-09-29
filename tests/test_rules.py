"""Règles rules.toml (SPEC §5.4)."""

import tomllib
from pathlib import Path

import pytest

from fortimig.model import Command, format_path, walk
from fortimig.parser import parse
from fortimig.report import Category, Report
from fortimig.rules import RulesError, apply_rules, load_rules, parse_rules
from fortimig.serializer import serialize
from tests.helpers import fixture_bytes

ROOT = Path(__file__).resolve().parents[1]

SOURCE = """config global
config system npu
    set dedicated-management-cpu enable
end
config system global
    set hostname "X"
    set exemple-option 1
end
end
config vdom
edit root
config router ospf
    config ospf-interface
        edit "o1"
            set interface "port1"
            set cost 10
        next
    end
end
config firewall policy
    edit 1
        set name "a"
        set exemple-policy-option enable
    next
    edit 2
        set exemple-policy-option disable
    next
end
end
"""


def rules(text: str):
    return parse_rules(tomllib.loads(text))


def run(text: str, source: str = SOURCE):
    doc = parse(source)
    report = Report()
    apply_rules(doc, rules(text), report)
    return doc, report


def test_remove_block_everywhere() -> None:
    doc, report = run('[[rule]]\npath = "config system npu"\naction = "remove"\nreason = "NP6"\n')
    assert "config system npu" not in serialize(doc)
    (f,) = report.findings
    assert (f.category, f.path, f.reason) == (Category.SUPPRIME, "config global > config system npu", "NP6")


def test_flag_block_changes_nothing() -> None:
    doc, report = run('[[rule]]\npath = "config system npu"\naction = "flag"\nreason = "à voir"\n')
    assert serialize(doc) == SOURCE
    assert [(f.category, f.message) for f in report.findings] == [(Category.A_REVOIR, "bloc signalé par règle")]


def test_remove_option_in_block_and_edits() -> None:
    doc, report = run(
        '[[rule]]\npath = "config firewall policy"\noption = "exemple-policy-option"\n'
        'action = "remove"\nreason = "absent du 120G"\n'
    )
    assert "exemple-policy-option" not in serialize(doc)
    assert [f.path for f in report.findings] == [
        "config vdom > edit root > config firewall policy > edit 1 > set exemple-policy-option",
        "config vdom > edit root > config firewall policy > edit 2 > set exemple-policy-option",
    ]
    assert report.findings[0].before == "set exemple-policy-option enable"


def test_nested_path_ignores_edit_levels() -> None:
    doc, report = run(
        '[[rule]]\npath = "config router ospf > config ospf-interface"\noption = "cost"\n'
        'action = "flag"\nreason = "r"\n'
    )
    assert [f.path for f in report.findings] == [
        'config vdom > edit root > config router ospf > config ospf-interface > edit "o1" > set cost'
    ]


def test_option_rule_on_global_block() -> None:
    doc, _ = run(
        '[[rule]]\npath = "config system global"\noption = "exemple-option"\naction = "remove"\nreason = "r"\n'
    )
    values = {format_path(p) for p, n in walk(doc.children) if isinstance(n, Command)}
    assert "config global > config system global > set exemple-option" not in values
    assert "config global > config system global > set hostname" in values


def test_rule_without_match_is_a_global_warning() -> None:
    _, report = run('[[rule]]\npath = "config system inexistant"\naction = "flag"\nreason = "r"\n')
    assert report.findings == []
    assert report.warnings == [
        "règle n°1 (flag config system inexistant) : aucune correspondance dans la configuration source"
    ]


def test_identical_blocks_removed_by_identity() -> None:
    source = "config a\nend\nconfig system npu\nend\nconfig system npu\nend\n"
    doc, report = run('[[rule]]\npath = "config system npu"\naction = "remove"\nreason = "r"\n', source)
    assert serialize(doc) == "config a\nend\n"
    assert len(report.findings) == 2


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('[[rule]]\npath = "system npu"\naction = "flag"\nreason = "r"\n', "suite de « config"),
        ('[[rule]]\npath = "config system npu"\naction = "delete"\nreason = "r"\n', "remove ou flag"),
        ('[[rule]]\npath = "config system npu"\naction = "flag"\n', "« reason » manquante"),
        ('[[rule]]\npath = "config system npu"\naction = "flag"\nreason = "r"\nautre = 1\n', "clé(s) inconnue(s)"),
        ('[[rule]]\npath = "config a"\noption = "a b"\naction = "flag"\nreason = "r"\n', "« option » invalide"),
        ('regle = 1\n', "clé(s) inconnue(s)"),
    ],
)
def test_invalid_rules(text: str, message: str) -> None:
    with pytest.raises(RulesError) as exc:
        rules(text)
    assert message in str(exc.value)


def test_repository_rules_file_is_valid_and_only_flags() -> None:
    loaded = load_rules(ROOT / "rules.toml")
    assert loaded and all(r.action == "flag" for r in loaded)
    doc = parse(fixture_bytes("target-default.conf").decode())
    report = Report()
    apply_rules(doc, loaded, report)
    assert [f.path for f in report.findings] == ["config global > config system npu"]
