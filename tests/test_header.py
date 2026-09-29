"""Remplacement de l'en-tête (SPEC §5.2, D1, D2)."""

from fortimig.header import replace_header
from fortimig.mapping import Mapping
from fortimig.parser import parse
from fortimig.report import Category, Report

SRC = (
    "#config-version=FGSRC0-7.4.9-FW-build2829-250924:opmode=0:vdom=1:user=exemple\n"
    "#conf_file_ver=1111\n"
    "#buildno=2829\n"
    "#global_vdom=1\n"
    "\n"
    "config vdom\nedit root\nnext\nend\n"
)


def tgt(version: str = "7.4.9", build: str = "2829", vdom: str = "1", extra: str = "") -> str:
    return (
        f"#config-version=FGDST0-{version}-FW-build{build}-260126:opmode=0:vdom={vdom}:user=admin\n"
        "#conf_file_ver=2222\n"
        f"#buildno={build}\n"
        "#global_vdom=1\n"
        f"{extra}"
        "config vdom\nedit root\nnext\nend\n"
    )


def run(target: str, mapping: Mapping | None = None, source: str = SRC):
    doc = parse(source)
    report = Report()
    replace_header(doc, parse(target), mapping or Mapping(), report)
    return doc, report


def cat(report: Report, category: Category) -> list[tuple[str, str]]:
    return [(f.path, f.message) for f in report.findings if f.category is category]


def test_config_version_replaced_and_rest_kept() -> None:
    doc, report = run(tgt())
    assert [h.text for h in doc.header] == [
        "#config-version=FGDST0-7.4.9-FW-build2829-260126:opmode=0:vdom=1:user=admin\n",
        "#conf_file_ver=1111\n",
        "#buildno=2829\n",
        "#global_vdom=1\n",
    ]  # la ligne vide qui suit le dernier « # » appartient au corps
    (modified,) = [f for f in report.findings if f.category is Category.MODIFIE]
    assert modified.path == "en-tête > #config-version"
    assert modified.before.startswith("FGSRC0-7.4.9") and modified.after.startswith("FGDST0-7.4.9")
    assert cat(report, Category.ERREUR) == []
    # conf_file_ver diffère : conservé mais signalé.
    assert [p for p, _ in cat(report, Category.A_REVOIR)] == ["en-tête > #conf_file_ver"]


def test_vdom_mode_mismatch_is_blocking() -> None:
    # Cas réel : backup du 120G pris en mono-VDOM alors que la source est multi-VDOM.
    _, report = run(tgt(vdom="0"))
    (error,) = cat(report, Category.ERREUR)
    assert "mode VDOM différent : source vdom=1, cible vdom=0" in error[1]


def test_version_mismatch_is_flagged() -> None:
    _, report = run(tgt(version="7.4.11", build="2878"))
    review = [m for _, m in cat(report, Category.A_REVOIR)]
    assert any("source 7.4.9 build 2829, cible 7.4.11 build 2878" in m for m in review)
    assert any("#buildno" in p for p, _ in cat(report, Category.A_REVOIR))
    assert cat(report, Category.ERREUR) == []


def test_from_target_replaces_and_inserts() -> None:
    target = tgt(build="2878", extra="#platform=FORTIGATE-DST0\n")
    doc, report = run(target, Mapping(header_from_target=("buildno", "platform")))
    texts = [h.text for h in doc.header]
    assert "#buildno=2878\n" in texts
    assert texts[1] == "#platform=FORTIGATE-DST0\n"  # insérée après #config-version
    assert not any("#buildno" in p for p, _ in cat(report, Category.A_REVOIR))


def test_from_target_key_missing_in_target() -> None:
    _, report = run(tgt(), Mapping(header_from_target=("platform",)))
    assert ("en-tête > #platform", "#platform demandé par [header] from_target mais absent de target-default.conf") in cat(
        report, Category.A_REVOIR
    )


def test_missing_config_version_is_blocking() -> None:
    _, report = run(tgt(), source="config a\nend\n")
    assert cat(report, Category.ERREUR) == [
        ("en-tête > #config-version", "ligne #config-version absente de la configuration source")
    ]


def test_crlf_header_keeps_line_endings() -> None:
    doc, _ = run(tgt(), source=SRC.replace("\n", "\r\n"))
    assert doc.header[0].text.endswith("user=admin\r\n")
