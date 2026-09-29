"""Commande convert de bout en bout (SPEC §8, §9, §10)."""

import json
from pathlib import Path

import pytest

from fortimig.cli import main
from fortimig.parser import parse
from fortimig.report import block_group
from tests.helpers import FIXTURES, fixture_bytes

ROOT = Path(__file__).resolve().parents[1]
CANARY = "CANARY-SECRET"

MAPPING = """
[device]
hostname = "FW-NOUVEAU-01"
hostname_secondary = "FW-NOUVEAU-02"
ha_priority_primary = 250
ha_priority_secondary = 100

[interfaces]
"ha" = "ha"
"mgmt" = "mgmt"
"port1" = "port3"
"port3" = "port5"
"port4" = "port6"
"port2" = "x1"
"port15" = "port1"
"port30" = "drop"
"npu0_vlink0" = "npu0_vlink0"
"npu0_vlink1" = "npu0_vlink1"
"""

# Règle qui fait apparaître le mot de passe HA dans le rapport : il doit y être masqué.
EXTRA_RULE = """
[[rule]]
path = "config system ha"
option = "password"
action = "flag"
reason = "test de masquage"
"""


def source_with_canaries() -> str:
    text = fixture_bytes("flat.conf").decode()
    text = text.replace("FAKE-ENC-BLOB-HA-0006==", "CANARY-SECRET-HA-0001==")
    return text.replace(
        "set vdom-mode multi-vdom\n", "set vdom-mode multi-vdom\nset private-data-encryption enable\n", 1
    )


def setup(tmp_path: Path, mapping: str = MAPPING, source: str | None = None) -> list[str]:
    (tmp_path / "source.conf").write_text(source or source_with_canaries(), "utf-8")
    (tmp_path / "target.conf").write_bytes(fixture_bytes("target-default.conf"))
    (tmp_path / "mapping.toml").write_text(mapping, "utf-8")
    rules = (ROOT / "rules.toml").read_text("utf-8") + EXTRA_RULE
    (tmp_path / "rules.toml").write_text(rules, "utf-8")
    return [
        "convert",
        "--source", str(tmp_path / "source.conf"),
        "--target-default", str(tmp_path / "target.conf"),
        "--mapping", str(tmp_path / "mapping.toml"),
        "--rules", str(tmp_path / "rules.toml"),
        "--out", str(tmp_path / "out"),
    ]


def test_convert_produces_all_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(setup(tmp_path))
    out = tmp_path / "out"
    assert code == 1  # succès avec des A_REVOIR
    assert sorted(p.name for p in out.iterdir()) == [
        "converted.conf", "report.json", "report.md", "secondary-ha.txt",
    ]
    converted = (out / "converted.conf").read_text("utf-8")
    parse(converted)
    assert converted.startswith("#config-version=FGDST0-7.4.9-FW-build9999-000000")
    assert 'edit "port3"\nset vdom "root"\nset type physical\nset speed 1000full' in converted
    # Les secrets restent intacts dans la configuration convertie.
    assert "set password ENC CANARY-SECRET-HA-0001==" in converted
    secondary = (out / "secondary-ha.txt").read_text("utf-8")
    assert "set password <A_RENSEIGNER>" in secondary and "set priority 100" in secondary
    console = capsys.readouterr()
    assert "convert : ERREUR 0, A_REVOIR" in console.out
    assert "private-data-encryption" in console.err


def test_report_json_structure(tmp_path: Path) -> None:
    main(setup(tmp_path))
    data = json.loads((tmp_path / "out" / "report.json").read_text("utf-8"))
    assert data["entrees_fichiers"]["source"] == "source.conf"
    assert data["resume"]["ERREUR"] == 0 and data["resume"]["A_REVOIR"] > 0
    assert data["avertissements"][0].startswith("private-data-encryption est activé")
    total = sum(data["resume"].values())
    assert total == len(data["entrees"])
    entry = next(e for e in data["entrees"] if e["chemin"].endswith("set hbdev"))
    assert entry == {
        "categorie": "MODIFIE",
        "chemin": "config global > config system ha > set hbdev",
        "bloc": "[global] config system ha",
        "message": "référence d'interface mise à jour",
        "avant": 'set hbdev "ha" 0 "port15" 0',
        "apres": 'set hbdev "ha" 0 "port1" 0',
        "raison": None,
    }


def test_report_markdown_layout(tmp_path: Path) -> None:
    main(setup(tmp_path))
    md = (tmp_path / "out" / "report.md").read_text("utf-8")
    assert md.startswith("# Rapport de conversion fortimig\n")
    assert "Conversion effectuée, **points à revoir**." in md
    # Résumé et avertissements en tête, puis catégories du plus urgent au moins urgent.
    positions = [md.index(s) for s in ("## Résumé", "## Avertissements globaux", "## A_REVOIR", "## SUPPRIME", "## MODIFIE")]
    assert positions == sorted(positions)
    assert "### [global] config system interface" in md
    assert "### [root] config firewall policy" in md


@pytest.mark.parametrize("variant", ["success", "error"])
def test_no_secret_leaks_anywhere(tmp_path: Path, capsys: pytest.CaptureFixture[str], variant: str) -> None:
    mapping = MAPPING if variant == "success" else MAPPING.replace('"port4" = "port6"\n', "")
    main(setup(tmp_path, mapping))
    console = capsys.readouterr()
    assert CANARY not in console.out and CANARY not in console.err
    for name in ("report.md", "report.json", "secondary-ha.txt"):
        path = tmp_path / "out" / name
        if path.exists():
            assert CANARY not in path.read_text("utf-8"), name
    md = (tmp_path / "out" / "report.md").read_text("utf-8")
    assert "set password ENC <SECRET-MASQUE>" in md  # la règle de test a bien cité la ligne


def test_blocking_error_writes_no_configuration(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = setup(tmp_path)
    assert main(args) == 1  # première exécution valide : fichiers écrits
    (tmp_path / "mapping.toml").write_text(MAPPING.replace('"port4" = "port6"\n', ""), "utf-8")
    assert main(args) == 2
    out = tmp_path / "out"
    assert not (out / "converted.conf").exists() and not (out / "secondary-ha.txt").exists()
    md = (out / "report.md").read_text("utf-8")
    assert "**ERREUR bloquante : aucune configuration n'a été écrite.**" in md
    assert "converted.conf d'une exécution précédente supprimé" in md
    assert "ERREUR bloquante" in capsys.readouterr().err


def test_convert_is_deterministic(tmp_path: Path) -> None:
    outputs = []
    for run in ("a", "b"):
        base = tmp_path / run
        base.mkdir()
        main(setup(base))
        outputs.append({p.name: p.read_bytes() for p in (base / "out").iterdir()})
    # Les noms de fichiers d'entrée sont identiques ; seuls les chemins diffèrent.
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize(
    ("broken", "message"),
    [
        ("mapping.toml", "mapping.toml : section(s) inconnue(s)"),
        ("rules.toml", "rules.toml : règle n°1"),
    ],
)
def test_invalid_input_files_are_blocking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], broken: str, message: str
) -> None:
    args = setup(tmp_path)
    content = "[autre]\n" if broken == "mapping.toml" else '[[rule]]\npath = "x"\naction = "flag"\nreason = "r"\n'
    (tmp_path / broken).write_text(content, "utf-8")
    assert main(args) == 2
    assert message in capsys.readouterr().err
    assert not (tmp_path / "out" / "converted.conf").exists()


def test_parse_error_in_source_is_blocking(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = setup(tmp_path, source='config a\nset password "CANARY-SECRET-X\n')
    assert main(args) == 2
    err = capsys.readouterr().err
    assert "configuration source" in err and CANARY not in err


@pytest.mark.parametrize(
    ("path", "group"),
    [
        ("config vdom > edit root > config firewall policy > edit 10 > set srcintf", "[root] config firewall policy"),
        ("config global > config system ha > config ha-mgmt-interfaces > edit 1", "[global] config system ha > config ha-mgmt-interfaces"),
        ('config system interface > edit "port1"', "config system interface"),
        ("mapping.toml > [interfaces] > port2", "mapping.toml"),
        ("en-tête > #config-version", "en-tête"),
    ],
)
def test_block_group(path: str, group: str) -> None:
    assert block_group(path) == group


def test_fixtures_directory_contains_no_real_config() -> None:
    # Garde-fou : seules les fixtures synthétiques connues sont présentes.
    assert sorted(p.name for p in FIXTURES.glob("*.conf")) == [
        "flat.conf", "multiline.conf", "multivdom.conf", "secrets.conf", "simple.conf", "target-default.conf",
    ]


def test_port_option_identical_to_target_default_not_flagged(tmp_path: Path) -> None:
    # mgmt : "set dedicated-to management" dans la source ET dans le défaut de la cible.
    main(setup(tmp_path))
    data = json.loads((tmp_path / "out" / "report.json").read_text("utf-8"))
    assert not [e for e in data["entrees"] if e["chemin"].endswith("set dedicated-to")]
    # port1 -> port3 : "set speed 1000full" absent du défaut de port3 : toujours signalé.
    assert [e for e in data["entrees"] if e["chemin"].endswith('edit "port1" > set speed')]
