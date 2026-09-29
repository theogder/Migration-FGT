"""Messages d'erreur de structure et commande diagnose (aucune valeur affichée)."""

from pathlib import Path

import pytest

from fortimig.cli import main
from fortimig.diagnose import diagnose
from fortimig.lexer import Token
from fortimig.model import format_path, walk
from fortimig.parser import ParseError, parse
from fortimig.serializer import serialize

CANARY = "CANARY-SECRET"

# Valeur terminée par un antislash : avec l'hypothèse U1 (\" = guillemet
# échappé), la valeur « déborde » sur les lignes suivantes et décale la
# structure. Cas plausible d'erreur sur une configuration réelle.
TRAILING_BACKSLASH = """config global
config system global
set alias "C:\\CANARY-SECRET-DIR\\"
end
config system interface
edit "CANARY-SECRET-PORT"
set vdom "root"
next
end
end
"""


VDOM_SECTION = """config vdom
edit root
config firewall address
edit "a"
set subnet 192.0.2.0 255.255.255.0
next
end
end
config vdom
edit dmz
config firewall address
edit "b"
next
end
end
"""


def test_vdom_section_closed_by_single_end() -> None:
    # Forme observée sur le backup réel du 300E : pas de « next » avant le
    # « end » qui clôt la section du VDOM.
    doc = parse(VDOM_SECTION)
    assert doc.warnings == []
    assert serialize(doc) == VDOM_SECTION  # aucun « next » ajouté
    paths = [format_path(p) for p, _ in walk(doc.children)]
    assert 'config vdom > edit root > config firewall address > edit "a" > set subnet' in paths
    assert 'config vdom > edit dmz > config firewall address > edit "b"' in paths


def test_renamed_vdom_entry_still_gets_no_next() -> None:
    doc = parse(VDOM_SECTION)
    entry = doc.children[0].children[0]
    entry.key = Token.make("vd1", quoted=False)
    assert serialize(doc).startswith("config vdom\nedit vd1\nconfig firewall address\n")
    assert "next\nend\nend\n" in serialize(doc)


def test_end_closing_edit_outside_vdom_is_accepted_with_warning() -> None:
    text = "config a\nedit 1\nset x 1\nend\n"
    doc = parse(text)
    assert serialize(doc) == text
    assert doc.warnings == [
        "ligne 4 : « end » ferme aussi l'« edit » de la ligne 2 sans « next » "
        "(forme observée seulement sous « config vdom »)"
    ]


def test_diagnose_accepts_vdom_form() -> None:
    lines = diagnose(VDOM_SECTION, line=8, context=10)
    assert not any("ANOMALIE" in l for l in lines)
    assert lines[-1] == "Blocs ouverts en fin de fenêtre : aucun bloc ouvert"


def test_next_with_open_config() -> None:
    with pytest.raises(ParseError) as exc:
        parse("config a\nedit 1\nconfig b\nnext\n")
    assert "le « config » de la ligne 3 n'est pas fermé par « end »" in str(exc.value)


def test_error_reports_last_multiline_value_without_content() -> None:
    with pytest.raises(ParseError) as exc:
        parse(TRAILING_BACKSLASH)
    message = str(exc.value)
    assert "dernière valeur multi-lignes : lignes 3-6" in message
    assert CANARY not in message


def test_silent_overflow_is_warned() -> None:
    # Débordement « équilibré » : la structure reste valide, la valeur est faussée.
    text = 'config system global\nset alias "C:\\CANARY-SECRET\\"\nend\nconfig system dns\nset domain "x"\nend\n'
    doc = parse(text)
    assert doc.warnings == [
        "lignes 2-5 : valeur multi-lignes contenant \\\" en fin de ligne, délimitation incertaine "
        "(vérifier avec « diagnose »)"
    ]


def test_diagnose_shows_structure_and_no_values() -> None:
    lines = diagnose(TRAILING_BACKSLASH, line=8, context=20)
    text = "\n".join(lines)
    assert CANARY not in text and "root" not in text
    assert any("set alias" in l and "valeur sur les lignes 3-6" in l for l in lines)
    assert any("suite de la valeur commencée l. 3" in l for l in lines)
    assert any(l.startswith(">>") and "      8" in l for l in lines)
    assert any("ANOMALIE" in l for l in lines)
    # La ligne "edit" (l. 6) est avalée par la valeur qui déborde : elle
    # apparaît comme suite de valeur, pas comme structure.
    assert "edit <clé>" not in text
    assert any("     6" in l and "suite de la valeur" in l for l in lines)


def test_diagnose_on_unclosed_quote() -> None:
    lines = diagnose('config a\nset x "CANARY-SECRET-OPEN\nset y 1\n', line=2, context=5)
    assert any("ERREUR du lexer : ligne 2" in l for l in lines)
    assert CANARY not in "\n".join(lines)


def test_cli_diagnose(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    conf = tmp_path / "x.conf"
    conf.write_text(TRAILING_BACKSLASH, "utf-8")
    assert main(["diagnose", "--config", str(conf), "--line", "8", "--context", "3"]) == 0
    out = capsys.readouterr().out
    assert "Diagnostic structurel" in out and CANARY not in out
    # La lecture normale échoue avec un message utile et sans contenu.
    assert main(["sanitize", "--config", str(conf), "--out", str(tmp_path / "o.conf")]) == 2
    err = capsys.readouterr().err
    assert "dernière valeur multi-lignes" in err and CANARY not in err
