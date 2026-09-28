"""Parser / sérialiseur : round-trip et structure de l'arbre (SPEC §5.1, §10)."""

from pathlib import Path

import pytest

from fortimig.lexer import Token, iter_logical_lines
from fortimig.model import Command, ConfigBlock, Edit, RawLine, format_path, walk
from fortimig.parser import ParseError, parse, parse_bytes
from fortimig.serializer import serialize

from tests.helpers import FIXTURES, fixture_bytes

ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.conf"))


def roundtrip(data: bytes) -> bytes:
    return serialize(parse_bytes(data)).encode("utf-8", "surrogateescape")


# --- Round-trip ----------------------------------------------------------------


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_roundtrip_fixtures(name: str) -> None:
    data = fixture_bytes(name)
    assert roundtrip(data) == data


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_roundtrip_crlf(name: str) -> None:
    data = fixture_bytes(name).replace(b"\n", b"\r\n")
    assert roundtrip(data) == data


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_roundtrip_without_final_newline(name: str) -> None:
    data = fixture_bytes(name).rstrip(b"\n")
    assert roundtrip(data) == data


def test_roundtrip_irregular_whitespace_and_invalid_utf8() -> None:
    data = (
        b"#config-version=X\n"
        b"config system global\n"
        b"\tset alias   \"a  b\"   \n"
        b"    set description \"caf\xe9 latin-1\"\n"
        b"\n"
        b"end\n"
        b"   \n"
    )
    assert roundtrip(data) == data


def test_roundtrip_empty_file() -> None:
    assert roundtrip(b"") == b""


# --- Découpage en jetons ---------------------------------------------------------


def test_escaped_quotes_are_decoded() -> None:
    (line,) = iter_logical_lines('set description "Lien \\"principal\\" et \\\\ ok"\n')
    assert [t.value for t in line.tokens] == ["set", "description", 'Lien "principal" et \\ ok']
    assert line.tokens[2].quoted


def test_unknown_backslash_sequence_is_kept_literally() -> None:
    (line,) = iter_logical_lines('set x "a\\nb"\n')
    assert line.tokens[2].value == "a\\nb"


def test_apostrophe_is_not_a_quote() -> None:
    lines = list(iter_logical_lines("set comment l'exemple\nset x y\n"))
    assert len(lines) == 2
    assert lines[0].tokens[2].value == "l'exemple"


def test_multiline_value_spans_lines() -> None:
    text = 'set certificate "-----BEGIN-----\nFAKE\n-----END-----"\nset range global\n'
    lines = list(iter_logical_lines(text))
    assert len(lines) == 2
    assert lines[0].tokens[2].value == "-----BEGIN-----\nFAKE\n-----END-----"
    assert (lines[0].line, lines[0].end_line) == (1, 3)
    assert lines[1].line == 4


def test_token_make_escapes() -> None:
    tok = Token.make('a "b" \\c')
    assert tok.text == '"a \\"b\\" \\\\c"'
    (line,) = iter_logical_lines(f"set x {tok.text}\n")
    assert line.tokens[2].value == 'a "b" \\c'
    with pytest.raises(ValueError):
        Token.make("a b", quoted=False)


# --- Structure de l'arbre ---------------------------------------------------------


def test_header_is_separated_from_body() -> None:
    doc = parse(fixture_bytes("simple.conf").decode())
    assert [h.text.split("=")[0] for h in doc.header] == [
        "#config-version",
        "#conf_file_ver",
        "#buildno",
        "#global_vdom",
    ]
    assert isinstance(doc.children[0], ConfigBlock)


def test_lists_and_order_preserved() -> None:
    doc = parse(fixture_bytes("simple.conf").decode())
    policy = next(c for c in doc.children if isinstance(c, ConfigBlock) and c.name == "firewall policy")
    edits = [c for c in policy.children if isinstance(c, Edit)]
    assert [e.name for e in edits] == ["42", "7"]  # ordre du fichier, pas l'ordre numérique
    service = next(c for c in edits[0].children if isinstance(c, Command) and c.option == "service")
    assert service.values == ["HTTP", "HTTPS"]
    unset = next(c for c in edits[1].children if isinstance(c, Command) and c.verb == "unset")
    assert unset.option == "logtraffic" and unset.args == []


def test_deep_nesting_paths() -> None:
    doc = parse(fixture_bytes("simple.conf").decode())
    paths = {format_path(p): n for p, n in walk(doc.children)}
    key = (
        'config system sdwan > config health-check > edit "hc-exemple" > '
        "config sla > edit 1 > set latency-threshold"
    )
    assert isinstance(paths[key], Command)
    assert paths[key].values == ["100"]


def test_multiline_value_is_not_parsed_as_structure() -> None:
    doc = parse(fixture_bytes("multiline.conf").decode())
    paths = [format_path(p) for p, _ in walk(doc.children)]
    # Le script contient "config system global" / "end" à l'intérieur d'une valeur.
    assert 'config system automation-action > edit "script-exemple" > set script' in paths
    assert not any(p.startswith("config system automation-action > config") for p in paths)
    script = next(
        n for p, n in walk(doc.children) if isinstance(n, Command) and n.option == "script"
    )
    assert script.values[0].splitlines() == ["config system global", "set admin-timeout 30", "end"]


def test_multivdom_structure() -> None:
    doc = parse(fixture_bytes("multivdom.conf").decode())
    top = [c.name for c in doc.children if isinstance(c, ConfigBlock)]
    assert top == ["vdom", "global", "vdom"]
    paths = {format_path(p) for p, _ in walk(doc.children)}
    assert "config global > config system ha > set hbdev" in paths
    assert (
        "config global > config system ha > config ha-mgmt-interfaces > edit 1 > set interface"
        in paths
    )
    assert "config vdom > edit dmz > config firewall address > edit \"net-dmz\" > set subnet" in paths


def test_line_numbers() -> None:
    doc = parse(fixture_bytes("simple.conf").decode())
    first = doc.children[0]
    assert isinstance(first, ConfigBlock)
    assert (first.line, first.end_line) == (5, 9)


# --- Erreurs de structure -----------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("config system global\n    set x 1\n", 1),  # bloc jamais fermé
        ("next\n", 1),
        ("config a\nend\nend\n", 3),
        ("config a\n    edit 1\nend\n", 3),  # "end" alors qu'un edit est ouvert
        ("edit 1\nnext\n", 1),
        ("set x 1\n", 1),
        ('config a\n    set x "jamais ferme\n    set y 2\nend\n', 2),
    ],
)
def test_structure_errors(text: str, line: int) -> None:
    with pytest.raises(ParseError) as exc:
        parse(text)
    assert exc.value.line == line


def test_errors_never_echo_line_content() -> None:
    with pytest.raises(ParseError) as exc:
        parse('config a\n    set password "CANARY-SECRET-UNCLOSED\n')
    assert "CANARY" not in str(exc.value)


def test_unknown_line_is_kept_and_warned() -> None:
    text = "config a\n    frobnicate CANARY-SECRET-X\nend\n"
    doc = parse(text)
    block = doc.children[0]
    assert isinstance(block, ConfigBlock)
    assert isinstance(block.children[0], RawLine) and block.children[0].unknown
    assert doc.warnings == ["ligne 2 : ligne non reconnue, conservée telle quelle"]
    assert serialize(doc) == text


# --- Régénération des nœuds modifiés ------------------------------------------------


def test_modified_command_is_regenerated_only_there() -> None:
    original = fixture_bytes("simple.conf").decode()
    doc = parse(original)
    for _, node in walk(doc.children):
        if isinstance(node, Command) and node.option == "srcintf" and node.values == ["port1"]:
            node.args = [Token.make("port9")]
    result = serialize(doc)
    diff = [(a, b) for a, b in zip(original.splitlines(), result.splitlines()) if a != b]
    assert diff == [('        set srcintf "port1"', '        set srcintf "port9"')]


def test_renamed_edit_keeps_children_raw() -> None:
    doc = parse(fixture_bytes("simple.conf").decode())
    iface = next(c for c in doc.children if isinstance(c, ConfigBlock) and c.name == "system interface")
    port1 = iface.children[0]
    assert isinstance(port1, Edit)
    port1.key = Token.make("x1")
    result = serialize(doc)
    assert '    edit "x1"\n        set vdom "root"\n' in result
    assert 'edit "port1"' not in result


def test_new_nodes_take_sibling_or_parent_indentation() -> None:
    doc = parse("config global\nconfig system global\n    set a 1\nend\nend\n")
    glob = doc.children[0]
    assert isinstance(glob, ConfigBlock)
    inner = glob.children[0]
    assert isinstance(inner, ConfigBlock)
    inner.children.append(Command("set", "b", [Token.make("2", quoted=False)]))
    new_block = ConfigBlock(("system", "ha"))
    new_block.children.append(Command("set", "priority", [Token.make("100", quoted=False)]))
    glob.children.append(new_block)
    assert serialize(doc) == (
        "config global\n"
        "config system global\n"
        "    set a 1\n"
        "    set b 2\n"
        "end\n"
        "config system ha\n"
        "    set priority 100\n"
        "end\n"
        "end\n"
    )


def test_regenerated_lines_use_document_newline() -> None:
    doc = parse("config a\r\n    set x 1\r\nend\r\n")
    block = doc.children[0]
    assert isinstance(block, ConfigBlock)
    block.children.append(Command("set", "y", [Token.make("2", quoted=False)]))
    assert serialize(doc) == "config a\r\n    set x 1\r\n    set y 2\r\nend\r\n"


def test_load_reads_bytes(tmp_path: Path) -> None:
    from fortimig.parser import load
    from fortimig.serializer import dump

    src = tmp_path / "in.conf"
    src.write_bytes(fixture_bytes("multiline.conf"))
    out = tmp_path / "out.conf"
    dump(load(src), out)
    assert out.read_bytes() == src.read_bytes()
