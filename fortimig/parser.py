"""Construction de l'arbre de configuration à partir du texte (SPEC §5.1).

Le parsing est strict sur la structure (config/edit/next/end doivent être
équilibrés) : un fichier mal formé est refusé plutôt que deviné. Les lignes
non reconnues sont conservées telles quelles et signalées en avertissement.
"""

from __future__ import annotations

from pathlib import Path

from fortimig.lexer import LexError, LogicalLine, iter_logical_lines
from fortimig.model import (
    COMMAND_VERBS,
    Command,
    ConfigBlock,
    Container,
    Document,
    Edit,
    Node,
    RawLine,
)

# Lecture / écriture en UTF-8 avec "surrogateescape" : tout octet invalide est
# conservé à l'identique, ce qui garantit le round-trip sur n'importe quel
# fichier.
ENCODING = "utf-8"
ERRORS = "surrogateescape"


class ParseError(ValueError):
    """Erreur de structure. Le message ne contient que des numéros de ligne."""

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"ligne {line} : {message}")
        self.line = line


def _detect_newline(text: str) -> str:
    nl = text.find("\n")
    if nl > 0 and text[nl - 1] == "\r":
        return "\r\n"
    return "\n"


def parse(text: str) -> Document:
    doc = Document(newline=_detect_newline(text))
    stack: list[Container] = []

    def children() -> list[Node]:
        return stack[-1].children if stack else doc.children

    try:
        lines = list(iter_logical_lines(text))
    except LexError as exc:
        raise ParseError(exc.line, exc.message) from None

    # Style d'indentation : certains backups (ex. celui du 300E observé)
    # n'indentent pas du tout ; les nœuds régénérés suivent alors ce style.
    if not any(ll.indent for ll in lines if ll.tokens):
        doc.indent_step = ""

    # En-tête : lignes "#..." en tout début de fichier. Les lignes vides
    # intercalées en font partie (observé : ligne vide après #config-version),
    # mais pas les lignes vides qui suivent le dernier "#".
    header_end = 0
    for i, ll in enumerate(lines):
        if ll.is_comment:
            header_end = i + 1
        elif not ll.is_blank:
            break
    for ll in lines[:header_end]:
        doc.header.append(RawLine(ll.raw, ll.line))

    for ll in lines[header_end:]:

        if ll.is_comment or ll.is_blank:
            children().append(RawLine(ll.raw, ll.line))
            continue

        first = ll.tokens[0]
        keyword = None if first.quoted else first.value

        if keyword == "config":
            if len(ll.tokens) < 2:
                raise ParseError(ll.line, "« config » sans nom de bloc")
            block = ConfigBlock(
                words=tuple(t.value for t in ll.tokens[1:]),
                raw_open=ll.raw,
                indent=ll.indent,
                line=ll.line,
            )
            block._sig = block.signature()
            children().append(block)
            stack.append(block)
        elif keyword == "edit":
            if not stack or not isinstance(stack[-1], ConfigBlock):
                raise ParseError(ll.line, "« edit » hors d'un bloc « config »")
            if len(ll.tokens) != 2:
                raise ParseError(ll.line, "« edit » attend exactement une clé")
            entry = Edit(key=ll.tokens[1], raw_open=ll.raw, indent=ll.indent, line=ll.line)
            entry._sig = entry.signature()
            children().append(entry)
            stack.append(entry)
        elif keyword == "next":
            _close(stack, Edit, ll, "« next » sans « edit » ouvert")
        elif keyword == "end":
            _close(stack, ConfigBlock, ll, "« end » sans « config » ouvert")
        elif keyword in COMMAND_VERBS:
            if not stack:
                raise ParseError(ll.line, f"« {keyword} » hors de tout bloc")
            if len(ll.tokens) < 2:
                raise ParseError(ll.line, f"« {keyword} » sans nom d'option")
            cmd = Command(
                verb=keyword,
                option=ll.tokens[1].value,
                args=list(ll.tokens[2:]),
                raw=ll.raw,
                indent=ll.indent,
                line=ll.line,
                end_line=ll.end_line,
            )
            cmd._sig = cmd.signature()
            children().append(cmd)
        else:
            children().append(RawLine(ll.raw, ll.line, unknown=True))
            doc.warnings.append(f"ligne {ll.line} : ligne non reconnue, conservée telle quelle")

    if stack:
        raise ParseError(stack[-1].line, "bloc ouvert ici et jamais fermé")
    return doc


def _close(stack: list[Container], kind: type, ll: LogicalLine, message: str) -> None:
    if not stack or not isinstance(stack[-1], kind):
        raise ParseError(ll.line, message)
    node = stack.pop()
    node.raw_close = ll.raw
    node.end_line = ll.line


def parse_bytes(data: bytes) -> Document:
    return parse(data.decode(ENCODING, ERRORS))


def load(path: str | Path) -> Document:
    return parse_bytes(Path(path).read_bytes())
