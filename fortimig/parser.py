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

    # Dernière valeur multi-lignes lue : indice précieux en cas d'erreur de
    # structure (une valeur mal délimitée décale toute la suite du fichier).
    last_multiline: LogicalLine | None = None

    def fail(line: int, message: str) -> ParseError:
        return ParseError(line, f"{message} ({_context(stack, last_multiline)})")

    for ll in lines[header_end:]:
        if ll.end_line > ll.line:
            last_multiline = ll
            # Hypothèse U1 : \" est un guillemet échappé. Une valeur dont une
            # ligne se termine par \" a peut-être « débordé » (ex. chemin
            # Windows terminé par un antislash) : la structure peut rester
            # valide alors que la valeur est faussée. On le signale.
            if any(t.quoted and ('\\"\n' in t.text or '\\"\r\n' in t.text) for t in ll.tokens):
                doc.warnings.append(
                    f"lignes {ll.line}-{ll.end_line} : valeur multi-lignes contenant \\\" en fin "
                    "de ligne, délimitation incertaine (vérifier avec « diagnose »)"
                )

        if ll.is_comment or ll.is_blank:
            children().append(RawLine(ll.raw, ll.line))
            continue

        first = ll.tokens[0]
        keyword = None if first.quoted else first.value

        if keyword == "config":
            if len(ll.tokens) < 2:
                raise fail(ll.line, "« config » sans nom de bloc")
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
                raise fail(ll.line, "« edit » hors d'un bloc « config »")
            if len(ll.tokens) != 2:
                raise fail(ll.line, "« edit » attend exactement une clé")
            entry = Edit(key=ll.tokens[1], raw_open=ll.raw, indent=ll.indent, line=ll.line)
            entry._sig = entry.signature()
            children().append(entry)
            stack.append(entry)
        elif keyword in ("next", "end"):
            kind: type = Edit if keyword == "next" else ConfigBlock
            if not stack:
                opener = "edit" if keyword == "next" else "config"
                raise fail(ll.line, f"« {keyword} » sans « {opener} » ouvert")
            if not isinstance(stack[-1], kind):
                other, closer = ("config", "end") if keyword == "next" else ("edit", "next")
                raise fail(
                    ll.line,
                    f"« {keyword} » alors que le « {other} » de la ligne {stack[-1].line} "
                    f"n'est pas fermé par « {closer} »",
                )
            node = stack.pop()
            node.raw_close = ll.raw
            node.end_line = ll.line
        elif keyword in COMMAND_VERBS:
            if not stack:
                raise fail(ll.line, f"« {keyword} » hors de tout bloc")
            if len(ll.tokens) < 2:
                raise fail(ll.line, f"« {keyword} » sans nom d'option")
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
        raise fail(stack[-1].line, "bloc ouvert ici et jamais fermé")
    return doc


def describe_stack(stack: list[Container]) -> str:
    """Blocs ouverts, sans valeur : noms de blocs "config" et lignes des "edit"."""
    if not stack:
        return "aucun bloc ouvert"
    parts = [
        f"config {n.name} (l. {n.line})" if isinstance(n, ConfigBlock) else f"edit (l. {n.line})"
        for n in stack
    ]
    return "blocs ouverts : " + " > ".join(parts)


def _context(stack: list[Container], last_multiline: LogicalLine | None) -> str:
    text = describe_stack(stack)
    if last_multiline is not None:
        text += (
            f" ; dernière valeur multi-lignes : lignes {last_multiline.line}"
            f"-{last_multiline.end_line}"
        )
    return text


def parse_bytes(data: bytes) -> Document:
    return parse(data.decode(ENCODING, ERRORS))


def load(path: str | Path) -> Document:
    return parse_bytes(Path(path).read_bytes())
