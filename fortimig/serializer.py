"""Sérialisation de l'arbre en texte de configuration FortiOS.

Un nœud dont le contenu n'a pas changé depuis le parsing est réémis à partir
de son texte brut (round-trip exact). Un nœud modifié ou créé est régénéré :
son indentation est celle d'origine si elle est connue, sinon celle d'un nœud
frère, sinon celle du parent + le pas du document (4 espaces, ou rien si le
fichier source n'est pas indenté).
"""

from __future__ import annotations

from pathlib import Path

from fortimig.model import Command, ConfigBlock, Document, Edit, Node, RawLine
from fortimig.parser import ENCODING, ERRORS

def serialize(doc: Document) -> str:
    out: list[str] = [h.text for h in doc.header]
    _emit_children(doc.children, "", out, doc.newline, doc.indent_step)
    return "".join(out)


def dump(doc: Document, path: str | Path) -> None:
    Path(path).write_bytes(serialize(doc).encode(ENCODING, ERRORS))


def _child_indent(children: list[Node], default: str) -> str:
    for child in children:
        if not isinstance(child, RawLine) and child.indent is not None:
            return child.indent
    return default


def _emit_children(
    children: list[Node], default_indent: str, out: list[str], nl: str, step: str
) -> None:
    indent = _child_indent(children, default_indent)
    for node in children:
        _emit(node, indent, out, nl, step)


def _unchanged(node: Command | ConfigBlock | Edit) -> bool:
    return node._sig is not None and node.signature() == node._sig


def _emit(node: Node, default_indent: str, out: list[str], nl: str, step: str) -> None:
    if isinstance(node, RawLine):
        out.append(node.text)
        return

    indent = node.indent if node.indent is not None else default_indent

    if isinstance(node, Command):
        if node.raw is not None and _unchanged(node):
            out.append(node.raw)
        else:
            words = [node.verb, node.option, *(t.text for t in node.args)]
            out.append(indent + " ".join(words) + nl)
        return

    if isinstance(node, ConfigBlock):
        opening = f"config {node.name}"
        closing = "end"
    else:
        opening = f"edit {node.key.text}"
        closing = "next"

    if node.raw_open is not None and _unchanged(node):
        out.append(node.raw_open)
    else:
        out.append(indent + opening + nl)
    _emit_children(node.children, indent + step, out, nl, step)
    out.append(node.raw_close if node.raw_close is not None else indent + closing + nl)
