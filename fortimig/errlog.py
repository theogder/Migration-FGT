"""Analyse de la sortie de ``diagnose debug config-error-log read`` (SPEC §5.10).

Format observé sur le 120G de lab (7.4.9), après restauration de la
configuration convertie (DECISIONS.md U5) :

    "config" "system" "np6" @ 60:global:command parse error (error -61)

- la commande refusée, mot par mot, entre guillemets ;
- après ``@`` : un nombre (supposé être le numéro de ligne dans le fichier
  restauré — vérifié automatiquement contre la configuration fournie), la
  portée (``global`` ou nom de VDOM), le message, et le code d'erreur.

Pour chaque erreur, l'outil cherche la ligne et le bloc correspondants dans la
configuration convertie, puis regroupe par bloc et propose une règle
rules.toml à valider (jamais appliquée automatiquement). Les lignes au format
inconnu sont listées telles quelles. Tout ce qui est affiché passe par le
masquage des secrets.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from fortimig.lexer import Token
from fortimig.model import Command, ConfigBlock, Document, Edit, Node, format_path, segment
from fortimig.secrets import render_command

_ENTRY_RE = re.compile(
    r'^\s*(?P<cmd>(?:"(?:[^"\\]|\\.)*"\s*)+)@\s*(?P<pos>[^:]*):(?P<scope>[^:]*):'
    r"(?P<msg>.*?)(?:\s*\(error\s*(?P<code>-?\d+)\))?\s*$"
)
_WORD_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass(slots=True)
class LogEntry:
    raw_line: int  # ligne dans le fichier de log
    words: list[str]
    position: str
    scope: str
    message: str
    code: str | None


@dataclass(slots=True)
class Located:
    entry: LogEntry
    path: str | None = None  # chemin du nœud trouvé dans la configuration
    config_line: int | None = None
    confirmed_line: bool = False  # la position du log désigne bien cette ligne
    candidates: int = 0
    block: str = ""  # chaîne "config ..." pour une règle
    option: str | None = None


@dataclass(slots=True)
class ErrlogResult:
    located: list[Located] = field(default_factory=list)
    unparsed: list[tuple[int, str]] = field(default_factory=list)


def parse_log(text: str) -> tuple[list[LogEntry], list[tuple[int, str]]]:
    entries: list[LogEntry] = []
    unparsed: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = _ENTRY_RE.match(line)
        if match is None:
            unparsed.append((number, line))
            continue
        words = [w.replace('\\"', '"').replace("\\\\", "\\") for w in _WORD_RE.findall(match.group("cmd"))]
        entries.append(
            LogEntry(
                number,
                words,
                match.group("pos").strip(),
                match.group("scope").strip(),
                match.group("msg").strip(),
                match.group("code"),
            )
        )
    return entries, unparsed


def _scope_nodes(doc: Document, scope: str) -> list[tuple[tuple[str, ...], list[Node]]]:
    """Listes de nœuds où chercher, selon la portée annoncée par le log."""
    scopes: list[tuple[tuple[str, ...], list[Node]]] = []
    for node in doc.children:
        if isinstance(node, ConfigBlock) and node.words == ("global",) and scope == "global":
            scopes.append(((segment(node),), node.children))
        elif isinstance(node, ConfigBlock) and node.words == ("vdom",):
            for entry in node.children:
                if isinstance(entry, Edit) and entry.name == scope:
                    scopes.append(((segment(node), segment(entry)), entry.children))
    if not scopes:  # configuration mono-VDOM, ou portée inconnue : tout le document
        scopes.append(((), doc.children))
    return scopes


def _walk(nodes: list[Node], prefix: tuple[str, ...], configs: tuple[str, ...]):
    for node in nodes:
        path = prefix + (segment(node),)
        if isinstance(node, ConfigBlock):
            chain = configs + (f"config {node.name}",)
            yield path, node, chain
            yield from _walk(node.children, path, chain)
        elif isinstance(node, Edit):
            yield path, node, configs
            yield from _walk(node.children, path, configs)
        else:
            yield path, node, configs


def _matches(node: Node, words: list[str]) -> bool:
    if not words:
        return False
    if words[0] == "config" and isinstance(node, ConfigBlock):
        return list(node.words) == words[1:]
    if words[0] == "edit" and isinstance(node, Edit):
        return len(words) == 2 and node.name == words[1]
    if isinstance(node, Command) and words[0] == node.verb and len(words) > 1:
        return node.option == words[1] and (len(words) == 2 or node.values == words[2:])
    return False


def _node_line(node: Node) -> int:
    return getattr(node, "line", 0)


def locate(doc: Document, entry: LogEntry) -> Located:
    result = Located(entry)
    found = []
    for prefix, nodes in _scope_nodes(doc, entry.scope):
        for path, node, chain in _walk(nodes, prefix, ()):
            if _matches(node, entry.words):
                found.append((path, node, chain))
    result.candidates = len(found)
    if not found:
        return result
    chosen = found[0]
    if entry.position.isdigit():
        line = int(entry.position)
        exact = [f for f in found if _node_line(f[1]) == line]
        if exact:
            chosen, result.confirmed_line = exact[0], True
    path, node, chain = chosen
    result.path = format_path(path)
    result.config_line = _node_line(node) or None
    result.block = " > ".join(chain)
    if isinstance(node, Command):
        result.option = node.option
    return result


def analyze(doc: Document, text: str) -> ErrlogResult:
    entries, unparsed = parse_log(text)
    return ErrlogResult([locate(doc, e) for e in entries], unparsed)


def _toml_str(text: str) -> str:
    """Chaîne TOML de base (les échappements JSON sont valides en TOML)."""
    return json.dumps(text, ensure_ascii=False)


def _token(word: str) -> Token:
    """Mot du log redevenu jeton : sans guillemets quand c'est possible (ex. ENC)."""
    try:
        return Token.make(word, quoted=False)
    except ValueError:
        return Token.make(word)


def _command_text(words: list[str]) -> str:
    """Commande du log, secrets masqués (même règles que les rapports)."""
    if len(words) >= 2 and words[0] in ("set", "unset", "append", "select", "unselect"):
        return render_command(Command(words[0], words[1], [_token(w) for w in words[2:]]))
    return " ".join(words)


def render(result: ErrlogResult) -> str:
    lines = ["# Analyse du config-error-log", ""]
    lines.append(f"{len(result.located)} erreur(s) reconnue(s), {len(result.unparsed)} ligne(s) au format inconnu.")
    groups: dict[str, list[Located]] = {}
    for item in result.located:
        groups.setdefault(item.block or "(non localisé dans la configuration)", []).append(item)
    for block, items in groups.items():
        lines += ["", f"## {block}", ""]
        for item in items:
            e = item.entry
            code = f" (error {e.code})" if e.code else ""
            lines.append(f"- log l.{e.raw_line} : `{_command_text(e.words)}` — {e.message}{code} [portée {e.scope}]")
            if item.path is None:
                lines.append("  - introuvable dans la configuration fournie")
                continue
            where = f"ligne {item.config_line}" if item.config_line else "ligne inconnue"
            check = (
                "position du log confirmée" if item.confirmed_line
                else f"position du log « {e.position} » non confirmée"
            )
            lines.append(f"  - `{item.path}` ({where} ; {check} ; {item.candidates} occurrence(s))")
        lines += ["", "Règle proposée (à valider avant de l'ajouter à rules.toml) :", "", "```toml"]
        options = sorted({i.option for i in items if i.option})
        messages = sorted({i.entry.message for i in items})
        reason = f"Refusé par le 120G (config-error-log) : {' ; '.join(messages)}"
        if block.startswith("config ") and not options:
            lines += ["[[rule]]", f"path = {_toml_str(block)}", 'action = "remove"', f"reason = {_toml_str(reason)}"]
        elif block.startswith("config "):
            for option in options:
                lines += ["[[rule]]", f"path = {_toml_str(block)}", f"option = {_toml_str(option)}",
                          'action = "remove"', f"reason = {_toml_str(reason)}", ""]
        else:
            lines.append("# aucune règle proposée : erreur non localisée")
        lines.append("```")
    if result.unparsed:
        lines += ["", "## Lignes au format inconnu", ""]
        lines += [f"- l.{n} : `{text.strip()}`" for n, text in result.unparsed]
    return "\n".join(lines).rstrip() + "\n"
