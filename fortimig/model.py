"""Arbre de configuration FortiOS.

Chaque nœud conserve le texte brut de ses lignes d'origine ainsi qu'une
« signature » de son contenu au moment du parsing. Le sérialiseur réémet le
texte brut tant que la signature n'a pas changé, et ne régénère que les nœuds
effectivement modifiés : le round-trip est exact sans dépendre des conventions
d'indentation de FortiOS, et aucun indicateur « modifié » n'est à maintenir à
la main.

Structure FortiOS représentée :

    config <mots...>          -> ConfigBlock (fermé par "end")
        edit <clé>            -> Edit        (fermé par "next")
            set <option> <valeurs...>   -> Command (verb = set)
            unset <option>              -> Command (verb = unset)
            config <sous-bloc> ... end  -> ConfigBlock imbriqué
        next
    end

Les lignes vides, commentaires et lignes non reconnues sont des RawLine.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Union

from fortimig.lexer import Token

# Verbes FortiOS portant sur une option. Les backups contiennent surtout
# set/unset ; append/select/unselect sont acceptés par la CLI et parsés par
# précaution.
COMMAND_VERBS = frozenset({"set", "unset", "append", "select", "unselect"})


@dataclass(slots=True)
class RawLine:
    """Ligne conservée telle quelle : vide, commentaire, en-tête ou inconnue."""

    text: str
    line: int = 0
    unknown: bool = False


@dataclass(slots=True)
class Command:
    verb: str
    option: str
    args: list[Token] = field(default_factory=list)
    raw: str | None = None
    indent: str | None = None
    line: int = 0
    end_line: int = 0
    _sig: tuple[object, ...] | None = field(default=None, repr=False, compare=False)

    def signature(self) -> tuple[object, ...]:
        return (self.verb, self.option, tuple(t.text for t in self.args))

    @property
    def values(self) -> list[str]:
        return [t.value for t in self.args]


@dataclass(slots=True)
class Edit:
    key: Token
    children: list[Node] = field(default_factory=list)
    raw_open: str | None = None
    raw_close: str | None = None
    indent: str | None = None
    line: int = 0
    end_line: int = 0
    _sig: tuple[object, ...] | None = field(default=None, repr=False, compare=False)

    def signature(self) -> tuple[object, ...]:
        return (self.key.text,)

    @property
    def name(self) -> str:
        return self.key.value


@dataclass(slots=True)
class ConfigBlock:
    words: tuple[str, ...]
    children: list[Node] = field(default_factory=list)
    raw_open: str | None = None
    raw_close: str | None = None
    indent: str | None = None
    line: int = 0
    end_line: int = 0
    _sig: tuple[object, ...] | None = field(default=None, repr=False, compare=False)

    def signature(self) -> tuple[object, ...]:
        return self.words

    @property
    def name(self) -> str:
        return " ".join(self.words)


Node = Union[ConfigBlock, Edit, Command, RawLine]
Container = Union[ConfigBlock, Edit]


@dataclass(slots=True)
class Document:
    header: list[RawLine] = field(default_factory=list)
    children: list[Node] = field(default_factory=list)
    newline: str = "\n"
    # Pas d'indentation des nœuds régénérés : 4 espaces, ou "" si le fichier
    # source n'est pas indenté.
    indent_step: str = "    "
    # Avertissements de parsing (numéros de ligne seulement, jamais de contenu).
    warnings: list[str] = field(default_factory=list)


# --- Chemins -----------------------------------------------------------------

PATH_SEP = " > "


def segment(node: Node) -> str:
    """Libellé d'un nœud dans un chemin, ex. ``edit "port1"`` ou ``set srcintf``."""
    if isinstance(node, ConfigBlock):
        return f"config {node.name}"
    if isinstance(node, Edit):
        return f"edit {node.key.text}"
    if isinstance(node, Command):
        return f"{node.verb} {node.option}"
    return f"ligne {node.line}"


def format_path(path: tuple[str, ...]) -> str:
    return PATH_SEP.join(path)


def walk(
    nodes: list[Node], prefix: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], Node]]:
    """Parcours en profondeur, dans l'ordre du fichier.

    Produit ``(chemin, nœud)``, le chemin incluant le segment du nœud.
    """
    for node in nodes:
        path = prefix + (segment(node),)
        yield path, node
        if isinstance(node, (ConfigBlock, Edit)):
            yield from walk(node.children, path)
