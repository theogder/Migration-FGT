"""Découpage d'une configuration FortiOS en instructions logiques et en jetons.

Une instruction logique correspond à une ligne physique, sauf lorsqu'une
valeur entre guillemets s'étend sur plusieurs lignes (certificats et clés PEM,
scripts, messages de remplacement) : l'instruction se poursuit alors jusqu'au
guillemet fermant, retours à la ligne compris.

Hypothèses FortiOS (à confirmer sur des backups réels, cf. DECISIONS.md) :
- seules les doubles quotes délimitent une valeur ; les apostrophes sont
  traitées comme des caractères ordinaires (les traiter comme délimiteurs
  risquerait d'avaler tout le reste du fichier sur un texte libre) ;
- dans une valeur entre guillemets, seuls ``\\"`` et ``\\\\`` sont des
  échappements ; tout autre antislash est conservé tel quel dans la valeur ;
- une ligne dont le premier caractère non blanc est ``#`` est un commentaire
  ou une ligne d'en-tête (``#config-version=...``) et n'est pas découpée.

Le texte brut de chaque instruction est conservé : le round-trip ne dépend
pas de l'exactitude de ces hypothèses, seule la valeur décodée en dépend.

Les messages d'erreur ne contiennent jamais le contenu des lignes, qui peut
être un secret : uniquement des numéros de ligne.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

# Blancs séparateurs de jetons ; "\n" termine l'instruction (hors guillemets).
_HSPACE = frozenset(" \t\r\f\v")


class LexError(ValueError):
    """Erreur de découpage. Le message ne contient que des numéros de ligne."""

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"ligne {line} : {message}")
        self.line = line
        self.message = message


@dataclass(frozen=True, slots=True)
class Token:
    """Un mot d'une instruction.

    ``text`` est le texte exact du fichier (guillemets et échappements
    compris), ``value`` la valeur décodée.
    """

    text: str
    value: str
    quoted: bool

    @classmethod
    def make(cls, value: str, quoted: bool = True) -> Token:
        """Construit un nouveau jeton à partir d'une valeur décodée."""
        if not quoted:
            if not value or any(c in _HSPACE or c in '\n"' for c in value):
                raise ValueError("valeur non représentable sans guillemets")
            return cls(value, value, False)
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return cls(f'"{escaped}"', value, True)


@dataclass(frozen=True, slots=True)
class LogicalLine:
    raw: str  # texte exact, terminaison(s) de ligne comprise(s)
    tokens: tuple[Token, ...]
    line: int  # première ligne physique (1-based)
    end_line: int  # dernière ligne physique
    is_comment: bool = False

    @property
    def is_blank(self) -> bool:
        return not self.tokens and not self.is_comment

    @property
    def indent(self) -> str:
        stripped = self.raw.lstrip(" \t")
        return self.raw[: len(self.raw) - len(stripped)]


def iter_logical_lines(text: str) -> Iterator[LogicalLine]:
    """Découpe ``text`` en instructions logiques, en un seul passage."""
    pos = 0
    line = 1
    n = len(text)
    while pos < n:
        start = pos
        start_line = line

        # Ligne de commentaire / d'en-tête : prise telle quelle jusqu'au "\n".
        probe = pos
        while probe < n and text[probe] in " \t":
            probe += 1
        if probe < n and text[probe] == "#":
            nl = text.find("\n", probe)
            pos = n if nl == -1 else nl + 1
            yield LogicalLine(text[start:pos], (), start_line, start_line, is_comment=True)
            if nl != -1:
                line += 1
            continue

        tokens: list[Token] = []
        while pos < n:
            c = text[pos]
            if c == "\n":
                pos += 1
                line += 1
                break
            if c in _HSPACE:
                pos += 1
                continue
            if c == '"':
                tok_start = pos
                pos += 1
                chars: list[str] = []
                while True:
                    if pos >= n:
                        raise LexError(start_line, "guillemet ouvrant sans guillemet fermant")
                    c = text[pos]
                    if c == "\\" and pos + 1 < n and text[pos + 1] in '"\\':
                        chars.append(text[pos + 1])
                        pos += 2
                        continue
                    if c == '"':
                        pos += 1
                        break
                    if c == "\n":
                        line += 1
                    chars.append(c)
                    pos += 1
                tokens.append(Token(text[tok_start:pos], "".join(chars), True))
            else:
                tok_start = pos
                while pos < n and text[pos] not in _HSPACE and text[pos] != "\n":
                    pos += 1
                word = text[tok_start:pos]
                tokens.append(Token(word, word, False))

        end_line = line - 1 if text[pos - 1] == "\n" else line
        yield LogicalLine(text[start:pos], tuple(tokens), start_line, end_line)
