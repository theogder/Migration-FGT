"""Diagnostic structurel d'une configuration que le parser refuse.

Affiche, autour d'une ligne, la structure vue par le lexer : mots-clés
(config / edit / next / end / set...), noms de blocs et d'options, valeurs
multi-lignes, nombre de guillemets par ligne. **Aucune valeur n'est affichée**
(ni clé d'edit, ni argument de set) : la sortie peut être partagée telle
quelle pour analyser une erreur sur une configuration réelle.
"""

from __future__ import annotations

from dataclasses import dataclass

from fortimig.lexer import LexError, LogicalLine, iter_logical_lines
from fortimig.model import COMMAND_VERBS
from fortimig.parser import ENCODING, ERRORS


@dataclass(slots=True)
class _Frame:
    kind: str  # "config" ou "edit"
    label: str
    line: int


def _summary(ll: LogicalLine) -> str:
    """Description sans valeur d'une instruction logique."""
    if ll.is_comment:
        return "# (commentaire / en-tête)"
    if ll.is_blank:
        return "(vide)"
    first = ll.tokens[0]
    keyword = None if first.quoted else first.value
    if keyword == "config":
        # Les mots de bloc non quotés sont des mots-clés FortiOS ; un mot
        # quoté (ex. nom de message de remplacement) est masqué.
        words = [t.value if not t.quoted else '"…"' for t in ll.tokens[1:]]
        return "config " + " ".join(words)
    if keyword == "edit":
        return f"edit <clé>{'' if len(ll.tokens) == 2 else f' ({len(ll.tokens) - 1} mots !)'}"
    if keyword in ("next", "end"):
        extra = f" (+{len(ll.tokens) - 1} mot(s) !)" if len(ll.tokens) > 1 else ""
        return keyword + extra
    if keyword in COMMAND_VERBS:
        option = ll.tokens[1].value if len(ll.tokens) > 1 and not ll.tokens[1].quoted else "<?>"
        return f"{keyword} {option} [{len(ll.tokens) - 2} valeur(s)]"
    return "(ligne non reconnue)"


def _apply(stack: list[_Frame], ll: LogicalLine) -> str | None:
    """Fait évoluer la pile simulée ; retourne une anomalie éventuelle."""
    if not ll.tokens or ll.tokens[0].quoted:
        return None
    keyword = ll.tokens[0].value
    if keyword == "config":
        words = [t.value if not t.quoted else '"…"' for t in ll.tokens[1:]]
        stack.append(_Frame("config", "config " + " ".join(words), ll.line))
    elif keyword == "edit":
        stack.append(_Frame("edit", "edit", ll.line))
    elif keyword in ("next", "end"):
        expected = "edit" if keyword == "next" else "config"
        if not stack:
            return f"« {keyword} » sans bloc ouvert"
        if stack[-1].kind != expected:
            top = stack[-1]
            return f"« {keyword} » alors que le bloc ouvert est « {top.label} » (l. {top.line})"
        stack.pop()
    return None


def _stack_text(stack: list[_Frame]) -> str:
    if not stack:
        return "aucun bloc ouvert"
    return " > ".join(f"{f.label} (l. {f.line})" for f in stack)


def diagnose(text: str, line: int, context: int = 30) -> list[str]:
    out = [
        f"Diagnostic structurel autour de la ligne {line} (aucune valeur affichée).",
        "Colonnes : n° de ligne, profondeur après la ligne, nombre de guillemets \" "
        "et de séquences \\\" sur la ligne physique, structure lue.",
    ]
    physical = text.split("\n")
    try:
        logical = list(iter_logical_lines(text))
    except LexError as exc:
        out.append(f"ERREUR du lexer : ligne {exc.line} : {exc.message}")
        logical = list(iter_logical_lines(text[: _offset_of_line(text, exc.line)]))

    first_shown, last_shown = max(1, line - context), line + context
    stack: list[_Frame] = []
    stack_at_start: str | None = None
    for ll in logical:
        if ll.line >= first_shown and stack_at_start is None:
            stack_at_start = _stack_text(stack)
            out.append(f"Blocs ouverts avant la ligne {ll.line} : {stack_at_start}")
        anomaly = _apply(stack, ll)
        if ll.end_line < first_shown or ll.line > last_shown:
            continue
        for n in range(ll.line, ll.end_line + 1):
            if not first_shown <= n <= last_shown:
                continue
            raw = physical[n - 1] if n - 1 < len(physical) else ""
            quotes = raw.count('"')
            escaped = raw.count('\\"')
            marker = ">>" if n == line else "  "
            if n == ll.line:
                desc = _summary(ll)
                if ll.end_line > ll.line:
                    desc += f" — valeur sur les lignes {ll.line}-{ll.end_line}"
            else:
                desc = f"  … suite de la valeur commencée l. {ll.line}"
            out.append(
                f"{marker} {n:>7}  prof={len(stack):<2} \"x{quotes:<2} \\\"x{escaped:<2} {desc}"
            )
            if anomaly and n == ll.line:
                out.append(f"   {'':>7}  ANOMALIE : {anomaly}")
    out.append(f"Blocs ouverts en fin de fenêtre : {_stack_text(stack)}")
    return out


def _offset_of_line(text: str, line: int) -> int:
    offset = 0
    for _ in range(line - 1):
        nl = text.find("\n", offset)
        if nl == -1:
            return len(text)
        offset = nl + 1
    return offset


def diagnose_bytes(data: bytes, line: int, context: int = 30) -> list[str]:
    return diagnose(data.decode(ENCODING, ERRORS), line, context)
