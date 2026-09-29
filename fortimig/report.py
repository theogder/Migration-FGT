"""Modèle des constats (findings) du rapport et codes de sortie.

Le rendu complet (report.md / report.json) arrive à l'étape 7. Ce module
fixe dès maintenant la structure commune utilisée par tous les traitements.

Règle de confidentialité : les champs `before` / `after` ne doivent recevoir
que des valeurs déjà masquées (voir fortimig.secrets).
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

EXIT_OK = 0
EXIT_REVIEW = 1
EXIT_ERROR = 2


class Category(StrEnum):
    MODIFIE = "MODIFIE"
    SUPPRIME = "SUPPRIME"
    A_REVOIR = "A_REVOIR"
    ERREUR = "ERREUR"


@dataclass(frozen=True, slots=True)
class Finding:
    category: Category
    path: str
    message: str
    before: str | None = None
    after: str | None = None
    reason: str | None = None


@dataclass(slots=True)
class Report:
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(
        self,
        category: Category,
        path: str,
        message: str,
        *,
        before: str | None = None,
        after: str | None = None,
        reason: str | None = None,
    ) -> Finding:
        finding = Finding(category, path, message, before, after, reason)
        self.findings.append(finding)
        return finding

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def counts(self) -> dict[Category, int]:
        counter = Counter(f.category for f in self.findings)
        return {cat: counter.get(cat, 0) for cat in Category}

    @property
    def has_errors(self) -> bool:
        return any(f.category is Category.ERREUR for f in self.findings)

    def exit_code(self) -> int:
        counts = self.counts()
        if counts[Category.ERREUR]:
            return EXIT_ERROR
        if counts[Category.A_REVOIR]:
            return EXIT_REVIEW
        return EXIT_OK


# --- Rendu (SPEC §9) --------------------------------------------------------------

# Ordre de présentation : du plus urgent au moins urgent.
DISPLAY_ORDER = (Category.ERREUR, Category.A_REVOIR, Category.SUPPRIME, Category.MODIFIE)

_SCOPE_GLOBAL = "config global"
_SCOPE_VDOM = "config vdom"


def block_group(path: str) -> str:
    """Bloc « config » de rattachement d'un chemin, pour regrouper le rapport.

    ``config vdom > edit root > config firewall policy > edit 10 > set srcintf``
    -> ``[root] config firewall policy`` ; ``config global > config system ha``
    -> ``[global] config system ha`` ; chemins hors configuration
    (``mapping.toml > …``, ``en-tête > …``) -> leur premier segment.
    """
    parts = path.split(" > ")
    scope = ""
    if parts[0] == _SCOPE_GLOBAL:
        scope, parts = "[global] ", parts[1:]
    elif parts[0] == _SCOPE_VDOM and len(parts) > 1 and parts[1].startswith("edit "):
        scope, parts = f"[{parts[1][5:]}] ", parts[2:]
    elif parts[0] == _SCOPE_VDOM:
        scope, parts = "[vdom] ", parts[1:]
    if not parts or not parts[0].startswith("config "):
        return scope + (parts[0] if parts else path)
    configs = []
    for part in parts:
        if not part.startswith("config "):
            break
        configs.append(part)
    return scope + " > ".join(configs)


def _code(text: str) -> str:
    return "`" + text.replace("`", "'") + "`"


def render_json(report: Report, *, header: dict[str, str] | None = None) -> str:
    data = {
        "outil": "fortimig",
        "entrees_fichiers": header or {},
        "resume": {cat.value: n for cat, n in report.counts().items()},
        "avertissements": report.warnings,
        "entrees": [
            {
                "categorie": f.category.value,
                "chemin": f.path,
                "bloc": block_group(f.path),
                "message": f.message,
                "avant": f.before,
                "apres": f.after,
                "raison": f.reason,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_markdown(report: Report, *, header: dict[str, str] | None = None) -> str:
    counts = report.counts()
    lines = ["# Rapport de conversion fortimig", ""]
    for key, value in (header or {}).items():
        lines.append(f"- {key} : {_code(value)}")
    if header:
        lines.append("")
    status = {
        EXIT_ERROR: "**ERREUR bloquante : aucune configuration n'a été écrite.**",
        EXIT_REVIEW: "Conversion effectuée, **points à revoir**.",
        EXIT_OK: "Conversion effectuée, aucun point à revoir.",
    }[report.exit_code()]
    lines += [status, "", "## Résumé", "", "| Catégorie | Nombre |", "|---|---:|"]
    lines += [f"| {cat.value} | {counts[cat]} |" for cat in DISPLAY_ORDER]
    lines += ["", "## Avertissements globaux", ""]
    lines += [f"- {w}" for w in report.warnings] or ["Aucun."]
    for cat in DISPLAY_ORDER:
        findings = [f for f in report.findings if f.category is cat]
        if not findings:
            continue
        lines += ["", f"## {cat.value} ({len(findings)})"]
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            groups.setdefault(block_group(f.path), []).append(f)
        for group, items in groups.items():
            lines += ["", f"### {group}", ""]
            for f in items:
                lines.append(f"- {_code(f.path)} — {f.message}")
                if f.before is not None:
                    lines.append(f"  - avant : {_code(f.before)}")
                if f.after is not None:
                    lines.append(f"  - après : {_code(f.after)}")
                if f.reason is not None:
                    lines.append(f"  - raison : {f.reason}")
    return "\n".join(lines) + "\n"
