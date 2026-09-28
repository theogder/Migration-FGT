"""Modèle des constats (findings) du rapport et codes de sortie.

Le rendu complet (report.md / report.json) arrive à l'étape 7. Ce module
fixe dès maintenant la structure commune utilisée par tous les traitements.

Règle de confidentialité : les champs `before` / `after` ne doivent recevoir
que des valeurs déjà masquées (voir fortimig.secrets).
"""

from __future__ import annotations

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
