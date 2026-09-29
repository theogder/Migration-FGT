"""Orchestration de la conversion (SPEC §8, commande ``convert``).

Ordre des traitements :
1. avertissements globaux (lecture des fichiers, private-data-encryption) ;
2. en-tête (SPEC §5.2) ;
3. règles de rules.toml (SPEC §5.4), appliquées sur les noms de la source ;
4. renommage des interfaces (SPEC §5.3) ;
5. ports et objets par défaut du modèle cible (SPEC §5.5) ;
6. haute disponibilité et contenu de secondary-ha.txt (SPEC §5.6).

La conversion travaille sur l'arbre de la source, modifié en place.
"""

from __future__ import annotations

from dataclasses import dataclass

from fortimig.fortios import interface_entries, physical_interfaces
from fortimig.ha import apply_ha
from fortimig.header import replace_header
from fortimig.interfaces import rename_interfaces
from fortimig.mapping import Mapping
from fortimig.model import Document
from fortimig.report import Report
from fortimig.rules import Rule, apply_rules
from fortimig.secrets import private_data_encryption_enabled
from fortimig.target import apply_target_defaults

PRIVATE_DATA_WARNING = (
    "private-data-encryption est activé sur la source : la même clé devra être "
    "positionnée sur le 120G AVANT la restauration, sinon les secrets chiffrés "
    "ne pourront pas être déchiffrés"
)


@dataclass(slots=True)
class ConvertResult:
    report: Report
    converted: Document
    secondary: str | None


def convert(source: Document, target: Document, mapping: Mapping, rules: list[Rule]) -> ConvertResult:
    report = Report()
    if private_data_encryption_enabled(source):
        report.warn(PRIVATE_DATA_WARNING)
    for warning in source.warnings:
        report.warn(f"lecture de la source : {warning}")
    for warning in target.warnings:
        report.warn(f"lecture de target-default.conf : {warning}")

    replace_header(source, target, mapping, report)
    apply_rules(source, rules, report)
    target_defaults = {e.name: e for _, e in interface_entries(target)}
    rename_interfaces(source, mapping, physical_interfaces(target), report, target_defaults)
    apply_target_defaults(source, target, mapping, report)
    secondary = apply_ha(source, mapping, report)
    return ConvertResult(report, source, secondary)
