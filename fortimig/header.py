"""Remplacement de l'en-tête (SPEC §5.2, décisions D1 et D2).

Formes observées :
- backup du 300E : ``#config-version=FG3H0E-7.4.9-FW-build2829-250924:opmode=0:vdom=1:user=…``
  suivi de ``#conf_file_ver=``, ``#buildno=``, ``#global_vdom=`` ;
- backup du 120G vierge : ``#config-version=FG120G-7.4.11-FW-build2878-260126:opmode=0:vdom=0:user=admin``.

Règles :
- la ligne ``#config-version`` est remplacée par celle de la cible ;
- les autres lignes de la source sont conservées, sauf celles listées dans
  ``[header] from_target`` de mapping.toml ;
- mode VDOM différent (champ ``vdom=``) : ERREUR (D1) ;
- version ou build différents, mode opératoire différent : A_REVOIR ;
- toute autre ligne d'en-tête commune de valeur différente : A_REVOIR.
"""

from __future__ import annotations

import re

from fortimig.mapping import Mapping
from fortimig.model import Document, RawLine
from fortimig.report import Category, Report

CONFIG_VERSION = "config-version"
_LINE_RE = re.compile(r"#([A-Za-z0-9_-]+)=(.*?)(\r?\n)?\Z", re.DOTALL)
_VERSION_RE = re.compile(r"-(\d+\.\d+(?:\.\d+)?)-FW-build(\d+)")
_FIELD_RE = re.compile(r":(opmode|vdom)=([^:]*)")


def _entries(header: list[RawLine]) -> dict[str, tuple[int, str, str]]:
    """clé -> (indice, valeur, fin de ligne), pour les lignes « #clé=valeur »."""
    found: dict[str, tuple[int, str, str]] = {}
    for i, raw in enumerate(header):
        match = _LINE_RE.match(raw.text)
        if match and match.group(1) not in found:
            found[match.group(1)] = (i, match.group(2), match.group(3) or "")
    return found


def _fields(config_version: str) -> dict[str, str]:
    return dict(_FIELD_RE.findall(config_version))


def _version(config_version: str) -> tuple[str, str] | None:
    match = _VERSION_RE.search(config_version)
    return (match.group(1), match.group(2)) if match else None


def replace_header(doc: Document, target: Document, mapping: Mapping, report: Report) -> None:
    src = _entries(doc.header)
    tgt = _entries(target.header)
    where = "en-tête > #config-version"
    if CONFIG_VERSION not in src:
        report.add(Category.ERREUR, where, "ligne #config-version absente de la configuration source")
        return
    if CONFIG_VERSION not in tgt:
        report.add(Category.ERREUR, where, "ligne #config-version absente de target-default.conf")
        return

    src_value, tgt_value = src[CONFIG_VERSION][1], tgt[CONFIG_VERSION][1]
    _compare_config_versions(src_value, tgt_value, report)

    replaced = {CONFIG_VERSION, *mapping.header_from_target}
    for key in [CONFIG_VERSION, *mapping.header_from_target]:
        line_where = f"en-tête > #{key}"
        if key not in tgt:
            report.add(Category.A_REVOIR, line_where,
                       f"#{key} demandé par [header] from_target mais absent de target-default.conf")
            continue
        value = tgt[key][1]
        if key in src:
            index, before, ending = src[key]
            if before == value:
                continue
            doc.header[index].text = f"#{key}={value}{ending}"
            report.add(Category.MODIFIE, line_where, "valeur reprise de target-default.conf",
                       before=before, after=value)
        else:
            # Insérée juste après #config-version.
            ending = src[CONFIG_VERSION][2] or doc.newline
            doc.header.insert(src[CONFIG_VERSION][0] + 1, RawLine(f"#{key}={value}{ending}"))
            src = _entries(doc.header)
            report.add(Category.MODIFIE, line_where, "ligne ajoutée depuis target-default.conf",
                       after=value)

    for key, (_, value, _) in src.items():
        if key in replaced or key not in tgt or tgt[key][1] == value:
            continue
        report.add(
            Category.A_REVOIR,
            f"en-tête > #{key}",
            f"valeur conservée de la source, différente de la cible ({tgt[key][1]}) : "
            "ajouter la clé à [header] from_target pour la reprendre",
            before=value,
        )


def _compare_config_versions(src: str, tgt: str, report: Report) -> None:
    where = "en-tête > #config-version"
    src_fields, tgt_fields = _fields(src), _fields(tgt)
    if src_fields.get("vdom") != tgt_fields.get("vdom"):
        report.add(
            Category.ERREUR,
            where,
            f"mode VDOM différent : source vdom={src_fields.get('vdom')}, cible "
            f"vdom={tgt_fields.get('vdom')}. Mettre le 120G dans le même mode VDOM "
            "que la source avant d'en sauvegarder la configuration par défaut",
        )
    if src_fields.get("opmode") != tgt_fields.get("opmode"):
        report.add(
            Category.A_REVOIR,
            where,
            f"mode opératoire différent : source opmode={src_fields.get('opmode')}, "
            f"cible opmode={tgt_fields.get('opmode')}",
        )
    src_version, tgt_version = _version(src), _version(tgt)
    if src_version is None or tgt_version is None:
        report.add(Category.A_REVOIR, where, "version FortiOS non reconnue dans #config-version")
    elif src_version != tgt_version:
        report.add(
            Category.A_REVOIR,
            where,
            f"versions différentes : source {src_version[0]} build {src_version[1]}, cible "
            f"{tgt_version[0]} build {tgt_version[1]} (SPEC §1 : même version que la source, "
            "ou la plus proche supportée par le modèle)",
        )
