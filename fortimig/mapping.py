"""Chargement et validation de ``mapping.toml`` (SPEC §6, décisions D2 et D6).

Format :

    [device]
    hostname = "FW-PROD-01"
    hostname_secondary = "FW-PROD-02"     # D6
    ha_priority_primary = 200
    ha_priority_secondary = 100

    [interfaces]                           # source (300E) = cible (120G) | "drop"
    "port1" = "port1"
    "port30" = "drop"

    [header]                               # D2, optionnel
    from_target = ["platform"]             # lignes "#<clé>=" reprises de la cible

Les erreurs de format sont bloquantes (``MappingError``). Les incohérences
avec les configurations (interface absente, cible inexistante...) sont
vérifiées plus tard, au renommage, et tracées dans le rapport.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DROP = "drop"

_DEVICE_STR = ("hostname", "hostname_secondary")
_DEVICE_INT = ("ha_priority_primary", "ha_priority_secondary")
_SECTIONS = ("device", "interfaces", "header")

# Nom d'interface acceptable : pas de blanc, pas de guillemet, pas d'antislash.
_NAME_RE = re.compile(r'[^\s"\\]+')


class MappingError(ValueError):
    """Erreur de format de mapping.toml (bloquante)."""


@dataclass(frozen=True, slots=True)
class Mapping:
    interfaces: dict[str, str] = field(default_factory=dict)  # hors "drop", ordre du fichier
    dropped: tuple[str, ...] = ()
    hostname: str | None = None
    hostname_secondary: str | None = None
    ha_priority_primary: int | None = None
    ha_priority_secondary: int | None = None
    header_from_target: tuple[str, ...] = ()

    def declares(self, name: str) -> bool:
        return name in self.interfaces or name in self.dropped


def load_mapping(path: str | Path) -> Mapping:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise MappingError(f"mapping.toml : syntaxe TOML invalide ({exc})") from None
    return parse_mapping(data)


def parse_mapping(data: dict[str, Any]) -> Mapping:
    unknown = sorted(set(data) - set(_SECTIONS))
    if unknown:
        raise MappingError(f"mapping.toml : section(s) inconnue(s) : {', '.join(unknown)}")

    device = _table(data, "device")
    unknown = sorted(set(device) - set(_DEVICE_STR) - set(_DEVICE_INT))
    if unknown:
        raise MappingError(f"mapping.toml : clé(s) inconnue(s) dans [device] : {', '.join(unknown)}")
    strings: dict[str, str | None] = {}
    for key in _DEVICE_STR:
        value = device.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            raise MappingError(f"mapping.toml : [device] {key} doit être une chaîne non vide")
        strings[key] = value
    ints: dict[str, int | None] = {}
    for key in _DEVICE_INT:
        value = device.get(key)
        # bool est un sous-type de int en Python : à exclure explicitement.
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise MappingError(f"mapping.toml : [device] {key} doit être un entier positif")
        ints[key] = value
    primary, secondary = ints["ha_priority_primary"], ints["ha_priority_secondary"]
    if primary is not None and primary == secondary:
        raise MappingError("mapping.toml : les priorités HA primaire et secondaire doivent différer")

    interfaces: dict[str, str] = {}
    dropped: list[str] = []
    for source, target in _table(data, "interfaces").items():
        if not _NAME_RE.fullmatch(source):
            raise MappingError(f"mapping.toml : nom d'interface source invalide : {source!r}")
        if not isinstance(target, str) or not _NAME_RE.fullmatch(target):
            raise MappingError(f"mapping.toml : cible invalide pour {source!r}")
        if target == DROP:
            dropped.append(source)
        else:
            interfaces[source] = target

    header = _table(data, "header")
    unknown = sorted(set(header) - {"from_target"})
    if unknown:
        raise MappingError(f"mapping.toml : clé(s) inconnue(s) dans [header] : {', '.join(unknown)}")
    from_target = header.get("from_target", [])
    if not isinstance(from_target, list) or not all(
        isinstance(k, str) and k and not k.startswith("#") for k in from_target
    ):
        raise MappingError(
            'mapping.toml : [header] from_target doit être une liste de clés, ex. ["platform"]'
        )

    return Mapping(
        interfaces=interfaces,
        dropped=tuple(dropped),
        hostname=strings["hostname"],
        hostname_secondary=strings["hostname_secondary"],
        ha_priority_primary=primary,
        ha_priority_secondary=secondary,
        header_from_target=tuple(from_target),
    )


def _table(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise MappingError(f"mapping.toml : [{name}] doit être une table")
    return value
