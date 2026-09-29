"""Suppressions et signalements pilotés par rules.toml (SPEC §5.4).

Format :

    [[rule]]
    path = "config system npu"                 # un ou plusieurs "config ..." séparés par " > "
    option = "exemple-option"                  # optionnel
    action = "flag"                            # remove | flag
    reason = "Pourquoi"

Correspondance :
- ``path`` désigne une chaîne de blocs ``config`` ; les niveaux ``edit`` sont
  ignorés (``config router ospf > config ospf-interface`` correspond quelle
  que soit l'interface) ;
- les préfixes de portée ``config global`` et ``config vdom > edit <vdom>``
  sont ignorés : une règle s'applique dans tous les VDOM ;
- sans ``option`` : la règle vise le bloc entier ;
- avec ``option`` : la règle vise les commandes ``set`` / ``unset`` de cette
  option placées directement dans le bloc ou dans ses entrées ``edit``.

``remove`` supprime (SUPPRIME), ``flag`` ne modifie rien (A_REVOIR). Une
règle qui ne correspond à rien est signalée en avertissement global.
Aucune règle n'est codée en dur.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fortimig.model import Command, ConfigBlock, Document, Edit, Node, format_path, segment
from fortimig.report import Category, Report
from fortimig.secrets import render_command

ACTIONS = ("remove", "flag")
_KEYS = {"path", "option", "action", "reason"}


class RulesError(ValueError):
    """Erreur de format de rules.toml (bloquante)."""


@dataclass(frozen=True, slots=True)
class Rule:
    index: int
    chain: tuple[tuple[str, ...], ...]  # mots de chaque bloc "config"
    option: str | None
    action: str
    reason: str

    @property
    def label(self) -> str:
        path = " > ".join("config " + " ".join(words) for words in self.chain)
        target = f"{path} / {self.option}" if self.option else path
        return f"règle n°{self.index} ({self.action} {target})"


def load_rules(path: str | Path) -> list[Rule]:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise RulesError(f"rules.toml : syntaxe TOML invalide ({exc})") from None
    return parse_rules(data)


def parse_rules(data: dict[str, Any]) -> list[Rule]:
    unknown = sorted(set(data) - {"rule"})
    if unknown:
        raise RulesError(f"rules.toml : clé(s) inconnue(s) : {', '.join(unknown)}")
    entries = data.get("rule", [])
    if not isinstance(entries, list):
        raise RulesError("rules.toml : utiliser des tables [[rule]]")
    rules: list[Rule] = []
    for index, entry in enumerate(entries, start=1):
        where = f"rules.toml : règle n°{index}"
        if not isinstance(entry, dict):
            raise RulesError(f"{where} : table attendue")
        extra = sorted(set(entry) - _KEYS)
        if extra:
            raise RulesError(f"{where} : clé(s) inconnue(s) : {', '.join(extra)}")
        path, action, reason = entry.get("path"), entry.get("action"), entry.get("reason")
        option = entry.get("option")
        if not isinstance(path, str) or not path.strip():
            raise RulesError(f"{where} : « path » manquant")
        chain: list[tuple[str, ...]] = []
        for part in path.split(">"):
            words = tuple(part.split())
            if len(words) < 2 or words[0] != "config":
                raise RulesError(f"{where} : « path » doit être une suite de « config ... » séparés par « > »")
            chain.append(words[1:])
        if action not in ACTIONS:
            raise RulesError(f"{where} : « action » doit valoir {' ou '.join(ACTIONS)}")
        if not isinstance(reason, str) or not reason.strip():
            raise RulesError(f"{where} : « reason » manquante")
        if option is not None and (not isinstance(option, str) or not option or " " in option):
            raise RulesError(f"{where} : « option » invalide")
        rules.append(Rule(index, tuple(chain), option, action, reason))
    return rules


def _matches(
    nodes: list[Node], chain: tuple[tuple[str, ...], ...], prefix: tuple[str, ...], configs: tuple[tuple[str, ...], ...]
) -> Iterator[tuple[tuple[str, ...], list[Node], ConfigBlock]]:
    """(chemin, liste parente, bloc) pour chaque bloc correspondant à ``chain``."""
    for node in nodes:
        if not isinstance(node, (ConfigBlock, Edit)):
            continue
        path = prefix + (segment(node),)
        if isinstance(node, ConfigBlock):
            if node.words in (("global",), ("vdom",)) and not configs:
                # Portée : ignorée pour la correspondance.
                yield from _matches(node.children, chain, path, configs)
                continue
            current = configs + (node.words,)
            if current == chain:
                yield path, nodes, node
            elif chain[: len(current)] == current:
                yield from _matches(node.children, chain, path, current)
        else:
            yield from _matches(node.children, chain, path, configs)


def apply_rules(doc: Document, rules: list[Rule], report: Report) -> None:
    for rule in rules:
        matched = list(_matches(doc.children, rule.chain, (), ()))
        hits = 0
        for path, parent, block in matched:
            if rule.option is None:
                hits += 1
                if rule.action == "remove":
                    _remove_identity(parent, block)
                    report.add(Category.SUPPRIME, format_path(path), "bloc supprimé", reason=rule.reason)
                else:
                    report.add(Category.A_REVOIR, format_path(path), "bloc signalé par règle", reason=rule.reason)
            else:
                hits += _apply_option(block, path, rule, report)
        if hits == 0:
            report.warn(f"{rule.label} : aucune correspondance dans la configuration source")


def _apply_option(block: ConfigBlock, path: tuple[str, ...], rule: Rule, report: Report) -> int:
    hits = 0
    containers: list[tuple[tuple[str, ...], ConfigBlock | Edit]] = [(path, block)]
    containers += [(path + (segment(e),), e) for e in block.children if isinstance(e, Edit)]
    for cpath, container in containers:
        for cmd in [c for c in container.children if isinstance(c, Command)]:
            if cmd.option != rule.option or cmd.verb not in ("set", "unset"):
                continue
            hits += 1
            where = format_path(cpath + (segment(cmd),))
            rendered = render_command(cmd, block.words)
            if rule.action == "remove":
                _remove_identity(container.children, cmd)
                report.add(Category.SUPPRIME, where, "option supprimée", before=rendered, reason=rule.reason)
            else:
                report.add(Category.A_REVOIR, where, "option signalée par règle", before=rendered, reason=rule.reason)
    return hits


def _remove_identity(nodes: list[Node], target: Node) -> None:
    """Retire ``target`` par identité (deux nœuds peuvent être égaux en contenu)."""
    for i, node in enumerate(nodes):
        if node is target:
            del nodes[i]
            return
