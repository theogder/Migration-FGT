"""Suppressions et signalements pilotés par rules.toml (SPEC §5.4).

Format :

    [[rule]]
    path = "config system npu"                 # un ou plusieurs "config ..." séparés par " > "
    option = "exemple-option"                  # optionnel
    action = "flag"                            # remove | flag | keep_target
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

``keep_target`` (extension de la SPEC, issue du lab — DECISIONS.md U14) :
un bloc propre au matériel cible, présent dans ``target-default.conf`` mais
absent de la source, est repris de la configuration par défaut de la cible
(MODIFIE). Sans cela, la restauration le vide sur le primaire alors qu'un
membre neuf l'a encore : les checksums HA diffèrent et le cluster ne se
synchronise pas (observé avec ``config system npu``). Si la source contient
déjà le bloc, il est conservé et signalé (A_REVOIR). ``keep_target`` ne
s'applique qu'à un bloc entier, placé directement dans ``config global``,
dans un VDOM ou à la racine.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import copy

from fortimig.model import Command, ConfigBlock, Document, Edit, Node, detach, format_path, segment
from fortimig.report import Category, Report
from fortimig.secrets import render_command

ACTIONS = ("remove", "flag", "keep_target")
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
        if action == "keep_target" and option is not None:
            raise RulesError(f"{where} : « keep_target » s'applique à un bloc entier, sans « option »")
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


def apply_rules(doc: Document, rules: list[Rule], report: Report, target: Document | None = None) -> None:
    for rule in rules:
        if rule.action == "keep_target":
            _keep_target(doc, target, rule, report)
            continue
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


def _keep_target(doc: Document, target: Document | None, rule: Rule, report: Report) -> None:
    present = list(_matches(doc.children, rule.chain, (), ()))
    for path, _, _ in present:
        report.add(
            Category.A_REVOIR,
            format_path(path),
            "bloc présent dans la source : conservé tel quel (keep_target sans effet) ; "
            "le comparer au bloc par défaut du 120G",
            reason=rule.reason,
        )
    if present:
        return
    if target is None:
        report.warn(f"{rule.label} : configuration cible non fournie, règle ignorée")
        return
    defaults = list(_matches(target.children, rule.chain, (), ()))
    if not defaults:
        report.warn(f"{rule.label} : bloc absent de la source et de target-default.conf")
        return
    for path, parent, block in defaults:
        scope = path[:-1]
        siblings = _scope_children(doc, scope)
        where = format_path(path)
        if siblings is None or len(rule.chain) != 1:
            report.add(Category.A_REVOIR, where,
                       "bloc à reprendre du 120G, mais emplacement introuvable dans la configuration "
                       "convertie : à ajouter à la main", reason=rule.reason)
            continue
        clone = copy.deepcopy(block)
        detach(clone)
        siblings.insert(_insert_position(parent, block, siblings), clone)
        report.add(Category.MODIFIE, where,
                   "bloc absent de la source, repris de la configuration par défaut du 120G",
                   after=f"config {block.name}", reason=rule.reason)


def _scope_children(doc: Document, scope: tuple[str, ...]) -> list[Node] | None:
    """Liste de nœuds de la configuration convertie correspondant à une portée de la cible."""
    if not scope:
        return doc.children
    if scope == ("config global",):
        for node in doc.children:
            if isinstance(node, ConfigBlock) and node.words == ("global",):
                return node.children
        return None
    if len(scope) == 2 and scope[0] == "config vdom":
        found: list[Node] | None = None
        for node in doc.children:
            if isinstance(node, ConfigBlock) and node.words == ("vdom",):
                for entry in node.children:
                    if isinstance(entry, Edit) and segment(entry) == scope[1]:
                        # La section de contenu du VDOM (pas la déclaration vide).
                        if any(isinstance(c, ConfigBlock) for c in entry.children) or found is None:
                            found = entry.children
        return found
    return None


def _insert_position(target_parent: list[Node], block: ConfigBlock, siblings: list[Node]) -> int:
    """Même place relative que dans la cible : avant le bloc qui le suit, sinon après celui qui le précède."""
    index = next(i for i, n in enumerate(target_parent) if n is block)
    names = {n.words: i for i, n in enumerate(siblings) if isinstance(n, ConfigBlock)}
    for following in target_parent[index + 1 :]:
        if isinstance(following, ConfigBlock) and following.words in names:
            return names[following.words]
    for preceding in reversed(target_parent[:index]):
        if isinstance(preceding, ConfigBlock) and preceding.words in names:
            return names[preceding.words] + 1
    return len(siblings)


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
