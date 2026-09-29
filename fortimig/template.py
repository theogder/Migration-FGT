"""Squelette de mapping.toml à compléter (aide à la rédaction, hors SPEC).

Principes : rien n'est décidé à la place de l'ingénieur.
- chaque port physique de la source reçoit la valeur ``A_DEFINIR`` : tant
  qu'elle n'est pas remplacée, ``convert`` s'arrête en ERREUR (cible
  inexistante). Aucune correspondance n'est proposée, même quand un port de
  même nom existe sur la cible (le plan de câblage fait foi) ; ce cas est
  seulement indiqué en commentaire ;
- les paramètres [device] sont en commentaire : une valeur d'exemple ne peut
  pas être appliquée par oubli.
Pour chaque port, un commentaire indique le nombre de références dans la
source (hors sa propre définition), son type d'usage et s'il est désactivé.
"""

from __future__ import annotations

from collections import Counter

from fortimig.fortios import interface_entries, is_physical_interface, iter_blocks, set_value, set_values
from fortimig.model import Command, ConfigBlock, Document, Edit, Node

TO_DEFINE = "A_DEFINIR"


def _reference_counts(doc: Document) -> Counter[str]:
    counts: Counter[str] = Counter()

    def visit(nodes: list[Node]) -> None:
        for node in nodes:
            if isinstance(node, Command):
                counts.update(t.value for t in node.args)
            elif isinstance(node, Edit):
                counts[node.name] += 1
                visit(node.children)
            elif isinstance(node, ConfigBlock):
                visit(node.children)

    visit(doc.children)
    return counts


def _roles(doc: Document) -> dict[str, list[str]]:
    """Rôle de chaque interface dans la source, pour éviter un « drop » par erreur.

    Un port sans adresse IP peut être indispensable : membre d'un agrégat,
    parent de VLAN, lien ou interface surveillée du HA, membre de zone.
    """
    roles: dict[str, list[str]] = {}
    vlans: Counter[str] = Counter()

    def add(name: str, role: str) -> None:
        roles.setdefault(name, [])
        if role not in roles[name]:
            roles[name].append(role)

    for _, entry in interface_entries(doc):
        for member in set_values(entry, "member") or []:
            add(member, f"membre de l'agrégat « {entry.name} »")
        parent = set_value(entry, "interface")
        if parent is not None and set_value(entry, "vlanid") is not None:
            vlans[parent] += 1
    for parent, count in vlans.items():
        add(parent, f"porte {count} VLAN")
    for _, block in iter_blocks(doc.children, ("system", "switch-interface")):
        for entry in block.children:
            if isinstance(entry, Edit):
                for member in set_values(entry, "member") or []:
                    add(member, f"membre du switch « {entry.name} »")
    for _, block in iter_blocks(doc.children, ("system", "zone")):
        for entry in block.children:
            if isinstance(entry, Edit):
                for member in set_values(entry, "interface") or []:
                    add(member, f"membre de la zone « {entry.name} »")
    for _, block in iter_blocks(doc.children, ("system", "ha")):
        hbdev = set_values(block, "hbdev") or []
        for name in hbdev[::2]:  # hbdev alterne nom et priorité
            add(name, "lien HA (hbdev)")
        for name in set_values(block, "session-sync-dev") or []:
            add(name, "synchro de sessions HA")
        for name in set_values(block, "monitor") or []:
            add(name, "surveillé par le HA (monitor)")
    return roles


def mapping_template(source: Document, target: Document, source_name: str, target_name: str) -> str:
    target_ports = [e.name for _, e in interface_entries(target) if is_physical_interface(e)]
    counts = _reference_counts(source)
    roles = _roles(source)
    lines = [
        "# Squelette de mapping.toml généré par « fortimig mapping-template »",
        f"# source : {source_name} ; cible : {target_name}",
        "#",
        f"# Remplacer chaque « {TO_DEFINE} » par un port du 120G, ou par \"drop\".",
        "# Aucune correspondance n'est proposée : le plan de câblage fait foi.",
        "# Un port sans adresse IP peut être indispensable (membre d'agrégat, parent",
        "# de VLAN, lien HA...) : voir son rôle en commentaire avant tout \"drop\".",
        "# Les interfaces logiques (VLAN, agrégats, zones) ne figurent pas ici :",
        "# elles gardent leur nom et suivent automatiquement leurs ports.",
        "",
        "[device]",
        '# hostname = "..."',
        '# hostname_secondary = "..."',
        "# ha_priority_primary = 200",
        "# ha_priority_secondary = 100",
        "",
        "[interfaces]",
    ]
    width = max((len(e.name) for _, e in interface_entries(source)), default=0) + 2
    for _, entry in interface_entries(source):
        if not is_physical_interface(entry):
            continue
        name = entry.name
        notes = [*roles.get(name, []), f"{counts[name] - 1} référence(s)"]
        if set_value(entry, "status") == "down":
            notes.append("status down")
        if set_value(entry, "ip") is not None:
            notes.append("adresse IP")
        mode = set_value(entry, "mode")
        if mode is not None:
            notes.append(f"mode {mode}")
        if name in target_ports:
            notes.append("port de même nom disponible sur la cible")
        key = f'"{name}"'
        lines.append(f'{key:<{width}} = "{TO_DEFINE}"  # {", ".join(notes)}')
    lines += [
        "",
        "# Ports physiques disponibles sur la cible :",
        "# " + ", ".join(target_ports),
        "",
    ]
    return "\n".join(lines)
