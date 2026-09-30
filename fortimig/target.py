"""Configuration par défaut du modèle cible (SPEC §5.5, décisions D4 et D5).

À partir de ``target-default.conf`` :
1. ports physiques mappés : le bloc de la source est conservé (D4) ; les
   options du bloc par défaut du 120G qu'il ne reprend pas sont signalées
   (ex. ``mediatype`` / ``speed`` d'un port SFP+, adressage par défaut) ;
2. ports physiques non utilisés par le mapping : leur bloc par défaut est
   repris, inséré après le dernier port physique (D5). Un accès
   administratif ou un adressage DHCP par défaut sur un tel port est signalé ;
3. objets de la configuration par défaut qui disparaîtront à la restauration
   (interfaces logiques par défaut, switches matériels / virtuels, serveurs
   DHCP par défaut) : signalés en A_REVOIR.

Les blocs repris de la cible sont régénérés dans le style (indentation, fins
de ligne) de la configuration convertie.
"""

from __future__ import annotations

import copy

from fortimig.fortios import INTERFACE_BLOCK, interface_entries, is_physical_interface, iter_blocks
from fortimig.mapping import Mapping
from fortimig.model import Command, ConfigBlock, Document, Edit, Node, detach, format_path, segment
from fortimig.report import Category, Report
from fortimig.secrets import render_command

# Options sans intérêt pour la comparaison d'un port mappé avec son bloc par
# défaut : identiques par construction (vdom, type) ou traitées ailleurs
# (snmp-index, cf. interfaces.PORT_SPECIFIC_OPTIONS).
_IGNORED_DEFAULT_OPTIONS = frozenset({"vdom", "type", "snmp-index"})

# Blocs dont les entrées par défaut sont comparées à la configuration convertie
# (SPEC §5.5 : switch matériel / virtuel par défaut, serveur DHCP par défaut).
DEFAULT_OBJECT_BLOCKS: tuple[tuple[str, ...], ...] = (
    ("system", "physical-switch"),
    ("system", "virtual-switch"),
    ("system", "dhcp", "server"),
)


def apply_target_defaults(doc: Document, target: Document, mapping: Mapping, report: Report) -> None:
    target_entries = {e.name: (p, e) for p, e in interface_entries(target)}
    converted = {e.name: e for _, e in interface_entries(doc)}

    _compare_mapped_ports(mapping, target_entries, converted, report)
    _insert_unused_ports(doc, target, mapping, target_entries, converted, report)
    _flag_disappearing_interfaces(target, doc, report)
    _flag_disappearing_objects(target, doc, report)
    _flag_duplicate_snmp_index(doc, report)
    _flag_missing_default_blocks(target, doc, report)


# --- 1. Ports mappés ------------------------------------------------------------


def _set_options(entry: Edit) -> set[str]:
    return {c.option for c in entry.children if isinstance(c, Command) and c.verb == "set"}


def _compare_mapped_ports(
    mapping: Mapping,
    target_entries: dict[str, tuple[tuple[str, ...], Edit]],
    converted: dict[str, Edit],
    report: Report,
) -> None:
    for source, name in mapping.interfaces.items():
        if name not in target_entries or name not in converted:
            continue
        path, default = target_entries[name]
        kept = _set_options(converted[name])
        lost = [
            render_command(c)
            for c in default.children
            if isinstance(c, Command)
            and c.verb == "set"
            and c.option not in _IGNORED_DEFAULT_OPTIONS
            and c.option not in kept
        ]
        if lost:
            report.add(
                Category.A_REVOIR,
                format_path(path),
                f"{source} -> {name} : options du bloc par défaut du 120G non reprises "
                f"(bloc de la source conservé) : {' ; '.join(lost)}",
            )


# --- 2. Ports non utilisés ---------------------------------------------------------


def _insert_unused_ports(
    doc: Document,
    target: Document,
    mapping: Mapping,
    target_entries: dict[str, tuple[tuple[str, ...], Edit]],
    converted: dict[str, Edit],
    report: Report,
) -> None:
    used = set(mapping.interfaces.values())
    unused = [
        (name, path, entry)
        for name, (path, entry) in target_entries.items()
        if is_physical_interface(entry) and name not in used
    ]
    if not unused:
        return
    blocks = list(iter_blocks(doc.children, INTERFACE_BLOCK))
    if not blocks:
        report.add(Category.ERREUR, "config system interface",
                   "bloc « config system interface » absent de la configuration convertie")
        return
    block_path, block = blocks[0]
    position = _after_last_physical(block)
    for name, path, entry in unused:
        where = format_path(block_path + (segment(entry),))
        if name in converted:
            report.add(
                Category.ERREUR,
                where,
                f"port « {name} » du 120G non mappé, mais ce nom est déjà porté par une "
                "interface de la configuration convertie",
            )
            continue
        clone = copy.deepcopy(entry)
        detach(clone)
        block.children.insert(position, clone)
        position += 1
        report.add(
            Category.MODIFIE,
            where,
            "port du 120G non utilisé par le mapping : bloc par défaut repris (à valider sur le lab)",
            after=name,
        )
        options = {c.option: c.values for c in entry.children if isinstance(c, Command)}
        exposed = "allowaccess" in options and options.get("status") != ["down"]
        if exposed or options.get("mode") == ["dhcp"]:
            report.add(
                Category.A_REVOIR,
                where,
                "port non utilisé avec accès administratif et/ou adressage DHCP par défaut : "
                "à désactiver ou restreindre",
                before="; ".join(
                    render_command(c) for c in entry.children
                    if isinstance(c, Command) and c.option in ("allowaccess", "mode", "ip")
                ),
            )


def _after_last_physical(block: ConfigBlock) -> int:
    position = 0
    for i, child in enumerate(block.children):
        if isinstance(child, Edit) and is_physical_interface(child):
            position = i + 1
    return position


# --- 3. Objets par défaut qui disparaîtront --------------------------------------------


def _flag_disappearing_interfaces(target: Document, doc: Document, report: Report) -> None:
    converted = {e.name for _, e in interface_entries(doc)}
    for path, entry in interface_entries(target):
        if is_physical_interface(entry) or entry.name in converted:
            continue
        kind = next(
            (c.values[0] for c in entry.children
             if isinstance(c, Command) and c.option == "type" and c.values),
            "?",
        )
        report.add(
            Category.A_REVOIR,
            format_path(path),
            f"interface par défaut du 120G « {entry.name} » (type {kind}) absente de la "
            "configuration convertie : elle disparaîtra à la restauration",
            before=_summary(entry),
        )


def _signature(nodes: list[Node]) -> tuple[object, ...]:
    """Contenu comparable d'une entrée (commandes rendues masquées, récursivement)."""
    items: list[object] = []
    for node in nodes:
        if isinstance(node, Command):
            items.append(render_command(node))
        elif isinstance(node, ConfigBlock):
            items.append((node.words, _signature(node.children)))
        elif isinstance(node, Edit):
            items.append((node.key.value, _signature(node.children)))
    return tuple(items)


def _flag_disappearing_objects(target: Document, doc: Document, report: Report) -> None:
    for words in DEFAULT_OBJECT_BLOCKS:
        converted: dict[str, tuple[object, ...]] = {}
        for _, block in iter_blocks(doc.children, words):
            for entry in block.children:
                if isinstance(entry, Edit):
                    converted.setdefault(entry.name, _signature(entry.children))
        for path, block in iter_blocks(target.children, words):
            for entry in block.children:
                if not isinstance(entry, Edit):
                    continue
                where = format_path(path + (segment(entry),))
                existing = converted.get(entry.name)
                if existing is None:
                    message = "entrée par défaut du 120G absente de la configuration convertie : elle disparaîtra à la restauration"
                elif existing != _signature(entry.children):
                    message = "entrée par défaut du 120G remplacée par l'entrée de même nom de la source"
                else:
                    continue
                report.add(Category.A_REVOIR, where, message, before=_summary(entry))


def _summary(entry: Edit) -> str:
    return "; ".join(
        render_command(c) for c in entry.children
        if isinstance(c, Command) and c.option in ("type", "ip", "interface", "member", "physical-switch")
    )


# --- 4. Index SNMP en double ------------------------------------------------------------


def _flag_duplicate_snmp_index(doc: Document, report: Report) -> None:
    """Index SNMP portés par plusieurs interfaces de la configuration convertie.

    DECISIONS.md U6 : les ports repris du 300E gardent leur index, les ports
    du 120G repris par défaut gardent le leur ; un doublon est signalé, rien
    n'est renuméroté.
    """
    seen: dict[str, list[tuple[str, str]]] = {}
    for path, entry in interface_entries(doc):
        for child in entry.children:
            if isinstance(child, Command) and child.option == "snmp-index" and child.values:
                seen.setdefault(child.values[0], []).append((format_path(path), entry.name))
    for index, users in seen.items():
        if len(users) < 2:
            continue
        names = ", ".join(f"« {name} »" for _, name in users)
        for where, _ in users:
            report.add(
                Category.A_REVOIR,
                f"{where} > set snmp-index",
                f"index SNMP {index} porté par plusieurs interfaces ({names}) : à renuméroter",
            )


# --- 5. Blocs par défaut du 120G absents de la configuration convertie ----------------


def _scoped_blocks(doc: Document) -> dict[str, dict[tuple[str, ...], tuple[str, ...]]]:
    """Blocs « config » de premier niveau par portée : {portée: {mots: chemin}}.

    Portées : « global », « vdom <nom> » (toutes les sections du VDOM réunies),
    ou « racine » pour une configuration mono-VDOM.
    """
    scopes: dict[str, dict[tuple[str, ...], tuple[str, ...]]] = {}

    def add(scope: str, prefix: tuple[str, ...], nodes: list[Node]) -> None:
        for node in nodes:
            if isinstance(node, ConfigBlock):
                scopes.setdefault(scope, {}).setdefault(node.words, prefix + (segment(node),))

    for node in doc.children:
        if isinstance(node, ConfigBlock) and node.words == ("global",):
            add("global", (segment(node),), node.children)
        elif isinstance(node, ConfigBlock) and node.words == ("vdom",):
            for entry in node.children:
                if isinstance(entry, Edit):
                    add(f"vdom {entry.name}", (segment(node), segment(entry)), entry.children)
        elif isinstance(node, ConfigBlock):
            scopes.setdefault("racine", {}).setdefault(node.words, (segment(node),))
    return scopes


def _flag_missing_default_blocks(target: Document, doc: Document, report: Report) -> None:
    """Blocs présents dans la configuration par défaut du 120G et absents de la convertie.

    La source et la cible étant dans la même version de FortiOS, un tel écart
    désigne en général un bloc propre au matériel cible : la restauration le
    videra sur ce membre, alors qu'un membre neuf l'a encore (checksums HA
    différents — observé avec « config system npu », DECISIONS.md U14).
    """
    converted = _scoped_blocks(doc)
    for scope, blocks in _scoped_blocks(target).items():
        present = converted.get(scope, {})
        for words, path in blocks.items():
            if words in present or words in DEFAULT_OBJECT_BLOCKS:
                continue
            report.add(
                Category.A_REVOIR,
                format_path(path),
                "bloc présent dans la configuration par défaut du 120G, absent de la configuration "
                "convertie : la restauration le videra. S'il est propre au matériel, le reprendre "
                "avec une règle « keep_target » dans rules.toml (sinon risque de désynchronisation HA)",
            )
