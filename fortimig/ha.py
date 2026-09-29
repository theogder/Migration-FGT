"""Haute disponibilité (SPEC §5.6, décisions D6 et D7).

Le renommage des interfaces HA (hbdev, session-sync-dev, monitor,
ha-mgmt-interfaces...) est fait par fortimig.interfaces. Ce module :
- applique le hostname et la priorité HA du primaire définis dans mapping.toml ;
- produit le contenu de ``secondary-ha.txt`` : hostname du secondaire et copie
  intégrale du bloc ``config system ha`` du primaire converti, priorité
  remplacée, mot de passe et tout autre secret remplacés par ``<A_RENSEIGNER>``.

Le fichier secondaire est produit dans le même mode VDOM que la configuration
convertie : si le bloc HA est sous ``config global`` (multi-VDOM), le fichier
est encadré par ``config global`` / ``end`` ; le second 120G doit alors être
passé en multi-VDOM avant collage.
"""

from __future__ import annotations

import copy

from fortimig.fortios import iter_blocks
from fortimig.lexer import Token
from fortimig.mapping import Mapping
from fortimig.model import Command, ConfigBlock, Document, Edit, Node, format_path, segment
from fortimig.report import Category, Report
from fortimig.secrets import render_command, secret_indices
from fortimig.serializer import serialize

TO_FILL = "<A_RENSEIGNER>"
_TO_FILL_TOKEN = Token(TO_FILL, TO_FILL, False)

HA_BLOCK = ("system", "ha")
GLOBAL_BLOCK = ("system", "global")


def apply_ha(doc: Document, mapping: Mapping, report: Report) -> str | None:
    """Applique hostname et priorité au primaire ; retourne le texte du secondaire.

    Retourne None si le fichier secondaire ne peut pas être produit (les
    raisons sont dans le rapport).
    """
    _apply_hostname(doc, mapping.hostname, report)

    blocks = list(iter_blocks(doc.children, HA_BLOCK))
    if not blocks:
        report.add(
            Category.A_REVOIR,
            "config system ha",
            "aucun bloc « config system ha » dans la source : secondary-ha.txt non produit",
        )
        return None
    if len(blocks) > 1:
        report.add(
            Category.A_REVOIR,
            format_path(blocks[1][0]),
            "plusieurs blocs « config system ha » : seul le premier est traité",
        )
    path, ha = blocks[0]

    if mapping.ha_priority_primary is not None:
        _set_single(ha, path, "priority", Token.make(str(mapping.ha_priority_primary), quoted=False), report)
    else:
        report.add(
            Category.A_REVOIR,
            format_path(path),
            "ha_priority_primary absent de mapping.toml : priorité du primaire inchangée",
        )
    _check_priorities(ha, path, mapping, report)
    _flag_nested_priorities(ha, path, report)
    return _secondary_text(doc, ha, path, mapping, report)


# --- Primaire -------------------------------------------------------------------


def _apply_hostname(doc: Document, hostname: str | None, report: Report) -> None:
    if hostname is None:
        report.add(
            Category.A_REVOIR,
            "config system global > set hostname",
            "hostname absent de mapping.toml : hostname inchangé",
        )
        return
    blocks = list(iter_blocks(doc.children, GLOBAL_BLOCK))
    if not blocks:
        report.add(
            Category.A_REVOIR,
            "config system global",
            "bloc « config system global » absent : hostname non appliqué",
        )
        return
    path, block = blocks[0]
    _set_single(block, path, "hostname", Token.make(hostname), report)


def _set_single(
    block: ConfigBlock, path: tuple[str, ...], option: str, value: Token, report: Report
) -> None:
    """Remplace ``set <option>`` du bloc (ou l'ajoute), et trace la modification."""
    where = format_path(path + (f"set {option}",))
    for child in block.children:
        if isinstance(child, Command) and child.verb == "set" and child.option == option:
            if [t.value for t in child.args] == [value.value]:
                return
            before = render_command(child)
            child.args = [value]
            report.add(Category.MODIFIE, where, f"{option} appliqué depuis mapping.toml",
                       before=before, after=render_command(child))
            return
    cmd = Command("set", option, [value])
    _insert_command(block, cmd)
    report.add(Category.MODIFIE, where, f"{option} ajouté depuis mapping.toml",
               after=render_command(cmd))


def _insert_command(block: ConfigBlock, cmd: Command) -> None:
    """Insère une commande avant le premier sous-bloc (ordre habituel des backups)."""
    for i, child in enumerate(block.children):
        if isinstance(child, ConfigBlock):
            block.children.insert(i, cmd)
            return
    block.children.append(cmd)


def _check_priorities(ha: ConfigBlock, path: tuple[str, ...], mapping: Mapping, report: Report) -> None:
    primary, secondary = mapping.ha_priority_primary, mapping.ha_priority_secondary
    override = _set_values(ha, "override") == ["enable"]
    if primary is not None and secondary is not None and secondary > primary and override:
        report.add(
            Category.A_REVOIR,
            format_path(path),
            f"override activé et priorité du secondaire ({secondary}) supérieure à celle du "
            f"primaire ({primary}) : le « secondaire » deviendra primaire",
        )


def _flag_nested_priorities(ha: ConfigBlock, path: tuple[str, ...], report: Report) -> None:
    """Priorités dans des sous-blocs (ex. virtual clustering) : non traitées, signalées."""

    def visit(nodes: list[Node], prefix: tuple[str, ...], depth: int) -> None:
        for node in nodes:
            p = prefix + (segment(node),)
            if isinstance(node, Command) and node.option == "priority" and depth > 0:
                report.add(
                    Category.A_REVOIR,
                    format_path(p),
                    "priorité dans un sous-bloc HA : non modifiée, à définir pour chaque membre",
                    before=render_command(node),
                )
            elif isinstance(node, (ConfigBlock, Edit)):
                visit(node.children, p, depth + 1)

    visit(ha.children, path, 0)


def _set_values(block: ConfigBlock, option: str) -> list[str] | None:
    for child in block.children:
        if isinstance(child, Command) and child.verb == "set" and child.option == option:
            return child.values
    return None


# --- Secondaire -------------------------------------------------------------------


def _secondary_text(
    doc: Document, ha: ConfigBlock, path: tuple[str, ...], mapping: Mapping, report: Report
) -> str | None:
    missing = [
        key
        for key, value in (
            ("hostname_secondary", mapping.hostname_secondary),
            ("ha_priority_secondary", mapping.ha_priority_secondary),
        )
        if value is None
    ]
    if missing:
        report.add(
            Category.ERREUR,
            "mapping.toml > [device]",
            f"{', '.join(missing)} requis pour produire secondary-ha.txt",
        )
        return None

    ha_copy = copy.deepcopy(ha)
    assert mapping.ha_priority_secondary is not None and mapping.hostname_secondary is not None
    _set_single(ha_copy, path, "priority", Token.make(str(mapping.ha_priority_secondary), quoted=False), Report())

    has_password = _replace_secrets(ha_copy)
    if has_password:
        report.add(
            Category.A_REVOIR,
            "secondary-ha.txt > config system ha > set password",
            f"mot de passe HA à renseigner à la place de {TO_FILL} (identique au primaire)",
        )
    else:
        report.add(
            Category.A_REVOIR,
            format_path(path),
            "aucun mot de passe HA dans la source : vérifier la configuration du cluster",
        )

    glob = ConfigBlock(GLOBAL_BLOCK)
    glob.children.append(Command("set", "hostname", [Token.make(mapping.hostname_secondary)]))

    out = Document(newline=doc.newline, indent_step=doc.indent_step)
    multi_vdom = len(path) > 1 and path[0] == "config global"
    if multi_vdom:
        wrapper = ConfigBlock(("global",))
        wrapper.children.extend([glob, ha_copy])
        out.children.append(wrapper)
        report.add(
            Category.A_REVOIR,
            "secondary-ha.txt",
            "configuration multi-VDOM : passer le second 120G en multi-VDOM avant de coller "
            "secondary-ha.txt (le fichier commence par « config global »)",
        )
    else:
        out.children.extend([glob, ha_copy])
    return serialize(out)


def _replace_secrets(block: ConfigBlock) -> bool:
    """Remplace tout secret du bloc par <A_RENSEIGNER>. Vrai si un mot de passe HA existait."""
    found_password = False

    def visit(nodes: list[Node], words: tuple[str, ...]) -> None:
        nonlocal found_password
        for node in nodes:
            if isinstance(node, Command):
                if node.option == "password" and node.verb == "set":
                    found_password = True
                    node.args = [_TO_FILL_TOKEN]
                elif secret_indices(node, words):
                    node.args = [_TO_FILL_TOKEN]
            elif isinstance(node, ConfigBlock):
                visit(node.children, node.words)
            elif isinstance(node, Edit):
                visit(node.children, words)

    visit(block.children, block.words)
    return found_password
