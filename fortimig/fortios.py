"""Aides de lecture de la structure FortiOS, communes à plusieurs traitements."""

from __future__ import annotations

from collections.abc import Iterator

from fortimig.model import Command, ConfigBlock, Document, Edit, Node, segment

INTERFACE_BLOCK = ("system", "interface")


def set_values(container: Edit | ConfigBlock, option: str) -> list[str] | None:
    """Valeurs de ``set <option>`` directement sous ``container``, ou None."""
    for child in container.children:
        if isinstance(child, Command) and child.verb == "set" and child.option == option:
            return child.values
    return None


def set_value(container: Edit | ConfigBlock, option: str) -> str | None:
    values = set_values(container, option)
    return values[0] if values else None


def iter_blocks(
    nodes: list[Node], words: tuple[str, ...], prefix: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], ConfigBlock]]:
    """Tous les blocs ``config <words>``, à toute profondeur (mono ou multi-VDOM)."""
    for node in nodes:
        if isinstance(node, (ConfigBlock, Edit)):
            path = prefix + (segment(node),)
            if isinstance(node, ConfigBlock) and node.words == words:
                yield path, node
            yield from iter_blocks(node.children, words, path)


def interface_entries(doc: Document) -> Iterator[tuple[tuple[str, ...], Edit]]:
    """Entrées ``edit`` de ``config system interface``, dans l'ordre du fichier."""
    for path, block in iter_blocks(doc.children, INTERFACE_BLOCK):
        for entry in block.children:
            if isinstance(entry, Edit):
                yield path + (segment(entry),), entry


def is_physical_interface(entry: Edit) -> bool:
    """Entrée de ``config system interface`` considérée comme physique.

    Formes confirmées sur l'extrait réel du 300E (DECISIONS.md U2) :
    - ports physiques, y compris ``ha``, ``mgmt`` et ``npu0_vlink0/1`` :
      ``set type physical`` ;
    - agrégats : ``set type aggregate`` ;
    - VLAN : **pas** de ``set type`` (``vlan`` est le type par défaut), mais
      ``set vlanid``.
    Une entrée sans type et sans ``vlanid`` est considérée comme physique, par
    prudence : elle devra alors figurer dans le mapping.
    """
    kind = set_value(entry, "type")
    if kind is not None:
        return kind == "physical"
    return set_value(entry, "vlanid") is None


def physical_interfaces(doc: Document) -> list[str]:
    """Noms des interfaces physiques, dans l'ordre du fichier, sans doublon."""
    seen: dict[str, None] = {}
    for _, entry in interface_entries(doc):
        if is_physical_interface(entry):
            seen.setdefault(entry.name)
    return list(seen)


def all_interfaces(doc: Document) -> list[str]:
    seen: dict[str, None] = {}
    for _, entry in interface_entries(doc):
        seen.setdefault(entry.name)
    return list(seen)
