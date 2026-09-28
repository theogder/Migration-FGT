"""Renommage des interfaces physiques (SPEC §5.3).

Principes :
- **renommage simultané** : chaque jeton est comparé une seule fois à la table
  d'origine ``ancien -> nouveau`` ; ``port1 -> port3`` et ``port3 -> port5``
  ne produisent jamais ``port1 -> port5`` ;
- seuls sont modifiés les emplacements **connus** pour contenir des noms
  d'interface (``INTERFACE_REFS`` et ``EDIT_KEY_BLOCKS``) ;
- partout ailleurs, un jeton égal à un ancien nom est une **référence non
  couverte** : elle n'est pas modifiée et est signalée en ``A_REVOIR`` avec
  son chemin complet ;
- les interfaces logiques gardent leur nom, seules leurs références vers des
  interfaces physiques sont mises à jour.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from fortimig.fortios import INTERFACE_BLOCK, all_interfaces, interface_entries, is_physical_interface
from fortimig.lexer import Token
from fortimig.mapping import Mapping
from fortimig.model import Command, ConfigBlock, Document, Edit, Node, format_path, segment
from fortimig.report import Category, Report
from fortimig.secrets import render_command

MAPPING_PATH = "mapping.toml > [interfaces]"


@dataclass(frozen=True, slots=True)
class InterfaceRef:
    """Option dont les valeurs sont des noms d'interface.

    ``blocks`` : mots du bloc ``config`` englobant le plus proche où l'option
    est reconnue ; ``None`` = tout contexte (l'option ne désigne que des
    interfaces, quel que soit le bloc).
    ``pairs`` : les valeurs alternent nom / nombre (seuls les noms changent).
    """

    option: str
    blocks: frozenset[tuple[str, ...]] | None = None
    pairs: bool = False


def _in(*blocks: tuple[str, ...]) -> frozenset[tuple[str, ...]]:
    return frozenset(blocks)


# Table des emplacements contenant des noms d'interface. Chaque entrée est
# justifiée ; toute référence hors de cette table est signalée, jamais modifiée.
INTERFACE_REFS: tuple[InterfaceRef, ...] = (
    # SPEC §5.3. Tout contexte : parent d'un VLAN (system interface), membres
    # d'une zone (system zone), membres SD-WAN, phase1 IPsec, serveur DHCP,
    # ha-mgmt-interfaces, interface source des services (dns, ntp, log...).
    InterfaceRef("interface"),
    # SPEC §5.3. Interfaces d'entrée / sortie des policies (firewall policy,
    # shaping-policy, multicast-policy...).
    InterfaceRef("srcintf"),
    InterfaceRef("dstintf"),
    # SPEC §5.3. Interface de sortie d'une route statique. Restreint au bloc
    # connu : "device" n'est pas garanti désigner une interface ailleurs.
    InterfaceRef("device", _in(("router", "static"))),
    # SPEC §5.3. Membres d'un agrégat / redondant (system interface) ou d'un
    # software switch (system switch-interface). Restreint : dans
    # "firewall addrgrp", "member" désigne des adresses.
    InterfaceRef("member", _in(INTERFACE_BLOCK, ("system", "switch-interface"))),
    # SPEC §5.3. Interface associée à une adresse (firewall address...).
    InterfaceRef("associated-interface"),
    # SPEC §5.3. Paramètres HA. hbdev alterne nom et priorité :
    # set hbdev "ha" 0 "port15" 0 (forme confirmée sur l'extrait réel).
    InterfaceRef("hbdev", _in(("system", "ha")), pairs=True),
    InterfaceRef("session-sync-dev", _in(("system", "ha"))),
    InterfaceRef("monitor", _in(("system", "ha"))),
    InterfaceRef("pingserver-monitor-interface", _in(("system", "ha"))),
    # SPEC §5.3. Contexte non identifié (DECISIONS.md U4) ; sans risque : une
    # valeur qui n'est pas un nom d'interface mappé n'est jamais modifiée.
    InterfaceRef("gateway-address"),
    # Ajout : interface externe d'une VIP (firewall vip).
    InterfaceRef("extintf"),
    # Ajout : interface d'une local-in policy.
    InterfaceRef("intf", _in(("firewall", "local-in-policy"), ("firewall", "local-in-policy6"))),
    # Ajout : interfaces d'entrée / sortie d'une route de policy (router policy).
    InterfaceRef("input-device", _in(("router", "policy"))),
    InterfaceRef("output-device", _in(("router", "policy"))),
)

# Blocs dont les clés d'"edit" sont des noms d'interface.
EDIT_KEY_BLOCKS: frozenset[tuple[str, ...]] = frozenset(
    {
        INTERFACE_BLOCK,
        # Ajout : le service DNS est configuré par interface (edit "<interface>").
        ("system", "dns-server"),
    }
)

# Options d'un port physique dépendant du matériel cible (SPEC §5.3) :
# signalées, jamais transformées.
PORT_SPECIFIC_OPTIONS: dict[str, str] = {
    "speed": "vitesse / duplex dépendant du type de port cible (RJ45, SFP, SFP+)",
    "mediatype": "type de média dépendant du transceiver et du port cible",
    "forward-error-correction": "FEC dépendant du type de port cible",
    # DECISIONS.md U6 : l'index SNMP du 300E peut entrer en conflit avec ceux du 120G.
    "snmp-index": "index SNMP propre au boîtier source, conflit possible sur la cible",
}

_VERBS_WITH_VALUES = frozenset({"set", "append", "select", "unselect"})


def covered_indices(cmd: Command, block_words: tuple[str, ...]) -> range | None:
    """Indices des arguments de ``cmd`` qui sont des noms d'interface, ou None."""
    if cmd.verb not in _VERBS_WITH_VALUES:
        return None
    for ref in INTERFACE_REFS:
        if ref.option == cmd.option and (ref.blocks is None or block_words in ref.blocks):
            return range(0, len(cmd.args), 2) if ref.pairs else range(len(cmd.args))
    return None


def validate_mapping(
    doc: Document, mapping: Mapping, target_physical: list[str], report: Report
) -> None:
    """Contrôles bloquants et points à revoir, avant tout renommage."""
    entries = list(interface_entries(doc))
    source_all = set(all_interfaces(doc))
    physical_paths = {e.name: p for p, e in entries if is_physical_interface(e)}
    logical = source_all - set(physical_paths)
    targets = set(target_physical)

    for name, path in physical_paths.items():
        if not mapping.declares(name):
            report.add(
                Category.ERREUR,
                format_path(path),
                f"interface physique « {name} » absente du mapping "
                "(la mapper vers un port du 120G ou la déclarer \"drop\")",
            )

    for name in [*mapping.interfaces, *mapping.dropped]:
        where = f"{MAPPING_PATH} > {name}"
        if name in logical:
            report.add(
                Category.ERREUR,
                where,
                f"« {name} » est une interface logique : elle garde son nom, "
                "le mapping ne concerne que les interfaces physiques",
            )
        elif name not in source_all:
            report.add(
                Category.A_REVOIR, where, f"« {name} » n'existe pas dans la configuration source"
            )

    counts = Counter(mapping.interfaces.values())
    for source, target in mapping.interfaces.items():
        where = f"{MAPPING_PATH} > {source}"
        if target not in targets:
            report.add(
                Category.ERREUR,
                where,
                f"interface cible « {target} » absente des ports physiques de target-default.conf",
            )
        if counts[target] > 1:
            report.add(
                Category.ERREUR, where, f"interface cible « {target} » attribuée plusieurs fois"
            )
        if target in logical:
            report.add(
                Category.ERREUR,
                where,
                f"interface cible « {target} » : nom déjà porté par une interface logique de la source",
            )


def rename_interfaces(
    doc: Document, mapping: Mapping, target_physical: list[str], report: Report
) -> None:
    """Valide le mapping puis renomme en place. Les constats vont dans ``report``."""
    validate_mapping(doc, mapping, target_physical, report)
    physical = {e.name for _, e in interface_entries(doc) if is_physical_interface(e)}
    mapped = {s: t for s, t in mapping.interfaces.items() if s in physical}
    dropped = frozenset(n for n in mapping.dropped if n in physical)
    _Renamer(mapped, dropped, report).visit(doc.children, (), ())


class _Renamer:
    def __init__(self, mapped: dict[str, str], dropped: frozenset[str], report: Report) -> None:
        self.mapped = mapped  # ports physiques mappés, y compris à l'identique
        self.renamed = {s: t for s, t in mapped.items() if s != t}
        self.dropped = dropped
        self.report = report

    def _describe(self, value: str) -> str:
        if value in self.dropped:
            return f"« {value} » (interface abandonnée : drop)"
        return f"« {value} » (renommée en « {self.renamed[value]} »)"

    def visit(self, nodes: list[Node], prefix: tuple[str, ...], words: tuple[str, ...]) -> None:
        kept: list[Node] = []
        for node in nodes:
            path = prefix + (segment(node),)
            if isinstance(node, ConfigBlock):
                self.visit(node.children, path, node.words)
            elif isinstance(node, Edit):
                if not self._edit(node, path, words):
                    continue  # entrée supprimée
                self.visit(node.children, path, words)
            elif isinstance(node, Command):
                self._command(node, path, words)
            kept.append(node)
        nodes[:] = kept

    def _edit(self, entry: Edit, path: tuple[str, ...], words: tuple[str, ...]) -> bool:
        """Traite la clé d'une entrée. Retourne False si l'entrée est supprimée."""
        name = entry.name
        where = format_path(path)
        if words in EDIT_KEY_BLOCKS:
            if words == INTERFACE_BLOCK and name in self.dropped:
                self.report.add(
                    Category.SUPPRIME,
                    where,
                    f"interface physique « {name} » supprimée",
                    reason="déclarée \"drop\" dans mapping.toml",
                )
                return False
            if words == INTERFACE_BLOCK and name in self.mapped:
                # Avant renommage : le chemin et le message citent l'ancien nom.
                self._port_options(entry, path, name, self.mapped[name])
            if name in self.renamed:
                new = self.renamed[name]
                entry.key = Token.make(new, quoted=entry.key.quoted)
                self.report.add(
                    Category.MODIFIE,
                    where,
                    "interface renommée" if words == INTERFACE_BLOCK else "clé d'interface renommée",
                    before=name,
                    after=new,
                )
            elif name in self.dropped:
                self.report.add(
                    Category.A_REVOIR, where, f"entrée pour {self._describe(name)}"
                )
        elif name in self.renamed or name in self.dropped:
            self.report.add(
                Category.A_REVOIR,
                where,
                f"référence non couverte : clé d'edit égale à {self._describe(name)}, non modifiée",
            )
        return True

    def _port_options(self, entry: Edit, path: tuple[str, ...], old: str, new: str) -> None:
        for child in entry.children:
            if isinstance(child, Command) and child.option in PORT_SPECIFIC_OPTIONS:
                self.report.add(
                    Category.A_REVOIR,
                    format_path(path + (segment(child),)),
                    f"{old} -> {new} : {PORT_SPECIFIC_OPTIONS[child.option]}",
                    before=render_command(child),
                )

    def _command(self, cmd: Command, path: tuple[str, ...], words: tuple[str, ...]) -> None:
        covered = covered_indices(cmd, words)
        covered_set = set(covered) if covered is not None else set()
        where = format_path(path)
        before = render_command(cmd, words)
        new_args = list(cmd.args)
        changed = False
        for i, tok in enumerate(cmd.args):
            value = tok.value
            if value not in self.renamed and value not in self.dropped:
                continue
            if i not in covered_set:
                self.report.add(
                    Category.A_REVOIR,
                    where,
                    f"référence non couverte : valeur égale à {self._describe(value)}, non modifiée",
                    before=before,
                )
            elif value in self.dropped:
                self.report.add(
                    Category.A_REVOIR, where, f"référence vers {self._describe(value)}", before=before
                )
            else:
                new_args[i] = Token.make(self.renamed[value], quoted=tok.quoted)
                changed = True
        if changed:
            cmd.args = new_args
            self.report.add(
                Category.MODIFIE,
                where,
                "référence d'interface mise à jour",
                before=before,
                after=render_command(cmd, words),
            )
