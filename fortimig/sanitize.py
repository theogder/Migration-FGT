"""Production d'une configuration partageable (SPEC §5.9).

Ordre des traitements :
1. masquage de tous les secrets (toujours) ;
2. masquage des lignes non reconnues et des commentaires hors en-tête
   (toujours : leur contenu n'a pas pu être analysé) ;
3. ``--names`` : noms d'objets, de policies, de comptes et commentaires
   remplacés par des identifiants génériques déterministes ;
4. ``--ips`` : adresses IPv4 remplacées (voir fortimig.ipanon).

Ne sont jamais modifiés : les mots-clés FortiOS (verbes, noms d'options,
valeurs non quotées hors adresses IP), les noms d'interfaces physiques, les
noms intégrés (``all``, ``root``...) et, si fournis, les noms présents dans
une configuration de référence (typiquement ``target-default.conf`` : les
objets d'usine ne sont pas sensibles et restent lisibles).

La table de correspondance est retournée à part ; elle ne contient jamais de
secret.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from fortimig.fortios import is_physical_interface, physical_interfaces
from fortimig.ipanon import DEFAULT_SEED, IPv4Anonymizer, parse_ipv4
from fortimig.lexer import Token
from fortimig.model import Command, ConfigBlock, Document, Edit, Node, RawLine
from fortimig.secrets import SECRET_MARKER, mask_document

MASKED_LINE = "# <LIGNE MASQUEE PAR SANITIZE>"

# Noms intégrés FortiOS à ne jamais remplacer, même sans configuration de
# référence : mots réservés utilisés comme valeurs de référence.
BUILTIN_NAMES = frozenset({"all", "none", "any", "ALL", "always", "root", "default"})

# Options dont la valeur (entre guillemets) est un nom libre à anonymiser.
NAME_OPTIONS = frozenset({"name", "hostname", "alias", "group-name", "username"})

# Options de texte libre, remplacées par "comment-NNNN".
COMMENT_OPTIONS = frozenset({"comment", "comments", "description"})

# Options potentiellement identifiantes que --names ne traite PAS (hors
# périmètre SPEC §5.9) : seul leur nombre est signalé, pour vérification
# manuelle avant partage.
IDENTIFYING_OPTIONS = frozenset(
    {"fqdn", "wildcard-fqdn", "dn", "server", "domain", "email", "sender", "email-to"}
)


@dataclass(slots=True)
class SanitizeResult:
    document: Document
    secrets_masked: int = 0
    lines_masked: int = 0
    ip_table: dict[str, str] = field(default_factory=dict)
    name_table: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def sanitize(
    doc: Document,
    *,
    ips: bool = False,
    names: bool = False,
    seed: str = DEFAULT_SEED,
    keep_names: frozenset[str] = frozenset(),
) -> SanitizeResult:
    """Anonymise ``doc`` en place et retourne le résultat."""
    result = SanitizeResult(doc)
    result.secrets_masked = mask_document(doc)
    result.lines_masked = _mask_raw_lines(doc.children)
    if result.lines_masked:
        result.warnings.append(
            f"{result.lines_masked} ligne(s) non reconnue(s) ou commentaire(s) masqué(s)"
        )
    if names:
        protected = BUILTIN_NAMES | keep_names | frozenset(physical_interfaces(doc))
        result.name_table = _collect_names(doc, protected)
        _replace_names(doc.children, result.name_table, in_vdom_table=False)
        _replace_header_user(doc, result.name_table, protected)
        identifying = _count_identifying(doc.children)
        for option, count in sorted(identifying.items()):
            result.warnings.append(
                f"{count} valeur(s) de l'option « {option} » non anonymisée(s) : à vérifier avant partage"
            )
    if ips:
        anonymizer = IPv4Anonymizer(seed)
        _replace_ips(doc.children, anonymizer)
        result.ip_table = dict(sorted(anonymizer.table.items(), key=lambda kv: _ip_key(kv[0])))
    return result


# Champ "user=" de l'en-tête : compte ayant produit le backup (observé :
# "#config-version=FG3H0E-7.4.9-FW-build2829-250924:opmode=0:vdom=1:user=adm-xxx").
_HEADER_USER_RE = re.compile(r"(:user=)([^:\r\n]+)")
HEADER_USER_KIND = "system-admin"


def _replace_header_user(doc: Document, table: dict[str, str], protected: frozenset[str]) -> None:
    """Remplace le compte de l'en-tête, de façon cohérente avec ``config system admin``."""
    for raw in doc.header:
        if not raw.text.startswith("#config-version="):
            continue
        match = _HEADER_USER_RE.search(raw.text)
        if match is None or match.group(2) in protected:
            continue
        user = match.group(2)
        if user not in table:
            used = set(table.values())
            n = 1
            while f"{HEADER_USER_KIND}-{n:04d}" in used:
                n += 1
            table[user] = f"{HEADER_USER_KIND}-{n:04d}"
        raw.text = raw.text[: match.start(2)] + table[user] + raw.text[match.end(2) :]


def _ip_key(entry: str) -> tuple[int, ...]:
    """Clé de tri numérique : "10.0.0.0/24" -> (10, 0, 0, 0, 24) ; hôte -> /33."""
    address, _, plen = entry.partition("/")
    return (*(int(o) for o in address.split(".")), int(plen) if plen else 33)


# --- Lignes brutes ------------------------------------------------------------


def _mask_raw_lines(nodes: list[Node]) -> int:
    count = 0
    for node in nodes:
        if isinstance(node, RawLine):
            body = node.text.rstrip("\r\n")
            if body.strip():
                newline = node.text[len(body) :]
                indent = body[: len(body) - len(body.lstrip(" \t"))]
                node.text = indent + MASKED_LINE + newline
                count += 1
        elif isinstance(node, (ConfigBlock, Edit)):
            count += _mask_raw_lines(node.children)
    return count


# --- Noms ---------------------------------------------------------------------


def reference_names(doc: Document) -> frozenset[str]:
    """Noms à conserver tirés d'une configuration de référence (clés d'edit)."""
    found: set[str] = set()

    def visit(nodes: list[Node]) -> None:
        for node in nodes:
            if isinstance(node, Edit):
                found.add(node.name)
            if isinstance(node, (ConfigBlock, Edit)):
                visit(node.children)

    visit(doc.children)
    return frozenset(found)


_KIND_RE = re.compile(r"[^a-z0-9]+")


def _kind(words: tuple[str, ...]) -> str:
    return _KIND_RE.sub("-", "-".join(words).lower()).strip("-") or "objet"


def _all_values(nodes: list[Node], out: set[str]) -> None:
    for node in nodes:
        if isinstance(node, Command):
            out.update(t.value for t in node.args)
        elif isinstance(node, (ConfigBlock, Edit)):
            if isinstance(node, Edit):
                out.add(node.name)
            _all_values(node.children, out)


def _collect_names(doc: Document, protected: frozenset[str]) -> dict[str, str]:
    """Associe chaque nom à anonymiser à un identifiant, dans l'ordre du fichier."""
    existing: set[str] = set()
    _all_values(doc.children, existing)
    table: dict[str, str] = {}
    counters: Counter[str] = Counter()

    def assign(value: str, kind: str) -> None:
        if not value or value in table or value in protected or value == SECRET_MARKER:
            return
        while True:
            counters[kind] += 1
            candidate = f"{kind}-{counters[kind]:04d}"
            if candidate not in existing:
                break
        table[value] = candidate

    def visit(nodes: list[Node], block: ConfigBlock | None) -> None:
        for node in nodes:
            if isinstance(node, ConfigBlock):
                visit(node.children, node)
            elif isinstance(node, Edit):
                if block is not None and _renamable_key(node, block):
                    assign(node.name, _kind(block.words))
                visit(node.children, block)
            elif isinstance(node, Command) and node.verb == "set":
                if node.option in COMMENT_OPTIONS:
                    kind = "comment"
                elif node.option in NAME_OPTIONS:
                    kind = node.option
                else:
                    continue
                for tok in node.args:
                    if tok.quoted:
                        assign(tok.value, kind)

    visit(doc.children, None)
    return table


def _renamable_key(entry: Edit, block: ConfigBlock) -> bool:
    if block.words == ("vdom",):
        return True  # noms de VDOM (non quotés) ; "root" est protégé
    if not entry.key.quoted:
        return False  # identifiants numériques (policies, routes...)
    if block.words == ("system", "interface"):
        return not is_physical_interface(entry)
    return True


def _replace_names(nodes: list[Node], table: dict[str, str], in_vdom_table: bool) -> None:
    for node in nodes:
        if isinstance(node, ConfigBlock):
            _replace_names(node.children, table, node.words == ("vdom",))
        elif isinstance(node, Edit):
            new = table.get(node.name)
            if new is not None and (node.key.quoted or in_vdom_table):
                node.key = Token.make(new, quoted=node.key.quoted)
            _replace_names(node.children, table, False)
        elif isinstance(node, Command):
            if any(t.quoted and t.value in table for t in node.args):
                node.args = [
                    Token.make(table[t.value]) if t.quoted and t.value in table else t
                    for t in node.args
                ]


def _count_identifying(nodes: list[Node]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for node in nodes:
        if isinstance(node, Command):
            # Une valeur qui est une simple adresse IP relève de --ips, pas de --names.
            if node.option in IDENTIFYING_OPTIONS and any(
                t.quoted and parse_ipv4(t.value) is None for t in node.args
            ):
                counts[node.option] += 1
        elif isinstance(node, (ConfigBlock, Edit)):
            counts += _count_identifying(node.children)
    return counts


# --- Adresses IP -------------------------------------------------------------


def _anon_token(tok: Token, anonymizer: IPv4Anonymizer) -> Token:
    # Une adresse IP ne contient ni guillemet ni antislash : la substitution
    # peut se faire directement sur le texte brut, sans ré-échappement.
    text = anonymizer.anonymize(tok.text)
    if text == tok.text:
        return tok
    return Token(text, anonymizer.anonymize(tok.value), tok.quoted)


def _replace_ips(nodes: list[Node], anonymizer: IPv4Anonymizer) -> None:
    for node in nodes:
        if isinstance(node, Command):
            networks = anonymizer.network_pairs([t.value for t in node.args])
            new_args = []
            for i, tok in enumerate(node.args):
                if i in networks:
                    # La valeur est exactement une adresse : le texte brut est
                    # la valeur, éventuellement entre guillemets.
                    text = tok.text.replace(tok.value, networks[i])
                    new_args.append(Token(text, networks[i], tok.quoted))
                else:
                    new_args.append(_anon_token(tok, anonymizer))
            if any(a is not b for a, b in zip(new_args, node.args)):
                node.args = new_args
        elif isinstance(node, (ConfigBlock, Edit)):
            if isinstance(node, Edit):
                node.key = _anon_token(node.key, anonymizer)
            _replace_ips(node.children, anonymizer)
