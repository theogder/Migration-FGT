"""Détection et masquage des secrets (SPEC §7).

Les secrets restent intacts dans la configuration convertie (le boîtier doit
pouvoir les déchiffrer) mais ne doivent jamais apparaître dans ce que l'outil
affiche ou écrit par ailleurs : console, rapports, diffs, messages d'erreur,
sortie de ``sanitize``.

Deux mécanismes complémentaires :

1. **Masquage** : toute commande est rendue via ``masked_args`` /
   ``render_command`` avant d'être affichée. Un argument est secret si :
   - l'option porte un nom de secret (table ci-dessous) ;
   - ou l'argument suit un jeton ``ENC`` (valeur chiffrée FortiOS :
     ``set password ENC <blob>``) ;
   - ou la valeur contient un bloc PEM (``-----BEGIN ...``) ;
   - ou le contexte l'impose (nom de communauté SNMP v1/v2c).
   En cas de doute, on masque : un masquage de trop ne coûte que de la
   lisibilité.

2. **Garde anti-fuite** (``LeakGuard``) : les valeurs secrètes de la
   configuration sont collectées, et tout texte destiné à une sortie est
   vérifié ; une occurrence est remplacée par le marqueur et comptée, sans
   jamais être affichée.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from fortimig.lexer import Token
from fortimig.model import Command, ConfigBlock, Document, Edit, Node, format_path, segment, walk

SECRET_MARKER = "<SECRET-MASQUE>"

# Dernier segment (séparé par "-") d'un nom d'option désignant un secret.
# Exemples FortiOS couverts : password, passwd, sso-password, sae-password,
# auth-pwd / priv-pwd (SNMP v3), secret / secondary-secret (RADIUS),
# psksecret / ppk-secret (IPsec), key (TACACS+, NTP), private-key, api-key,
# passphrase / wifi-passphrase, token.
_SECRET_LAST_SEGMENTS = frozenset(
    {"password", "passwd", "passphrase", "pwd", "secret", "psksecret", "key", "token"}
)

# Noms complets qui ne se terminent pas par un des segments ci-dessus.
_SECRET_EXACT = frozenset(
    {
        "authkey",  # clé d'authentification IPsec manuelle
        "enckey",  # clé de chiffrement IPsec manuelle
        "key-string",  # clés MD5 de routage (OSPF / RIP)
        "psksecret-remote",  # PSK distante IPsec
    }
)

# Contextes où une option ordinaire porte un secret :
# (mots du bloc "config" le plus proche, option).
# SNMP v1/v2c : le nom de la communauté fait office de mot de passe.
_SECRET_IN_CONTEXT = frozenset({(("system", "snmp", "community"), "name")})

# Longueur minimale d'une valeur recherchée par la garde anti-fuite : en
# dessous, le risque de faux positif sur du texte ordinaire est trop élevé.
_GUARD_MIN_LENGTH = 6


def is_secret_option(option: str, block_words: tuple[str, ...] = ()) -> bool:
    name = option.lower()
    if name in _SECRET_EXACT or name.split("-")[-1] in _SECRET_LAST_SEGMENTS:
        return True
    return (block_words, name) in _SECRET_IN_CONTEXT


def is_secret_value(value: str) -> bool:
    """Valeur secrète quel que soit le nom de l'option."""
    return value.startswith("ENC ") or "-----BEGIN" in value


def secret_indices(cmd: Command, block_words: tuple[str, ...] = ()) -> frozenset[int]:
    """Indices des arguments de ``cmd`` à masquer."""
    by_option = is_secret_option(cmd.option, block_words)
    result: set[int] = set()
    after_enc = False
    for i, tok in enumerate(cmd.args):
        if not tok.quoted and tok.value == "ENC":
            # Le mot-clé ENC lui-même n'est pas secret ; le jeton suivant l'est.
            after_enc = True
            continue
        if by_option or after_enc or is_secret_value(tok.value):
            result.add(i)
        after_enc = False
    return frozenset(result)


def _marker_like(tok: Token) -> Token:
    if tok.quoted:
        return Token(f'"{SECRET_MARKER}"', SECRET_MARKER, True)
    return Token(SECRET_MARKER, SECRET_MARKER, False)


def masked_args(cmd: Command, block_words: tuple[str, ...] = ()) -> list[Token]:
    hidden = secret_indices(cmd, block_words)
    return [_marker_like(t) if i in hidden else t for i, t in enumerate(cmd.args)]


def render_command(cmd: Command, block_words: tuple[str, ...] = ()) -> str:
    """Rendu sur une ligne, secrets masqués, pour la console et les rapports."""
    words = [cmd.verb, cmd.option, *(t.text for t in masked_args(cmd, block_words))]
    # Une valeur multi-lignes non secrète est aplatie pour rester sur une ligne.
    return " ".join(words).replace("\r\n", "\\n").replace("\n", "\\n")


def mask_document(doc: Document) -> int:
    """Masque en place tous les secrets de ``doc``. Retourne le nombre de valeurs masquées."""
    count = 0

    def visit(nodes: list[Node], words: tuple[str, ...]) -> None:
        nonlocal count
        for node in nodes:
            if isinstance(node, Command):
                hidden = secret_indices(node, words)
                if hidden:
                    node.args = masked_args(node, words)
                    count += len(hidden)
            elif isinstance(node, ConfigBlock):
                visit(node.children, node.words)
            elif isinstance(node, Edit):
                visit(node.children, words)

    visit(doc.children, ())
    return count


def iter_secret_commands(doc: Document) -> Iterable[tuple[str, Command, tuple[str, ...]]]:
    """Commandes contenant au moins un secret : (chemin, commande, mots du bloc)."""

    def visit(
        nodes: list[Node], prefix: tuple[str, ...], words: tuple[str, ...]
    ) -> Iterable[tuple[str, Command, tuple[str, ...]]]:
        for node in nodes:
            path = prefix + (segment(node),)
            if isinstance(node, Command):
                if secret_indices(node, words):
                    yield format_path(path), node, words
            elif isinstance(node, ConfigBlock):
                yield from visit(node.children, path, node.words)
            elif isinstance(node, Edit):
                yield from visit(node.children, path, words)

    return visit(doc.children, (), ())


def collect_secret_values(doc: Document) -> set[str]:
    """Toutes les valeurs secrètes de ``doc``, pour la garde anti-fuite.

    Pour une valeur multi-lignes (PEM), chaque ligne significative est aussi
    collectée afin de détecter une fuite partielle.
    """
    values: set[str] = set()
    for _, cmd, words in iter_secret_commands(doc):
        for i in secret_indices(cmd, words):
            tok = cmd.args[i]
            values.update((tok.value, tok.text))
            for line in tok.value.splitlines():
                line = line.strip()
                if not line.startswith("-----"):
                    values.add(line)
    return {v for v in values if len(v) >= _GUARD_MIN_LENGTH and v != SECRET_MARKER}


@dataclass(slots=True)
class LeakGuard:
    """Filet de sécurité : remplace toute valeur secrète connue par le marqueur."""

    needles: tuple[str, ...]
    hits: int = 0

    @classmethod
    def from_documents(cls, *docs: Document) -> LeakGuard:
        values: set[str] = set()
        for doc in docs:
            values |= collect_secret_values(doc)
        # Les plus longues d'abord, pour qu'une valeur ne soit pas masquée
        # partiellement par l'une de ses sous-chaînes.
        return cls(tuple(sorted(values, key=lambda v: (-len(v), v))))

    def scrub(self, text: str) -> str:
        for needle in self.needles:
            if needle in text:
                self.hits += text.count(needle)
                text = text.replace(needle, SECRET_MARKER)
        return text


def private_data_encryption_enabled(doc: Document) -> bool:
    """Vrai si ``set private-data-encryption enable`` figure sous ``config system global``.

    Le bloc peut se trouver à la racine (mono-VDOM) ou sous ``config global``.
    """
    for path, node in walk(doc.children):
        if (
            isinstance(node, Command)
            and node.verb == "set"
            and node.option == "private-data-encryption"
            and node.values == ["enable"]
            and len(path) >= 2
            and path[-2] == "config system global"
        ):
            return True
    return False
