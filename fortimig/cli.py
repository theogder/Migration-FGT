"""Interface en ligne de commande de fortimig (SPEC §8)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from fortimig import __version__
from fortimig.report import EXIT_ERROR

Handler = Callable[[argparse.Namespace], int]


def _not_implemented(args: argparse.Namespace) -> int:
    print(f"fortimig: la commande « {args.command} » n'est pas encore implémentée", file=sys.stderr)
    return EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortimig",
        description="Conversion de configuration FortiGate 300E (FortiOS 7.4) vers 120G. "
        "Aucune action réseau : l'outil ne lit et n'écrit que des fichiers locaux.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMANDE")

    p = sub.add_parser("convert", help="convertir la configuration source pour le modèle cible")
    p.add_argument("--source", required=True, help="backup complet du 300E")
    p.add_argument("--target-default", required=True, help="backup de la configuration par défaut du 120G")
    p.add_argument("--mapping", required=True, help="mapping.toml")
    p.add_argument("--rules", required=True, help="rules.toml")
    p.add_argument("--out", required=True, help="répertoire de sortie")
    p.set_defaults(handler=_not_implemented)

    p = sub.add_parser("check", help="contrôler l'intégrité des références d'une configuration")
    p.add_argument("--config", required=True)
    p.add_argument("--target-default")
    p.set_defaults(handler=_not_implemented)

    p = sub.add_parser("diff", help="diff lisible entre deux configurations, secrets masqués")
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    p.set_defaults(handler=_not_implemented)

    p = sub.add_parser("sanitize", help="produire une version anonymisée et partageable")
    p.add_argument("--config", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--ips", action="store_true", help="remplacer les adresses IP")
    p.add_argument("--names", action="store_true", help="remplacer les noms d'objets et commentaires")
    p.set_defaults(handler=_not_implemented)

    p = sub.add_parser("errlog", help="analyser la sortie de 'diagnose debug config-error-log read'")
    p.add_argument("--log", required=True)
    p.add_argument("--config", required=True)
    p.set_defaults(handler=_not_implemented)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Handler = args.handler
    return handler(args)
