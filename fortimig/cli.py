"""Interface en ligne de commande de fortimig (SPEC §8).

Toute sortie console passe par ``_Console``, qui applique la garde anti-fuite
de secrets avant d'écrire.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from fortimig import __version__
from fortimig.convert import convert
from fortimig.diagnose import diagnose_bytes
from fortimig.errlog import analyze, render
from fortimig.ipanon import DEFAULT_SEED
from fortimig.mapping import MappingError, load_mapping
from fortimig.model import Document
from fortimig.parser import ENCODING, ERRORS, ParseError, load
from fortimig.report import DISPLAY_ORDER, EXIT_ERROR, EXIT_OK, render_json, render_markdown
from fortimig.rules import RulesError, load_rules
from fortimig.sanitize import reference_names, sanitize
from fortimig.secrets import LeakGuard
from fortimig.serializer import serialize
from fortimig.template import mapping_template

Handler = Callable[[argparse.Namespace], int]

SENSITIVE_SUFFIX = ".SENSIBLE.json"

# Fichiers produits par convert dans DIR (décision D10).
CONVERTED_NAME = "converted.conf"
SECONDARY_NAME = "secondary-ha.txt"
REPORT_MD_NAME = "report.md"
REPORT_JSON_NAME = "report.json"


class CliError(Exception):
    """Erreur bloquante affichée sans trace. Le message ne contient aucun secret."""


class _Console:
    def __init__(self, guard: LeakGuard | None = None) -> None:
        self.guard = guard

    def _clean(self, text: str) -> str:
        return self.guard.scrub(text) if self.guard else text

    def out(self, text: str) -> None:
        print(self._clean(text))

    def err(self, text: str) -> None:
        print(self._clean(text), file=sys.stderr)


def _load(path: str, role: str) -> Document:
    p = Path(path)
    if not p.is_file():
        raise CliError(f"{role} introuvable : {p}")
    try:
        return load(p)
    except ParseError as exc:
        # Le message de ParseError ne contient que des numéros de ligne.
        raise CliError(f"{role} ({p.name}) : {exc}") from None


def _not_implemented(args: argparse.Namespace) -> int:
    print(f"fortimig: la commande « {args.command} » n'est pas encore implémentée", file=sys.stderr)
    return EXIT_ERROR


def _cmd_sanitize(args: argparse.Namespace) -> int:
    src = Path(args.config)
    out = Path(args.out)
    if src.resolve() == out.resolve():
        raise CliError("--out doit être différent de --config")

    doc = _load(args.config, "configuration")
    guard = LeakGuard.from_documents(doc)
    console = _Console(guard)
    keep: frozenset[str] = frozenset()
    if args.keep_names_from:
        keep = reference_names(_load(args.keep_names_from, "configuration de référence"))

    for warning in doc.warnings:
        console.err(f"avertissement : {warning}")
    if args.ips and args.seed is None:
        console.err(
            "avertissement : graine par défaut ; l'anonymisation des IP est reproductible "
            "par quiconque dispose de l'outil (utiliser --seed)"
        )

    result = sanitize(
        doc,
        ips=args.ips,
        names=args.names,
        seed=args.seed if args.seed is not None else DEFAULT_SEED,
        keep_names=keep,
    )
    text = guard.scrub(serialize(result.document))
    out.write_bytes(text.encode(ENCODING, ERRORS))

    table_path: Path | None = None
    if args.ips or args.names:
        table_path = out.with_name(out.name + SENSITIVE_SUFFIX)
        table = {
            "AVERTISSEMENT": "FICHIER SENSIBLE : correspondance entre valeurs réelles et "
            "valeurs anonymisées. Ne jamais le partager ni le committer.",
            "ips": result.ip_table,
            "noms": result.name_table,
        }
        payload = json.dumps(table, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        table_path.write_bytes(guard.scrub(payload).encode("utf-8"))

    for warning in result.warnings:
        console.err(f"avertissement : {warning}")
    if guard.hits:
        console.err(
            f"avertissement : {guard.hits} occurrence(s) de valeurs secrètes masquée(s) "
            "par la garde anti-fuite"
        )
    console.out(
        f"sanitize : {result.secrets_masked} secret(s) masqué(s), "
        f"{len(result.ip_table)} adresse(s) IP et {len(result.name_table)} nom(s) remplacés"
    )
    console.out(f"sortie : {out}")
    if table_path is not None:
        console.out(f"table de correspondance (SENSIBLE, ne pas partager) : {table_path}")
    return EXIT_OK


def _cmd_convert(args: argparse.Namespace) -> int:
    source = _load(args.source, "configuration source")
    target = _load(args.target_default, "target-default")
    for path, role in ((args.mapping, "mapping.toml"), (args.rules, "rules.toml")):
        if not Path(path).is_file():
            raise CliError(f"{role} introuvable : {path}")
    try:
        mapping = load_mapping(args.mapping)
        rules = load_rules(args.rules)
    except (MappingError, RulesError) as exc:
        raise CliError(str(exc)) from None

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    converted_path, secondary_path = out / CONVERTED_NAME, out / SECONDARY_NAME
    for produced in (converted_path, secondary_path):
        if produced.resolve() in (Path(args.source).resolve(), Path(args.target_default).resolve()):
            raise CliError(f"--out écraserait un fichier d'entrée : {produced}")

    # Garde anti-fuite construite AVANT la conversion, sur les valeurs d'origine.
    guard = LeakGuard.from_documents(source, target)
    console = _Console(guard)
    result = convert(source, target, mapping, rules)
    report = result.report
    header = {
        "source": Path(args.source).name,
        "target-default": Path(args.target_default).name,
        "mapping": Path(args.mapping).name,
        "rules": Path(args.rules).name,
    }

    if report.has_errors:
        # SPEC §8 : aucune configuration écrite. Un fichier d'une exécution
        # précédente ne doit pas pouvoir être restauré par erreur.
        for stale in (converted_path, secondary_path):
            if stale.exists():
                stale.unlink()
                report.warn(f"{stale.name} d'une exécution précédente supprimé")
    else:
        converted_path.write_bytes(serialize(result.converted).encode(ENCODING, ERRORS))
        if result.secondary is not None:
            secondary_path.write_bytes(guard.scrub(result.secondary).encode(ENCODING, ERRORS))
        elif secondary_path.exists():
            secondary_path.unlink()

    (out / REPORT_MD_NAME).write_text(guard.scrub(render_markdown(report, header=header)), "utf-8")
    (out / REPORT_JSON_NAME).write_text(guard.scrub(render_json(report, header=header)), "utf-8")

    counts = report.counts()
    console.out("convert : " + ", ".join(f"{cat.value} {counts[cat]}" for cat in DISPLAY_ORDER))
    for warning in report.warnings:
        console.err(f"avertissement : {warning}")
    if report.has_errors:
        console.err(f"ERREUR bloquante : aucune configuration écrite (voir {out / REPORT_MD_NAME})")
    else:
        console.out(f"configuration convertie : {converted_path}")
        if result.secondary is not None:
            console.out(f"configuration du second 120G : {secondary_path}")
    console.out(f"rapport : {out / REPORT_MD_NAME} et {out / REPORT_JSON_NAME}")
    if guard.hits:
        console.err(f"avertissement : {guard.hits} valeur(s) secrète(s) masquée(s) par la garde anti-fuite")
    return report.exit_code()


def _cmd_mapping_template(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists():
        raise CliError(f"{out} existe déjà : choisir un autre nom (aucun écrasement)")
    source = _load(args.source, "configuration source")
    target = _load(args.target_default, "target-default")
    text = mapping_template(source, target, Path(args.source).name, Path(args.target_default).name)
    out.write_text(text, "utf-8")
    print(f"squelette écrit : {out} (remplacer chaque « A_DEFINIR » selon le plan de câblage)")
    return EXIT_OK


def _cmd_errlog(args: argparse.Namespace) -> int:
    log = Path(args.log)
    if not log.is_file():
        raise CliError(f"journal introuvable : {log}")
    doc = _load(args.config, "configuration")
    # Le journal recopie des lignes de configuration : même garde anti-fuite.
    console = _Console(LeakGuard.from_documents(doc))
    text = log.read_bytes().decode(ENCODING, "replace")
    console.out(render(analyze(doc, text)).rstrip("\n"))
    return EXIT_OK


def _cmd_diagnose(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if not path.is_file():
        raise CliError(f"configuration introuvable : {path}")
    if args.line < 1 or args.context < 0:
        raise CliError("--line doit être ≥ 1 et --context ≥ 0")
    for line in diagnose_bytes(path.read_bytes(), args.line, args.context):
        print(line)
    return EXIT_OK


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
    p.set_defaults(handler=_cmd_convert)

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
    p.add_argument("--ips", action="store_true", help="remplacer les adresses IPv4")
    p.add_argument("--names", action="store_true", help="remplacer les noms d'objets et commentaires")
    p.add_argument("--seed", help="graine de l'anonymisation des IP (recommandée)")
    p.add_argument(
        "--keep-names-from",
        metavar="CONF",
        help="configuration de référence (ex. target-default.conf) dont les noms sont conservés",
    )
    p.set_defaults(handler=_cmd_sanitize)

    p = sub.add_parser(
        "mapping-template", help="générer un squelette de mapping.toml à compléter"
    )
    p.add_argument("--source", required=True)
    p.add_argument("--target-default", required=True)
    p.add_argument("--out", required=True, help="fichier à créer (jamais écrasé)")
    p.set_defaults(handler=_cmd_mapping_template)

    p = sub.add_parser(
        "diagnose",
        help="structure autour d'une ligne (sans aucune valeur), pour analyser une erreur de lecture",
    )
    p.add_argument("--config", required=True)
    p.add_argument("--line", type=int, required=True, help="ligne signalée par l'erreur")
    p.add_argument("--context", type=int, default=30, help="lignes affichées de part et d'autre")
    p.set_defaults(handler=_cmd_diagnose)

    p = sub.add_parser("errlog",help="analyser la sortie de 'diagnose debug config-error-log read'")
    p.add_argument("--log", required=True, help="sortie collée dans un fichier texte")
    p.add_argument("--config", required=True, help="configuration restaurée (converted.conf)")
    p.set_defaults(handler=_cmd_errlog)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Handler = args.handler
    try:
        return handler(args)
    except CliError as exc:
        print(f"fortimig: erreur : {exc}", file=sys.stderr)
        return EXIT_ERROR
