"""Analyse du config-error-log (SPEC §5.10), sur le format observé sur le 120G."""

import tomllib
from pathlib import Path

import pytest

from fortimig.cli import main
from fortimig.errlog import analyze, parse_log, render
from fortimig.parser import parse
from fortimig.rules import parse_rules

CANARY = "CANARY-SECRET"

# Configuration restaurée (synthétique) : "config system np6" en ligne 7, sous config global.
CONFIG = """#config-version=FGDST0-7.4.9-FW-build9999-000000:opmode=0:vdom=1:user=admin
config vdom
edit root
next
end
config global
config system np6
    edit "np6_0"
        set fastpath enable
    next
end
config system ha
    set password ENC CANARY-SECRET-HA==
end
end
config vdom
edit root
config firewall policy
    edit 1
        set exemple-option enable
    next
    edit 2
        set exemple-option enable
    next
end
end
"""

# Première ligne : forme exacte observée sur le lab.
LOG = """"config" "system" "np6" @ 7:global:command parse error (error -61)
"set" "exemple-option" "enable" @ 20:root:command parse error (error -61)
"set" "password" "ENC" "CANARY-SECRET-HA==" @ 13:global:value parse error (error -651)
ligne libre au format inconnu
"""


def test_parse_observed_format() -> None:
    entries, unparsed = parse_log(LOG)
    first = entries[0]
    assert (first.words, first.position, first.scope, first.message, first.code) == (
        ["config", "system", "np6"], "7", "global", "command parse error", "-61",
    )
    assert unparsed == [(4, "ligne libre au format inconnu")]


def test_locate_block_and_confirm_line() -> None:
    result = analyze(parse(CONFIG), LOG)
    np6 = result.located[0]
    assert np6.path == "config global > config system np6"
    assert (np6.config_line, np6.confirmed_line, np6.block) == (7, True, "config system np6")
    policy = result.located[1]
    # Deux occurrences : la position du log (ligne 20) désigne la policy 1.
    assert policy.candidates == 2 and policy.confirmed_line
    assert policy.path == "config vdom > edit root > config firewall policy > edit 1 > set exemple-option"
    assert (policy.block, policy.option) == ("config firewall policy", "exemple-option")


def test_unconfirmed_position_is_reported() -> None:
    result = analyze(parse(CONFIG), LOG.replace("@ 7:", "@ 99:"))
    assert not result.located[0].confirmed_line
    assert "position du log « 99 » non confirmée" in render(result)


def test_render_groups_and_proposes_valid_rules() -> None:
    text = render(analyze(parse(CONFIG), LOG))
    assert "## config system np6" in text and "## config firewall policy" in text
    blocks = text.split("```toml\n")[1:]
    rules = parse_rules(tomllib.loads("\n".join(b.split("```")[0] for b in blocks)))
    by_path = {(r.chain, r.option): r.action for r in rules}
    assert by_path[((("system", "np6"),), None)] == "remove"
    assert by_path[((("firewall", "policy"),), "exemple-option")] == "remove"


def test_secrets_masked_in_render() -> None:
    text = render(analyze(parse(CONFIG), LOG))
    assert "set password ENC <SECRET-MASQUE>" in text


def test_cli_errlog_no_leak(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    conf, log = tmp_path / "converted.conf", tmp_path / "errlog.txt"
    conf.write_text(CONFIG, "utf-8")
    log.write_text(LOG + "texte libre contenant CANARY-SECRET-HA== par erreur\n", "utf-8")
    assert main(["errlog", "--log", str(log), "--config", str(conf)]) == 0
    out = capsys.readouterr().out
    assert "3 erreur(s) reconnue(s), 2 ligne(s) au format inconnu." in out
    assert CANARY not in out


def test_empty_log() -> None:
    assert render(analyze(parse(CONFIG), "\n")).startswith(
        "# Analyse du config-error-log\n\n0 erreur(s) reconnue(s), 0 ligne(s) au format inconnu."
    )
