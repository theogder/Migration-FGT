"""Détection et masquage des secrets (SPEC §7)."""

import pytest

from fortimig.lexer import Token
from fortimig.model import Command
from fortimig.parser import parse
from fortimig.secrets import (
    SECRET_MARKER,
    LeakGuard,
    collect_secret_values,
    is_secret_option,
    iter_secret_commands,
    mask_document,
    private_data_encryption_enabled,
    render_command,
)
from fortimig.serializer import serialize
from tests.helpers import fixture_bytes

CANARY = "CANARY-SECRET"


def cmd(option: str, *values: str, quoted: bool = True) -> Command:
    return Command("set", option, [Token.make(v, quoted=quoted) for v in values])


@pytest.mark.parametrize(
    "option",
    [
        "password", "passwd", "sso-password", "psksecret", "psksecret-remote", "ppk-secret",
        "secret", "secondary-secret", "key", "private-key", "api-key", "passphrase",
        "wifi-passphrase", "auth-pwd", "priv-pwd", "authkey", "enckey", "key-string", "token",
    ],
)
def test_secret_option_names(option: str) -> None:
    assert is_secret_option(option)


@pytest.mark.parametrize(
    "option",
    ["password-expire", "key-inactivity", "keylife", "certificate", "name", "server", "passive"],
)
def test_non_secret_option_names(option: str) -> None:
    assert not is_secret_option(option)


def test_snmp_community_name_is_secret_in_context_only() -> None:
    assert is_secret_option("name", ("system", "snmp", "community"))
    assert not is_secret_option("name", ("firewall", "policy"))


def test_enc_keyword_is_kept_blob_is_masked() -> None:
    c = Command("set", "password", [Token.make("ENC", quoted=False), Token.make("BLOB", quoted=False)])
    assert render_command(c) == f"set password ENC {SECRET_MARKER}"


def test_enc_value_under_any_option_is_masked() -> None:
    c = Command("set", "whatever", [Token.make("ENC", quoted=False), Token.make("BLOB", quoted=False)])
    assert "BLOB" not in render_command(c)


def test_pem_value_under_any_option_is_masked() -> None:
    c = cmd("certificate", "-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----")
    assert render_command(c) == f'set certificate "{SECRET_MARKER}"'


def test_certificate_reference_is_not_masked() -> None:
    c = cmd("certificate", "Fortinet_Factory")
    assert render_command(c) == 'set certificate "Fortinet_Factory"'


def test_multiline_non_secret_rendered_on_one_line() -> None:
    c = cmd("buffer", "ligne1\nligne2")
    assert render_command(c) == 'set buffer "ligne1\\nligne2"'


def test_every_canary_command_is_detected() -> None:
    doc = parse(fixture_bytes("secrets.conf").decode())
    rendered = [render_command(c, w) for _, c, w in iter_secret_commands(doc)]
    assert rendered, "aucune commande secrète détectée"
    for line in rendered:
        assert CANARY not in line
    # Toute ligne de la fixture contenant un canari appartient à une commande détectée.
    detected_values = collect_secret_values(doc)
    for line in fixture_bytes("secrets.conf").decode().splitlines():
        if CANARY in line:
            token = line.strip().split()[-1].strip('"')
            assert any(token in v for v in detected_values), line


def test_mask_document_removes_all_canaries() -> None:
    doc = parse(fixture_bytes("secrets.conf").decode())
    count = mask_document(doc)
    text = serialize(doc)
    assert CANARY not in text
    assert count == 17
    # La structure et les valeurs non secrètes sont intactes.
    assert "set key-inactivity 30" in text
    assert "set password-expire 2099-01-01 00:00:00" in text
    assert f"set password ENC {SECRET_MARKER}" in text
    parse(text)  # toujours parsable


def test_leak_guard_scrubs_full_and_partial_values() -> None:
    doc = parse(fixture_bytes("secrets.conf").decode())
    guard = LeakGuard.from_documents(doc)
    leaked = "a CANARY-SECRET-0001-ADMIN== b CANARY-SECRET-0008-PEMKEY-LINE2 c"
    assert guard.scrub(leaked) == f"a {SECRET_MARKER} b {SECRET_MARKER} c"
    assert guard.hits == 2
    assert guard.scrub("rien a signaler") == "rien a signaler"


def test_private_data_encryption_detection() -> None:
    assert private_data_encryption_enabled(parse(fixture_bytes("secrets.conf").decode()))
    assert not private_data_encryption_enabled(parse(fixture_bytes("simple.conf").decode()))
    disabled = "config system global\n    set private-data-encryption disable\nend\n"
    assert not private_data_encryption_enabled(parse(disabled))
