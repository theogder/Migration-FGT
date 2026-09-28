import subprocess
import sys

import pytest

from fortimig.cli import main
from fortimig.report import EXIT_ERROR, EXIT_OK, EXIT_REVIEW, Category, Report


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for command in ("convert", "check", "diff", "sanitize", "errlog"):
        assert command in out


def test_missing_required_argument_is_blocking() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["convert", "--source", "x.conf"])
    assert exc.value.code == EXIT_ERROR


def test_python_dash_m_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "fortimig", "--version"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert "fortimig" in result.stdout


def test_report_exit_codes() -> None:
    report = Report()
    assert report.exit_code() == EXIT_OK
    report.add(Category.MODIFIE, "config system global > set hostname", "hostname")
    assert report.exit_code() == EXIT_OK
    report.add(Category.A_REVOIR, "config system interface > edit \"port1\" > set speed", "speed")
    assert report.exit_code() == EXIT_REVIEW
    report.add(Category.ERREUR, "config system interface > edit \"port9\"", "non mappée")
    assert report.exit_code() == EXIT_ERROR
    assert report.counts()[Category.A_REVOIR] == 1
