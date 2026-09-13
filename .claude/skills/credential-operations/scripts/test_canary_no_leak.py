"""Canary leak test for `probe_env_presence.py` and `parse_dotenv_keys.py`.

HORO-980: this is a good-faith first pass, not the final safety
authority for these scripts — a separate independent adversarial pass
re-verifies this empirically. It proves the two straightforward things a
first pass should catch: neither script's stdout or stderr contains an
unmistakable canary value that was fed to it as a credential value (via
env var, dotenv value, or the file path/argv itself), across a handful of
the dotenv edge cases the scripts claim to handle.

Run: python3 -m pytest agents/skills/credential-operations/scripts/test_canary_no_leak.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

CANARY = "CANARY_VALUE_DO_NOT_LEAK_8f3a2b91"

SCRIPTS_DIR = Path(__file__).resolve().parent
PROBE_ENV = SCRIPTS_DIR / "probe_env_presence.py"
PARSE_DOTENV = SCRIPTS_DIR / "parse_dotenv_keys.py"


def _run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        env=full_env,
        timeout=10,
    )


def _assert_no_canary(result: subprocess.CompletedProcess[str], label: str) -> None:
    assert CANARY not in result.stdout, f"{label}: canary leaked in stdout: {result.stdout!r}"
    assert CANARY not in result.stderr, f"{label}: canary leaked in stderr: {result.stderr!r}"


def test_probe_env_presence_does_not_leak_value(tmp_path: Path) -> None:
    result = _run([str(PROBE_ENV), "MY_SECRET_VAR"], env={"MY_SECRET_VAR": CANARY})
    _assert_no_canary(result, "probe_env_presence (present)")
    assert result.stdout.strip() == "PRESENT"
    assert result.returncode == 0


def test_probe_env_presence_absent_does_not_leak(tmp_path: Path) -> None:
    env = dict(os.environ)
    env.pop("DEFINITELY_ABSENT_VAR", None)
    result = _run([str(PROBE_ENV), "DEFINITELY_ABSENT_VAR"], env=env)
    _assert_no_canary(result, "probe_env_presence (absent)")
    assert result.stdout.strip() == "ABSENT"
    assert result.returncode == 1


def test_probe_env_presence_help_does_not_leak(tmp_path: Path) -> None:
    result = _run([str(PROBE_ENV), "--help"], env={"MY_SECRET_VAR": CANARY})
    _assert_no_canary(result, "probe_env_presence (--help)")


def test_parse_dotenv_keys_simple_value(tmp_path: Path) -> None:
    fixture = tmp_path / ".env"
    fixture.write_text(f"API_TOKEN={CANARY}\nOTHER_KEY=whatever\n", encoding="utf-8")
    result = _run([str(PARSE_DOTENV), str(fixture)])
    _assert_no_canary(result, "parse_dotenv_keys (simple)")
    keys = result.stdout.splitlines()
    assert keys == ["API_TOKEN", "OTHER_KEY"]
    assert result.returncode == 0


def test_parse_dotenv_keys_quoted_and_export(tmp_path: Path) -> None:
    fixture = tmp_path / ".env"
    fixture.write_text(
        "\n".join(
            [
                "# a comment mentioning nothing sensitive",
                "",
                f'export DOUBLE_QUOTED="{CANARY}"',
                f"SINGLE_QUOTED='{CANARY}'",
                "  ",
                f"SPACED_KEY = {CANARY}",
            ]
        ),
        encoding="utf-8",
    )
    result = _run([str(PARSE_DOTENV), str(fixture)])
    _assert_no_canary(result, "parse_dotenv_keys (quoted/export)")
    keys = set(result.stdout.splitlines())
    assert keys == {"DOUBLE_QUOTED", "SINGLE_QUOTED", "SPACED_KEY"}


def test_parse_dotenv_keys_multiline_quoted_value(tmp_path: Path) -> None:
    fixture = tmp_path / ".env"
    fixture.write_text(
        f'MULTILINE_KEY="line1-{CANARY}\nline2-{CANARY}"\nAFTER_KEY=fine\n',
        encoding="utf-8",
    )
    result = _run([str(PARSE_DOTENV), str(fixture)])
    _assert_no_canary(result, "parse_dotenv_keys (multiline quoted)")
    keys = result.stdout.splitlines()
    assert keys == ["AFTER_KEY", "MULTILINE_KEY"]


def test_parse_dotenv_keys_malformed_lines_are_skipped_silently(tmp_path: Path) -> None:
    fixture = tmp_path / ".env"
    fixture.write_text(
        "\n".join(
            [
                f"this is not a valid line but has {CANARY} in it",
                f"=leading-equals-{CANARY}",
                f"1BAD_KEY={CANARY}",
                "VALID_KEY=fine",
            ]
        ),
        encoding="utf-8",
    )
    result = _run([str(PARSE_DOTENV), str(fixture)])
    _assert_no_canary(result, "parse_dotenv_keys (malformed lines)")
    keys = result.stdout.splitlines()
    assert keys == ["VALID_KEY"]


def test_parse_dotenv_keys_duplicate_keys_dedupe(tmp_path: Path) -> None:
    fixture = tmp_path / ".env"
    fixture.write_text(f"DUP_KEY=first-{CANARY}\nDUP_KEY=second-{CANARY}\n", encoding="utf-8")
    result = _run([str(PARSE_DOTENV), str(fixture)])
    _assert_no_canary(result, "parse_dotenv_keys (duplicates)")
    keys = result.stdout.splitlines()
    assert keys == ["DUP_KEY"]


def test_parse_dotenv_keys_bom_does_not_corrupt_first_key(tmp_path: Path) -> None:
    fixture = tmp_path / ".env"
    fixture.write_bytes(f"﻿FIRST_KEY={CANARY}\nSECOND_KEY=fine\n".encode())
    result = _run([str(PARSE_DOTENV), str(fixture)])
    _assert_no_canary(result, "parse_dotenv_keys (BOM)")
    keys = result.stdout.splitlines()
    assert keys == ["FIRST_KEY", "SECOND_KEY"]


def test_parse_dotenv_keys_help_does_not_leak(tmp_path: Path) -> None:
    result = _run([str(PARSE_DOTENV), "--help"])
    _assert_no_canary(result, "parse_dotenv_keys (--help)")
