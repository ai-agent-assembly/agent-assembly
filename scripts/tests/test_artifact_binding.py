#!/usr/bin/env python3
"""Tests for scripts/release/artifact_binding.py (AAASM-6468).

Each red case is a one-edit mutation of a green fixture: the digests come from
the 'build' side (digest_files over genuine bytes), the directory is what a
later job could have tampered with.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "release"))
import artifact_binding as ab  # noqa: E402

VER = "v0.0.1-rc.9"


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.d = self.root / "artifacts"
        self.d.mkdir()
        self.env: dict[str, str] = {}
        for target in ab.TARGET_OSARCH:
            names = ab.expected_names(target, VER)
            for n in names:
                (self.d / n).write_bytes(f"genuine:{n}".encode())
            self.env[ab.env_name(target)] = json.dumps(
                ab.digest_files([self.d / n for n in names]), sort_keys=True
            )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_main(self, argv: list[str], environ: dict[str, str] | None = None) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = ab.main(argv, self.env if environ is None else environ)
        return rc, err.getvalue()

    def verify(self) -> tuple[int, str]:
        return self.run_main(["verify-archives", "--version", VER, "--dir", str(self.d)])


class Archives(Fixture):
    def test_twenty_files_expected(self) -> None:
        self.assertEqual(len(list(self.d.iterdir())), 20)

    def test_genuine_set_passes(self) -> None:
        self.assertEqual(self.verify()[0], 0)

    def test_tampered_file_fails(self) -> None:
        with (self.d / f"aasm-cli-{VER}-linux-amd64.tar.gz").open("ab") as f:
            f.write(b"\0")
        rc, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("does not match the build job's", err)

    def test_replaced_file_fails(self) -> None:
        (self.d / "aasm-x86_64-unknown-linux-gnu.tar.gz").write_bytes(b"attacker tarball")
        self.assertEqual(self.verify()[0], 1)

    def test_extra_file_fails(self) -> None:
        (self.d / "aasm-evil-injected.tar.gz").write_bytes(b"junk")
        rc, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("unexpected file", err)

    def test_missing_file_fails(self) -> None:
        (self.d / f"aasm-proxy-{VER}-darwin-arm64.tar.gz").unlink()
        rc, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("missing from", err)

    def test_empty_output_fails(self) -> None:
        for blank in ("", "   ", None):
            env = dict(self.env)
            key = ab.env_name("aarch64-apple-darwin")
            if blank is None:
                del env[key]
            else:
                env[key] = blank
            rc, err = self.run_main(["verify-archives", "--version", VER, "--dir", str(self.d)], env)
            self.assertEqual(rc, 1, blank)
            self.assertIn("empty or unset", err)

    def test_malformed_output_fails(self) -> None:
        env = dict(self.env)
        env[ab.env_name("aarch64-apple-darwin")] = "not json"
        self.assertEqual(self.run_main(["verify-archives", "--version", VER, "--dir", str(self.d)], env)[0], 1)

    def test_output_with_extra_name_fails(self) -> None:
        key = ab.env_name("x86_64-apple-darwin")
        data = json.loads(self.env[key])
        data["aasm-evil.tar.gz"] = "0" * 64
        env = dict(self.env)
        env[key] = json.dumps(data)
        rc, err = self.run_main(["verify-archives", "--version", VER, "--dir", str(self.d)], env)
        self.assertEqual(rc, 1)
        self.assertIn("unexpected", err)

    def test_output_with_missing_name_fails(self) -> None:
        key = ab.env_name("x86_64-apple-darwin")
        data = json.loads(self.env[key])
        data.pop(f"aasm-api-{VER}-darwin-amd64.tar.gz")
        env = dict(self.env)
        env[key] = json.dumps(data)
        self.assertEqual(self.run_main(["verify-archives", "--version", VER, "--dir", str(self.d)], env)[0], 1)

    def test_malformed_sha_fails(self) -> None:
        key = ab.env_name("x86_64-apple-darwin")
        data = json.loads(self.env[key])
        data[f"aasm-api-{VER}-darwin-amd64.tar.gz"] = "ABC"
        env = dict(self.env)
        env[key] = json.dumps(data)
        self.assertEqual(self.run_main(["verify-archives", "--version", VER, "--dir", str(self.d)], env)[0], 1)

    def test_wrong_version_fails(self) -> None:
        rc, _ = self.run_main(["verify-archives", "--version", "v9.9.9", "--dir", str(self.d)])
        self.assertEqual(rc, 1)

    def test_symlink_instead_of_file_fails(self) -> None:
        victim = self.d / f"aasm-cli-{VER}-linux-arm64.tar.gz"
        real = self.root / "real"
        real.write_bytes(victim.read_bytes())
        victim.unlink()
        os.symlink(real, victim)
        rc, err = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("not a plain regular file", err)

    def test_subdirectory_fails(self) -> None:
        (self.d / "nested").mkdir()
        self.assertEqual(self.verify()[0], 1)


class Ebpf(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        for n in ab.EBPF_OBJECTS:
            (self.d / n).write_bytes(f"bpf:{n}".encode())
        self.env = {"AA_EBPF_DIGESTS": json.dumps(ab.digest_files([self.d / n for n in ab.EBPF_OBJECTS]))}

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_main(self, env: dict[str, str]) -> int:
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return ab.main(["verify-ebpf", "--dir", str(self.d)], env)

    def test_genuine_passes(self) -> None:
        self.assertEqual(self.run_main(self.env), 0)

    def test_tampered_fails(self) -> None:
        (self.d / "aa-tls-probes").write_bytes(b"swapped")
        self.assertEqual(self.run_main(self.env), 1)

    def test_extra_fails(self) -> None:
        (self.d / "aa-extra").write_bytes(b"x")
        self.assertEqual(self.run_main(self.env), 1)

    def test_missing_fails(self) -> None:
        (self.d / "aa-file-io").unlink()
        self.assertEqual(self.run_main(self.env), 1)

    def test_empty_output_fails(self) -> None:
        self.assertEqual(self.run_main({"AA_EBPF_DIGESTS": ""}), 1)
        self.assertEqual(self.run_main({}), 1)


class DigestCli(unittest.TestCase):
    def test_digest_roundtrip_matches_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.tar.gz"
            p.write_bytes(b"hello")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = ab.main(["digest", str(p)], {})
            self.assertEqual(rc, 0)
            self.assertEqual(
                json.loads(out.getvalue()),
                {"a.tar.gz": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
            )

    def test_digest_missing_file_is_usage_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ab.main(["digest", "/nonexistent/x"], {}), 2)


if __name__ == "__main__":
    unittest.main()
