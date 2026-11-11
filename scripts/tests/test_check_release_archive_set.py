#!/usr/bin/env python3
"""Tests for scripts/release/check_release_archive_set.py (AAASM-4542).

Every red case is the one-edit mutation of a green fixture, so the gate is
proven able to tell a complete darwin leg from one that silently lost its proxy.
"""
from __future__ import annotations

import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "release"))
import check_release_archive_set as gate  # noqa: E402

VER = "v0.0.1-rc.9"


def make_tar(path: Path, members: dict[str, bytes], mode: int = 0o755) -> None:
    with tarfile.open(path, "w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), mode
            t.addfile(ti, io.BytesIO(data))


def build_leg(d: Path, osarch: str, skip: str | None = None) -> None:
    for comp, members in gate.COMPONENT_MEMBERS.items():
        if comp != skip:
            make_tar(d / f"aasm-{comp}-{VER}-{osarch}.tar.gz", {m: b"x" for m in members})


class ArchiveSetGate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def check(self, *osarch: str) -> list[str]:
        return [p for o in osarch for p in gate.check_leg(self.d, VER, o)]

    def test_complete_darwin_legs_pass(self) -> None:
        for o in ("darwin-arm64", "darwin-amd64"):
            build_leg(self.d, o)
        self.assertEqual(self.check("darwin-arm64", "darwin-amd64"), [])
        self.assertEqual(gate.main(["--version", VER, "--osarch", "darwin-arm64", "--osarch", "darwin-amd64", str(self.d)]), 0)

    def test_darwin_leg_missing_proxy_fails(self) -> None:
        build_leg(self.d, "darwin-arm64")
        build_leg(self.d, "darwin-amd64", skip="proxy")
        self.assertEqual(self.check("darwin-arm64"), [])
        problems = self.check("darwin-amd64")
        self.assertEqual(len(problems), 1)
        self.assertIn("aasm-proxy-v0.0.1-rc.9-darwin-amd64.tar.gz is missing", problems[0])
        rc = gate.main(["--version", VER, "--osarch", "darwin-arm64", "--osarch", "darwin-amd64", str(self.d)])
        self.assertEqual(rc, 1)

    def test_every_component_is_required(self) -> None:
        for comp in gate.COMPONENT_MEMBERS:
            with self.subTest(comp=comp):
                leg = Path(tempfile.mkdtemp(dir=self.d))
                build_leg(leg, "darwin-arm64", skip=comp)
                self.assertEqual(len(gate.check_leg(leg, VER, "darwin-arm64")), 1)

    def test_proxy_tarball_without_the_binary_fails(self) -> None:
        build_leg(self.d, "darwin-arm64")
        make_tar(self.d / f"aasm-proxy-{VER}-darwin-arm64.tar.gz", {"something-else": b"x"})
        self.assertIn("no member 'aa-proxy'", "\n".join(self.check("darwin-arm64")))

    def test_empty_or_non_executable_binary_fails(self) -> None:
        build_leg(self.d, "darwin-arm64")
        make_tar(self.d / f"aasm-proxy-{VER}-darwin-arm64.tar.gz", {"aa-proxy": b""})
        self.assertIn("non-empty regular file", "\n".join(self.check("darwin-arm64")))
        make_tar(self.d / f"aasm-proxy-{VER}-darwin-arm64.tar.gz", {"aa-proxy": b"x"}, mode=0o644)
        self.assertIn("not executable", "\n".join(self.check("darwin-arm64")))

    def test_wrong_version_token_counts_as_missing(self) -> None:
        build_leg(self.d, "darwin-arm64")
        self.assertEqual(len(gate.check_leg(self.d, "v9.9.9", "darwin-arm64")), 4)

    def test_unreadable_tarball_fails(self) -> None:
        build_leg(self.d, "darwin-arm64")
        (self.d / f"aasm-proxy-{VER}-darwin-arm64.tar.gz").write_bytes(b"not gzip")
        self.assertIn("not a readable", "\n".join(self.check("darwin-arm64")))

    def test_unknown_osarch_is_usage_error(self) -> None:
        self.assertEqual(gate.main(["--version", VER, "--osarch", "windows-amd64", str(self.d)]), 2)


if __name__ == "__main__":
    unittest.main()
