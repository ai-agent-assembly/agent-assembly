#!/usr/bin/env python3
"""Tests for scripts/release/check_linux_glibc_baseline.py (AAASM-6440).

The guard exists because the rc.8 Linux tarballs silently required GLIBC_2.39.
A guard that cannot tell a 2.39 binary from a 2.28 one reproduces that false
green, so every test pairs a passing ELF with the one-field edit (the GLIBC
version it needs) that must turn it red, using synthetic ELF images that carry
a real .gnu.version_r + .dynsym + .gnu.version, the same sections ld.so reads.
"""
from __future__ import annotations

import io
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "release"))
import check_linux_glibc_baseline as guard  # noqa: E402


def make_elf(glibc_syms: dict[str, str], e_type: int = 3) -> bytes:
    """ELF64 LE image whose only content is a dynamic symbol table versioned
    against libc.so.6: {symbol: "GLIBC_x.y"}."""
    versions = sorted(set(glibc_syms.values()))
    dynstr = bytearray(b"\0")

    def add(s: str) -> int:
        off = len(dynstr)
        dynstr.extend(s.encode() + b"\0")
        return off

    libc = add("libc.so.6")
    ver_name = {v: add(v) for v in versions}
    sym_name = {s: add(s) for s in glibc_syms}
    ver_index = {v: 2 + i for i, v in enumerate(versions)}  # 0/1 are local/global
    dynsym = b"\0" * 24 + b"".join(
        struct.pack("<IBBHQQ", sym_name[s], 0x12, 0, 0, 0, 0) for s in glibc_syms
    )
    versym = struct.pack("<H", 0) + b"".join(
        struct.pack("<H", ver_index[v]) for v in glibc_syms.values()
    )
    verneed = struct.pack("<HHIII", 1, len(versions), libc, 16, 0)
    for i, v in enumerate(versions):
        nxt = 16 if i < len(versions) - 1 else 0
        verneed += struct.pack("<IHHII", 0, 0, ver_index[v], ver_name[v], nxt)

    shstr = b"\0.dynsym\0.dynstr\0.gnu.version\0.gnu.version_r\0"
    # Section 0 null, 1 dynsym, 2 dynstr, 3 versym, 4 verneed
    blobs = [dynsym, bytes(dynstr), versym, verneed]
    off = 64
    offs = []
    for b in blobs:
        offs.append(off)
        off += len(b)
    shoff = off
    sh = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    sh.append(struct.pack("<IIQQQQIIQQ", 0, guard.SHT_DYNSYM, 2, 0, offs[0], len(dynsym), 2, 1, 8, 24))
    sh.append(struct.pack("<IIQQQQIIQQ", 0, 3, 2, 0, offs[1], len(dynstr), 0, 0, 1, 0))
    sh.append(struct.pack("<IIQQQQIIQQ", 0, guard.SHT_GNU_versym, 2, 0, offs[2], len(versym), 1, 0, 2, 2))
    sh.append(struct.pack("<IIQQQQIIQQ", 0, guard.SHT_GNU_verneed, 2, 0, offs[3], len(verneed), 2, 1, 8, 0))
    ehdr = (
        b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
        + struct.pack("<HHIQQQIHHHHHH", e_type, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sh), 0)
    )
    return ehdr + b"".join(blobs) + b"".join(sh)


class GlibcRequirements(unittest.TestCase):
    def test_reads_versions_and_attributes_symbols(self) -> None:
        reqs = guard.glibc_requirements(
            make_elf({"memcpy": "GLIBC_2.14", "pidfd_spawnp": "GLIBC_2.39"})
        )
        self.assertEqual(reqs, {"GLIBC_2.14": ["memcpy"], "GLIBC_2.39": ["pidfd_spawnp"]})

    def test_non_elf_and_relocatable_objects_are_ignored(self) -> None:
        self.assertIsNone(guard.glibc_requirements(b"#!/bin/sh\n"))
        self.assertIsNone(guard.glibc_requirements(make_elf({"a": "GLIBC_2.2"}, e_type=1)))


class Check(unittest.TestCase):
    baseline = (2, 28)

    def run_on(self, *files: tuple[str, bytes]) -> tuple[int, int]:
        with tempfile.TemporaryDirectory() as d:
            for name, data in files:
                (Path(d) / name).write_bytes(data)
            return guard.check([Path(d)], self.baseline)

    def test_within_baseline_passes(self) -> None:
        self.assertEqual(self.run_on(("ok", make_elf({"memcpy": "GLIBC_2.14", "dlsym": "GLIBC_2.2.5"}))), (1, 0))

    def test_exactly_at_baseline_passes(self) -> None:
        self.assertEqual(self.run_on(("ok", make_elf({"x": "GLIBC_2.28"}))), (1, 0))

    def test_one_minor_above_baseline_fails(self) -> None:
        self.assertEqual(self.run_on(("bad", make_elf({"x": "GLIBC_2.29"}))), (1, 1))

    def test_rc8_shape_fails(self) -> None:
        # The rc.8 aasm requirement: C23 scanf/strtol plus pidfd_spawnp.
        elf = make_elf({"__isoc23_strtol": "GLIBC_2.38", "pidfd_spawnp": "GLIBC_2.39", "memcpy": "GLIBC_2.14"})
        self.assertEqual(self.run_on(("aasm", elf)), (1, 1))

    def test_version_compared_numerically_not_lexically(self) -> None:
        # "2.9" > "2.28" lexically; must still pass.
        self.assertEqual(self.run_on(("ok", make_elf({"x": "GLIBC_2.9"}))), (1, 0))

    def test_one_bad_binary_among_good_fails_the_set(self) -> None:
        self.assertEqual(
            self.run_on(("a", make_elf({"x": "GLIBC_2.2.5"})), ("b", make_elf({"y": "GLIBC_2.34"}))), (2, 1)
        )

    def test_tarball_members_are_inspected(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = make_elf({"x": "GLIBC_2.39"})
            info = tarfile.TarInfo("aasm")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        self.assertEqual(self.run_on(("a.tar.gz", buf.getvalue())), (1, 1))


class Cli(unittest.TestCase):
    def test_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            good, bad = Path(d, "good"), Path(d, "bad")
            good.write_bytes(make_elf({"x": "GLIBC_2.17"}))
            bad.write_bytes(make_elf({"x": "GLIBC_2.39"}))
            self.assertEqual(guard.main([str(good), "--baseline", "2.28"]), 0)
            self.assertEqual(guard.main([str(bad), "--baseline", "2.28"]), 1)
            # An input with no Linux ELF must not pass: that is a vacuous green.
            Path(d, "text").write_text("not elf")
            self.assertEqual(guard.main([str(Path(d, "text"))]), 2)

    def test_checked_in_baseline_is_a_version(self) -> None:
        self.assertGreaterEqual(guard.parse_version(guard.read_baseline()), (2, 17))


if __name__ == "__main__":
    unittest.main()
