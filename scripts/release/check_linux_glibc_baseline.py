#!/usr/bin/env python3
"""Fail when a shipped Linux executable needs a GLIBC symbol above the baseline.

AAASM-6440: the rc.8 Linux tarballs were built on ubuntu-24.04 and required
GLIBC_2.39, so they did not start on Debian 12 / Ubuntu 22.04 / RHEL 9. The
baseline lives in scripts/release/linux-glibc-baseline.txt (single source for
the release workflow, this guard, and the docs check).

Stdlib only: parses ELF .gnu.version_r / .dynsym directly, so it runs on any
host (macOS included) without binutils. Inputs may be ELF files, directories
(walked), or .tar.gz archives (members extracted in memory).

Exit 0: every ELF executable/shared object is within the baseline.
Exit 1: at least one exceeds it (offending symbols are listed).
Exit 2: usage error or no Linux ELF found (a guard that inspected nothing
must not pass).
"""
from __future__ import annotations

import argparse
import io
import struct
import sys
import tarfile
from pathlib import Path

ET_EXEC, ET_DYN = 2, 3
SHT_DYNSYM, SHT_GNU_verneed, SHT_GNU_versym = 11, 0x6FFFFFFE, 0x6FFFFFFF
BASELINE_FILE = Path(__file__).with_name("linux-glibc-baseline.txt")

Version = tuple[int, ...]


def parse_version(text: str) -> Version:
    return tuple(int(p) for p in text.split("."))


def read_baseline() -> str:
    for line in BASELINE_FILE.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            return line
    raise SystemExit(f"no baseline in {BASELINE_FILE}")


def _cstr(blob: bytes, off: int) -> str:
    return blob[off : blob.index(b"\0", off)].decode()


def glibc_requirements(data: bytes) -> dict[str, list[str]] | None:
    """Return {GLIBC_x.y: [symbols]} for an ELF image, or None if not a
    loadable little-endian ELF executable/shared object."""
    if data[:4] != b"\x7fELF" or data[5] != 1:  # little-endian only (x86_64, aarch64)
        return None
    is64 = data[4] == 2
    if not is64:
        return None
    (e_type,) = struct.unpack_from("<H", data, 16)
    if e_type not in (ET_EXEC, ET_DYN):
        return None
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        sh = struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        sections.append(sh)  # name,type,flags,addr,off,size,link,info,align,entsize
    by_type = {}
    for sh in sections:
        by_type.setdefault(sh[1], sh)
    if SHT_GNU_verneed not in by_type:
        return {}
    vn = by_type[SHT_GNU_verneed]
    strtab = sections[vn[6]]
    strs = data[strtab[4] : strtab[4] + strtab[5]]
    # index -> "GLIBC_x.y" for version needs from libc.so.6 / libm / etc.
    idx_to_ver: dict[int, str] = {}
    off = vn[4]
    for _ in range(vn[7]):
        _ver, cnt, _file, aux, nxt = struct.unpack_from("<HHIII", data, off)
        a = off + aux
        for _ in range(cnt):
            _hash, _flags, other, name, anext = struct.unpack_from("<IHHII", data, a)
            idx_to_ver[other] = _cstr(strs, name)
            a += anext
        off += nxt
    result: dict[str, list[str]] = {}
    for v in idx_to_ver.values():
        if v.startswith("GLIBC_"):
            result.setdefault(v, [])
    # Attribute symbols to versions via .dynsym + .gnu.version.
    if SHT_DYNSYM in by_type and SHT_GNU_versym in by_type:
        ds, vs = by_type[SHT_DYNSYM], by_type[SHT_GNU_versym]
        dstr = sections[ds[6]]
        dstrs = data[dstr[4] : dstr[4] + dstr[5]]
        for i in range(ds[5] // 24):
            st_name, = struct.unpack_from("<I", data, ds[4] + i * 24)
            (ver,) = struct.unpack_from("<H", data, vs[4] + i * 2)
            ver &= 0x7FFF
            name = idx_to_ver.get(ver)
            if name and name.startswith("GLIBC_"):
                result[name].append(_cstr(dstrs, st_name))
    return result


def iter_inputs(paths: list[Path]):
    for p in paths:
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() or f.suffixes[-2:] == [".tar", ".gz"]:
                    yield from iter_inputs([f])
        elif p.name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(p) as tf:
                for m in tf.getmembers():
                    if m.isfile():
                        yield f"{p.name}:{m.name}", tf.extractfile(m).read()
        elif p.is_file():
            yield str(p), p.read_bytes()


def check(paths: list[Path], baseline: Version) -> tuple[int, int]:
    inspected = failed = 0
    for label, data in iter_inputs(paths):
        reqs = glibc_requirements(data)
        if reqs is None:
            continue
        inspected += 1
        top = max((parse_version(v[6:]) for v in reqs), default=())
        shown = ".".join(map(str, top)) if top else "none"
        bad = {v: s for v, s in reqs.items() if parse_version(v[6:]) > baseline}
        if bad:
            failed += 1
            print(f"FAIL {label}: max GLIBC_{shown} > baseline {'.'.join(map(str, baseline))}")
            for v in sorted(bad, key=lambda x: parse_version(x[6:])):
                print(f"       {v}: {', '.join(sorted(set(bad[v]))[:8]) or '(symbols not attributed)'}")
        else:
            print(f"ok   {label}: max GLIBC_{shown}")
    return inspected, failed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--baseline", help="override (default: linux-glibc-baseline.txt)")
    args = ap.parse_args(argv)
    baseline = parse_version(args.baseline or read_baseline())
    inspected, failed = check(args.paths, baseline)
    if inspected == 0:
        print("error: no Linux ELF executables found in the given inputs", file=sys.stderr)
        return 2
    print(f"inspected {inspected} ELF file(s), {failed} above baseline")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
