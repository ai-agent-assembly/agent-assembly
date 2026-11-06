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
import re
import struct
import sys
import tarfile
from pathlib import Path

ET_EXEC, ET_DYN = 2, 3
PT_INTERP, PT_DYNAMIC = 3, 2
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


def _program_header_types(data: bytes) -> set[int]:
    (e_phoff,) = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    return {
        struct.unpack_from("<I", data, e_phoff + i * e_phentsize)[0] for i in range(e_phnum)
    }


def inspect_elf(data: bytes) -> dict | None:
    """Classify an ELF image, or return None if it is not a little-endian
    64-bit ELF executable/shared object (BPF objects, scripts, ... are skipped).

    Result keys: ``reqs`` {GLIBC_x: [symbols]}, ``problem`` (str or None: the
    reason the image cannot be vouched for), ``static`` (bool).
    """
    if data[:4] != b"\x7fELF" or data[5] != 1 or data[4] != 2:
        return None
    (e_type,) = struct.unpack_from("<H", data, 16)
    if e_type not in (ET_EXEC, ET_DYN):
        return None
    dynamic = bool(_program_header_types(data) & {PT_INTERP, PT_DYNAMIC})
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    if e_shnum == 0:
        # Section-stripped: the version tables cannot be read, so a pass would
        # be a vacuous one. Refuse rather than fail open.
        return {"reqs": {}, "problem": "no section headers (stripped); cannot verify", "static": False}
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        for i in range(e_shnum)
    ]  # name,type,flags,addr,off,size,link,info,align,entsize
    by_type: dict[int, tuple] = {}
    for sh in sections:
        by_type.setdefault(sh[1], sh)
    if SHT_GNU_verneed not in by_type:
        if dynamic:
            return {"reqs": {}, "problem": "dynamically linked but has no .gnu.version_r; cannot verify", "static": False}
        return {"reqs": {}, "problem": None, "static": True}
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
    return {"reqs": result, "problem": None, "static": False}


def glibc_requirements(data: bytes) -> dict[str, list[str]] | None:
    info = inspect_elf(data)
    return None if info is None else info["reqs"]


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


_NUMERIC = re.compile(r"\d+(\.\d+)*")


def check(paths: list[Path], baseline: Version) -> tuple[int, int]:
    inspected = failed = 0
    base = ".".join(map(str, baseline))
    for label, data in iter_inputs(paths):
        info = inspect_elf(data)
        if info is None:
            continue
        inspected += 1
        if info["problem"]:
            failed += 1
            print(f"FAIL {label}: {info['problem']}")
            continue
        if info["static"]:
            print(f"ok   {label}: static executable, no glibc dependency")
            continue
        reqs = info["reqs"]
        # GLIBC_PRIVATE (or any non-numeric tag) is glibc-internal ABI: a shipped
        # binary must never need it, and it has no orderable version.
        odd = sorted(v for v in reqs if not _NUMERIC.fullmatch(v[6:]))
        numeric = {v: s for v, s in reqs.items() if v not in odd}
        top = max((parse_version(v[6:]) for v in numeric), default=())
        shown = ".".join(map(str, top)) if top else "none"
        bad = {v: s for v, s in numeric.items() if parse_version(v[6:]) > baseline}
        if odd or bad:
            failed += 1
            print(f"FAIL {label}: max GLIBC_{shown} vs baseline {base}")
            for v in odd:
                print(f"       {v}: non-numeric glibc version tag is not allowed "
                      f"({', '.join(sorted(set(reqs[v]))[:8]) or 'symbols not attributed'})")
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
