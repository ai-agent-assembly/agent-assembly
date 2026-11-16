# AAASM-6262 (J84): run inside lldb against an attached same-uid process to count how often
# a synthetic credential appears in that process's writable memory (heap, stack, data).
#
# The needles come from the lldb process's environment (J84_NEEDLES, comma separated), never from
# argv, and the only thing printed is a count. Nothing is written to disk, so no core file exists.
import os

import lldb

needles = [n.encode() for n in os.environ["J84_NEEDLES"].split(",") if n]
proc = lldb.debugger.GetSelectedTarget().GetProcess()
err = lldb.SBError()
counts = [0] * len(needles)
regions = proc.GetMemoryRegions()
info = lldb.SBMemoryRegionInfo()
scanned = 0
scanned_regions = 0
read_failures = 0
CHUNK = 1 << 20
overlap = max(len(n) for n in needles) - 1
for i in range(regions.GetSize()):
    if not regions.GetMemoryRegionAtIndex(i, info):
        continue
    if not (info.IsReadable() and info.IsWritable()):
        continue
    base, end = info.GetRegionBase(), info.GetRegionEnd()
    if end - base > (1 << 31):
        continue
    addr = base
    tail = b""
    scanned_regions += 1
    while addr < end:
        size = min(CHUNK, end - addr)
        data = proc.ReadMemory(addr, size, err)
        if err.Fail() or not data:
            read_failures += 1
            break
        buf = tail + data
        for k, n in enumerate(needles):
            counts[k] += buf.count(n)
        tail = buf[-overlap:] if overlap else b""
        scanned += len(data)
        addr += size
print("J84SCAN counts=%s bytes_scanned=%d regions=%d read_failures=%d" % (counts, scanned, scanned_regions, read_failures))
