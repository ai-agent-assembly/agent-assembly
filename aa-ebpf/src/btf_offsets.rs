//! Resolve `task_struct` field byte-offsets from the running kernel's BTF
//! (AAASM-3921c).
//!
//! The exec probe reads `current->real_parent->tgid` directly at exec time to
//! report the real parent pid (the `sched_process_exec` tracepoint only carries
//! the new process's own pid, and the fork-populated map path is unreliable
//! under load). `aya-ebpf` 0.1 ships an *opaque* `task_struct` binding, so the
//! probe cannot emit true CO-RE field relocations; instead the loader resolves
//! the field offsets from the kernel's own BTF at load time and publishes them
//! into the probe's `TASK_OFFSETS` map. This is equivalent to CO-RE — the
//! offsets always match the running kernel — without depending on
//! compile-time-generated `vmlinux` bindings.
//!
//! Only two offsets are needed: `task_struct.real_parent` (a
//! `struct task_struct *`) and `task_struct.tgid` (a `pid_t`). The parser
//! ([`parse_task_offsets`]) is a small, self-contained BTF walker so it can be
//! unit-tested off-Linux; [`task_offsets_from_sys`] is the thin wrapper that
//! reads `/sys/kernel/btf/vmlinux` on the running host.

/// Byte offsets of the `task_struct` fields the exec probe walks to resolve the
/// real parent tgid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskOffsets {
    /// Byte offset of `task_struct.real_parent`.
    pub real_parent: u32,
    /// Byte offset of `task_struct.tgid`.
    pub tgid: u32,
}

// --- BTF on-disk constants -------------------------------------------------

/// BTF header magic (`0xEB9F`), read in the file's own endianness.
const BTF_MAGIC: u16 = 0xEB9F;
/// Size of `struct btf_type` (name_off, info, size/type — three `u32`s).
const BTF_TYPE_HDR_LEN: usize = 12;
/// Size of `struct btf_member` (name_off, type, offset — three `u32`s).
const BTF_MEMBER_LEN: usize = 12;

// BTF kind codes (`info >> 24 & 0x1f`).
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_ENUM64: u32 = 19;

/// Endianness-aware `u32` reader over a raw BTF blob.
struct Reader<'a> {
    bytes: &'a [u8],
    little_endian: bool,
}

impl<'a> Reader<'a> {
    fn u16_at(&self, off: usize) -> Option<u16> {
        let s = self.bytes.get(off..off + 2)?;
        let arr = [s[0], s[1]];
        Some(if self.little_endian {
            u16::from_le_bytes(arr)
        } else {
            u16::from_be_bytes(arr)
        })
    }

    fn u32_at(&self, off: usize) -> Option<u32> {
        let s = self.bytes.get(off..off + 4)?;
        let arr = [s[0], s[1], s[2], s[3]];
        Some(if self.little_endian {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    }
}

/// Trailing bytes that follow the 12-byte `btf_type` header for `kind`/`vlen`.
///
/// Kinds not listed carry no trailing data (PTR, FWD, TYPEDEF, VOLATILE,
/// CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG).
fn trailing_len(kind: u32, vlen: usize) -> usize {
    match kind {
        BTF_KIND_INT => 4,
        BTF_KIND_ARRAY => 12,
        BTF_KIND_STRUCT | BTF_KIND_UNION => vlen * BTF_MEMBER_LEN,
        BTF_KIND_ENUM => vlen * 8,
        BTF_KIND_FUNC_PROTO => vlen * 8,
        BTF_KIND_VAR => 4,
        BTF_KIND_DATASEC => vlen * 12,
        BTF_KIND_DECL_TAG => 4,
        BTF_KIND_ENUM64 => vlen * 12,
        _ => 0,
    }
}

/// Read a NUL-terminated string at `name_off` within the BTF string section.
fn read_str(str_section: &[u8], name_off: u32) -> Option<&str> {
    let start = name_off as usize;
    let rest = str_section.get(start..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end]).ok()
}

/// Parse a raw BTF blob and return the `task_struct` field byte-offsets the
/// exec probe needs, or `None` if the blob is malformed or `task_struct` (with
/// both `real_parent` and `tgid`) is not present.
pub fn parse_task_offsets(btf: &[u8]) -> Option<TaskOffsets> {
    // Detect endianness from the magic, trying little then big.
    let little_endian = {
        let le = Reader {
            bytes: btf,
            little_endian: true,
        };
        if le.u16_at(0)? == BTF_MAGIC {
            true
        } else {
            let be = Reader {
                bytes: btf,
                little_endian: false,
            };
            if be.u16_at(0)? == BTF_MAGIC {
                false
            } else {
                return None;
            }
        }
    };
    let r = Reader {
        bytes: btf,
        little_endian,
    };

    // struct btf_header: magic(u16) version(u8) flags(u8) hdr_len(u32)
    //   type_off(u32) type_len(u32) str_off(u32) str_len(u32)
    let hdr_len = r.u32_at(4)? as usize;
    let type_off = r.u32_at(8)? as usize;
    let type_len = r.u32_at(12)? as usize;
    let str_off = r.u32_at(16)? as usize;
    let str_len = r.u32_at(20)? as usize;

    let type_start = hdr_len.checked_add(type_off)?;
    let type_end = type_start.checked_add(type_len)?;
    let str_start = hdr_len.checked_add(str_off)?;
    let str_end = str_start.checked_add(str_len)?;
    let str_section = btf.get(str_start..str_end)?;

    let mut pos = type_start;
    while pos + BTF_TYPE_HDR_LEN <= type_end {
        let name_off = r.u32_at(pos)?;
        let info = r.u32_at(pos + 4)?;
        let vlen = (info & 0xffff) as usize;
        let kind = (info >> 24) & 0x1f;

        let trailing = trailing_len(kind, vlen);
        let members_start = pos + BTF_TYPE_HDR_LEN;
        let next = members_start.checked_add(trailing)?;

        if kind == BTF_KIND_STRUCT && read_str(str_section, name_off) == Some("task_struct") {
            let mut real_parent: Option<u32> = None;
            let mut tgid: Option<u32> = None;
            for i in 0..vlen {
                let m = members_start + i * BTF_MEMBER_LEN;
                let m_name_off = r.u32_at(m)?;
                // m + 4 is the member type id (unused — we only need offsets).
                let m_offset_bits = r.u32_at(m + 8)?;
                // Mask off the bitfield-size high byte (kind_flag structs); the
                // fields we want are not bitfields, so the low 24 bits are the
                // plain bit offset.
                let byte_off = (m_offset_bits & 0x00ff_ffff) / 8;
                match read_str(str_section, m_name_off) {
                    Some("real_parent") => real_parent = Some(byte_off),
                    Some("tgid") => tgid = Some(byte_off),
                    _ => {}
                }
            }
            if let (Some(real_parent), Some(tgid)) = (real_parent, tgid) {
                return Some(TaskOffsets { real_parent, tgid });
            }
            // A `task_struct` STRUCT without both fields is unexpected; keep
            // scanning in case another definition carries them.
        }

        pos = next;
    }

    None
}

/// Resolve the `task_struct` offsets from the running kernel's BTF at
/// `/sys/kernel/btf/vmlinux`. Returns `None` if BTF is unavailable or cannot be
/// parsed, in which case the exec probe falls back to its map-based path.
pub fn task_offsets_from_sys() -> Option<TaskOffsets> {
    let bytes = std::fs::read("/sys/kernel/btf/vmlinux").ok()?;
    parse_task_offsets(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal little-endian BTF blob containing a single
    /// `task_struct` STRUCT with `real_parent` and `tgid` members at known
    /// byte offsets, then round-trip it through the parser.
    #[test]
    fn parses_task_struct_member_offsets() {
        // --- string section ---
        // offset 0 is the conventional empty string.
        let mut strs: Vec<u8> = vec![0];
        let off_task = strs.len() as u32;
        strs.extend_from_slice(b"task_struct\0");
        let off_real_parent = strs.len() as u32;
        strs.extend_from_slice(b"real_parent\0");
        let off_tgid = strs.len() as u32;
        strs.extend_from_slice(b"tgid\0");

        // --- type section: one STRUCT with two members ---
        let real_parent_byte: u32 = 1408;
        let tgid_byte: u32 = 2464;
        let vlen: u32 = 2;
        let info = (BTF_KIND_STRUCT << 24) | (vlen & 0xffff);

        let mut types: Vec<u8> = Vec::new();
        types.extend_from_slice(&off_task.to_le_bytes()); // name_off
        types.extend_from_slice(&info.to_le_bytes()); // info
        types.extend_from_slice(&0u32.to_le_bytes()); // size
                                                      // member 0: real_parent
        types.extend_from_slice(&off_real_parent.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes()); // type id (unused)
        types.extend_from_slice(&(real_parent_byte * 8).to_le_bytes()); // bit offset
                                                                        // member 1: tgid
        types.extend_from_slice(&off_tgid.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&(tgid_byte * 8).to_le_bytes());

        // --- header ---
        let hdr_len: u32 = 24;
        let type_off: u32 = 0;
        let type_len = types.len() as u32;
        let str_off = type_len;
        let str_len = strs.len() as u32;

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC.to_le_bytes()); // magic
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&hdr_len.to_le_bytes());
        blob.extend_from_slice(&type_off.to_le_bytes());
        blob.extend_from_slice(&type_len.to_le_bytes());
        blob.extend_from_slice(&str_off.to_le_bytes());
        blob.extend_from_slice(&str_len.to_le_bytes());
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strs);

        let got = parse_task_offsets(&blob).expect("should parse task_struct");
        assert_eq!(got.real_parent, real_parent_byte);
        assert_eq!(got.tgid, tgid_byte);
    }

    #[test]
    fn rejects_non_btf_blob() {
        assert!(parse_task_offsets(&[0, 1, 2, 3, 4, 5, 6, 7]).is_none());
        assert!(parse_task_offsets(&[]).is_none());
    }

    #[test]
    fn returns_none_when_task_struct_absent() {
        // Header with an empty type section and a one-byte string section.
        let hdr_len: u32 = 24;
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&hdr_len.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes()); // type_off
        blob.extend_from_slice(&0u32.to_le_bytes()); // type_len
        blob.extend_from_slice(&0u32.to_le_bytes()); // str_off
        blob.extend_from_slice(&1u32.to_le_bytes()); // str_len
        blob.push(0); // empty string
        assert!(parse_task_offsets(&blob).is_none());
    }
}
