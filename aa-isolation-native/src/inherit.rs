//! What this process would hand the confined program without being asked, and
//! what this backend does about it.
//!
//! # Why a filesystem boundary does not make this unnecessary
//!
//! It makes it *more* necessary. A Landlock rule is evaluated when a path is
//! resolved; a descriptor that is already open carries its access with it and is
//! never re-resolved. So a directory descriptor inherited across `exec` is a
//! standing hole in a path-scoped boundary — `openat(inherited_dir, "secret")`
//! reaches a file no rule permits — and an authenticated socket is authority the
//! boundary was never asked about at all. ADR 0035 §5 requires the supervisor to
//! stay outside the confined tree, and an inherited descriptor is the most direct
//! way for it not to.
//!
//! # What this module does, and the two things it does not
//!
//! [`seal_inherited_descriptors`] enumerates the descriptors this process holds
//! and marks every one that is not a standard stream *close-on-exec*, so it does
//! not survive into the launcher and therefore cannot survive into the program
//! the launcher becomes. It returns the inventory either way, so a descriptor it
//! could not act on is reported as
//! [`DescriptorDisposition::ResidualUnclosable`] rather than omitted.
//!
//! It does **not** close anything. Closing a descriptor this process does not own
//! would break whatever does own it, and would race a concurrent open that reuses
//! the number. Setting the close-on-exec flag changes nothing about how the owner
//! may use the descriptor; it only stops it crossing an `exec`.
//!
//! It also does **not** run after `fork`. ADR 0035 §5 warns specifically against
//! accumulating boundary setup in a post-`fork` callback, where allocation, locks
//! and ordinary library behaviour are unsafe. The whole of this module runs in
//! the parent, before any process is created.
//!
//! # Why this is not shared with the other backend
//!
//! `aa-isolation-sandlock` carries an equivalent module, and the two are the same
//! idea because the hazard is the same. Hoisting one into `aa-isolation` would be
//! the right shape and is deliberately **not** done here: that crate is the
//! backend-neutral *contract*, the move would have to delete the sandlock copy in
//! the same change, and that file is owned by concurrent work. Recorded as a
//! follow-up rather than improvised across a boundary this ticket does not own.

use aa_isolation::{DescriptorDisposition, DescriptorInventory, InheritedDescriptor, STANDARD_DESCRIPTORS};

/// Why the three standard descriptors are handed over.
const STANDARD_REASON: &str = "a governed launch runs the operator's own program; taking its streams away \
                               would change what running it means";

/// Enumerate this process's open descriptors and keep the non-required ones from
/// surviving `exec`.
///
/// Returns the inventory of what was found and what was done about each entry.
/// Run in the parent, before any process is created.
///
/// # Hazard
///
/// Marking a descriptor close-on-exec is invisible to code that reads or writes
/// it and visible only across an `exec`. A caller that deliberately passes a
/// descriptor to a child through a post-`fork` hook, concurrently with a call to
/// this function, will find that descriptor absent in its child. Nothing in this
/// repository does that.
pub fn seal_inherited_descriptors() -> DescriptorInventory {
    #[cfg(target_os = "linux")]
    {
        linux::seal()
    }
    #[cfg(not(target_os = "linux"))]
    {
        DescriptorInventory::not_enumerable(
            format!(
                "enumerating a process's open descriptors has no portable form, and this host is {}; this \
                 backend confines Linux processes and is unavailable here",
                std::env::consts::OS
            ),
            standard_descriptors(),
        )
    }
}

/// The three standard streams, described as the delegated authority they are.
fn standard_descriptors() -> Vec<InheritedDescriptor> {
    STANDARD_DESCRIPTORS
        .iter()
        .map(|(number, description)| InheritedDescriptor {
            number: *number,
            description: (*description).to_string(),
            disposition: DescriptorDisposition::Delegated {
                reason: STANDARD_REASON.to_string(),
            },
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::path::PathBuf;

    /// Where the kernel lists this process's open descriptors.
    const FD_DIR: &str = "/proc/self/fd";

    pub(super) fn seal() -> DescriptorInventory {
        let Ok(entries) = std::fs::read_dir(FD_DIR) else {
            return DescriptorInventory::not_enumerable(
                format!("{FD_DIR} could not be read, so the open descriptors are unknown"),
                standard_descriptors(),
            );
        };

        let mut descriptors = standard_descriptors();
        for entry in entries.flatten() {
            let Some(number) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if number <= 2 {
                continue;
            }
            let target = std::fs::read_link(entry.path()).ok();
            // The directory handle opened by `read_dir` above is itself in the
            // listing, and it is closed when this function returns. Counting it
            // as residual authority would put a permanent phantom entry in every
            // inventory this backend takes.
            if is_the_enumeration_handle(target.as_ref()) {
                continue;
            }
            descriptors.push(InheritedDescriptor {
                number,
                description: target
                    .map(|t| t.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "target could not be resolved".to_string()),
                disposition: match set_close_on_exec(number) {
                    Ok(()) => DescriptorDisposition::ClosedBeforeExec,
                    Err(error) => DescriptorDisposition::ResidualUnclosable {
                        reason: format!(
                            "the close-on-exec flag could not be set on it ({error}), so it reaches the \
                             confined program and the path-scoped boundary never sees the access it carries"
                        ),
                    },
                },
            });
        }
        descriptors.sort_by_key(|d| d.number);
        DescriptorInventory::enumerated(descriptors)
    }

    /// Whether a descriptor's target is the process's own descriptor directory.
    fn is_the_enumeration_handle(target: Option<&PathBuf>) -> bool {
        target.is_some_and(|t| {
            let path = t.to_string_lossy();
            path.starts_with("/proc/") && path.ends_with("/fd")
        })
    }

    /// Mark one descriptor close-on-exec, preserving the rest of its flags.
    ///
    /// Read-modify-write rather than a bare `F_SETFD`: `FD_CLOEXEC` is the only
    /// descriptor flag Linux defines today, but writing a computed value over
    /// whatever is there would silently clear anything added later.
    fn set_close_on_exec(number: u32) -> Result<(), std::io::Error> {
        let fd = number as libc::c_int;
        // SAFETY: `fcntl` with `F_GETFD`/`F_SETFD` reads and writes one integer
        // flag word belonging to a descriptor this process holds — the number
        // came from the kernel's own listing of them a moment ago. Neither
        // command transfers ownership, closes anything, or dereferences a
        // pointer, so a descriptor closed by another thread between the listing
        // and this call yields `EBADF` and is reported, not undefined behaviour.
        let existing = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if existing < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if existing & libc::FD_CLOEXEC != 0 {
            return Ok(());
        }
        // SAFETY: as above.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, existing | libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three standard streams are always present and always delegated — they
    /// are the authority this backend keeps by design, and an inventory that
    /// omitted them would understate what the child holds.
    #[test]
    fn the_standard_streams_are_always_reported_as_delegated() {
        let inventory = seal_inherited_descriptors();
        for (number, _) in STANDARD_DESCRIPTORS {
            let found = inventory
                .descriptors()
                .iter()
                .find(|d| d.number == *number)
                .unwrap_or_else(|| panic!("descriptor {number} is not in the inventory"));
            assert!(
                matches!(found.disposition, DescriptorDisposition::Delegated { .. }),
                "{found}"
            );
        }
    }

    /// Off Linux the enumeration is impossible, and the inventory must say so
    /// rather than report an empty, clean-looking result.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_non_linux_host_reports_an_unmeasurable_inventory() {
        let inventory = seal_inherited_descriptors();
        assert!(matches!(
            inventory.completeness(),
            aa_isolation::InventoryCompleteness::NotEnumerable { .. }
        ));
        assert!(
            !inventory.asserts_clean_boundary(),
            "a host that cannot enumerate descriptors claimed a clean boundary"
        );
    }

    /// On Linux the enumeration is real, and a descriptor this test opens must
    /// appear in it and be marked as not surviving `exec`.
    ///
    /// The control is the descriptor's own absence afterwards: once it is closed
    /// the number leaves the inventory, so the entry below is the file this test
    /// opened and not a fixed range this function reports whatever is open.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_open_descriptor_is_found_and_marked_not_to_survive_exec() {
        use std::os::fd::AsRawFd;

        let file = std::fs::File::open("/proc/self/status").expect("this host has /proc");
        let number = file.as_raw_fd() as u32;

        let inventory = seal_inherited_descriptors();
        assert!(matches!(
            inventory.completeness(),
            aa_isolation::InventoryCompleteness::Complete
        ));
        let found = inventory
            .descriptors()
            .iter()
            .find(|d| d.number == number)
            .unwrap_or_else(|| panic!("descriptor {number} was open and is not in the inventory"));
        assert_eq!(
            found.disposition,
            DescriptorDisposition::ClosedBeforeExec,
            "an open descriptor was left able to cross exec: {found}"
        );

        drop(file);
        let after = seal_inherited_descriptors();
        assert!(
            !after.descriptors().iter().any(|d| d.number == number),
            "a closed descriptor is still reported as inherited"
        );
    }
}
