//! The contract between the supervisor and the launcher binary: one argument
//! vector, built on one side and parsed on the other.
//!
//! # Why the contract is a module and not a convention
//!
//! The supervisor ([`crate::backend`]) builds the vector and the launcher
//! binary (`src/bin/aa-isolation-launch.rs`) reads it. Those are different processes,
//! so nothing but a test can hold them together — and a test can only hold them
//! together if both sides go through the same code. [`build`] and [`parse`] are
//! that code, and [`tests::every_built_command_line_parses_back_to_its_input`]
//! is the round trip.
//!
//! # Argv is argv
//!
//! Nothing here builds a shell command, quotes, splits or joins. Every element
//! of [`LauncherArgv`] becomes exactly one element of `execve`'s argument
//! vector, so a program named `; rm -rf /` is a program with a strange name and
//! not a second command. Two further rules make that hold under adversarial
//! input:
//!
//! * **Every value-taking flag is one argument**, `--flag=value`. A permitted
//!   path is policy data; emitted as a separate argument, a value beginning with
//!   `-` would sit exactly where the parser looks for the next flag, and whether
//!   it were read as a value or as a flag would be a property of the parser
//!   rather than of the policy. `--flag=value` cannot be re-read as two.
//! * **The separator is mandatory.** Everything after [`ARG_SEPARATOR`] is the
//!   caller's program and arguments and is never inspected; everything before it
//!   is the backend's and is never caller-supplied.
//!
//! # No flag can widen the boundary
//!
//! There is no `--allow-all`, no `--disable`, no profile file and no escape
//! hatch. The whole grammar is two repeatable grant flags and a separator, so
//! the strongest thing an attacker who controls policy selectors can do is grant
//! a path — which is what a selector *is*. [`parse`] rejects anything it does
//! not recognise rather than ignoring it, so a future flag added on one side and
//! not the other fails closed.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Separates the launcher's own flags from the program it is to execute.
pub const ARG_SEPARATOR: &str = "--";

/// Grants read access to a path and everything beneath it.
pub const FLAG_FS_READ: &str = "--fs-read";

/// Grants write, create, rename and delete access to a path and everything
/// beneath it.
pub const FLAG_FS_WRITE: &str = "--fs-write";

/// The exit status the launcher uses when it could not establish the boundary
/// and therefore did **not** execute the program.
///
/// # Why a distinctive number, and why it is still not conclusive
///
/// A supervisor that sees this needs to know the difference between "the program
/// ran and failed" and "nothing ran". The launcher writes a
/// [`FAILURE_MARKER`]-prefixed line to standard error as well, because the
/// program it would have executed is free to exit with this same number: an exit
/// code is a one-byte channel shared with untrusted code and cannot be made
/// exclusive. The marker is the load-bearing signal; the code is the convenient
/// one.
pub const EXIT_LAUNCH_REFUSED: i32 = 121;

/// The first token of every line the launcher writes when it refuses.
///
/// Distinctive enough that a confined program cannot produce it by accident, and
/// deliberately not a word the launched program's own diagnostics would use.
pub const FAILURE_MARKER: &str = "aa-isolation-launch:refused:";

/// A malformed launcher command line.
///
/// Every variant is a refusal rather than a recovery. A launcher that
/// "helpfully" ignored an argument it did not understand would install a
/// boundary narrower or wider than the one the supervisor built, with nothing
/// recording which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgvError {
    /// No [`ARG_SEPARATOR`] appeared.
    MissingSeparator,
    /// The separator appeared with no program after it.
    MissingProgram,
    /// An argument before the separator was not a flag this launcher has.
    UnknownArgument(String),
    /// A grant flag carried a path that is not absolute.
    ///
    /// A relative grant has no meaning without a working directory, and the
    /// working directory of a confined program is not a boundary input. The
    /// policy layer rejects these at authoring time
    /// (`aa_security::policy::filesystem::PathScopeError::NotAbsolute`); this is
    /// the same rule restated where the kernel call is made, because the two
    /// sides are different processes and this one cannot assume the other ran.
    RelativeGrant {
        /// The flag that carried it.
        flag: &'static str,
        /// The path as it arrived.
        path: String,
    },
}

impl core::fmt::Display for ArgvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingSeparator => write!(
                f,
                "no `{ARG_SEPARATOR}` separator: the launcher cannot tell its own flags from the program \
                 it is to execute, and guessing would let a program name be read as a flag"
            ),
            Self::MissingProgram => write!(f, "`{ARG_SEPARATOR}` was the last argument; no program follows it"),
            Self::UnknownArgument(arg) => write!(
                f,
                "unrecognised argument `{arg}` before the separator. This launcher has exactly two flags \
                 ({FLAG_FS_READ}=PATH and {FLAG_FS_WRITE}=PATH); anything else is refused rather than \
                 ignored, so a boundary is never installed from a command line only one side understood"
            ),
            Self::RelativeGrant { flag, path } => write!(
                f,
                "`{flag}={path}` is not absolute; a relative grant has no meaning without a working \
                 directory, which is not a boundary input"
            ),
        }
    }
}

impl std::error::Error for ArgvError {}

/// The permitted filesystem scope one launch installs, per verb.
///
/// Ordered sets so a command line is deterministic: the same requirements
/// produce the same argument vector on every host, which is what lets
/// `--dry-run` output and an evidence record be compared across runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grants {
    /// Paths whose subtree may be read and executed.
    pub read: BTreeSet<String>,
    /// Paths whose subtree may be written, created within, renamed and deleted.
    pub write: BTreeSet<String>,
}

impl Grants {
    /// Whether this launch grants nothing at all.
    ///
    /// The strictest expressible posture, not an absent one: the kernel
    /// primitive is default-deny within every handled access right, so an empty
    /// grant set denies the whole filesystem rather than leaving it open.
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }

    /// Every granted path, with the verbs granted on it.
    ///
    /// One entry per path, so a path named by both verbs is installed once with
    /// both rights rather than twice with one each. Which of those the kernel
    /// would do with two separate rules is a question this crate declines to
    /// depend on.
    pub fn by_path(&self) -> BTreeMap<&str, PathVerbs> {
        let mut merged: BTreeMap<&str, PathVerbs> = BTreeMap::new();
        for path in &self.read {
            merged.entry(path.as_str()).or_default().read = true;
        }
        for path in &self.write {
            merged.entry(path.as_str()).or_default().write = true;
        }
        merged
    }
}

/// Which verbs one granted path carries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathVerbs {
    /// The subtree may be read and executed.
    pub read: bool,
    /// The subtree may be written, created within, renamed and deleted.
    pub write: bool,
}

/// A launcher command line, parsed or ready to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherArgv {
    /// The filesystem scope to install before executing anything.
    pub grants: Grants,
    /// The program to execute once the boundary is installed.
    pub program: String,
    /// Its arguments, excluding the program name.
    pub args: Vec<String>,
}

/// Build the launcher's argument vector.
///
/// The returned vector excludes `argv[0]`: the caller supplies the launcher's
/// own path from measured host facts, so a spec can never name the binary that
/// confines it.
pub fn build(grants: &Grants, program: &str, args: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(grants.read.len() + grants.write.len() + args.len() + 2);
    for path in &grants.read {
        argv.push(format!("{FLAG_FS_READ}={path}"));
    }
    for path in &grants.write {
        argv.push(format!("{FLAG_FS_WRITE}={path}"));
    }
    argv.push(ARG_SEPARATOR.to_string());
    // From here down every element is caller-supplied and is pushed whole. No
    // element is split, quoted, escaped or joined — the vector is the argument
    // vector.
    argv.push(program.to_string());
    argv.extend(args.iter().cloned());
    argv
}

/// Parse the launcher's argument vector, excluding `argv[0]`.
///
/// # Errors
///
/// [`ArgvError`] for anything this launcher does not recognise or cannot act on.
/// Nothing is ignored and nothing is defaulted.
pub fn parse<I, S>(argv: I) -> Result<LauncherArgv, ArgvError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut grants = Grants::default();
    let mut iter = argv.into_iter().map(Into::into);
    let mut saw_separator = false;
    let mut tail: Vec<String> = Vec::new();

    for arg in iter.by_ref() {
        if arg == ARG_SEPARATOR {
            saw_separator = true;
            break;
        }
        if let Some(path) = arg.strip_prefix(&format!("{FLAG_FS_READ}=")) {
            grants.read.insert(absolute(FLAG_FS_READ, path)?);
            continue;
        }
        if let Some(path) = arg.strip_prefix(&format!("{FLAG_FS_WRITE}=")) {
            grants.write.insert(absolute(FLAG_FS_WRITE, path)?);
            continue;
        }
        return Err(ArgvError::UnknownArgument(arg));
    }
    if !saw_separator {
        return Err(ArgvError::MissingSeparator);
    }
    tail.extend(iter);
    let mut tail = tail.into_iter();
    let program = tail.next().ok_or(ArgvError::MissingProgram)?;
    Ok(LauncherArgv {
        grants,
        program,
        args: tail.collect(),
    })
}

/// Accept a grant path only if it is absolute.
fn absolute(flag: &'static str, path: &str) -> Result<String, ArgvError> {
    if path.starts_with('/') {
        return Ok(path.to_string());
    }
    Err(ArgvError::RelativeGrant {
        flag,
        path: path.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(read: &[&str], write: &[&str]) -> Grants {
        Grants {
            read: read.iter().map(|s| (*s).to_string()).collect(),
            write: write.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// The property that makes the two-process contract checkable at all.
    #[test]
    fn every_built_command_line_parses_back_to_its_input() {
        let built = LauncherArgv {
            grants: grants(&["/usr", "/etc"], &["/workspace/build"]),
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "printf x".to_string()],
        };
        let argv = build(&built.grants, &built.program, &built.args);
        assert_eq!(parse(argv).expect("a built command line parses"), built);
    }

    /// Every one of these strings is a shell metacharacter sequence that would
    /// change the meaning of a concatenated command line, and one of them is the
    /// launcher's own separator. Each must arrive as exactly one argument, byte
    /// for byte, on the caller's side of the separator.
    #[test]
    fn caller_argv_survives_verbatim_and_cannot_be_read_as_a_flag() {
        let hostile: Vec<String> = [
            "; rm -rf /",
            "$(id)",
            "`id`",
            "a b\tc",
            "--fs-write=/",
            "--",
            "*",
            "\n--fs-read=/\n",
            "'",
            "\"",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let argv = build(&grants(&["/usr"], &[]), "--fs-write=/etc", &hostile);
        let parsed = parse(argv).expect("parses");
        assert_eq!(parsed.program, "--fs-write=/etc");
        assert_eq!(parsed.args, hostile);
        // The control: the grant the launcher WILL install is the one the
        // supervisor asked for, and none of the caller's lookalike arguments
        // joined it.
        assert_eq!(parsed.grants, grants(&["/usr"], &[]));
    }

    /// A path is policy data. Emitted as its own argument it would sit exactly
    /// where the parser looks for the next flag.
    #[test]
    fn a_grant_value_that_looks_like_a_flag_stays_a_value() {
        let argv = build(&grants(&["/--fs-write=/etc"], &[]), "/bin/true", &[]);
        assert_eq!(argv[0], "--fs-read=/--fs-write=/etc");
        let parsed = parse(argv).expect("parses");
        assert_eq!(parsed.grants, grants(&["/--fs-write=/etc"], &[]));
        assert!(parsed.grants.write.is_empty(), "a read grant became a write grant");
    }

    /// Fail closed on anything unrecognised: a launcher that ignored an argument
    /// would install a boundary only one of the two processes understood.
    #[test]
    fn an_unrecognised_flag_is_refused_rather_than_ignored() {
        for hostile in ["--allow-all", "--fs-read", "-r", "--fs-write", "--disable"] {
            let error = parse([hostile, ARG_SEPARATOR, "/bin/true"]).expect_err("must refuse");
            assert_eq!(error, ArgvError::UnknownArgument(hostile.to_string()), "{hostile}");
        }
    }

    #[test]
    fn a_relative_grant_is_refused() {
        let error = parse(["--fs-read=workspace", ARG_SEPARATOR, "/bin/true"]).expect_err("must refuse");
        assert!(matches!(error, ArgvError::RelativeGrant { .. }), "{error:?}");
    }

    #[test]
    fn a_command_line_with_no_separator_or_no_program_is_refused() {
        assert_eq!(
            parse(["--fs-read=/usr"]).expect_err("no separator"),
            ArgvError::MissingSeparator
        );
        assert_eq!(
            parse(["--fs-read=/usr", ARG_SEPARATOR]).expect_err("no program"),
            ArgvError::MissingProgram
        );
    }

    /// An empty grant set is a policy, not an omission, and must survive the
    /// round trip as one.
    #[test]
    fn an_empty_grant_set_round_trips_as_deny_everything() {
        let argv = build(&Grants::default(), "/bin/true", &[]);
        assert_eq!(argv, [ARG_SEPARATOR, "/bin/true"]);
        let parsed = parse(argv).expect("parses");
        assert!(parsed.grants.is_empty());
    }

    /// A path named by both verbs is one rule with both rights, not two rules
    /// whose combination is the kernel's business.
    #[test]
    fn a_path_named_by_both_verbs_merges_into_one_entry() {
        let both = grants(&["/workspace"], &["/workspace"]);
        let merged = both.by_path();
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged["/workspace"],
            PathVerbs {
                read: true,
                write: true
            }
        );
    }
}
