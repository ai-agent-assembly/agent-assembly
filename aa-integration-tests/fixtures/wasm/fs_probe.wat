;; AAASM-2020 / F116 ST-W Scenario 1 — filesystem-isolation probe.
;;
;; Places the literal "/etc/passwd" at memory offset 0, then invokes
;; WASI preview 1 `path_open` with `fd = 3` (the first non-stdio fd,
;; unbound when `SandboxConfig::preopened_dirs` is empty). The returned
;; errno is surfaced via `proc_exit`, which the sandbox runtime catches
;; as `I32Exit(errno)` and maps to
;; `SandboxError::FilesystemBlocked { errno }` (errno is EBADF / 8 under
;; the empty-allowlist case; ENOTCAPABLE / 76 if a path escapes a
;; preopen tree).
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "/etc/passwd")
  (func (export "_start")
    (call $proc_exit
      (call $path_open
        (i32.const 3)
        (i32.const 0)
        (i32.const 0)
        (i32.const 11)
        (i32.const 0)
        (i64.const 0)
        (i64.const 0)
        (i32.const 0)
        (i32.const 100)
      )
    )
  )
)
