;; AAASM-2020 / F116 ST-W Scenario 2b — memory exhaustion.
;;
;; Declares a 1-page initial linear memory then immediately tries to
;; grow it by 100 pages (= 6.4 MiB), well past the default
;; `SandboxLimits::memory_pages = 16` (1 MiB) cap. The `MemoryLimit`
;; `ResourceLimiter` returns `Err(MemoryExhaustedMarker)` for the grow,
;; which wasmtime surfaces as a trap; the runtime maps it to
;; `SandboxError::MemoryExhausted`.
(module
  (memory (export "memory") 1)
  (func (export "_start")
    (drop (memory.grow (i32.const 100)))
  )
)
