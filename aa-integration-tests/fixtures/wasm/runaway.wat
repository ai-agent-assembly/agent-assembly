;; AAASM-2020 / F116 ST-W Scenario 2a — runaway loop / CPU timeout.
;;
;; `_start` enters an infinite WebAssembly loop. Each iteration consumes
;; ~1 unit of wasmtime instruction fuel, so a small `SandboxLimits::fuel`
;; budget trips `Trap::OutOfFuel` within microseconds. The runtime maps
;; that to `SandboxError::CpuTimeout`.
(module
  (func (export "_start")
    (loop $infinite (br $infinite))
  )
)
