# Stage 3 & 4 — Closed-Loop Differential FFI Verification & Executive Scorecard (`libBlurDetection.camera.samsung.so` -> `s9_blur_detection`)

## 1. Executive Summary

- **Target Artifact:** `libBlurDetection.camera.samsung.so` (SHA-256: `07baf5e21a19cd1c53ab61aa47c19949da47e1bbbeb66f855a67e2b2c19d5615`)
- **Reconstructed Safe Rust Crate:** [`s9_blur_detection`](../src/lib.rs) (`#![forbid(unsafe_code)]`, zero external dependencies)
- **Standalone Parity & Remediation Suite:** [`tests/parity_regression.rs`](../tests/parity_regression.rs)
- **Verification Engine:** `verify_rust_parity` (`harness_mode: "native-rustc"`, `seed: 1337420`, `float_ulp_tolerance: 0`, `forbid_unsafe: true`)
- **Overall Parity Verdict:** **`verified_bit_exact`** (`0` divergences across `30,118` total randomized SplitMix64 + boundary FFI test vectors and `300,000` benchmark invocations)

---

## 2. Differential FFI Verification, Benchmark Telemetry & Pinned FNV-1a Digests

| Kernel Symbol | Evidence ID | Arg Types | Return Type | Status | Random + Boundary Vectors | Pinned 64-Bit FNV-1a Output Digest | `#![forbid(unsafe_code)]` / Unsafe Blocks | C Oracle (`ns/call`) | Safe Rust (`ns/call`) | Speedup vs. C Oracle |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [`blur_multi_scale_residual`](../src/lib.rs#L185-L196) | `ev_ac1c154a6afa7684b892fe5cb91baa791d20e7b666fa7ec5b5d35f0dd8ecbbe0` | `["u8", "u8", "u8", "u8", "u8", "u8", "u8"]` | `i32` | **`verified_bit_exact`** | `10,000 + 64 = 10,064` | `0x14cd_4b02_1b22_c0fd` | `true` / `0` | `7.0403 ns` | `5.9807 ns` | **`1.18x`** |
| [`blur_dif_lt_kernel`](../src/lib.rs#L362-L373) | `ev_88a55e350e2425d0c0f6503c92171ef13f74a88a11593006f0b408c46ee830fb` | `["bytes"]` | `i32` | **`verified_bit_exact`** | `10,000 + 27 = 10,027` | `0xb637_e542_8d55_5071` | `true` / `0` | `3,102.8621 ns` | `1,165.9509 ns` | **`2.66x`** |
| [`get_blur_val_tile`](../src/lib.rs#L378-L386) | `ev_8ffaa3058f958653bc35c52a9dc883e1f53d0c0c445ebae4ed0a735f3c50417a` | `["bytes"]` | `i32` | **`verified_bit_exact`** | `10,000 + 27 = 10,027` | `0x8579_3ffe_6e04_6840` | `true` / `0` | `9,410.5065 ns` | `3,657.1140 ns` | **`2.57x`** |

---

## 3. C-to-Rust Mathematical Invariant & Memory-Safety Mapping Table

| AArch64 Binary Function (`VA`) | C/C++ Reference Behavior & Latent Hazards | Safe Rust Reconstruction (`src/lib.rs`) | Verified Mathematical & Memory Invariant |
| :--- | :--- | :--- | :--- |
| `_Z10get_dif_ltPhiiiS_` (`0x0fc8`) | Computes 1st-order `\|dx\|` and `\|dy\|` across `(width_lt - 1) × height_lt` and applies a 2-pixel directional maximum filter (`max(d[i], d[i+1])`) into an aliased `uint8_t* diff_buf` offset by `height_lt * width_lt`. Unchecked pointer arithmetic overflows if `src` or `diff_buf` is undersized. | [`get_dif_lt`](../src/lib.rs#L28-L74) | Splits `dx_buf` and `dy_buf` into disjoint mutable slices (`&mut [u8]`) with `.get()`/`.get_mut()` bounds checks and `saturating_mul` stride offsets; verified bit-exact via `blur_dif_lt_kernel` (`10,027` vectors, `0` ULP diff). |
| `_Z10get_cnt_ltPhS_iiiPiS0_S0_S0_` (`0x138c`) | Partitions `dx_buf` and `dy_buf` into `4×4` blocks (`blocks_x × blocks_y`), sums 16 bytes per block, and increments `cnt_x` / `cnt_y` when `(int32_t)((uint32_t)sum << 16) < (40 << 16)`. Leaves two trailing pointer parameters (`unused_3`, `unused_4`) uninitialized (`SAM-BUG-10b`). | [`get_cnt_lt`](../src/lib.rs#L84-L107) | Replaces raw out-pointers and unused pointer arguments with a pure `(i32, i32)` return tuple while preserving the exact `(((sx as u32) << 16) as i32) < (40 << 16)` comparison semantics. |
| `_Z16calc_low_texturePhiiS_` (`0x15d4`) | Computes 4-pixel-aligned interior ROI dimensions `width_lt = ((w - 9) - ((w - 9) % 4)) + 2`, `height_lt = ((h - 9) - ((h - 9) % 4)) + 2`, offsets `img + 4 * width + 4`, and reads the unwritten 3rd stack counter (`[sp, #0x8]`) at `0x16bc` when both `10 * cnt_x > 9 * total_blocks` and `10 * cnt_y > 9 * total_blocks` (`SAM-BUG-10b`). | [`calc_low_texture`](../src/lib.rs#L121-L149), [`calc_low_texture_remediated`](../src/lib.rs#L156-L180) | Bounds dimensions to `[10, 16_384]`, splits `work_buf` safely via `split_at_mut(plane_len)`, preserves C-oracle parity in `calc_low_texture`, and restores the intended `10 * cnt_x > thresh && 10 * cnt_y > thresh` check in `calc_low_texture_remediated`. |
| `get_blur_val` (`0x1710`) | Aliases `work_buf` as two `uint16_t*` planes (`buf_v` at `+0` and `buf_h` at `+2 * width * height`), computes multi-scale residuals `max(0, 9 * (d1 & 0xff) - d9)`, accumulates `16×8` macroblock `f64` sharpness ratios `1.0 - (double)sum_res / (double)(9 * sum_1)` when `((uint32_t)(sum_1 - 400) >> 4) < 475u`, and truncates `(int)(final_ratio * 100.0)`. | [`blur_multi_scale_residual`](../src/lib.rs#L185-L196), [`get_blur_val`](../src/lib.rs#L208-L287), [`get_blur_val_remediated`](../src/lib.rs#L292-L309) | Allocates strongly typed `Vec<u16>` planes (`buf_v`, `buf_h`) and `work_buf` sized to `plane_len.saturating_mul(2)`, preserves reverse row iteration (`for r in (0..16).rev()`) and IEEE-754 `f64` evaluation order, and restores `LOW_TEXTURE_SENTINEL` (`-100`) in `get_blur_val_remediated`. |
| `compute_blur` (`0x1c08`) | Wraps raw `uint8_t*` in an OpenCV `cv::Mat`, resizes to `288×216` (`INTER_LINEAR`), calls `malloc(0x4bf00)` (`311,040` bytes) without a `NULL` check (`SAM-BUG-10`), and returns `100 - get_blur_val(...)`. | [`compute_blur`](../src/lib.rs#L318-L356) | Eliminates `libopencv_core.so` / `libopencv_imgproc.so` FFI dependencies and unchecked `malloc(0x4bf00)` via pure Safe Rust bilinear resampling and bounds-checked slices. |

---

## 4. Repository Layout

- **Cargo Manifest:** [`Cargo.toml`](../Cargo.toml)
- **Verified Safe Rust Library:** [`src/lib.rs`](../src/lib.rs)
- **Stage 1 Subgraph Audit:** [`docs/STAGE1_SUBGRAPH_AUDIT.md`](./STAGE1_SUBGRAPH_AUDIT.md)
- **Deterministic SplitMix64 & Remediation Suite:** [`tests/parity_regression.rs`](../tests/parity_regression.rs)
