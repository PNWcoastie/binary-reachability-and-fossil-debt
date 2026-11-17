# Live Attack Surface, Dead Fossils, and Zombie Activation (`s9_blur_detection`)

[![Language: Safe Rust](https://img.shields.io/badge/rust-%23!%5Bforbid(unsafe__code)%5D-brightgreen.svg)](https://www.rust-lang.org/)
[![Verification: 30,118 FFI Vectors](https://img.shields.io/badge/verify__rust__parity-30%2C118%20vectors%20(0%20ULP)-blue.svg)](./docs/STAGE3_4_PARITY_SCORECARD.md)
[![Part I Predecessor DOI](https://img.shields.io/badge/Part%20I%20DOI-10.5281%2Fzenodo.24261883-informational.svg)](https://doi.org/10.5281/zenodo.24261883)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-informational.svg)](./LICENSE-MIT)

Official companion artifact and `#![forbid(unsafe_code)]` Safe Rust reference crate (`s9_blur_detection`) for the Part II follow-up research study:

> **Live Attack Surface, Dead Fossils, and Zombie Activation: Multi-Edge Reachability and Linker-Hygiene Auditing of Stripped Android Vendor Binaries**  
> **Author:** M. Larrabee (`PNWcoastie`), Independent Systems & Security Researcher (November 2026)  
> **Predecessor Study (Part I):** [`DOI: 10.5281/zenodo.24261883`](https://doi.org/10.5281/zenodo.24261883) ([`PNWcoastie/borrow-checker-binary-auditor`](https://github.com/PNWcoastie/borrow-checker-binary-auditor))  
> 📄 **[Read the Full Part II Research Paper (`PAPER.md`)](./PAPER.md)**

---

## Overview

When binary reconstruction or static auditing uncovers defects inside stripped OEM shared libraries (`.so`), vendor triage teams frequently ask: *Which defects lie on active production execution paths, and which are unreachable "factory-line fossils" accumulated across firmware generations?*

This repository presents **Stage 1.5: Multi-Edge Binary Reachability and Linker-Hygiene Auditing** across **53 AArch64 ELF64 binaries** (`28` Samsung Galaxy S9 baseline binaries, `7` Galaxy S25 Ultra Android 16 binaries, and `18` Galaxy S26 Ultra Android 16 binaries plus `com.samsung.android.biometrics.face.signed.apex`), demonstrating why **all three empirical reachability classes require remediation**:

1. **[`PAPER.md`](./PAPER.md):** Complete Part II research paper establishing:
   - **Why Naive `DT_NEEDED`/`.dynsym` Scanners Fail on Android:** Models the **4 Universal Dynamic-Linkage Edges** (`DT_NEEDED`/`.dynsym` `UND`, `.rodata`/XML `dlopen` plugin tables, `JNI` `Java_*` & `RegisterNatives` arrays in `.data`/`.relr.dyn`, and `.data.rel.ro` C++ vtables / `HMI` modules) while filtering out **5 C++ ABI Linker Collision Traps** (`_Znwm`/`_ZdlPv` NDK static-link collisions, weak `std::__1` `_ZTI*`/`_ZTV*` typeinfo collisions, statically linked `libyuv` collisions, sibling HAL callback collisions, and `.rodata` substring false positives).
   - **Class I — Live Wired Production Paths (`16 of 20` bugs):** Unbroken intra-binary and cross-binary call chains from public `JNI_OnLoad`, `Java_*`, `HMI`, and C factory entry points directly to the vulnerable instruction site.
   - **Class II — Intra-Binary Dead Fossils & Cloned Inlines (`SAM-BUG-19`, half of `SAM-BUG-12`, and the `ButterworthFilter` subgraph of `SAM-BUG-11`):** Exported `GLOBAL DEFAULT` functions with `0` callers left behind when developers inlined or multithreaded the code (`libsrib_outfocus.camera.samsung.so`) while copying the exact same unguarded division bugs into the live threaded clones.
   - **Class III — Cross-Generation "Zombie Activation" (`SAM-BUG-15` in `libsecimaging_pdk.camera.samsung.so`):** Empirical proof that Class II dead functions are latent landmines: `_Z8get_SIZEPKhRiS1_` (`0x1a654`) had `0` callers on the 2018 Galaxy S9, but was refactored into `_Z8get_SIZEPKhiRiS1_` (`0x34dac`) and wired directly into the live `decodeFromMemory` $\to$ `fastJpegDecode` hot path (`0x35fdc`) on the 2025/2026 Galaxy S25 Ultra and S26 Ultra, truncating a 64-bit `size_t` into a 32-bit signed `int`.
   - **Android 16 Symbol-Visibility & APEX Forensics:** Proves that **16 of 18 evaluated S26 Ultra libraries omit `-fvisibility=hidden`** (`90%–95%` `GLOBAL DEFAULT` export bloat; `100%` of intra-binary calls routed through `.plt` stubs), identifies duplicate `2.48 MB` copies of `libsrib_humanaware_engine.camera.samsung.so` across `/system` and `/vendor`, and shows that `com.samsung.android.biometrics.face.signed.apex` contains an empty `apex_payload.img` stub (`0` `.so` files).
2. **[`src/lib.rs`](./src/lib.rs):** Standalone, zero-dependency `#![forbid(unsafe_code)]` Safe Rust reconstruction (`s9_blur_detection`) of `libBlurDetection.camera.samsung.so` (`SHA-256: 07baf5e21a19cd1c53ab61aa47c19949da47e1bbbeb66f855a67e2b2c19d5615`), implementing:
   - [`get_dif_lt`](./src/lib.rs#L28-L74) (`0x0fc8`) & [`get_cnt_lt`](./src/lib.rs#L84-L107) (`0x138c`): 1st-order directional gradient differences, 2-tap local maximum filtering, and `4×4` low-texture block counting.
   - [`calc_low_texture`](./src/lib.rs#L121-L149) (`0x15d4`, binary-exact oracle) & [`calc_low_texture_remediated`](./src/lib.rs#L156-L180) (`SAM-BUG-10b` fix): Reproduces and remediates **`SAM-BUG-10b`**, where `get_cnt_lt` left its 3rd output pointer (`[sp, #0x8]`) unpopulated (`0`), causing `calc_low_texture` (`0x16d8`) to evaluate `0 > 9 * total_blocks` (`((thresh as u32) >> 31) as i32`) and permanently disabling the `-100` low-texture sentinel on all valid frames.
   - [`blur_multi_scale_residual`](./src/lib.rs#L185-L196) (`0x1814..0x18b0`), [`get_blur_val`](./src/lib.rs#L208-L287) (`0x1710`), [`get_blur_val_remediated`](./src/lib.rs#L292-L309), and [`compute_blur`](./src/lib.rs#L318-L356) (`0x1c08`): Eliminates the `malloc(0x4bf00)` `NULL`-dereference hazard (`SAM-BUG-10`) and raw `uint16_t*` aliasing while achieving a **`1.18×` to `2.66×` speedup** over the vendor C++ binary.
3. **[`tests/parity_regression.rs`](./tests/parity_regression.rs):** Self-executing `#![forbid(unsafe_code)]` regression suite that replays all **`30,118` deterministic SplitMix64 (`seed = 1337420`) + boundary test vectors** (`10,064 + 10,027 + 10,027`) against standalone AArch64 instruction-level reference oracles at `0 ULP`, verifies their pinned 64-bit FNV-1a output digests (`0x14cd4b021b22c0fd`, `0xb637e5428d555071`, `0x85793ffe6e046840`), and proves `SAM-BUG-10` and `SAM-BUG-10b` remediation.
4. **[`docs/STAGE1_SUBGRAPH_AUDIT.md`](./docs/STAGE1_SUBGRAPH_AUDIT.md) & [`docs/STAGE3_4_PARITY_SCORECARD.md`](./docs/STAGE3_4_PARITY_SCORECARD.md):** Full Stage 1 AArch64 disassembly/mathematical specification and Stage 3 & 4 differential FFI parity scorecard.

---

## Differential FFI Verification Summary (`s9_blur_detection`)

| Kernel Symbol | Arg Types | Return Type | Parity Status | Vectors Tested | 64-Bit FNV-1a Output Digest | C Oracle (`ns/call`) | Safe Rust (`ns/call`) | Speedup vs. C |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| [`blur_multi_scale_residual`](./src/lib.rs#L185-L196) | `["u8"; 7]` | `i32` | **`verified_bit_exact` (`0 ULP`)** | `10,064` | `0x14cd4b021b22c0fd` | `7.04 ns` | `5.98 ns` | **`1.18×`** |
| [`blur_dif_lt_kernel`](./src/lib.rs#L362-L373) | `["bytes"]` | `i32` | **`verified_bit_exact` (`0 ULP`)** | `10,027` | `0xb637e5428d555071` | `3,102.86 ns` | `1,165.95 ns` | **`2.66×`** |
| [`get_blur_val_tile`](./src/lib.rs#L378-L386) | `["bytes"]` | `i32` | **`verified_bit_exact` (`0 ULP`)** | `10,027` | `0x85793ffe6e046840` | `9,410.51 ns` | `3,657.11 ns` | **`2.57×`** |

---

## Quickstart: Build, Test, Lint & Docs

```bash
# Self-execute all 30,118 SplitMix64 + boundary vectors (10,064 + 10,027 + 10,027),
# verify their 64-bit FNV-1a state digests (0 ULP), and run SAM-BUG-10 / 10b proofs
cargo test

# Enforce zero compiler or Clippy warnings (with rust-zero-drift lints enabled)
cargo clippy --all-targets -- -D warnings

# Generate rustdoc documentation
cargo doc --no-deps
```

---

## Discussions, Issues & Responsible Disclosure

- 💬 **[GitHub Discussions](https://github.com/PNWcoastie/binary-reachability-and-fossil-debt/discussions):** Open-ended Q&A on Stage 1.5 reachability auditing, ELF linker hygiene, and `#![forbid(unsafe_code)]` binary reconstruction.
- 🔬 **[Open a Research / Methodology Discussion Issue](../../issues/new?template=research_discussion.yml):** Structured discussion on specific paper sections, reachability classes, or related work.
- 🛠️ **[Report Crate Reproduction Feedback or Paper Errata](../../issues/new?template=reproduction_or_errata.yml):** Report test vector questions or suggest paper errata.
- 🛡️ **[Security & Clean-Room Policy (`SECURITY.md`)](./SECURITY.md):** Guidelines on coordinated vulnerability disclosure and strict exclusion of proprietary `.so` binaries.

## License & Ethics Statement

- **Code & Documentation License:** Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.
- **Zero Proprietary Binary Redistribution:** No proprietary OEM `.so` binaries, APEX containers, or firmware images are included in this repository. All code is a 100% clean-room `#![forbid(unsafe_code)]` Safe Rust implementation developed for defensive security research and interoperability under DMCA Section 1201(j).
