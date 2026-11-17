## Summary

<!-- Briefly describe the purpose of this Pull Request and reference the tracking issue (e.g., Closes #1). -->

## Verification & Safety Checklist

- [ ] **Zero `unsafe` Code:** Crate root and test suite retain `#![forbid(unsafe_code)]` with zero unsafe blocks.
- [ ] **Bit-Exact (`0 ULP`) Parity & 30,118-Vector FNV-1a Digests Preserved:** `cargo test` passes all unit, remediation, and 30,118 SplitMix64 + boundary vectors.
- [ ] **Zero Warnings:** `cargo clippy --all-targets -- -D warnings` and `cargo doc --no-deps` complete with `0` warnings.
- [ ] **Clean-Room & Sanitization Boundary:** No proprietary OEM `.so` binaries, firmware images, unredacted exploit payloads, `.env*` files, or local machine paths are included.
