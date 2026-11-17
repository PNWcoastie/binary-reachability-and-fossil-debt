# Security & Responsible Disclosure Policy

## Clean-Room Research Artifact Boundary

This repository contains the open-access follow-up research paper (**[PAPER.md](PAPER.md)**) and the clean-room, `#![forbid(unsafe_code)]` Safe Rust reconstruction crate (`s9_blur_detection`) accompanying:

> **Live Attack Surface, Dead Fossils, and Zombie Activation: Multi-Edge Reachability and Linker-Hygiene Auditing of Stripped Android Vendor Binaries**  
> *(Part II of "The Borrow Checker as a Binary Auditor", [DOI: 10.5281/zenodo.24261883](https://doi.org/10.5281/zenodo.24261883))*

To uphold strict legal, ethical, and coordinated vulnerability disclosure standards:

1. **No Proprietary Binary Redistribution:** This repository contains **zero** proprietary OEM shared libraries (`.so`), APEX images, firmware dumps, or copyrighted vendor code. All binary provenance and linkage metrics are documented strictly via cryptographic digests (`SHA-256`), ELF `BuildID`s, symbol/offset metadata, and clean-room Safe Rust reconstructions.
2. **No Weaponized Exploit Payloads or Scanning Weapons:** Do **not** submit Pull Requests, Issues, or Discussions containing weaponized Proof-of-Concept (`PoC`) exploit chains, privilege-escalation payloads, automated offensive scanners, or unredacted memory dumps targeting commercial devices.
3. **Reporting Vulnerabilities in Third-Party Firmware:** If you use the `#![forbid(unsafe_code)]` reconstruction and Stage 1.5 reachability methodology described in [PAPER.md](PAPER.md) to discover new vulnerabilities in third-party vendor binaries, please report them directly to the affected vendor's Product Security Incident Response Team (PSIRT) — for example, [Samsung Mobile Security](https://security.samsungmobile.com/) or the [Android Security Bounty Program](https://bughunters.google.com/) — under standard 90-day Coordinated Vulnerability Disclosure (CVD) guidelines before public discussion.

## Reporting Issues in This Crate

If you discover a mathematical discrepancy, soundness issue, or documentation erratum in the `s9_blur_detection` Safe Rust crate or [PAPER.md](PAPER.md), please open a structured issue via the **[Crate Reproduction or Paper Errata](../../issues/new?template=reproduction_or_errata.yml)** template.
