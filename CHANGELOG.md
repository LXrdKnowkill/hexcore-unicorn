# Changelog

All notable changes to `hexcore-unicorn` will be documented in this file.

## [1.2.1] - 2026-02-15

### Fixed

- **Hook memory leaks** — replaced 5 raw `new`/`delete` hook callback allocations with `std::unique_ptr` RAII pattern to prevent leaks when exceptions occur before manual `delete`.
- **Prebuild loader** — `index.js` now tries both underscore and hyphen naming conventions for prebuilt binaries.

## [1.2.0] - 2026-02-14

### Added

- Published to npm.

### Fixed

- **Prebuild naming mismatch** — loader tries multiple naming conventions.
- **`.vscodeignore`** — added `!prebuilds/**` force-include.

## [1.1.0] - 2026-02-08

### Added

- Native breakpoints with O(1) lookup.
- Shared memory support (zero-copy, GC safe) via `memMapPtr`.
- State snapshotting (save/restore full CPU + RAM state).

## [1.0.0] - 2026-01-31

### Added

- Initial release.
- Complete Unicorn Engine N-API bindings.
- All architectures: x86, x86-64, ARM, ARM64, MIPS, SPARC, PPC, M68K, RISC-V.
- Memory operations, register operations, hook system.
- Async emulation with Promises.
- Context save/restore.
- 29/29 tests passing.
