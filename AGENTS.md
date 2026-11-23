# Release Guard: Maintainer & Agent Scope Guide

`awakekt/release-guard` is a public, Apache-2.0, **engine-agnostic** KMP release-hardening and
static binary-verification library. Follow these invariants on every change:

## 1. Never slip game-authoring logic into Release Guard

- **Allowed here**: Standard, engine-agnostic binary and packaging formats (`.class`, `.dex`,
  AXML/Protobuf `AndroidManifest.xml`, ELF, PE, Mach-O, WASM, SPIR-V, WGSL/GLSL, `bplist00`,
  `glTF`/FBX magic headers, TLS SPKI), generic configurable rules (`forbiddenClasses`,
  `ownJarNames`, `ContainerHeaderRule`, `minContainerEntropy`, secret regex/entropy scans),
  static debug strippers, scoring/reporting, and the `ReleaseGuardCheck` / `ReleaseGuardCheckProvider`
  callback SPI.
- **Forbidden here**: Game-specific content pipelines, scene graphs, world/zone partitioning rules,
  sign-in set budgets, character/item schemas, or proprietary asset-pack authoring builders.
  Consumers implement those in their own `build-logic` via `ReleaseGuardCheck` callbacks or
  `ServiceLoader` (`ReleaseGuardCheckProvider`).

## 2. Never put runtime RASP, encryption keys, or server infrastructure here

- Do not add Frida/ptrace/root/jailbreak runtime detectors, attestation checks, decryption keys,
  or server/proxy configs (Caddy, Nginx, firewalls).
- Static auditing raises reverse-engineering cost and prevents shipping leaks; server authority and
  private runtime defenses stay outside this public repository.

## 3. Zero third-party game brands or proprietary consumer names

Never mention a commercial game, consumer game brand, private repository name, or proprietary format
in code, tests, fixtures, docs, commit messages, PRs, or issues. Use neutral examples such as
`com.example.game` and `harbortown`.

## 4. Verification before pushing

Always run:
```bash
./gradlew test detekt spotlessCheck apiCheck --console=plain
```
If public API in `:release-guard-core` changed, run `./gradlew apiDump` and review the diff in
`release-guard-core/api/release-guard-core.api`.
