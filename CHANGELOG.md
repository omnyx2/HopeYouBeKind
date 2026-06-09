# Changelog

All notable changes to Lattice are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the API and on-wire protocol are unstable: minor
bumps (`0.x.0`) may break compatibility, patch bumps (`0.0.x`) are additive/fixes.

## [Unreleased]

### Added
- Initial Cargo workspace and crate boundaries (proto, crypto, tun, net,
  overlay, engine, daemon, cli).
- Architecture, protocol, roadmap, and security design documents.
- CI (fmt, clippy, test, 3-OS build matrix) and tag-driven release workflow.

## [0.1.0] — 2026-06-09

### Added
- Project scaffold and module skeletons.

[Unreleased]: https://github.com/your-org/lattice/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/lattice/releases/tag/v0.1.0
