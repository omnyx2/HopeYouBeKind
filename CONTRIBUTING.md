# Contributing to Lattice

## Branching & versioning

- `main` is always releasable. Work on feature branches, open a PR.
- We follow [Semantic Versioning](https://semver.org). The version lives in
  `[workspace.package]` in the root `Cargo.toml` and is inherited by every
  crate — bump it in exactly one place.
- Every user-visible change gets a line under `## [Unreleased]` in
  `CHANGELOG.md`. Releases move those lines under a new version heading.

## Releasing

1. Move `Unreleased` entries under a new `## [x.y.z]` heading in `CHANGELOG.md`.
2. Bump `version` in the root `Cargo.toml`.
3. Commit, then tag: `git tag vX.Y.Z && git push --tags`.
4. The `release` workflow builds signed artifacts for macOS/Windows/Linux and
   attaches them to the GitHub release.

## Before you push

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs exactly these plus a 3-OS build matrix. Green locally ≈ green in CI.

## Code conventions

- One architectural concern per crate; if a change crosses crate boundaries,
  say why in the PR.
- Anything touching `crates/crypto` or the wire format in `crates/proto` needs a
  corresponding update to `docs/PROTOCOL.md` in the same PR.
- No `unwrap()`/`expect()` on paths that handle untrusted network input.
