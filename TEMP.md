# TEMP.md — live working memory

Scratchpad. Charter in CLAUDE.md → "Working memory". Only OPEN items here.

---

## OPEN: Mac version-label uniformity decision
Fleet: Oracle+lablinux = v0.7.10, Mac = v0.7.9. The v0.7.10 fix is `#[cfg(target_os="linux")]`
(purge legacy overlay FORWARD on the serving path) — macOS never accumulates those rules, so the
Mac binary is functionally identical. Swapping Mac = another dmg clean-teardown (utun-wedge risk on
the live VPN). AWAITING user decision: swap Mac to v0.7.10 for the label, or leave at v0.7.9.
Everything else this session is DONE (see COMPLETE.md 2026-07-25 entries).
