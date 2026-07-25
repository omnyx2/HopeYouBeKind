# TEMP.md — live working memory

Scratchpad. Charter in CLAUDE.md → "Working memory". Only OPEN items here.

---

## Current task: full empirical cross-check of v0.7.9 fleet (Mac switched to HOTSPOT mid-test)

Network change is deliberate — verify self-healing/re-discovery survives a Mac endpoint change.

### Verification matrix (check each, record PASS/FAIL)
1. [ ] Phase 0 — Mac on hotspot: new endpoint learned, meshd self-healed, mesh reconnected
2. [ ] Phase 1 — version uniformity: all 3 nodes v0.7.9 build 3a3646e
3. [ ] Phase 2 — connectivity matrix: Mac↔Oracle, Mac↔lablinux, Oracle↔lablinux overlay data (TCP, both dirs)
4. [ ] Phase 3 — exitable (v0.7.8): lablinux OFF→drop, ON→egress 210.107.188.8, ON→OFF live purge, per-subnet NAT only
5. [ ] Phase 4 — isolate/pinned-exit fix (v0.7.9): Oracle 999+1000 rules, reply→tun0, egress 138.2.14.219, member↔member OK
6. [ ] Phase 5 — split-tunnel: domain→chosen exit, rest direct
7. [ ] Phase 6 — NAT/rule hygiene: NO legacy 100.64/10 on any node
8. [ ] Phase 7 — code quality: cargo test, fmt, clippy clean
9. [ ] Phase 8 — organize docs if all pass
