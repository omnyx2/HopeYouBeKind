# TEMP.md — live working memory

Scratchpad. Charter in CLAUDE.md → "Working memory". Only OPEN items here.
Read docs/ERRORS.md blast-radius map before touching IPC enums (additive only!) / crypto seam (🔴).

---

## Current task: selectable mesh JOIN MODES (secure default + quick opt-in)

### Confirmed design decisions
- Mode chosen at invite-creation time. **Default = secure** (current 2-round-trip id→invite→join, key-bound — LOCKED protocol, preserve as-is).
- **quick** = opt-in bearer code (1 round-trip `join`), with reusability chosen at issue: **single-use** OR **reusable link (--max N, --expire)**. BOTH supported.
- Optional per-mesh floor: `--join secure` locks a mesh so quick is forbidden.
- "Convergent single-use": serverless can't hard-prevent replay; issuer gossips a pending grant{nonce,max_uses,used_count,expiry} via CTRL_ROSTER; members validate+increment (merge=max); over-count → signed revocation (reuse expulsion machinery). Short expiry makes it practical.

### Plan
1. [x] Explore + map — DONE
1b. [x] docs/JOIN_MODES.md spec — DONE (add789f)
1c. [x] Phase 1: Grant + Cert.grant + validation + 4 tests (70 pass) — DONE
2. [ ] Write docs/JOIN_MODES.md spec
3. [ ] Implement: IPC (additive), invite code format, join handler (bearer), grant tracking+gossip, revoke-on-overuse
4. [ ] CLI (`invite --quick/--reusable/--max/--expire`, join accepts both) + GUI invite picker
5. [ ] Verify OFFLINE (separate socket/state, no DATA_PLANE) then test mesh
