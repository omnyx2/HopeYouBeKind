# Join modes — `secure` (default) + `quick` (bearer)

How a new node becomes a member of a mesh. Two modes, **chosen by the inviter when the invite is
created**. The strong, key-bound flow stays the **default**; `quick` is an opt-in convenience that
trades some security for a one-round-trip, no-identity-ceremony join.

> This extends — it does not replace — the membership model in
> [`MEMBERSHIP.md`](MEMBERSHIP.md) / the cert chain in `crates/mesh/src/membership.rs`. Everything
> here is **additive** (new IPC variants, a new `Grant` type, a new cert-validation path). The
> existing `secure` flow is byte-for-byte unchanged.

## 1. Why two modes

The current join is a **3-step, 2-round-trip** handshake (see `getting-started`):

1. joiner: `lattice id` → mints an ephemeral `(MemberKey, EncKey)` into meshd's in-memory
   `pending` map, prints the **identity code** `{member_pubkey_hex, enc_pubkey_hex, issued_at}`;
2. inviter: `lattice invite <mesh> <name> <id_code>` → allocates a member id, **signs a `Cert`**
   for the joiner's key, **seals the mesh secret to the joiner's enc pubkey**, wraps an
   `InviteBlob` → the **invite code**;
3. joiner: `lattice join <code>` → unwraps, matches its pending identity, decrypts the secret,
   validates the cert chains to master, goes live.

It is secure (invite is bound to one specific key; can't be stolen/replayed; ~10-min identity TTL;
no open enrollment) but the **UX cost is high**: two codes bounced back and forth, and the identity
is **in-memory + expires in 600 s + lost on `meshd` restart** — the source of nearly every
onboarding failure (`identity too old`, `no pending identity for this invite`).

`quick` removes the joiner→inviter round-trip and the ephemeral-identity fragility, at the price of
making the code a **bearer token** (whoever holds it can join).

## 2. The two modes

| | **secure** (default) | **quick** (opt-in) |
|---|---|---|
| round-trips | 2 (id → invite → join) | 1 (invite → join) |
| what the code is | bound to ONE joiner pubkey | bearer (holder can join) |
| mesh secret | sealed to joiner's enc key | carried raw in the code |
| membership cert | inviter signs it for the joiner | joiner **self-issues**, backed by a signed **Grant** |
| reuse | single (one key) | issuer picks: **single-use** or **reusable** (`--max N`) |
| expiry | ~10 min identity TTL | issuer picks (`--expire`, default 10 min) |
| revocation | per-member (existing) | per-member; over-use auto-revokes the surplus |
| best for | high-trust / sensitive meshes | quick onboarding, links, QR |

`quick` is deliberately the *non*-default: `lattice invite home bob` with no flag is still the
`secure` flow, so nobody weakens their mesh by accident.

## 3. The `Grant` (what makes quick possible)

Membership is cert-based and rooted in the master key; there is **no self-registration path** —
today a joiner cannot mint its own valid cert. `quick` adds one, gated by a signed capability:

```rust
// crates/mesh/src/membership.rs  (new, additive)
struct Grant {
    network: PubKey,       // master pubkey (mesh identity) — same anchor as Cert
    grant_id: [u8; 16],    // random nonce; identifies this grant
    max_uses: u32,         // 1 = single-use; N = reusable link
    expires_at: u64,       // Unix-ms; hard deadline
    issuer: PubKey,        // master, or a member allowed to invite (OpenChain)
    issued_at: u64,
    sig: [u8; 64],         // issuer's ed25519 sig over grant_signing_bytes()
}
```

`grant_signing_bytes()` = `[b"GRANT" ‖ network ‖ grant_id ‖ max_uses_LE ‖ expires_at_LE ‖ issuer ‖
issued_at]` (length-discipline like `Cert::signing_bytes`). A `Grant` is valid iff `issuer` is the
master **or** a member whose own cert validly chains to master under the charter's invite policy —
exactly the check `CreateInvite` already does for "who may invite".

A member cert minted under a grant records the grant instead of a hand-signed inviter:

```rust
// Cert gains one additive, #[serde(default)] field:
struct Cert {
    // …existing fields (network, member, id, name, inviter, issued_at, sig)…
    grant: Option<Grant>,  // Some(g) = self-issued under a quick grant; None = classic inviter-signed
}
```

**Validation (additive branch in `valid_members`/`effective_members`):** a cert is authorized if
EITHER
- (existing) its `sig` verifies under `inviter`, and `inviter` is master or a valid member; OR
- (new) `cert.grant` is `Some(g)`, `g` is a **valid Grant** (sig chains to master), `now < g.expires_at`,
  and the cert's own `sig` verifies under **`cert.member`** (the joiner self-signs its own cert to
  prove key possession — the grant is what authorizes it, the self-sig binds it to the key).

So the grant delegates "you may add yourself once" without the master being online at join time.

## 4. The quick invite code

Same wrap machinery as today (`invitewrap::wrap`, P-C6 obscurity), but the plaintext is a
`QuickInviteBlob` instead of the per-joiner `InviteBlob`:

```rust
struct QuickInviteBlob {
    mesh_id, mesh_name, charter,
    epoch, cipher,             // live values (as InviteBlob)
    secret: [u8; 32],          // RAW mesh secret — bearer (NOT sealed to an enc key)
    grant: Grant,              // signed capability, carries max_uses + expiry
    certs: Vec<Cert>,          // current roster so the joiner can validate the chain
    endpoints: Vec<(MemberId, String)>,  // bootstrap (P-D1)
}
```

The **raw `secret`** is the crux of the bearer trade-off: anyone who reads the code can derive the
mesh keys. Mitigation = short `expires_at` + single-use + the grant being independently revocable.
(A re-cipher, `lattice recipher`, rotates `secret`/epoch and evicts anyone who only ever held an old
quick code — the standard containment.)

## 5. Joining with a quick code

`lattice join <quick_code>`:

1. unwrap → `QuickInviteBlob`; verify `grant` chains to master and `now < grant.expires_at`.
2. generate a **fresh local `MemberKey`** (no `NewIdentity`, no `pending` map, no TTL).
3. pick a member id: lowest free id in `1..=254` not present in `certs`. Races (two joiners pick
   the same id off the same reusable code before gossip converges) are resolved in §6.
4. self-issue `Cert { network, member=my_pk, id, name, inviter=grant.issuer, issued_at, sig=self,
   grant: Some(grant) }`.
5. adopt `secret`/`epoch`/`cipher`, seed endpoints, persist, bring up the data plane.
6. gossip the new cert (CTRL_ROSTER) so the mesh learns the member — same path a secure joiner uses.

No EncKey is needed (the secret arrived raw), so the whole `sealed_secret`/x25519 step is skipped.

## 6. Convergent single-use (serverless enforcement)

There is no server to atomically decrement `max_uses`, so `quick` gives **convergent** single-use,
not atomic:

- the grant is gossiped inside every quick-minted cert (CTRL_ROSTER already carries certs).
- each member counts **distinct certs carrying the same `grant_id`** = `used`. A cert is honored
  while `used ≤ max_uses`.
- if more than `max_uses` certs reference one grant (a leaked/replayed code), the **surplus is the
  set of certs with the latest `issued_at`** (tie-break: higher `member` pubkey). Members
  auto-issue a `Revocation` for the surplus member(s) — reusing the existing
  [`EXPULSION`](EXPULSION.md) `Revocation`/`RevSig`/`effective_members` machinery — under a new
  built-in authorization: *"any member may revoke a cert that exceeds its grant's `max_uses`."*
- result: a leaked single-use code can briefly admit a 2nd node, which is then converged out
  (seconds, bounded by gossip). Short `expires_at` keeps the exposure window tiny.

This is the honest serverless limit and is called out in the security section.

## 7. Per-mesh floor

A mesh can forbid `quick` at genesis so a member can't weaken it:

```
lattice new work --join secure     # this mesh: quick invites refused (CreateQuickInvite → error)
lattice new lan  --join any         # default: inviter may choose per invite
```

Stored on the charter (additive `#[serde(default)] join_floor: JoinFloor { Any | SecureOnly }`),
enforced in the `CreateQuickInvite` handler. `secure` is always allowed.

## 8. IPC (all additive — never renumber/remove; skew = "unknown variant")

```rust
// crates/mesh/src/ipc.rs
Request::CreateQuickInvite { mesh, name: Option<String>, max_uses: u32, ttl_secs: u64, algo: Option<String> }
Response::Invite(WrappedInvite)          // reuse — a quick code is still a WrappedInvite
// JoinMesh stays the same variant; the handler detects QuickInviteBlob vs InviteBlob after unwrap
//   (add a 1-byte tag / try-quick-then-classic) so `lattice join <code>` works for both.
// CTRL_ROSTER already gossips Vec<Cert>; Cert.grant rides along (additive serde field).
```

`name` is optional for quick (a reusable link doesn't know each joiner's name up front → joiner
supplies it, or it defaults to `node-<id>`).

## 9. CLI / GUI

```bash
lattice invite home bob                       # secure (default, unchanged)
lattice invite home bob --quick               # quick, single-use, 10-min TTL
lattice invite home --quick --max 5 --expire 1h   # reusable link, ≤5 joiners, 1 hour
lattice join <code>                           # accepts either code type
```
GUI invite screen: a mode picker — **Secure (verify device)** · **Quick code (single use)** ·
**Invite link (N people)** — plus a QR of the resulting code.

## 10. Security summary

- **secure** — unchanged; invite bound to one key, ~10-min identity TTL, no bearer risk.
- **quick** — bearer: the code = the mesh secret for its lifetime. Contained by (a) short default
  TTL, (b) single-use default with convergent enforcement, (c) independent revocability, (d)
  re-cipher evicting stale-code holders, (e) the per-mesh `SecureOnly` floor for sensitive meshes.
- A quick grant never grants more than membership at the **current** epoch: it cannot re-cipher,
  expel, or invite-secure on its own (those still require a real inviter/quorum).
- Every quick member still leaves a **cert with its grant_id** → full audit trail of who joined via
  which code.

## 11. Build order (verify OFFLINE at each step — separate socket + `MESHD_STATE_DIR`, no `DATA_PLANE`)

1. `Grant` type + `grant_signing_bytes` + sign/verify + the additive `Cert.grant` field + the
   new validation branch in `valid_members`/`effective_members` (+ unit tests). No IPC yet.
2. `QuickInviteBlob` + `CreateQuickInvite` handler (issue grant, build blob, wrap) + `join_mesh`
   detecting quick vs classic after unwrap + self-issue cert path.
3. Convergent single-use: count certs per grant_id, auto-`Revocation` of the surplus, wire into the
   existing revoke gossip/merge.
4. `join_floor` charter field + enforcement.
5. CLI flags + GUI picker + QR.
6. Live 3-node test: single-use (2nd use converges out), reusable link (N joins), `SecureOnly`
   mesh refuses quick, re-cipher evicts an old quick holder.

## 12. Files touched

- `crates/mesh/src/membership.rs` — `Grant`, `Cert.grant`, validation branch, surplus-revoke rule.
- `crates/mesh/src/ipc.rs` — `CreateQuickInvite`, `QuickInviteBlob`.
- `crates/mesh/src/invitewrap.rs` — reused as-is (wrap the quick blob).
- `crates/mesh/src/charter.rs` — `join_floor`.
- `crates/meshd/src/main.rs` — `CreateQuickInvite` handler, `join_mesh` quick branch, surplus-revoke
  in the roster-merge path.
- `scripts/lattice` — `invite --quick/--max/--expire`, `join` unchanged (auto-detects).
- `gui/src/main.js` — invite mode picker + QR.
