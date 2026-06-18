# Membership expulsion (revocation)

How a member is **removed** from a mesh — and how the rule for *who may remove* is chosen
per-mesh at creation. The daemon (`meshd`) implements all of this; the GUI/CLI only drive
and visualize it.

## Why it exists

A member joins by receiving a **cert** that chains to the mesh master (see
`crates/mesh/src/membership.rs`). A cert is self-proving and permanent — so:

- **Re-cipher** (key rotation) can deny an offline member the *current* secret, but its
  cert still chains, so it never leaves the roster. "Eviction via re-cipher" is key-denial,
  not removal.

That left **phantom members** lingering forever (e.g. a node you only minted an invite for,
or an old identity), inflating the roster count and the self-destruct floor. Expulsion is
the missing piece: a signed statement that actually drops a member.

## The policy is a charter choice (fixed at genesis)

`GenesisCharter.expel: ExpelPolicy` — picked when the mesh is created, immutable for life
(like the invite topology and re-cipher trigger). Who may sign a revocation:

| Policy | Who may expel | Notes |
|--------|---------------|-------|
| `CreatorOnly` *(default)* | the master (creator) only | simplest admin model; if the creator is offline, nobody can expel |
| `InviterChain` | the master, or the member that invited the target (its cert's `inviter`) | "you can remove whoever you brought in"; pairs with open-chain invites |
| `Quorum { k }` | any member, but `k` distinct members must co-sign | democratic; works with the creator away; default `k = 2` |
| `None` | nobody | membership is permanent; only voluntary leave + key rotation |

## How it works

A **`Revocation`** (`crates/mesh/src/membership.rs`) is a signed expulsion of a member:

```
Revocation { network, member, issued_at, signers: Vec<RevSig> }
```

- Each signature covers **only `(network, member)`** — deliberately **not** a timestamp — so
  signatures from different members (and at different times) all sign the *same* message and
  **merge into one revocation**. A quorum thus accumulates co-signers regardless of who
  proposed first or gossip timing. (Revocation is monotonic — a re-admit uses a fresh
  keypair — so no anti-replay nonce is needed.)
- The roster comes from **`effective_members(master, certs, topology, revocations, expel)`**:
  the certs that chain to the master, **minus** any member carrying a revocation that is
  *authorized* under `expel`. `roster()` in `meshd` uses this everywhere.
- Revocations **gossip + merge** exactly like the cert roster (control sub-tag
  `CTRL_REVOKE`), so an expulsion converges across the whole mesh. `meshd` also gossips them
  immediately on `expel` and periodically thereafter.

### Authorization (`revocation_authorized`)
- `CreatorOnly`: a valid signature by the master.
- `InviterChain`: master, or a valid signature by the target cert's `inviter`.
- `Quorum { k }`: `k` distinct signers that are themselves current members (or the master);
  the target can't sign its own expulsion.
- `None`: never.

## Driving it

**CLI** (`scripts/lattice`):
```
lattice new team --expel quorum        # creator | inviter | quorum[:k] | none  (default creator)
lattice expel team bob                 # expel member "bob" (or by id)
lattice info team                      # shows the "expel" policy line + the roster
```
For a quorum mesh, each member runs `lattice expel team bob` independently; the member
leaves once `k` co-signers are reached.

**GUI**: the Create-mesh page has a **“Who can expel a member”** dropdown; the Peers page
shows an **expel** button per member (hidden when the policy is `none`). Both just call the
same daemon requests (`CreateMesh{expel}`, `ExpelMember`).

## Related fix — invite id reservation

Expulsion testing surfaced a separate daemon bug: `CreateInvite` picked the joiner's 1-byte
id from the **current roster only**, so inviting several people back-to-back — before any of
them connected and gossiped back — gave them all the *same* id. The daemon now **reserves**
ids handed out in not-yet-joined invites (`MeshState.invited`, expiring after
`INVITE_RESERVE_MS`), so back-to-back invites get distinct ids. As a belt-and-suspenders,
`effective_members` also **de-duplicates by id deterministically** (earliest `issued_at`,
then lowest pubkey), so even a cross-node collision converges to the same single member on
every node instead of showing a phantom duplicate.

## Limitations / future
- **No un-revoke.** A revocation is permanent; to re-admit someone, they generate a fresh
  identity (new keypair) and join again.
- **Cross-node id collision** is *resolved* (deterministic de-dup) but not *prevented* — two
  members invited at the same instant from different nodes still briefly contend for an id;
  the loser's cert is simply never shown. A reservation gossip would prevent it outright.
- **Quorum requires each member to act** (`lattice expel`) — there is no auto-vote; that is
  intentional (a vote should be a deliberate act).

## Verification

- Unit tests in `crates/mesh/src/membership.rs` cover all four policies, signature tamper,
  and id de-dup.
- Live on a real data plane (Oracle, loopback): back-to-back invites get distinct ids
  (`#2`,`#3`); creator-only expel removes a member; a non-master is rejected; quorum needs
  `k` co-signers; `none` rejects expulsion. See `docs/ERRORS.md` for the run.
