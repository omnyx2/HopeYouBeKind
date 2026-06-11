# Mesh membership (network identity, enrollment & eviction)

Lattice meshes are **closed networks with a serverless certificate authority**.
A network has a name (its public id) that you remember and share; one node holds
the network key and decides who is in (issue a cert) and who is out (revoke it).
Everything is signed and gossiped peer-to-peer — there is no coordination server.

This layer is **orthogonal to the tunnel crypto** ([CRYPTO_SUITE](CRYPTO_SUITE.md)):
a node proves it belongs by presenting a certificate, and that proof is checked
no matter which cipher suite encrypts the session.

## Concepts

- **Network** — an Ed25519 keypair.
  - **Network ID** = the public half. The stable, mathematically-random id that
    *is* the mesh. Safe to share; you hand it to people so they refer to "the
    same network". (Also derives a short rendezvous tag used to scope discovery.)
  - **Network key** = the private half = the **CA**. Whoever holds it is the
    *admin*: they admit and evict members. Treat it like a master secret.
- **Member certificate** — a signed statement binding a node's identity key to
  the network, with a unique **serial** and optional expiry. Presented in the
  handshake; the peer verifies it against the network id.
- **Revocation** — a signed eviction of a serial. Independently verifiable, so
  it gossips across the mesh and merges by union — no central list, no ordering.

There is **no founder node**: the network lives in the secret, not in any
machine. The first node to come online just waits; others join when they present
a valid cert. If every node goes offline the network still exists — bring any
member back up and it resumes.

## Roles

- **Admin** — started with `--network-key <path>`. Holds the CA, self-issues its
  own cert, and can `issue` tokens and `revoke` members.
- **Member** — holds a cert issued by the admin (via `--member-cert <path>` or by
  joining at runtime). Can connect to other members; cannot enroll or evict.
- **Open** (default) — no network set. Any peer that completes the handshake is
  admitted. This is the original behaviour for quick LAN use.

## The enrollment flow (manual, serverless)

```
 admin                                    joiner
   │  net create  (start with --network-key)
   │  ── network id ──▶  (share out of band)
   │
   │            joiner shows its Node ID (Status tab / `lattice status`)
   │  ◀── node id ──
   │  net issue <node-id>  ──▶  join token ──▶  net join <token>
   │                                            (now a member, re-handshakes)
   │  members: joiner = active
   │
   │  net revoke <node-id>  ──▶  (gossiped) ──▶ joiner dropped across the mesh
```

### From the CLI

```sh
# Admin node (creates the network on first run):
lattice-daemon --network-key ~/.lattice/net.key   # + your usual flags

lattice net info                  # network id, role, member/revocation counts
lattice net issue <node-id> --label laptop   # → prints a join token
lattice net members               # list enrolled members (active / REVOKED)
lattice net revoke <node-id>      # evict a member

# Joining node (gets the token from the admin out of band):
lattice net join <token>          # adopt the cert and join now
lattice net info                  # → role: member
```

### From the GUI (**Mesh** tab)

- **Network identity** card — your role (admin / member / open) and the network
  id (click to copy).
- **Join a network** — paste a join token and press **Join**.
- **Members** (admin only) — every enrolled node with its serial and an active /
  revoked dot. Enter a peer's Node ID + label and press **Issue** to mint a token
  (copy it and send it to that node). Press **Revoke** to evict a member.

To enroll someone: they read their **Node ID** from the Status tab and send it to
you; you **Issue** a token and send it back; they paste it into **Join**.

## What the engine does

- The handshake payload carries the node's certificate (self-describing format,
  so open mode still works). Both the initiator and the responder verify the
  peer's cert against the trusted network id, confirm it is bound to the
  handshake-authenticated identity key, check expiry, and reject revoked serials.
  A failed check drops the session — a non-member never establishes a tunnel.
- Revocations gossip every keepalive tick (`MessageType::Revocation`); a received
  list is re-verified and merged, and any connected peer it evicts is dropped.
- **Joining at runtime drops existing sessions** so they re-handshake under the
  new network — otherwise a session formed in open mode would stay
  unauthenticated and couldn't be revoked.

## Security model & cautions

- The network key is the keys to the kingdom. Store it on the admin only; back it
  up; if it leaks, the network must be re-created.
- Revocation is **best-effort gossip**: an evicted node is refused by every honest
  node that has heard the revocation. Honest nodes propagate it on connect and
  each tick; a node that has never met any honest member won't learn it (it also
  can't reach the mesh, so this is moot in practice).
- Certs support expiry (`expires_at`); the CLI issues non-expiring certs by
  default. Short-lived certs + re-issue are a future ergonomic improvement.
- Discovery is **not yet scoped** by network: different networks on one LAN still
  *discover* each other over mDNS, they just can't form a session without a valid
  cert. Scoping discovery by the rendezvous tag is planned (see ROADMAP).

## Verification

- Unit tests in `crates/membership` (cert issue/verify/expiry/forgery, revocation
  gossip-by-union) and `crates/engine`
  (`same_network_connects_then_revocation_evicts`,
  `open_session_becomes_revocable_after_join`).
- Live-verified with a 3-node SDN (three Docker nodes): create → issue → join →
  full mesh → revoke → the evicted node is dropped across the whole mesh.
