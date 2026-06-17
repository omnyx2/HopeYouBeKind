# Mesh membership (network identity, enrollment & eviction)

> **§A below is the v2 (meshd) membership** — admin-free **invite chain** with a
> sealed mesh secret, which is what ships today. **§1 onward is the legacy v1
> (CA/admin) model** kept for the v1 daemon. v2 architecture: `docs/MESH_V2.md`.
> / 아래 **§A는 v2(meshd) 멤버십** — 관리자 없는 **초대 체인** + 봉인된 메쉬 시크릿(현재
> 출하본). **§1 이하는 v1(CA/관리자) 모델**(v1 데몬용). v2 설계는 `docs/MESH_V2.md`.

## §A. v2 join flow — invite chain + sealed secret / v2 가입 — 초대 체인 + 봉인 시크릿

A v2 mesh has a **master keypair** held only by its **creator** (`MeshState.master`
is `Option` — `None` on every joiner). Members are admitted by a **signed cert**
that chains to the master; the roster is the set of certs that validly chain. There
is **no online admin and no revocation gossip** — capture-detection + re-cipher
(MESH_V2.md §5) replace eviction. To actually connect, a joiner also needs the
**shared mesh secret** (it keys the data-plane cipher), so a member carries an
**X25519 encryption key** (`keydist::EncKey`) beside its ed25519 identity, and the
invite seals the secret to it. The whole exchange is three IPC calls + one
out-of-band blob:

```
 creator (holds master)                         joiner
   │                         NewIdentity ───────────┤  mints member(ed25519) + enc(x25519)
   │  ◀── member_pubkey, enc_pubkey ───────────────  │  (privates held until JoinMesh)
   │  CreateInvite{mesh,name,member_pubkey,enc_pubkey}
   │     · issue cert(member→id, signed by master)
   │     · seal mesh secret to enc_pubkey (keydist::seal_secret)
   │  ── InviteBlob{charter, member_id, certs[], sealed_secret} ──▶  (out of band)
   │                                            JoinMesh{invite}
   │                                              · find held identity by cert.member
   │                                              · open sealed_secret with enc key
   │                                              · verify cert chains to charter master
   │                                              · install mesh (master=None) + data plane
```

- **`NewIdentity`** → `Identity{member_pubkey_hex, enc_pubkey_hex}`. The joiner
  mints and **holds** both private keys until `JoinMesh` consumes them.
- **`CreateInvite{mesh, name, member_pubkey_hex, enc_pubkey_hex}`** (creator only —
  needs `master`) → `Invite(InviteBlob)`. The `InviteBlob` is **self-contained**:
  `charter` (carries the master pubkey = root of trust), the assigned `member_id`,
  the **full cert roster**, and the `sealed_secret`.
- **`JoinMesh{invite}`** → installs the mesh: matches the held identity by the
  cert's member key, opens the sealed secret (`EncKey::open`), re-verifies the cert
  chains to `charter.master_pubkey`, and brings up the data plane with `master=None`.

The blob travels **out of band** (the GUI/CLI shuttles the JSON). Live-verified
2026-06: Mac (creator) + Oracle (joiner) join one mesh, derive the **same** key
from the sealed secret, and pass traffic — Oracle learns Mac's NAT endpoint off the
data plane. `AdmitMember` still exists but is a **local cert-only admit** (no secret
hand-off) — use `CreateInvite` for a node that will actually connect.

/ v2 메쉬는 **마스터 키쌍**을 **생성자만** 보유(`MeshState.master`는 `Option`, 가입자는
`None`). 멤버는 마스터로 체인되는 **서명된 cert**로 가입하고, 로스터 = 마스터로 정상
체인되는 cert 집합. **온라인 관리자·폐기 가십 없음** — 탈취감지+re-cipher가 축출을 대신.
실제 연결하려면 가입자가 **공유 메쉬 시크릿**(데이터플레인 cipher 키)도 필요하므로, 멤버는
ed25519 외에 **X25519 암호화 키**(`keydist::EncKey`)를 갖고 초대가 시크릿을 거기에 봉인한다.
전체 교환은 IPC 3번 + 대역 외 blob 1개:

- **`NewIdentity`** → `Identity{member_pubkey_hex, enc_pubkey_hex}`. 가입자가 두 개인키를
  만들어 `JoinMesh` 때까지 **보관**.
- **`CreateInvite{mesh,name,member_pubkey_hex,enc_pubkey_hex}`**(생성자 전용, `master`
  필요) → `Invite(InviteBlob)`. blob은 **자기완결**: `charter`(마스터 공개키=신뢰 루트),
  배정 `member_id`, **전체 cert 로스터**, `sealed_secret`.
- **`JoinMesh{invite}`** → cert의 멤버키로 보관 신원 매칭 → `EncKey::open`으로 시크릿 개봉
  → cert가 `charter.master_pubkey`로 체인되는지 재검증 → `master=None`으로 메쉬+데이터플레인
  기동.

blob은 **대역 외**(GUI/CLI가 JSON 전달). 2026-06 라이브 검증: Mac(생성자)+Oracle(가입자)이
한 메쉬에 합류해 봉인 시크릿에서 **같은** 키를 유도하고 통신(Oracle이 Mac의 NAT 엔드포인트를
데이터플레인에서 학습). `AdmitMember`는 남아 있지만 **로컬 cert-only 가입**(시크릿 전달 없음)
— 실제 연결할 노드엔 `CreateInvite`를 쓴다.

---

## §1. Legacy v1 model (CA / admin) / v1 모델 (CA·관리자)

Lattice meshes are **closed networks with a serverless certificate authority**.
A network has a name (its public id) that you remember and share; one node holds
the network key and decides who is in (issue a cert) and who is out (revoke it).
Everything is signed and gossiped peer-to-peer — there is no coordination server.

This layer is **orthogonal to the tunnel crypto** ([CRYPTO_SUITE](../legacy/docs/CRYPTO_SUITE.md)):
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
