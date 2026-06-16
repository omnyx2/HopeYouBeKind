# Crypto surface — every communication & encryption site / 암호화 표면 — 모든 통신·암호화 지점

**Purpose / 목적.** Map *every place Lattice v2 moves bytes* and *what cryptography (if
any) wraps each*, so we can (a) reason about confidentiality per channel and (b) plug a
**different cipher into each structure** — in particular drop the research
**time-window / manifold** cipher (docs/CIPHER_TIMEWINDOW.md) into exactly the channels
where it makes sense, without touching the rest. / v2가 **바이트를 움직이는 모든 지점**과
**각각을 감싸는 암호(있다면)**를 매핑한다. 목적은 (a) 채널별 기밀성 판단, (b) **각 구조에 다른
cipher를 꽂기** — 특히 연구용 **시간창/manifold** cipher를 의미 있는 채널에만 꽂고 나머지는 안
건드리게.

> Scope = the **live v2 stack**: `crates/{mesh, meshrun, meshd, proto, tun}` + the parts of
> `crates/net` it uses. Legacy v1 (`crates/{daemon, crypto, engine, dht, overlay}`) is noted
> but out of scope. / 범위 = **라이브 v2 스택**. v1 레거시는 표시만 하고 제외.

---

## 1. The four primitives / 4개 프리미티브

| Primitive | Where | Role |
|---|---|---|
| **ChaCha20-Poly1305** (AEAD) | `mesh/src/crypto.rs` `MeshCipher` | Data + control frame confidentiality+integrity |
| **x25519** ECDH (sealed-box) | `mesh/src/keydist.rs` `seal_secret`/`open` | Seal the mesh secret to a joiner at invite time |
| **ed25519** signatures | `mesh/src/membership.rs` `MasterKey`/`MemberKey`/`Cert` | Membership: who is in the mesh (auth, **not** confidentiality) |
| **Blake2s-256** | `crypto.rs` (`epoch_key`, `lan_tag`), `keydist.rs` (`derive_key`) | Domain-separated KDF + the opaque LAN tag |

KO: 데이터/제어 = ChaChaPoly, 키 봉인 = x25519 sealed-box, 멤버십 = ed25519 서명(기밀성 아님,
인증), 그리고 모든 KDF·태그 = Blake2s.

---

## 2. Channel inventory / 채널 목록

Every byte-moving site, what wraps it, and whether the cipher is **pluggable** (swappable
without touching callers). / 모든 바이트 이동 지점 + 감싸는 암호 + **pluggable** 여부.

| # | Channel / 채널 | Transport | What travels | Crypto | Pluggable seam |
|---|---|---|---|---|---|
| 1 | **Data plane** (Transport frame) | UDP unicast | app IPv4 packets | **ChaCha20-Poly1305**, AAD = 5B v2 header | ✅ `MeshSuite` |
| 2 | **Endpoint gossip / keepalive** (Control frame) | UDP unicast | endpoint table, reflexion | **ChaCha20-Poly1305** (same suite, `FrameType::Control`) | ✅ `MeshSuite` |
| 3 | **Relay forward** (`Inbound::Forward`) | UDP unicast | a sealed frame for someone else | none added — **forwarded sealed, opaque** (header cleartext for routing) | n/a (carries #1/#2 sealed) |
| 4 | **Relay wrapper / circuit** (`net/relay.rs`) | UDP unicast | `0xF0` register/forward; `0xF1` circuit | **plaintext** wrapper (node-IDs or opaque CID); inner frame stays sealed | wrapper hardcoded |
| 5 | **LAN beacon** (P-D4, `meshrun/lan.rs`) | UDP multicast 239.255.42.99:42424 | tag+member+port (15B) | **plaintext**; tag = Blake2s(secret) is opaque, not encryption | none (by design) |
| 6 | **UDP/TCP transport** (`net/lib.rs`) | UDP / TCP | sealed frames | none at layer (opaque). **TCP hello = plaintext** peer addr | n/a |
| 7 | **NAT / STUN** (`net/nat.rs`) | UDP | STUN binding, hole-punch | **plaintext** (standard STUN) | n/a (pre-mesh) |
| 8 | **Control IPC** (meshd ↔ GUI/CLI) | unix socket / named pipe (local) | JSON Request/Response | **plaintext**; socket `0o666`; local-trust | none (local) |
| 9 | **Invite blob** (out-of-band) | inside #8, then user-shuttled | charter, certs, endpoints, **sealed_secret** | envelope **plaintext JSON**; only `sealed_secret` is **x25519-sealed** | sealing hardcoded |
| 10 | **Membership certs** (in #9 / rosters) | inside #9 | ed25519-signed certs | **signed, not encrypted** | signing hardcoded |

KO 요약: 봉인되는 건 **데이터·가십 프레임(ChaChaPoly)** 과 **invite의 mesh secret(x25519)**.
**평문**: LAN 비콘, 릴레이 래퍼, TCP hello, STUN, 로컬 IPC, invite 봉투(secret만 빼고). 릴레이는
봉인된 바이트를 **복호 없이 그대로** 전달.

---

## 3. Per-channel detail / 채널별 상세

### 3.1 Data plane + gossip (the one that matters) / 데이터플레인 + 가십 (핵심)
`mesh/src/dataplane.rs`: `seal_to` (Transport) and `seal_control` (Control) both call the
private `seal_frame` → `suite.seal(seq, payload, aad)`; `recv` → `suite.open`. The 5-byte
wire-v2 header is the **AAD** (tamper-evident), the 8-byte monotonic `send_seq` is the AEAD
**nonce**. **Same suite seals app traffic and gossip** — only the `FrameType` byte differs.
The suite is `MeshCipher` (epoch-keyed ChaCha20-Poly1305) selected by `crypto::suite(name,
secret, epoch)`. / 데이터·가십 둘 다 `MeshSuite`로 봉인, 헤더=AAD, `send_seq`=nonce. app
트래픽과 가십이 **같은 suite**. 이게 시간창 cipher가 들어갈 **바로 그 자리**.

### 3.2 Relay / 릴레이
`meshrun/lib.rs` `Inbound::Forward` → `transport.send_to(&frame, …)` re-sends the **sealed
bytes unchanged**; a relay reads only the cleartext header to route and **never decrypts**.
`net/relay.rs` adds a plaintext `0xF0` wrapper (node IDs visible) or an opaque `0xF1` circuit
id; the inner mesh frame stays sealed end-to-end. / 릴레이는 봉인 바이트를 그대로 전달(헤더만
보고 라우팅), 절대 복호 안 함. 래퍼는 평문(노드ID) 또는 불투명 circuit-id.

### 3.3 LAN beacon / LAN 비콘
`meshrun/lan.rs`: **plaintext** 15-byte multicast. Confidentiality comes only from the
**opaque tag** `lan_tag(secret) = Blake2s("…lan-tag-v1"‖secret)[..8]` — a non-member sees
random bytes and can't tie it to a mesh, but it is **not encryption** (an on-path observer
sees member-id + port). / 평문 멀티캐스트. 불투명 태그로 비멤버에겐 랜덤이지만 암호화는 아님.

### 3.4 Key distribution (sealed secret) / 키 배포 (봉인 secret)
`mesh/src/keydist.rs` `seal_secret(to_x25519_pub, secret)`: fresh **ephemeral x25519** →
ECDH → `derive_key = Blake2s("…sealedbox-v2"‖shared‖eph_pub‖recip_pub)` → ChaCha20-Poly1305
with a **zero nonce** (safe: the key is unique per fresh ephemeral). NaCl sealed-box shape.
`open` reverses it with the recipient's static key. This wraps **only the 32-byte mesh
secret**, once, at invite time. / invite 시점에 mesh secret 32B만 1회 봉인(임시 x25519 ECDH +
Blake2s KDF + ChaChaPoly, zero nonce는 임시키라 안전).

### 3.5 Membership signatures / 멤버십 서명
`mesh/src/membership.rs`: `MasterKey`/`MemberKey` are **ed25519**. `issue`/`invite` sign a
canonical `signing_bytes(network‖member‖id‖name‖inviter‖issued_at)`; `sig_ok` verifies;
`valid_members` runs a fixpoint chain-check (master-rooted, OpenChain lets a valid member
invite). This is **authentication, not confidentiality** — a separate axis from ciphers. /
ed25519 서명·검증·체인검증. 기밀성이 아니라 **인증** — cipher와 다른 축.

### 3.6 Control IPC + invite envelope / 제어 IPC + invite 봉투
`meshd/main.rs` + `mesh/src/ipc.rs`: newline-JSON over a **local** unix socket (`0o666`) /
named pipe; trust = same machine. `CreateInvite`/`Invite(InviteBlob)` carry the
**sealed_secret encrypted**, but the surrounding JSON — charter, full **roster of certs**
(member pubkeys), bootstrap **endpoints** — is **cleartext**. Same for the Tauri GUI bridge
(`gui/src-tauri/src/main.rs`). / 로컬 소켓 평문 JSON. invite의 secret만 봉인, charter·전체
cert 로스터·endpoints는 평문.

---

## 4. Pluggable today vs hardcoded / 지금 교체 가능 vs 하드코딩

- ✅ **Data + gossip cipher** — fully separated behind `MeshSuite` + `suite()` factory,
  selected by `charter.initial_cipher`. **This is the only real cipher seam, and it's the
  one that carries all bulk traffic.** Caveat: `suite()` currently **ignores the name** and
  always returns `MeshCipher` (one `match` arm away from real dispatch). / 데이터·가십만 진짜
  seam. 단 `suite()`가 아직 이름 무시하고 무조건 ChaChaPoly (분기 1줄 추가하면 됨).
- 🔒 **Sealed secret** (x25519 box) — hardcoded; could become a `KeyEnvelope` trait, but it's
  a one-shot key-wrap, low priority. / 하드코딩, 1회성 키랩이라 후순위.
- 🔒 **Membership** (ed25519) — hardcoded; a *signature* axis, orthogonal to the cipher. /
  서명 축, cipher와 직교.
- 🔓 **LAN beacon / IPC / relay wrapper / STUN** — plaintext by design (opaque-tag, local-
  trust, routing-metadata). / 설계상 평문.

---

## 5. The separation design — per-channel cipher policy / 분리 설계 — 채널별 cipher 정책

The good news: the structure the user wants **mostly already exists**. The data plane is
suite-agnostic; the charter names the suite per mesh. To make "each structure can run a
different cipher" real and clean: / 사용자가 원하는 구조는 **거의 이미 있음**. 데이터플레인은
suite-무관, charter가 mesh별 suite를 지정. 깔끔히 완성하려면:

1. **Make `suite(name, …)` dispatch** (one `match`) and register a second `impl MeshSuite`.
   This unblocks dropping in the research cipher with zero caller changes. / `suite()`를 이름
   분기하게 + 두 번째 suite 등록.
2. **Keep the axes separate.** Confidentiality (MeshSuite), key-wrap (sealed-box), and
   authentication (ed25519) are independent — don't fuse them. A per-mesh charter can pick
   the data cipher; the key-wrap and signatures stay fixed unless there's a reason. / 세 축
   (기밀성/키랩/인증)을 분리 유지.
3. **Frame-type granularity (optional).** If a channel ever needs a *different* cipher from
   the bulk data (e.g. gossip under a cheaper/faster suite, or the sealed-secret under the
   time-window suite so an invite self-expires), the seam point is `seal_frame`'s `FrameType`
   switch — route per-frame-type to a per-type suite. Not needed now; documented as the hook.
   / 필요하면 `FrameType`별로 다른 suite 라우팅 가능(지금은 불필요, 훅만 명시).

---

## 6. Where the time-window / manifold cipher actually applies / 시간창·manifold cipher가 실제로 의미 있는 곳

| Channel | Time-window cipher? | Why / 이유 |
|---|---|---|
| **Data plane** (#1) | ✅ **primary** | The bulk of recorded traffic; "unrecoverable after the window" is exactly forward-secrecy on the data path. Slots into `MeshSuite`. |
| **Gossip** (#2) | ◻ optional | Same suite today; endpoint data is low-value + short-lived, the window is irrelevant. |
| **Sealed secret** (#9) | ◻ interesting | A *time-windowed seal* would make an **invite self-expire** (can't join after the window). Different construction (key-wrap, not stream) — a separate research sub-track. |
| **Beacon / IPC / relay / STUN** | ✗ no | Plaintext/local/metadata — a confidentiality window has no meaning here. |

KO: 시간창 cipher의 **본진 = 데이터플레인(`MeshSuite`)**. 가십은 선택, 봉인 secret은 "invite
자기소멸"이라는 별도 연구 갈래, 평문 채널들은 무의미.

**Honest core (carry-over from the design discussion):** a time-window that just makes
`decrypt()` return `Err` after the window is **not** unrecoverability — anyone with the key
still reads it. Real "data never recoverable" needs **key erasure**: a forward-secure ratchet
`K_{t+1} = H(K_t)` that discards `K_t`, so past windows become mathematically underivable
even from a recording. The **manifold** part is the research novelty layered on the KDF /
encoding — to be specified in docs/CIPHER_TIMEWINDOW.md. / 창 지나면 `Err`은 진짜 불가역이
아님(키 아는 사람은 읽음). **키 폐기 래칫**(`K_{t+1}=H(K_t)`, `K_t` 폐기)이라야 녹화본도 못 푼다.
manifold는 그 위 연구 novelty.

---

## 7. Gaps & notes / 빈틈·메모

- **Rekey/epoch is declared but NOT wired** — `RecipherTrigger` + `Mesh.epoch` exist, but
  nothing increments the epoch or re-keys; `epoch` stays `0`. The forward-secure ratchet in
  §6 would build directly on this dormant epoch machinery. / 재키잉 미배선(epoch=0 고정) — §6
  래칫이 이 휴면 메커니즘 위에 바로 올라감.
- **Invite envelope is cleartext** — the sealed secret is protected, but the full roster
  (member pubkeys) + endpoints ride in plaintext JSON. Acceptable (you hand it to a future
  member) but worth noting if invites leak. / invite 봉투 평문(secret만 보호).
- **Control IPC is local-plaintext** — fine under same-machine trust; a compromised local
  user reads in-flight invites/keys. Not a transport to put the research cipher on. / 로컬
  평문 IPC(동일 머신 신뢰 가정).
- **State is RAM-only** — unrelated to crypto but the #1 stabilization item; a restart wipes
  mesh keys/secret/roster. / 상태 RAM-only(암호와 무관하지만 안정화 1순위).

---

## TL;DR
The cipher you actually research lives in **one seam — `MeshSuite`** (data + gossip), already
separated, charter-selected; finish `suite()` dispatch and drop in a forward-secure
time-window/manifold suite there. Everything else is either a different axis (signing,
key-wrap) or deliberately plaintext (local IPC, opaque beacon, routing metadata). / 연구
cipher의 집은 **`MeshSuite` 하나**(데이터+가십), 이미 분리됨. `suite()` 분기만 마치고 키-폐기
시간창/manifold suite를 거기 꽂으면 됨. 나머진 다른 축이거나 의도된 평문.
