# Endpoint discovery — gossip / 엔드포인트 발견 — 가십

**Problem / 문제.** Membership (certs, MEMBERSHIP.md) says **who** is in a mesh, not
**where** (IP:port). The data plane learns an endpoint from an inbound frame's `src`,
but that needs a *seed* — a fresh node knows nobody's address, so it can't reach the
exit or any peer (hence the manual SetPeer band-aid). / 멤버십(cert)은 mesh에 **누가**
있는지 알지만 **어디(IP:port)**인지는 모른다. 데이터플레인은 들어온 프레임의 `src`로 엔드포인트를
배우지만 *씨앗*이 필요하다 — 갓 들어온 노드는 아무 주소도 몰라 exit이든 피어든 못 닿는다(그래서
수동 SetPeer 임시방편).

**Design / 설계 (gossip, seeded by the inviter / 초대자가 씨앗).** Exactly the user's
model: credential → handshake with the inviter → propagate the live member list →
each node verifies it and builds its own table. / 정확히 사용자 모델: 자격증명 → 초대자와
핸드셰이크 → 현재 멤버 리스트 전파 → 각 노드가 검증하고 자기 테이블을 만든다.

### 1. Bootstrap via the invite / 초대로 부트스트랩
The `InviteBlob` (ipc.rs) gains **`inviter_endpoints`** + the inviter's current
**endpoint book** (signed `EndpointRecord`s it already holds). So the joiner, the
moment it installs the mesh, knows where the **inviter** is *and* everyone the inviter
knows → it can immediately send (handshake) to them. / `InviteBlob`에 **`inviter_endpoints`**
와 초대자가 가진 현재 **endpoint book**(서명된 `EndpointRecord`들)을 추가. 합류자는 mesh를
설치하는 즉시 **초대자** 위치 + 초대자가 아는 모두를 알아 바로 보낼(핸드셰이크) 수 있다.

### 2. Each node publishes a signed EndpointRecord / 각 노드가 서명된 레코드 발행
`EndpointRecord { network, member, endpoints, seq, at_ms, sig }` (discovery.rs) —
signed by the member's key; `seq` bumps when the endpoint changes. `endpoints` = this
node's reachable address(es): its **reflexive (public) address** (STUN, or set
explicitly for a public node — the Oracle exit declares `203.0.113.10:41000`), plus any
LAN address. / 멤버 키로 서명; 엔드포인트 바뀌면 `seq` 증가. `endpoints` = 도달 가능한 주소들:
**reflexive(공인) 주소**(STUN 또는 공인 노드는 명시 — Oracle exit은 `203.0.113.10:41000` 선언) +
LAN 주소.

### 3. Gossip / 가십
Periodically (every few seconds) and right after join, a node sends its whole
`EndpointBook` to its currently-known peers in a **`FrameType::Control`** frame
(wire_v2 — sealed with the mesh cipher, so only members read it). A receiver **merges**:
for each record, verify the sig chains to a roster member, then keep the **newest
`seq`** per member (`EndpointBook::merge`). / 주기적으로(수 초마다) + 합류 직후, 노드는 자기
`EndpointBook` 전체를 아는 피어들에게 **`FrameType::Control`** 프레임으로 보낸다(mesh cipher로
봉인 → 멤버만 읽음). 수신자는 **병합**: 각 레코드의 서명이 로스터 멤버로 체인되는지 검증 후 멤버별
**최신 `seq`** 유지.

### 4. Convergence → each node's table / 수렴 → 각 노드의 테이블
Epidemic spread: within a few rounds every node holds every member's record. A node's
**routing table = its merged EndpointBook** → it populates `PeerLinks` (the data-plane
loop already routes off `PeerLinks`). No central authority; each node converges to the
same view from signed records (cf. the sheaf-coherence argument, MATHEMATICAL_MODEL.md).
/ 전염적 확산: 몇 라운드면 모든 노드가 모든 레코드 보유. 노드의 **라우팅 테이블 = 병합된
EndpointBook** → `PeerLinks` 채움(데이터플레인 루프는 이미 `PeerLinks`로 라우팅). 중앙 없이 각
노드가 서명 레코드로 같은 view에 수렴.

### 5. NAT & relays / NAT·릴레이
A node behind NAT advertises its **reflexive** address; if two NAT'd peers can't reach
each other directly, a member with a reachable address relays (the data-plane loop
already forwards `Inbound::Forward`). Public nodes (the exit) are always reachable.
/ NAT 뒤 노드는 **reflexive** 주소 광고; 직접 못 닿는 두 NAT 피어는 도달 가능한 멤버가 릴레이
(데이터플레인 루프가 이미 `Inbound::Forward` 전달). 공인 노드(exit)는 항상 도달 가능.

## What exists vs to build / 있는 것 vs 만들 것
- ✅ `discovery.rs`: `EndpointRecord`, `EndpointBook`, `MemberKey::publish_endpoints`.
- ✅ `wire_v2::FrameType::Control` (the gossip frame type) + per-mesh cipher (seal/open).
- ✅ data-plane loop routes off `PeerLinks` + relays `Forward`.
- ⏳ **invite carries** `inviter_endpoints` + endpoint book (ipc.rs `InviteBlob`, meshd
  `CreateInvite`/`JoinMesh`).
- ⏳ **reflexive address** per node (STUN; explicit for public nodes via env/flag).
- ⏳ **gossip loop** in `meshrun::run`: emit a Control frame with the EndpointBook every
  N s + on join; on recv Control, merge into the book and update `PeerLinks`.
- ⏳ retire the manual **SetPeer** UI once gossip lands (keep as a fallback/override).

## Phases / 단계
1. **P-D1 invite-carries-endpoint** — joiner reaches the inviter immediately (smallest
   win; unblocks 2-node joins without SetPeer). / 합류자가 초대자에 바로 닿음(가장 작은 성과).
2. **P-D2 gossip Control frames** — EndpointBook emit/merge in `run`; full convergence.
   / EndpointBook 송수신·병합; 완전 수렴.
3. **P-D3 reflexive (STUN)** — auto public address; public nodes set it explicitly.
   / 자동 공인 주소; 공인 노드는 명시.
4. **P-D4 LAN fast-path (mDNS)** — same-router peers find each other without the WAN.
   / 같은 공유기 피어를 WAN 없이.
