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
explicitly for a public node — the Oracle exit declares `<PUBLIC_IP>:41000`), plus any
LAN address. / 멤버 키로 서명; 엔드포인트 바뀌면 `seq` 증가. `endpoints` = 도달 가능한 주소들:
**reflexive(공인) 주소**(STUN 또는 공인 노드는 명시 — Oracle exit은 `<PUBLIC_IP>:41000` 선언) +
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

## 6. Roaming & address churn / 로밍·주소 변동
A computer's underlay address changes often (Wi-Fi↔cellular, DHCP, NAT-port
rebinding). The mesh tolerates this by **separating stable identity from the volatile
endpoint**: routing is by **member id + pubkey** (and the fixed overlay IP); the
**IP:port is a cache** of "how to reach right now". When it changes: / 컴퓨터의 언더레이
주소는 자주 바뀐다(Wi-Fi↔셀룰러, DHCP, NAT 포트 재바인딩). mesh는 **불변 신원과 변동
엔드포인트를 분리**해 견딘다: 라우팅은 **member id + pubkey**(+ 고정 overlay IP), **IP:port는
"지금 어떻게 닿나" 캐시**. 바뀌면:

1. **Re-learn from any authenticated frame (WireGuard-style roaming).** A node that
   moved sends from a new address; the receiver updates that member's `Link.endpoint`
   from the frame's source on the spot — one packet re-binds the route. (The data-plane
   loop already learns `hdr.src → from`.) / **인증 프레임에서 재학습(WireGuard 로밍).**
   옮긴 노드가 새 주소에서 보내면 수신자가 즉시 그 멤버의 `Link.endpoint`를 갱신 — 패킷 하나면
   경로 재바인딩. (데이터플레인 루프가 이미 `hdr.src → from` 학습.)
2. **Re-publish with a higher `seq`.** The node detects its endpoint changed and emits a
   new `EndpointRecord (seq+1)`; gossip replaces older entries everywhere, including for
   peers it isn't directly talking to. / **`seq` 올려 재발행.** 엔드포인트 변화를 감지해 새
   레코드(seq+1) 발행; gossip이 직접 안 보내는 피어에게도 갱신 전파.
3. **Keepalives keep NAT mappings alive.** UDP NAT mappings expire in ~30 s–2 min, which
   *causes* the reflexive port to change. A **keepalive every ~20–25 s** (WireGuard's
   persistent-keepalive value) holds the mapping open, so the endpoint mostly *doesn't*
   change in the first place — and doubles as the liveness signal. / **Keepalive로 NAT
   매핑 유지.** UDP NAT 매핑은 ~30초–2분이면 만료돼 reflexive 포트가 *바뀐다*. **~20–25초마다
   keepalive**로 매핑을 열어둬 애초에 잘 안 바뀌게 — liveness 신호도 겸함.
4. **Relay fallback during the gap.** In the brief window before a new endpoint
   propagates, a reachable member (a public node like the exit) relays, then traffic
   returns to the direct path once the update lands. / **틈새엔 릴레이.** 새 엔드포인트가
   퍼지기 전 짧은 틈엔 도달 가능한 멤버(공인 노드/exit)가 릴레이, 갱신되면 직접 경로 복귀.

So churn never breaks the mesh — the **identity is permanent; the endpoint is a
self-healing cache** (re-learn + re-gossip + keepalive + relay). / 즉 churn은 mesh를 안
깨뜨린다 — **신원은 영구, 엔드포인트는 자가치유 캐시**.

## What exists vs to build / 있는 것 vs 만들 것
- ✅ `discovery.rs`: `EndpointRecord`, `EndpointBook`, `MemberKey::publish_endpoints`.
- ✅ `wire_v2::FrameType::Control` (the gossip frame type) + per-mesh cipher (seal/open).
- ✅ data-plane loop routes off `PeerLinks` + relays `Forward`.
- ✅ **P-D1 invite carries endpoints** — `InviteBlob.endpoints: Vec<(MemberId, String)>`
  (ipc.rs); meshd `CreateInvite` fills it (own advertised addr + known links), `JoinMesh`
  seeds the joiner's `PeerLinks` from it → reach the inviter at once, no manual SetPeer.
- ✅ **P-D2 gossip loop** in `meshrun::run` — a `Control` frame with the endpoint table
  every `GOSSIP_INTERVAL_SECS` (20 s; first tick immediate) to each known peer + NAT
  keepalive; on recv `Inbound::Control`, merge unknown members into `PeerLinks`. Own
  advertised endpoint = `MESHD_ADVERTISE` (public nodes) else the primary LAN addr.
- ✅ **P-D3 reflexive address via peer reflexion** — instead of an external STUN server,
  our own **public peer reflects** what it observes. The gossip payload carries a
  per-recipient `self ip:port` line = "where I (sender) see YOU"; a receiver adopts it
  as its advertised endpoint **only when the sender's source address is public**
  (`is_public`), i.e. the sender saw our real NAT mapping. `MESHD_ADVERTISE` nodes are
  `endpoint_pinned` (never overridden). Same UDP socket ⇒ the observed mapping is the
  one peers actually use (no separate-socket port mismatch). `my_endpoint` is a shared
  handle so meshd's invites pick up the upgraded address. LIVE: a campus-NAT Mac learned
  `203.0.113.20:25459` reflected by the Oracle exit and re-advertised it.
- ✅ **P-D4 LAN fast-path** (`meshrun::lan`) — a custom UDP **multicast beacon** (group
  `239.255.42.99:42424`, TTL 1) every 7 s. Each beacon = `LAT1` magic + an **opaque
  per-mesh tag** (`lattice_mesh::lan_tag` = Blake2s of the secret) + our member id + our
  data-plane port. A receiver matches the tag against its meshes and seeds `PeerLinks`
  with the sender's `src_ip:dp_port` — same-router peers connect directly, no WAN/exit/
  reflexion, no NAT. The opaque tag reveals neither mesh id nor pubkey to non-members;
  the sealed gossip is still the real membership gate. meshd runs one beacon for the
  whole node (snapshots all live meshes). LIVE: real beacon observed on the wire.
- ⏳ retire the manual **SetPeer** UI once gossip lands (keep as a fallback/override).

## Phases / 단계
1. ✅ **P-D1 invite-carries-endpoint** — joiner reaches the inviter immediately (smallest
   win; unblocks 2-node joins without SetPeer). / 합류자가 초대자에 바로 닿음(가장 작은 성과).
2. ✅ **P-D2 gossip Control frames** — endpoint table emit/merge in `run`; convergence.
   / 엔드포인트 테이블 송수신·병합; 수렴.
3. ✅ **P-D3 reflexive address** — a public peer reflects our observed public address in
   the gossip (`self` line); we adopt it when the reporter's source is public. Our own
   exit doubles as the STUN reflector — no external server. / 공인 피어가 가십으로 우리
   공인 주소를 반사(`self` 줄), 보고자 출발지가 공인일 때 채택. exit이 STUN 역할 — 외부 서버 X.
4. ✅ **P-D4 LAN fast-path** — a UDP multicast beacon (opaque per-mesh tag) lets
   same-router peers find each other directly, no WAN. / UDP 멀티캐스트 비콘(불투명
   per-mesh 태그)으로 같은 공유기 피어를 WAN 없이 직접 발견.
