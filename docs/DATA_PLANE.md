# v2 Data Plane — design / 데이터 플레인 설계

> How v2 actually moves packets: TUN → per-mesh demux → seal → transport → peer,
> and back. This is where the built pieces meet (wire-v2 header, `MeshSuite` cipher,
> `EndpointBook` discovery, `PolicyTable`, `Transport`, membership certs). Source of
> truth — update first, then code. Big, so it is **phased** (§9).
>
> v2가 실제로 패킷을 옮기는 법: TUN → 메쉬별 demux → seal → transport → 피어, 그리고
> 역방향. 지금까지 만든 조각이 여기서 합쳐진다. 코드 전에 이 문서를 먼저 고친다. 크므로
> **단계화**(§9).

## 0. Goal / 목표

A computer's normal apps use the network unchanged; a TUN captures the traffic the
policy assigns to a mesh, the data plane carries it encrypted to the right member
(or out an exit), and delivers inbound mesh traffic back to the TUN. Per-mesh
isolation, per-node exit, origin-default.
/ 앱은 평소대로 네트워크 사용. TUN이 정책상 메쉬에 할당된 트래픽을 잡아 암호화해 알맞은
멤버(또는 exit)로 옮기고, 들어오는 메쉬 트래픽을 TUN으로 되돌린다. 메쉬별 격리, 노드별
exit, 기본은 origin.

## 0.1 Ephemeral mesh / 휘발성 메쉬 (decided)

The data plane **and** the mesh state live in **RAM (userspace)** — chosen for
portability (one codebase for macOS/Linux/Windows; no kernel module/eBPF) and
because a personal mesh is uplink-bound, not TUN-bound. This pairs with an
ephemerality model:

- **Mesh = ephemeral.** A mesh exists only while ≥1 node holds it; when **all** nodes
  leave, it is **permanently gone** (no central record). Nothing on disk to recover —
  reinforces the unrecoverability goal (a powered-off stolen device is barren).
- **Node restart ≠ leave.** A node **persists its own join material locally** (its
  keypair + cert + mesh secret), so it rejoins its meshes after a restart. (That
  local material is the node's responsibility and is what capture-detection /
  re-cipher revoke if the node is taken — MESH_V2.md §5.)
- **Master key = creator-persisted, opt-in.** The creator stores the master key
  separately so it stays admin across restarts; if it doesn't, the mesh simply has
  no admin (existing members coast; no new admits/re-cipher) — "no save = no create."

/ 데이터 플레인·메쉬 상태는 **RAM(유저스페이스)**. 이식성 + 개인 VPN은 업링크 바운드라서.
**메쉬는 휘발**(전원 이탈 시 영구 소멸, 디스크에 안 남음 → 복구불가 강화). **노드 재시작 ≠
탈퇴**(노드가 자기 가입자료=키쌍+cert+메쉬시크릿을 로컬 보관해 복귀; 탈취 시 그게 §5
대상). **마스터 키는 생성자가 별도 저장(opt-in)** — 안 하면 admin 없는 메쉬("저장 안 하면
생성 안 한 것").

## 1. Where it runs / 어디서 도나

The data plane lives in **meshd** (it already holds each mesh's keys/certs). Today
meshd is an unprivileged control plane; with the data plane on it needs **root** (to
open the TUN and program routes). **[DECIDE]** meshd-gains-dataplane vs a separate
privileged `latticed` that meshd drives. Recommend: one binary, data plane behind a
flag, so the control plane stays usable without root.
/ 데이터 플레인은 **meshd**에 둔다(이미 메쉬 키/cert 보유). 단 TUN·라우트 때문에 **root**
필요. **[DECIDE]** meshd에 통합 vs 별도 권한 데몬. 추천: 한 바이너리, 데이터 플레인은
플래그 뒤 → 컨트롤 플레인은 root 없이도 동작.

## 2. Addressing / 주소

In-mesh there are no real IPs (§2 of MESH_V2.md); but the OS needs an IP to route
into the TUN. Map the 1-byte member id onto an overlay address:

```
overlay(mesh M, member K) = <prefix.0>.<prefix.1>.<M>.<K>     a /24 per mesh
  e.g. prefix [100,80] → mesh 3, member 7 = 100.80.3.7
```

- `prefix` = the charter's `overlay_prefix`, chosen collision-free by the §9
  coexistence pre-flight (not hardcoded 100.x).
- The host octet **is** the member's 1-byte id (1..254). 254 members per mesh /24.
- The TUN is assigned every active mesh's /24 (or a covering route) so matching
  packets enter it.

/ 메쉬 내부는 실제 IP 없음. 하지만 OS가 TUN으로 라우팅하려면 IP 필요 → 1바이트 멤버 id를
오버레이 주소로 매핑: `prefix.prefix.<meshid>.<memberid>` (메쉬당 /24, host 옥텟=멤버 id).
prefix는 §9 pre-flight가 충돌 없이 선택.

## 3. Outbound — TUN → wire / 아웃바운드

```
TUN.read_packet() → raw IPv4 packet p
  dst = p.dst_ip ; key = FlowKey{dst, proto, dport}
  if dst ∈ some mesh M's /24:                 # in-mesh delivery
        K = dst host octet (the member)
        decision = Via{mesh:M, member:K}
  else:                                        # internet-bound
        decision = PolicyTable.route(key)      # Direct(origin) | Via{mesh, exit}
  match decision:
    Direct           → leave to the host's normal path (not our packet) / drop
    Via{mesh:M, K}   → frame it:
        hdr  = [ver, M, my_member_id, K, Transport]      # wire_v2 (cleartext)
        body = MeshSuite(M).seal(seq, p, aad = hdr)      # per-mesh cipher
        addr = EndpointBook.get(member K).pick()         # discovery → where
        Transport(M).send_to([hdr ‖ body], addr)
```

For an internet flow routed `Via{mesh M, exit E}`, `K = E` (the exit member); the
inner packet `p` keeps its real internet dst.
/ TUN에서 읽은 패킷의 dst가 어떤 메쉬 /24면 그 멤버로, 아니면 정책표로 (origin이면 안 잡음,
메쉬면 exit 멤버로). 헤더(wire_v2, 평문) + 메쉬 cipher로 seal + EndpointBook로 주소 찾아
transport 전송. 인터넷 흐름이면 K=exit 멤버, 내부 패킷의 실제 dst 유지.

## 4. Inbound — wire → TUN / 인바운드

```
Transport.recv_from() → (frame, src_addr)
  (hdr, body) = wire_v2.decode(frame)              # ver/meshid/src/dst/type
  M = lookup mesh by hdr.meshid ; else drop
  p = MeshSuite(M).open(seq, body, aad = hdr)?     # auth fail → drop
  EndpointBook.learn(hdr.src ← src_addr)           # learn where src is
  match hdr.type, hdr.dst:
    Transport, dst == me      → TUN.write_packet(p)            # it's for me
    Transport, dst == me & p.dst is internet & I am exit
                              → NAT p out (exit path, §6)
    Transport, dst != me      → forward to dst's endpoint      # relay (§7)
    Control                   → rekey / expel / capture-alert
    Keepalive                 → liveness
```

/ 받은 프레임을 decode → meshid로 메쉬 찾고 cipher로 open(실패 시 drop). src의 주소를
학습. dst가 나면 TUN에 쓰기(또는 내가 exit면 NAT), 아니면 dst로 포워드(릴레이).

## 5. Sessions & keying / 세션·키

**No per-peer handshake.** A mesh has a **shared symmetric secret** (the epoch
secret); every member derives the same epoch key (`MeshSuite`), so any member can
seal/open mesh frames. A "session" is just: the peer's endpoint (`EndpointBook`) +
the shared cipher + the transport.

**Key distribution (at join):** the invite seals the mesh secret **to the joiner's
encryption key** so only they can read it. Members therefore carry an **X25519
encryption key** alongside their ed25519 identity (sealed-box). The invite payload =
`cert ‖ sealed(mesh_secret)`. **[NEW work]** — membership has ed25519 only today.

**Endpoints:** each member self-publishes a signed `EndpointRecord` (§10 of
MESH_V2.md); the data plane resolves `member → addr` from the `EndpointBook` and
dials via the mesh's transport (UDP default, TCP/QUIC selectable).

/ **피어별 핸드셰이크 없음.** 메쉬는 **공유 대칭 시크릿**(epoch secret) 보유 → 모든 멤버가
같은 키 유도, 누구나 seal/open. "세션"=피어 엔드포인트+공유 cipher+transport. **키 배포(가입
시)**: 초대가 메쉬 시크릿을 **가입자 암호화 키로 봉인** → 멤버는 ed25519 외에 **X25519 암호화
키** 보유(sealed-box). 초대 페이로드 = `cert ‖ sealed(mesh_secret)`. **[신규 작업]**(현재
멤버십은 ed25519만). 엔드포인트는 서명된 EndpointRecord로 해석 후 transport로 다이얼.

## 6. Egress / exit path / 외부 출구

A member set as exit (`dst = E`) receives internet-bound inner packets, **NATs** them
to the real internet, and returns replies back into the mesh toward the origin
member. Reuse the v1 cross-platform NAT/route/DNS (`crates/daemon/src/exit.rs`:
`enable_nat`, `route_through`, `set_dns`). Origin sees only the exit's location
(MESH_V2.md anonymity rule).
/ exit로 지정된 멤버가 인터넷행 내부 패킷을 받아 **NAT**으로 실제 인터넷에 내보내고, 응답을
origin 멤버로 되돌린다. v1 NAT 코드 재사용. 외부엔 exit 위치만 노출.

## 7. Reuse vs new / 재사용 vs 신규

**Reuse:** `lattice-tun` (`TunDevice`), `lattice-net` (`Transport`: UDP/TCP),
`exit.rs` NAT, `wire_v2`, `MeshSuite`, `EndpointBook`, `PolicyTable`, membership
certs. **New:** the per-mesh engine loop (TUN demux + seal/open + forward), the
overlay-IP ↔ member mapping, the X25519 key-seal at join, the meshd data-plane host.
/ 재사용: TUN·Transport·NAT·wire_v2·MeshSuite·EndpointBook·PolicyTable·cert. 신규:
메쉬별 엔진 루프, 오버레이IP↔멤버 매핑, 가입 시 X25519 봉인, meshd 데이터플레인 호스트.

## 8. Security notes / 보안 메모

- **Shared mesh key ⇒ no in-mesh origin auth.** Any member can decrypt all mesh
  traffic (by design — §3 transparency) **and** could forge another member's `src`.
  Mitigation: only valid members hold the key (membership-gated), and a misbehaving
  member is handled by **capture-detection + re-cipher** (MESH_V2.md §5), not by the
  data-plane crypto. If stronger origin-auth is needed, add a per-frame member
  signature **[DECIDE]** (cost).
- Confidentiality/integrity per frame from the AEAD; the cleartext header is AEAD
  associated data (tamper-evident). Replay = a per-(epoch,member) counter + window
  **[DECIDE]**.
/ **공유 키 ⇒ 메쉬 내 출발지 인증 없음**(누구나 복호화 + src 위조 가능, 설계상 투명성).
완화: 유효 멤버만 키 보유 + 악성 멤버는 탈취감지+re-cipher. 더 강한 인증 원하면 프레임별
멤버 서명 추가 **[DECIDE]**. 무결성은 AEAD, 헤더는 aad. 재생방지는 카운터+윈도우 **[DECIDE]**.

## 9. Phases / 단계 (big → incremental)

1. **P1 — loopback:** one process, `MemoryTransport`, one mesh: TUN-shaped packet →
   seal → open → back. Proves the demux + cipher + header wiring. (no real net)
2. **P2 — two nodes, in-mesh:** two real hosts, shared secret out-of-band, UDP,
   overlay /24, **ping over the mesh**. The first real packet flow.
3. **P3 — key distribution:** X25519 enc keys + sealed mesh-secret at join (replace
   the out-of-band secret).
4. **P4 — exit:** internet via an exit member + NAT (reuse exit.rs).
5. **P5 — relay/forward:** carry frames for unreachable pairs (reuse the relay
   pattern).
6. **P6 — meshd integration + GUI:** data plane in meshd; expose per-mesh
   connection/endpoint state over IPC → **Peers + Topology pages go live**.
/ P1 루프백 → P2 두 노드 in-mesh ping → P3 키 배포 → P4 exit → P5 릴레이 → P6 meshd 통합 +
GUI(Peers/Topology 라이브).

## 10. Open decisions / 열린 결정

**DECIDED (pre-P1):**
- **Location** — data plane in **meshd**, **RAM/userspace**, behind a flag (control
  plane stays root-free). [§0.1, §1]
- **In-mesh origin auth** — **accept the shared-key limitation** for now (no
  per-frame signature); in-mesh transparency + capture-detection cover it. Revisit
  if needed. [§8]
- **seq/nonce** — the frame carries an **8-byte cleartext `seq` right after the
  5-byte header**; it **is** the AEAD nonce (wrong seq → auth fail), and the 5-byte
  header is the AEAD `aad`. Frame = `header(5) ‖ seq(8) ‖ ciphertext`. [§5/§6]

**Still open:**
1. **[§1]** data plane in meshd vs separate privileged daemon. *(decided: meshd)*
2. **[§5]** X25519 key-seal scheme for mesh-secret distribution at join.
3. **[§8]** in-mesh origin auth: accept shared-key limitation vs per-frame member
   signature.
4. **[§8]** replay/nonce scheme (per-(epoch,member) counter + window size).
5. **[§2]** overlay prefix sizing + the coexistence pre-flight that picks it.
6. **[§5]** seq/nonce source in the header (the wire-v2 frame has no counter field
   yet — add one, or carry it in the sealed body).

> Confirm §10.1, .3, .6 before P1 (they shape the wire/loop); the rest can follow
> per phase. / P1 전에 §10.1·.3·.6 확정(와이어/루프에 영향), 나머지는 단계별로.
