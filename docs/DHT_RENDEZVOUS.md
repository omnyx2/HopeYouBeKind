# DHT rendezvous — re-finding a peer whose address changed

*(한국어 요약은 맨 아래)*

## The gap this closes

v2 discovery (`docs/DISCOVERY.md`, P-D1…P-D4) is **first-contact** machinery:

- **P-D1** invite carries the inviter's endpoint,
- **P-D2** sealed gossip propagates the `MemberId → ip:port` table,
- **P-D3** reflexive address via a public peer,
- **P-D4** LAN multicast beacon.

All four need an **overlapping live window**: at least one path by which the two
nodes are reachable *at the same time* so an address can propagate. If two peers
both change address while disconnected (laptop sleeps, moves network; the other
roams too) there is **no longer any channel** to re-exchange addresses — the mesh
knows they're members (the roster is gossiped certs) but not *where* they are.

v1 had this covered: a Kademlia DHT let any node **look up an address by node id**.
v2 tore the DHT out with the rest of the admin/CA stack. But a DHT is itself
**admin-free**, so it fits v2 — we reintroduce it, keyed by the thing that is
already globally unique and self-authenticating in v2: the **member public key**.

## Design — the DHT stores signed endpoint records, keyed by pubkey

The reusable v1 Kademlia (`legacy/crates/dht`, builds today) already stores
arbitrary `key:[u8;32] → value:Vec<u8>` records (`StoreRecord`/`FindRecord`,
`publish_record`/`get_record`). We use it as a **distributed cache of
`EndpointRecord`s** — the dormant `crates/mesh/src/discovery.rs` type, finally wired:

```
DHT key   = member public key            ([u8;32], globally unique per mesh membership)
DHT value = bincode(EndpointRecord)       (signed by that member; carries `network`,
                                           `member`, `endpoints`, `seq`, `at_ms`, `sig`)
```

The record is **self-authenticating**: the DHT nodes store opaque bytes and are
never trusted. Only the *reader* verifies — `EndpointRecord::verify()` checks the
signature against the claimed member key, and the reader additionally requires the
record's `network` + `member` to match the peer it is looking for, and a `seq`
newer than what it holds (`EndpointBook::observe`). A malicious DHT node can drop or
return stale records (availability), but **cannot forge an endpoint** (integrity).

### Why pubkey, not MemberId

The live data plane keys peers by **`MemberId`** (1 byte, per-mesh, reused across
meshes) — fine on the wire, useless as a global DHT key. The **pubkey** is unique
and stable. meshd already holds the `MemberId ↔ pubkey` map: it's the roster of
certs. So:

- **publish:** key by *our* member pubkey (from our cert), value = our signed record;
- **lookup:** peer is known locally as `MemberId M` with cert pubkey `P` → DHT
  `get_record(P)` → verify → inject the endpoint into the live peer table under `M`
  (the same seam `SetPeer` and gossip use).

## Architecture — one node-wide DHT service

```
                 meshd process
   ┌─────────────────────────────────────────────┐
   │  DhtService (one per node)                   │
   │   • DhtNode on UDP :MESHD_DHT_PORT           │  ← Kademlia overlay, separate
   │   • Kademlia<DhtNode transport>              │    from the per-mesh data plane
   │   • bootstrap(seeds)                          │
   │                                              │
   │   publish(EndpointRecord)  ───► StoreRecord  │
   │   lookup(pubkey) ──► get_record ──► verify   │
   └──────────────▲───────────────────┬───────────┘
                  │                   │
   per-mesh hooks │                   │ periodic reconnect task
   ───────────────┴───────────────────┴───────────
   • on bringup / reflexive-address upgrade:
        publish our record for that mesh
   • every RECONNECT_TICK, for each member with no
     fresh endpoint (endpoint==null or last_seen stale):
        lookup(peer pubkey) → seed PeerLinks[M].endpoint
```

- **One DHT node per machine**, not per mesh: keys are pubkeys, records carry their
  own `network`, so one overlay safely serves every mesh the node is in.
- **Separate UDP port** (`MESHD_DHT_PORT`, default `UDP_BASE + 900`) so it never
  contends with a mesh data-plane port (and benefits from §2 bind self-heal anyway).
- **DHT node id:** a stable random 32-byte id per node (routing only; not identity).
- **Bootstrap seeds:** `MESHD_DHT_BOOTSTRAP=ip:port,…` plus any public node
  (`MESHD_ADVERTISE`) — the always-on Oracle node is the natural seed. Newly learned
  peer endpoints are also fed to `bootstrap_addrs` so the overlay densifies.

## What we reuse vs. add

Reused **as-is** from `legacy/crates/dht` (per the code audit): `distance.rs`,
`routing.rs`, `rpc.rs`, `server.rs` (`DhtNode` + request-id demux), and
`node.rs`'s `KademliaNode::handle` + `Kademlia::iterative` lookup. The
`StoreRecord`/`FindRecord`/`publish_record`/`get_record` path needs **no change** —
it already carries `Vec<u8>`.

New, small: a `meshd` `dht` module that owns the `DhtService` lifecycle and bridges
`EndpointRecord ↔ publish_record/get_record`, plus the publish hooks and the
periodic reconnect task. The signed-record verification lives in `discovery.rs`
(`EndpointRecord::verify`, `EndpointBook`), now wired for the first time.

## Rollout / safety

- **On by default** whenever the data plane is up; `MESHD_DHT=0` opts out. (Shipped
  opt-in first, then promoted to default after 3-platform live verification — Mac +
  Oracle/Linux + Windows: a Windows node that received only the inviter's address
  re-discovered a third peer's address purely via the DHT.)
- **Availability only, never integrity:** if the DHT is empty/unreachable, behaviour
  is exactly today's (first-contact discovery); a returned record can never *worsen*
  state because it must verify and out-`seq` what we hold.
- **Privacy note:** publishing `pubkey → endpoint` to an overlay reveals a member's
  address to whoever holds the nearby keyspace. Acceptable for the mesh model
  (members already learn each other's endpoints via gossip), but a future option can
  encrypt the record body to the mesh secret so only members can read the address,
  keeping the DHT as a blind store. Tracked, not built.

## Test plan

1. **Unit / in-process:** two `KademliaNode`s, publish a record on A, `get_record`
   on B → bytes roundtrip; tamper the sig → `observe` rejects. (`dht` + `discovery`
   tests.)
2. **Local two-process:** two meshd on loopback, distinct DHT ports, B bootstraps
   off A; publish on A, lookup on B.
3. **Cross-network re-discovery (the real one):** Mac ↔ Oracle. Establish the mesh,
   confirm direct contact, then **change the Mac's address with no overlap** (drop
   the live links, move network) → the periodic reconnect task DHT-looks-up Oracle's
   record (and Oracle finds the Mac's republished record) → links re-established
   with **no manual SetPeer and no fresh invite**. Verified on macOS + Linux +
   Windows per `verify-all-three-platforms`.

---

## 한국어 요약 — DHT 랑데부(주소 바뀐 피어 재발견)

**메우는 갭:** v2 디스커버리(P-D1~D4)는 전부 "첫 접촉"용이라 **겹치는 생존 창**이
있어야 주소가 전파됩니다. 양쪽이 끊긴 채 동시에 주소가 바뀌면 재교환 경로가 없어
"멤버인 건 알지만 어디 있는지 모름" 상태가 됩니다. v1의 Kademlia DHT가 이걸 해결했고,
DHT는 그 자체로 admin-free라 v2 철학과 맞습니다 — **member pubkey로 키를 잡아** 재도입.

**설계:** 그대로 빌드되는 `legacy/crates/dht`(임의 `Vec<u8>` 레코드 저장)를
**서명된 `EndpointRecord` 분산 캐시**로 사용. 키 = member pubkey(전역 유일),
값 = `bincode(EndpointRecord)`(휴면 중이던 `discovery.rs` 타입을 드디어 배선).
레코드는 **self-authenticating** — DHT 노드는 불투명 바이트만 저장(신뢰 불필요),
**읽는 쪽만** 서명·network·member·seq를 검증. 악의적 DHT 노드도 endpoint **위조 불가**,
기껏해야 drop/stale(가용성)만 영향.

**왜 pubkey?** 라이브 평면은 `MemberId`(1바이트, mesh별 재사용)로 피어를 키잉 →
전역 키로 부적합. pubkey는 유일·안정. meshd는 cert 로스터로 `MemberId↔pubkey`를 이미 보유.

**구조:** 노드당 DHT 1개(메쉬별 아님), 전용 UDP 포트(`MESHD_DHT_PORT`), 공개노드
(Oracle)를 부트스트랩 시드로. 훅: ① bringup/reflexive 주소 갱신 시 우리 레코드 publish,
② 주기적으로 fresh endpoint 없는 멤버를 DHT lookup → `PeerLinks`에 주입(=재연결).

**재사용:** `distance/routing/rpc/server`와 `iterative` 룩업은 무수정 재사용,
`publish_record/get_record`도 그대로. 새로 추가는 `EndpointRecord↔DHT` 다리 + 훅뿐.

**안전:** 데이터플레인이 뜨면 **기본 활성**(`MESHD_DHT=0`으로 opt-out). 처음엔 opt-in으로
냈다가 3-플랫폼 라이브 검증(Mac+Oracle+Windows: invite로 초대자 주소만 받은 Windows 노드가
제3 피어 주소를 오직 DHT로 재발견) 후 기본화.
가용성만 영향·무결성 불변. 프라이버시: 후속으로 레코드 본문을 mesh secret로 암호화해
DHT를 blind store로 만드는 옵션 가능(설계만, 미구현).
