# Dynamic network resilience / 동적 환경 대응

> A node's IP is not stable. The daemon owns detecting that and healing the mesh; the
> overlay (member IPs `100.80.x.y`) never changes, so applications keep their connections.

---

## English

### The problem
A laptop, desktop, or server can get a **new IP at any time** — and the user shouldn't have
to do anything:
- **Sleep / wake** — the lease is renewed, often with a different address.
- **Roaming** — Wi-Fi ↔ cellular hotspot ↔ Ethernet, or moving between Wi-Fi networks.
- **Outage / disaster recovery** — the network drops and comes back on a different uplink or
  a re-issued address.

The mesh **underlay** addresses peers by `ip:port`, so when an IP changes the old address
goes dead. Two things must happen automatically: the node must **publish its new address**,
and every other node must **learn it**.

### The model
**The daemon (`meshd`) is the single authority.** It detects the change, refreshes what it
advertises for each mesh, and the change propagates — signed — to every node in every mesh,
which each update their stored address for that node. The GUI only visualizes this.

### How a change is detected
1. **Local trigger — network-change watcher** (`spawn_netchange_watcher`, `NETCHANGE_TICK_SECS`):
   polls the host's **default gateway**; a change means the network moved. On a change it:
   - **cleans a stale exit `/32` pin** (pinned via the *old* gateway it would blackhole the
     exit's IP → `connect()` fails with `EADDRNOTAVAIL`), or **re-pins it via the new gateway**
     if a full tunnel is active, so the tunnel survives roaming;
   - **re-learns the local address** and writes it into each mesh's advertised endpoint.
2. **Remote/reflexive trigger** — a public peer that receives our frame reflects back the
   public `ip:port` it observed (P-D3); we adopt it. This catches NAT-mapping changes the local
   gateway poll can't see.

### How the new address reaches everyone
The node's reachability is a **signed `EndpointRecord`** (`network, member, endpoints, seq,
at_ms, sig`). When the address changes, the node publishes a record with a **higher `seq`**;
**newest `seq` wins** at every reader. It travels by three paths that converge:
- **Endpoint gossip** — the advertised endpoint is gossiped to peers every 20 s.
- **DHT rendezvous** (`MESHD_DHT`) — the node **republishes** its record keyed by its public
  key; any peer that lost it **looks it up by pubkey** and re-seeds the address. This closes the
  case where *both* ends moved with no overlapping live window.
- **Data-plane roaming-learn** — the instant a moved peer sends us a frame, we learn its new
  source `ip:port` from the packet and reply there. No control round-trip needed.

Each receiving node verifies the signature (the address can't be spoofed), checks `seq`, and
updates its `links`/`EndpointBook` entry for that member. Connectivity self-heals within a tick.

### What does *not* change
- The **overlay** (member IDs, `100.80.x.y`) is stable, so apps/SSH sessions over the mesh are
  unaffected by an underlay IP change once the path re-converges.
- The data-plane UDP socket is bound to the wildcard, so it keeps receiving across the change —
  only routes and the *advertised* address are refreshed.

### Limitation (tracked)
Reaching a peer still needs a working underlay path to its `ip:port`. On an **IPv6-only /
NAT64** network reaching an **IPv4-literal** endpoint can fail; the fix is the dual-stack
underlay in `docs/IPV6_PLAN.md`. Stale-route blackholes from a network change are handled by the
watcher above (`docs/ERRORS.md` has the incident).

---

## 한국어

### 문제
노트북·데스크탑·서버는 **언제든 IP가 바뀔 수 있고**, 사용자가 손댈 필요가 없어야 합니다:
- **절전/복귀(sleep/wake)** — 임대(lease)가 갱신되며 주소가 달라지곤 함.
- **이동(roaming)** — Wi-Fi ↔ 셀룰러 핫스팟 ↔ 이더넷, 또는 Wi-Fi 망 간 이동.
- **장애/천재지변 복구** — 네트워크가 끊겼다 다른 회선/재발급 주소로 복귀.

메쉬 **언더레이**는 피어를 `ip:port`로 가리키므로, IP가 바뀌면 옛 주소는 죽습니다. 자동으로
두 가지가 일어나야 합니다 — 노드가 **새 주소를 알리고**, 다른 모든 노드가 **그걸 학습**해야 함.

### 모델
**데몬(`meshd`)이 단일 권위 주체입니다.** 데몬이 변경을 감지하고, 각 메쉬에 대해 자신이 광고하는
주소를 갱신하면, 그 변경이 **서명된 형태로** 각 메쉬의 모든 노드에 전파되어 각 노드가 해당 노드의
주소 기록을 갱신합니다. GUI는 이를 시각화만 합니다.

### 변경 감지 방법
1. **로컬 트리거 — 네트워크 변경 워처**(`spawn_netchange_watcher`, `NETCHANGE_TICK_SECS`):
   호스트의 **기본 게이트웨이**를 폴링하며, 바뀌면 네트워크가 이동한 것입니다. 변경 시:
   - **stale된 exit `/32` 핀을 정리**(옛 게이트웨이로 박힌 핀은 exit IP를 블랙홀시켜
     `connect()`가 `EADDRNOTAVAIL`로 실패) 하거나, 풀터널이 켜져 있으면 **새 게이트웨이로 재핀**해
     이동 중에도 터널이 살아있게 함;
   - **로컬 주소를 재학습**해 각 메쉬의 광고 엔드포인트에 기록.
2. **원격/반사 트리거** — 우리 프레임을 받은 공용 피어가 관측한 공인 `ip:port`를 되반사(P-D3)하면
   그걸 채택. 로컬 게이트웨이 폴링으로는 못 보는 NAT 매핑 변화를 잡습니다.

### 새 주소가 모두에게 도달하는 방법
노드의 도달성은 **서명된 `EndpointRecord`**(`network, member, endpoints, seq, at_ms, sig`)입니다.
주소가 바뀌면 노드는 **더 높은 `seq`**로 레코드를 발행하고, 모든 수신자에서 **최신 `seq`가 승리**
합니다. 수렴하는 세 경로로 전파됩니다:
- **엔드포인트 가십** — 광고 엔드포인트를 20초마다 피어에게 전파.
- **DHT 랑데부**(`MESHD_DHT`) — 노드가 자기 pubkey를 키로 레코드를 **재발행**하고, 그걸 잃은 피어가
  **pubkey로 조회**해 주소를 다시 심음. *양쪽 다* 겹치는 접속창 없이 이동한 경우까지 해결.
- **데이터플레인 로밍 학습** — 이동한 피어가 프레임을 보내는 즉시, 패킷의 출발 `ip:port`로 새 주소를
  학습해 그쪽으로 응답. 별도 제어 왕복 불필요.

각 수신 노드는 서명을 검증(주소 위조 불가)하고 `seq`를 확인한 뒤, 해당 멤버의 `links`/`EndpointBook`
항목을 갱신합니다. 한 틱 안에 연결이 스스로 회복됩니다.

### 바뀌지 않는 것
- **오버레이**(멤버 id, `100.80.x.y`)는 고정이라, 경로가 재수렴하면 메쉬 위의 앱/SSH 세션은 언더레이
  IP 변경의 영향을 받지 않습니다.
- 데이터플레인 UDP 소켓은 와일드카드 바인드라 변경 중에도 계속 수신 — 라우트와 *광고* 주소만 갱신.

### 한계(추적 중)
피어에 닿으려면 그 `ip:port`로 가는 동작하는 언더레이 경로가 여전히 필요합니다. **IPv6-only / NAT64**
망에서 **IPv4 리터럴** 엔드포인트에 닿는 건 실패할 수 있고, 해결책은 `docs/IPV6_PLAN.md`의 듀얼스택
언더레이입니다. 네트워크 변경으로 인한 stale-라우트 블랙홀은 위 워처가 처리합니다(사건 기록은
`docs/ERRORS.md`).
