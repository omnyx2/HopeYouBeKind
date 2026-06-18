# Traffic monitor / 트래픽 모니터

> See how communication flows **to and from this computer** over the mesh. The daemon
> (`meshd`) does the counting; the GUI/CLI only visualize it (single source of truth).

---

## English

### Two scopes
- **This computer (User mode → Traffic tab):** all meshes on this machine, aggregated. Each
  row/flow is tagged with its mesh.
- **One mesh (Mesh mode → Traffic tab):** just the opened mesh.

Both use the same daemon request: `TrafficStats { mesh: Some(id) | None }` (`None` = whole
computer).

### Two views — A (summary) → "Detail ▸" → B (flows)
- **A — per-peer summary:** for each peer, **down (rx)** and **up (tx)** in bytes + packets,
  plus a live **throughput** (`/s`) computed from the delta between 3-second polls. Peers are
  sorted by top talkers; totals at the top.
- **B — recent packet flows** (press **Detail ▸**): the last ~200 overlay packets, newest
  first, each showing:
  - **direction** — `↑ out` (this computer sent it) / `↓ in` (received);
  - **requester** — the node that originated the packet (the `src` member);
  - **proto** — tcp / udp / icmp;
  - **src→dst:port** — overlay addresses are **resolved to member names** (e.g.
    `mac(100.80.1.2) → oracle(100.80.1.1)`); an internet address behind the exit stays a raw
    IP (e.g. `mac → 1.2.3.4`);
  - **bytes**, and a **via exit** marker when the packet was routed to the internet through
    the mesh exit (so on the exit node you can see *which member* requested an internet flow).

### How it works (data plane → IPC → UI)
- **Counting** lives in the data-plane loop (`crates/meshrun/src/lib.rs`): every overlay
  packet crossing the TUN is counted per peer (`PeerTraffic`) and its IPv4 5-tuple pushed
  into a capped ring (`FLOW_RING_CAP = 200`, `Traffic`). Shared with the supervisor as
  `SharedTraffic`.
- **Projection** (`crates/meshd/src/main.rs` `traffic_view`/`mesh_traffic`): builds a
  `TrafficView` for one mesh or all of them, resolving member names and overlay addresses
  (overlay = `prefix + member-id` last octet) to names.
- **IPC** (`crates/mesh/src/ipc.rs`): `Request::TrafficStats` → `Response::Traffic(TrafficView)`
  with `PeerTrafficView` rows and `FlowView` flows (`src_node`/`dst_node` carry the resolved
  names; `src_node` is the requester).
- **CLI:** `lattice traffic [mesh] [--detail]` — omit the mesh for the whole computer.

### Limitations
- Header-only: the 5-tuple + size are recorded, **not** packet payloads (no DPI).
- The flow ring is capped (~200 recent); older flows drop. Counters are cumulative since the
  data plane came up (a re-bringup resets them).
- Control frames (gossip/roster/revocation) are not counted as app flows; only overlay app
  packets that cross the TUN are.

---

## 한국어

### 두 범위
- **이 컴퓨터 (User 모드 → Traffic 탭):** 이 머신의 **모든 메쉬** 합산. 각 행/흐름에 메쉬명 태그.
- **단일 메쉬 (Mesh 모드 → Traffic 탭):** 연 메쉬만.

둘 다 같은 데몬 요청 `TrafficStats { mesh: Some(id) | None }`를 씁니다 (`None` = 컴퓨터 전체).

### 두 뷰 — A(요약) → "Detail ▸" → B(흐름)
- **A — 피어별 요약:** 피어마다 **다운(rx)**·**업(tx)** 바이트+패킷, 그리고 3초 폴링 차이로 계산한
  실시간 **처리량(`/s`)**. 많이 쓰는 피어 순 정렬, 상단에 합계.
- **B — 최근 패킷 흐름** (**Detail ▸** 누르기): 최근 ~200개 오버레이 패킷(최신순), 각 항목:
  - **방향** — `↑ out`(이 컴퓨터가 보냄) / `↓ in`(받음);
  - **요청자(requester)** — 그 패킷을 만든 노드(= `src` 멤버);
  - **proto** — tcp / udp / icmp;
  - **src→dst:port** — 오버레이 주소는 **멤버 이름으로 해석**(예: `mac(100.80.1.2) → oracle(100.80.1.1)`),
    exit 뒤 인터넷 주소는 raw IP 그대로(예: `mac → 1.2.3.4`);
  - **바이트**, 그리고 패킷이 메쉬 exit를 통해 인터넷으로 나갔으면 **via exit** 표시 (exit 노드에서
    *어떤 멤버*가 인터넷 요청을 했는지 보임).

### 동작 (데이터플레인 → IPC → UI)
- **계측**은 데이터플레인 루프(`crates/meshrun/src/lib.rs`): TUN을 건너는 오버레이 패킷마다 피어별
  카운트(`PeerTraffic`) + IPv4 5-튜플을 캡 링버퍼(`FLOW_RING_CAP = 200`, `Traffic`)에 기록.
  `SharedTraffic`로 공유.
- **투영**(`crates/meshd/src/main.rs` `traffic_view`/`mesh_traffic`): 한 메쉬 또는 전체에 대해
  `TrafficView` 생성, 멤버 이름 + 오버레이 주소(오버레이 = `prefix + 멤버id` 마지막 옥텟)를 이름으로 해석.
- **IPC**(`crates/mesh/src/ipc.rs`): `Request::TrafficStats` → `Response::Traffic(TrafficView)`,
  `PeerTrafficView` 행 + `FlowView` 흐름(`src_node`/`dst_node`가 해석된 이름, `src_node`가 요청자).
- **CLI:** `lattice traffic [mesh] [--detail]` — 메쉬 생략 시 컴퓨터 전체.

### 한계
- 헤더만: 5-튜플 + 크기만 기록, **페이로드는 안 봄**(DPI 아님).
- 흐름 링은 캡(~200개), 오래된 건 드롭. 카운터는 데이터플레인 기동 후 누적(재기동 시 리셋).
- 제어 프레임(가십/로스터/취소)은 앱 흐름으로 안 셈 — TUN을 건너는 오버레이 앱 패킷만.
