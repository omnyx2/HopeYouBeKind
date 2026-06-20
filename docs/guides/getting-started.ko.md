# Lattice로 첫 VPN 만들기 (초보자 가이드)

> English: [getting-started.en.md](getting-started.en.md)

Lattice는 **서버 없는 메쉬 VPN**입니다. 몇 대의 컴퓨터에 설치하면 중앙 서버나
계정 없이 하나의 사설 암호화 네트워크로 묶입니다. 이 가이드는 0에서 시작해서
**"내 노트북의 모든 트래픽을 다른 나라에 있는 내 서버로 빼는 것"** 까지 데려갑니다.

`lattice` CLI(`scripts/lattice`)를 사용합니다. 로컬 소켓으로 `meshd` 데몬과
통신하므로 JSON을 직접 쓸 일이 없습니다.

---

## 0. 30초 개념 정리

- **메쉬(Mesh)** — 하나의 사설 네트워크. 한 컴퓨터가 동시에 여러 메쉬에 속할 수 있음.
- **멤버(Member)** — 메쉬 안의 컴퓨터 한 대. 오버레이 IP
  `100.80.<메쉬>.<멤버>`(예: `100.80.1.1`)를 받고 서로 직접 통신함.
- **생성자(Creator)** — `lattice new`를 실행한 사람. 메쉬의 마스터 키를 갖고
  초대할 수 있음. 관리 서버는 전혀 필요 없음.
- **출구(Exit)** — 다른 멤버들이 인터넷을 빌려 쓸 수 있는 멤버. 이게 "VPN" 부분.
  선택 사항.

---

## 1. 데몬 실행

`meshd`는 root 권한(TUN 네트워크 인터페이스 생성)과 `DATA_PLANE=1` 환경변수
(실제 패킷 전달)가 필요합니다.

```sh
# 저장소 루트에서 — 한 번만 빌드
RUSTUP_TOOLCHAIN=stable cargo build -p lattice-meshd

# 실행 (root, 데이터 플레인 ON). 이 터미널은 계속 켜두세요.
sudo DATA_PLANE=1 ./target/debug/meshd /tmp/lattice-meshd.sock
```

**공개 서버**(출구 노드)라면 주소도 광고해서 남들이 찾을 수 있게 합니다:

```sh
sudo DATA_PLANE=1 MESHD_BIND_PORT=41000 MESHD_ADVERTISE=<공인IP>:41000 \
     ./target/release/meshd /tmp/meshd.sock
```

CLI를 `PATH`에 걸어두면 편합니다:

```sh
sudo ln -sf "$PWD/scripts/lattice" /usr/local/bin/lattice
lattice ls          # "no meshes yet"가 떠야 정상
```

---

## 2. 메쉬 만들기 (A 컴퓨터)

```sh
lattice new home --me alice
# created mesh #1 'home' — you are 'alice'.
```

이제 `alice`는 멤버 `#1`, 오버레이 IP `100.80.1.1`입니다.

---

## 3. 두 번째 컴퓨터 초대 (B 컴퓨터)

멤버십은 초대 기반이고, 두 컴퓨터 사이에 **복사-붙여넣기 2번**이면 됩니다
(아무 메신저로 보내도 안전합니다):

**B 컴퓨터** — 신원 코드 발급:

```sh
lattice id
# eyJtZW1iZXJfcHVia2V5X2hleCI6IC4uLg...      <- 이 한 줄을 복사
```

**A 컴퓨터** — 그 코드를 "bob"용 초대장으로 변환:

```sh
lattice invite home bob eyJtZW1iZXJfcHVia2V5X2hleCI6IC4uLg...
# eyJzYWx0IjogWzk2LC4uLg...                   <- 이 한 줄을 다시 복사
```

**B 컴퓨터** — 초대장으로 가입:

```sh
lattice join eyJzYWx0IjogWzk2LC4uLg...
# joined mesh #1. `lattice info 1` to see peers.
```

끝입니다. 양쪽에서 확인:

```sh
lattice info home
#   members:
#     #1   alice   live   ...
#     #2   bob     live   ...
```

이제 B에서 A의 오버레이 IP로 바로 접속할 수 있습니다 — 예: `ssh alice@100.80.1.1`,
파일 복사, 뭐든 가능. 트래픽은 암호화되고 P2P로 흐릅니다.

> 신원 코드는 **약 10분 후 만료**됩니다 — 초대 직전에 발급하세요.

---

## 4. 완전한 VPN으로 만들기 (모든 트래픽을 출구로)

A 컴퓨터가 일본에 있는 서버이고, 당신(B 노트북)의 모든 트래픽을 일본에서
나가는 것처럼 만들고 싶다고 합시다.

```sh
# B 컴퓨터: alice(멤버 #1)를 출구로 지정한 뒤, 전부 그쪽으로 라우팅
lattice exit home alice
lattice vpn home
# full tunnel ON — all internet traffic now exits via mesh 1.
```

공인 IP가 바뀌었는지 확인:

```sh
curl https://1.1.1.1/cdn-cgi/trace | grep -E 'ip=|loc='
# ip=<A 컴퓨터의 공인 IP>   loc=JP
```

DNS와 라우팅은 자동으로 처리됩니다. 평소 인터넷으로 되돌리려면:

```sh
lattice off
# full tunnel OFF — back to direct internet.
```

터널 중 출구가 죽으면 **킬스위치**가 자동으로 직접 인터넷으로 되돌려서
인터넷이 먹통되는 일이 없습니다.

---

## 5. 자주 쓰는 명령

```sh
lattice ls                 # 이 컴퓨터의 모든 메쉬
lattice info <메쉬>        # 멤버, 누가 살아있는지, 출구, 암호
lattice exit <메쉬> <누구> # 인터넷 출구 선택
lattice vpn <메쉬>         # 풀터널 ON
lattice off                # 풀터널 OFF
lattice rm <메쉬>          # 이 컴퓨터에서 메쉬 떠나기/삭제
lattice raw '<json>'       # 비상 탈출구: 원시 요청 전송
```

`<메쉬>`와 `<누구>`는 **이름 또는 번호** 모두 됩니다 (`home` 또는 `1`, `alice` 또는 `1`).

---

## 다음으로

- **기능 쿡북** (사설 LAN, 휘발성 메쉬, 키 교체, 공격 대응, 암호 선택 등):
  [cookbook.ko.md](cookbook.ko.md)
- 프로토콜 내부: [`../MESH_V2.md`](../MESH_V2.md),
  [`../PROTOCOL_DESIGN.md`](../PROTOCOL_DESIGN.md)
- 디스커버리 / NAT 통과: [`../DISCOVERY.md`](../DISCOVERY.md)

## 문제 해결

| 증상 | 해결 |
|---|---|
| `meshd not reachable` | 데몬이 안 켜졌거나 소켓 경로가 틀림. `meshd` 실행, 또는 `--sock <경로>` 지정. |
| `join`이 `already in mesh` | 이 컴퓨터가 이미 그 메쉬의 멤버임. |
| `invite`가 신원이 너무 오래됐다고 함 | 코드 만료(~10분). `lattice id` 다시 실행 후 재시도. |
| 풀터널인데 인터넷이 안 됨 | 구버전 빌드일 가능성 — DNS/라우트 처리는 이후 릴리스에서 수정됨. 최신 `meshd`로 업데이트(재빌드 또는 최신 릴리스 설치). |
| 피어가 계속 `idle`, `live`가 안 됨 | 서로의 UDP 포트에 못 닿는 상태. 공개 출구는 `MESHD_ADVERTISE` 설정, 방화벽 확인. |
