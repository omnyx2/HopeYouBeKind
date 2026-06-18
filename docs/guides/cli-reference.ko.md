# Lattice CLI 운영자 레퍼런스

*(English: [cli-reference.en.md](cli-reference.en.md))*

운영자가 명령줄만으로 Lattice를 실행·관리하는 데 필요한 전부 — **GUI 없이, LLM 도움 없이.**
초보용 [시작하기](getting-started.ko.md)·[쿡북](cookbook.ko.md)과 짝을 이룹니다. 두 요소:

- **`meshd`** — 머신당 데몬(컨트롤 플레인 + 데이터 플레인). 머신당 하나.
- **`lattice`** — `meshd` 소켓을 감싼 의존성 없는 Python CLI(`scripts/lattice`). **같은 머신**에서만.

---

## 0. 복붙 치트시트 (TL;DR)

머신 2대: 공인 IP를 가진 **서버**(시드/출구)와 **클라이언트**(NAT 뒤 노트북). `<공인IP>`를
서버의 공인 IP로 바꾸세요. 각 줄 설명은 1~7장에 있고, 이건 그냥 통째로 복붙하면 됩니다.

**① 서버 — 한 번 빌드, 실행, 메쉬 생성** *(먼저 클라우드 방화벽에서 UDP 41000 + 41001 개방)*

```sh
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd
sudo ln -sf "$PWD/scripts/lattice" /usr/local/bin/lattice

sudo DATA_PLANE=1 MESHD_BIND_PORT=41000 MESHD_DHT_PORT=41001 \
  MESHD_ADVERTISE=<공인IP>:41000 \
  ./target/release/meshd /tmp/meshd.sock &
export LATTICE_SOCK=/tmp/meshd.sock

lattice new corp --me seed          # 당신이 멤버 #1
```

**② 클라이언트 — 한 번 빌드, 실행, 가입** *(초대는 아래 3단계로)*

```sh
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd
sudo ln -sf "$PWD/scripts/lattice" /usr/local/bin/lattice

sudo DATA_PLANE=1 MESHD_DHT_BOOTSTRAP=<공인IP>:41001 \
  ./target/release/meshd &

lattice id                          # 1) 신원 코드 출력 — 그 한 줄을 서버에 전달
#    서버 관리자 실행:  lattice invite corp laptop <그-신원코드>   -> 초대 코드 출력
lattice join <초대코드>             # 2) 초대 코드를 여기 붙여넣기
lattice info corp                   # 3) 모두 'live'로 떠야 함
```

**③ 풀 VPN — 클라이언트의 모든 인터넷을 서버로**

```sh
lattice exit corp seed              # 서버를 출구로 지정
lattice vpn corp                    # 모든 트래픽을 그쪽으로
curl -s https://ifconfig.co         # 서버의 공인 IP가 나와야 함
lattice off                         # 직접 인터넷으로 복귀
```

---

## 1. 빌드 & 설치

```sh
# 레포 루트에서 — 데몬 빌드(release)
cargo build --release -p lattice-meshd
# 바이너리: target/release/meshd

# CLI를 PATH에 등록(/usr/local/bin 심볼릭 링크; 복사는 --copy)
sudo ./scripts/lattice install
lattice --help            # 내장 도움말; 명령별 `lattice <명령> --help`
```

요건: 빌드는 Rust(stable), CLI는 Python 3, 데이터 플레인 실행은 root/관리자(TUN 장치 생성).
CLI 자체는 Python 3 외 의존성 없음.

---

## 2. 데몬 실행

`meshd`는 로컬 소켓에서 대기하고, 데이터 플레인이 켜지면 **메쉬마다** TUN 1개 + UDP 소켓 1개를
만듭니다. TUN 때문에 **root**(Linux/macOS) 또는 **elevated**(Windows)로 실행해야 합니다.

**쉬운 방법 (헤드리스 서버)** — CLI가 데몬을 대신 관리하니, 환경변수나 sudo 줄을 손으로 쓸
필요가 없습니다:

```sh
sudo lattice up                 # meshd를 백그라운드로 기동(데이터 플레인 ON)
lattice status                  # 데몬 건강 + 메쉬 / 출구 / 트래픽 (--watch N 으로 실시간)
lattice logs -f                 # 데몬 로그 팔로우
lattice down                    # 깨끗이 종료(sudo 불필요 — IPC 소켓 경유)
# 공개 주소 고정(출구/시드 노드) + 부팅 자동시작:
sudo lattice install-service --advertise <공개IP>:41000
```

`lattice up`은 `meshd` 바이너리를 자동 탐지(레포 빌드 디렉토리, 설치된 앱, 또는
`$LATTICE_MESHD`)하고, TUN을 위해 `sudo`로 재실행한 뒤, 소켓이 응답할 때까지 기다립니다.
플래그: `--advertise IP:PORT`, `--state-dir DIR`, `--dht-port N`, `--dht-bootstrap IP:PORT`,
`--bind-port N`, `--no-dht`, `--foreground`, `--log FILE`.

**수동 방법** (동일, 참고용):

```sh
# Linux / macOS — 데이터 플레인 ON, 포그라운드(Ctrl-C로 종료)
sudo DATA_PLANE=1 ./target/release/meshd
# 소켓: /tmp/lattice-meshd.sock   (첫 인자로 경로를 넘기면 변경)
```

컨트롤 플레인만(TUN·root 없이, 상태 확인/스크립팅용): `DATA_PLANE`을 빼세요. 메쉬 생성/가입은
되지만 데이터 플레인 데몬이 뜨기 전엔 트래픽이 흐르지 않습니다.

### 환경 변수 (권위 있는 목록)

| 변수 | 기본값 | 용도 |
|---|---|---|
| `DATA_PLANE=1` | off | 메쉬별 TUN+UDP 데이터 플레인 기동(root/관리자 필요). 없으면 컨트롤 플레인만. |
| `MESHD_DHT=0` | **on**(데이터 플레인 시) | DHT 랑데부(이동한 피어 재발견) **opt-out**. 기본 켜짐, `=0`으로 끔. |
| `MESHD_DHT_PORT` | `42900` | DHT 오버레이 UDP 포트. DHT 피어/시드로 쓰려면 **방화벽 개방 필수**. |
| `MESHD_DHT_BOOTSTRAP` | — | DHT 시드 노드 `ip:port,…`(공개 노드의 DHT 포트). 클라이언트가 시드를 가리킴. |
| `MESHD_BIND_PORT` | `42000 + mesh_id` | 메쉬 데이터 플레인 UDP 포트 고정. 단일 개방 포트 호스트(클라우드 방화벽)용. |
| `MESHD_ADVERTISE` | 자동(reflexive) | 이 노드의 공개 도달 가능 `ip:port` 데이터 플레인 엔드포인트 고정. **공개 시드/출구 노드**에 설정; NAT 뒤 클라이언트는 자동 학습. |
| `MESHD_STATE_DIR` | `$HOME/.lattice/meshd` | 메쉬 영속 위치(0700 디렉토리, 0600 JSON). |
| `MESHD_NO_PERSIST=1` | off | 디스크 영속 비활성(RAM 전용; 재시작 시 메쉬 소멸). |
| `MESHD_NO_SELF_DESTRUCT=1` | off | 생존성 자폭 워치독(P-C4) 비활성. |
| `MESHD_IMPORT` | `<tmp>/lattice-mesh-backup.json` | 시작 시 한 번 읽는 업데이트 이관 백업 경로. |
| `LATTICE_SOCK` | `/tmp/lattice-meshd.sock` | (CLI) 어느 데몬 소켓에 말할지. 또는 `lattice --sock <경로>`. |

### 포트 & 소켓

- **IPC**: 유닉스 소켓 `/tmp/lattice-meshd.sock`(Linux/macOS) 또는 네임드 파이프
  `\\.\pipe\lattice-meshd`(Windows). 유닉스 경로는 `meshd`의 첫 인자로 변경.
- **메쉬 데이터 플레인**: UDP `MESHD_BIND_PORT`(또는 `42000+mesh_id`).
- **DHT 랑데부**: UDP `MESHD_DHT_PORT`(기본 `42900`).

> **방화벽/클라우드 호스트:** 메쉬 포트 **와** DHT 포트(UDP)를 클라우드 보안 목록과 호스트
> 방화벽 양쪽에서 여세요. DHT 기본 `42900`은 개방 범위 밖인 경우가 많으니 — 열어둔 포트로
> `MESHD_DHT_PORT`를 고정하세요.

---

## 3. `lattice` 명령 레퍼런스

`lattice [--sock 경로] <명령> [인자]`. 메쉬/멤버 인자는 **id 또는 이름** 모두 가능.

| 명령 | 동작 |
|---|---|
| `ls` | 이 머신의 메쉬 목록. |
| `info <mesh>` | 한 메쉬: 멤버·생존성·엔드포인트·출구·건강. |
| `new <name> [--me 이름] [--max N] [--cipher C] [--ephemeral] [--master-gated]` | 메쉬 생성(당신이 멤버 #1). |
| `id` | 신원 코드 발급(메쉬 호스트에게 줘서 초대받기). |
| `invite <mesh> <name> <id_code> [--algo A]` | (호스트) 가입자 신원 코드로 초대 발급. |
| `join <invite_code> [--algo A]` | 초대 코드로 메쉬 가입. |
| `exit <mesh> <member>` | 인터넷 출구가 될 멤버 선택. |
| `vpn <mesh>` | **모든** 인터넷 트래픽을 그 메쉬 출구로(풀 터널). |
| `off` | 풀 터널 중지; 직접 인터넷으로 복귀. |
| `recipher <mesh> [--cipher C]` | 메쉬 키 교체(오프라인 멤버 축출). |
| `attack <mesh>` | 공격 경보(원-비토, fail-deadly 자폭). |
| `allclear <mesh>` | (생성자) 공격 경보 취소. |
| `rm <mesh>` | 이 머신에서 메쉬 삭제. |
| `ciphers` / `algos` | 데이터 플레인 암호 / 초대-랩 알고리즘 목록. |
| `policy` | 현재 라우팅 정책. |
| `backup [경로]` | 메쉬 스냅샷 파일(업데이트 이관). |
| `flows <mesh> [--block CIDR\|--exit CIDR\|--reset]` | SDN 플로우 테이블(라우팅 규칙) 조회/편집 — 전 멤버에게 gossip 전파. |
| `raw '<json>'` | 원시 IPC 요청(탈출구). |
| **— 서버 / 데몬 —** | |
| `up [meshd 플래그]` | meshd를 백그라운드로 기동(헤드리스; TUN 위해 자동 sudo). |
| `down` | 소켓 경유로 데몬 깨끗이 종료(sudo 불필요). |
| `restart [meshd 플래그]` | `down` 후 `up`. |
| `status [--watch N]` | 데몬 건강 + 메쉬 / 출구 / 트래픽, 선택적 실시간. |
| `logs [-f] [-n N]` | 데몬 로그 조회/팔로우. |
| `serve-exit <mesh> [--advertise IP:PORT]` | 이 노드를 메쉬의 인터넷 출구로 지정. |
| `install-service [meshd 플래그]` | systemd 유닛 설치+활성화(Linux; 부팅 자동시작). |
| `uninstall-service` | systemd 유닛 제거(Linux). |
| `install [--prefix DIR] [--copy]` | `lattice`를 PATH에 등록. |

---

## 4. 초대 → 가입 흐름 (3단계, 머신 2대)

멤버십은 admin-free: `--master-gated`가 아니면 **누구나** 초대 가능.

```sh
# 가입자(머신 B): 신원 코드 발급, 한 줄을 호스트에게 전달
lattice id
#  eyJtZW1iZXJfcHVia2V5...    <- 한 줄

# 호스트(머신 A): 그 코드로 초대 발급, 한 줄을 되돌려줌
lattice invite home bob eyJtZW1iZXJfcHVia2V5...
#  eyJzYWx0Ijog...           <- 한 줄

# 가입자(머신 B): 가입
lattice join eyJzYWx0Ijog...
lattice info home            # 두 멤버 모두 'live'여야 함
```

신원 코드는 만료됩니다(~10분, P-C6). 비밀성을 위해 호스트가 `invite`에 `--algo`를 줄 수 있고,
가입자는 `join`에 같은 `--algo`를 써야 합니다(out-of-band로 전달).

**헤드리스 단축** — `invite`/`join`에 `-`를 주면 코드를 **stdin**에서 읽으므로, SSH 가능한
머신 사이에서 교환 전체를 파이프로 연결할 수 있습니다:

```sh
# 호스트가 가입자의 신원 코드를 SSH로 받아 한 줄로 초대 발급
ssh joiner lattice id | lattice invite home bob -
# ...출력된 초대 코드를 다시 가입자에게 전달(또는 반대로 파이프)
```

---

## 5. 다중 노드 메쉬 배포 (공개 시드 1 + NAT 클라이언트들)

검증된 토폴로지: 항상 켜진 **공개 노드**(공인 IP 클라우드 VM)가 데이터 플레인 출구/릴레이
**겸** DHT 부트스트랩 시드 역할을 하고, 나머지 노드는 NAT 뒤에서 자동으로 피어를 찾습니다
(가십 + reflexive STUN + DHT 랑데부).

### 5a. 공개 시드/출구 노드 (systemd)

UDP **41000**(메쉬)과 **41001**(DHT)을 클라우드 보안 목록 **과** 호스트 방화벽에서 여세요.
그러면 **명령 하나**로 부팅 서비스를 설치+활성화합니다:

```sh
sudo lattice install-service --advertise <공인IP>:41000 --dht-port 41001
lattice status                                  # active + 도달 가능
sudo lattice serve-exit corp                    # 이 노드를 메쉬 출구로
```

`/etc/systemd/system/lattice-meshd.service`를 작성하고 `daemon-reload` + `enable --now`
까지 합니다. 관리: `lattice status` / `lattice logs -f` / `journalctl -u lattice-meshd -f`,
제거: `sudo lattice uninstall-service`.

<details><summary>동일한 수작업 유닛 (참고용)</summary>

```ini
# /etc/systemd/system/meshd-node.service
[Unit]
Description=Lattice meshd (public exit/relay + DHT seed)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=DATA_PLANE=1
Environment=MESHD_BIND_PORT=41000
Environment=MESHD_DHT_PORT=41001
Environment=MESHD_ADVERTISE=<공인IP>:41000
ExecStart=/home/ubuntu/myVpn/target/release/meshd /tmp/meshd.sock
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now meshd-node.service
sudo systemctl status meshd-node.service        # active (running) 확인
LATTICE_SOCK=/tmp/meshd.sock lattice ls         # 여기에 말 걸기
```

</details>

시드에서 메쉬를 만들고 멤버 #1이 됩니다:

```sh
export LATTICE_SOCK=/tmp/meshd.sock
lattice new corp --me seed
```

> **주의(직접 겪은 함정):** 위 systemd 유닛은 **영속 .service 파일**입니다 — `systemd-run`
> 트랜지언트 유닛으로 띄우면 `stop` 시 유닛이 사라져 `systemctl start`로 못 살립니다.
> 또 영속 상태는 **실행 사용자의** `$HOME`에 저장됩니다(root면 `/root/.lattice`).

### 5b. 클라이언트 노드 (NAT 뒤)

```sh
sudo lattice up --dht-bootstrap <공인IP>:41001
# (수동 등가: sudo DATA_PLANE=1 MESHD_DHT_BOOTSTRAP=<공인IP>:41001 ./target/release/meshd)
```

그다음 [초대/가입 흐름](#4-초대--가입-흐름-3단계-머신-2대): 클라이언트 `lattice id` →
시드 `lattice invite corp <이름> <id>` → 클라이언트 `lattice join <초대>`.

초대자 주소만 받은 클라이언트도 DHT 시드를 통해 나머지 피어를 재발견합니다 —
`lattice info corp`에 모든 멤버가 `live`로 뜹니다. 풀 터널 켜기:

```sh
# 클라이언트에서: 모든 인터넷 트래픽을 공개 시드로 내보냄
lattice exit corp seed
lattice vpn corp
curl -s https://ifconfig.co        # 시드의 공인 IP가 나와야 함
lattice off                        # 직접 인터넷으로 복귀
```

---

## 6. OS별 참고

| OS | TUN | 권한 | IPC | CLI |
|---|---|---|---|---|
| Linux | `/dev/net/tun` | `sudo` | 유닉스 소켓 | `lattice` 직접 |
| macOS | `utun` | `sudo` | 유닉스 소켓 | `lattice` 직접 |
| Windows | Wintun(`meshd.exe`에 내장) | **elevated** 프로세스 | 네임드 파이프 `\\.\pipe\lattice-meshd` | 아래 참고 |

**Windows:** `meshd.exe`를 **elevated**로 실행(데이터 플레인 Wintun에 관리자 필요).
SSH 헤드리스에선 `/ru SYSTEM /rl highest`로 만든 스케줄 작업을 PowerShell
`Start-ScheduledTask`로 띄우면 UAC 프롬프트 없이 elevated로 실행됩니다. Python `lattice`
CLI는 유닉스 소켓을 써서 **Windows 데몬을 직접 제어하지 못합니다** — `NewIdentity`/`JoinMesh`는
데스크톱 GUI나 네임드 파이프 IPC 클라이언트로 발행하세요. DHT/메쉬 포트는 Windows 방화벽에서도
허용해야 합니다.

---

## 7. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `meshd not running (… )` | 데몬 미실행 또는 `LATTICE_SOCK` 잘못됨. `meshd` 실행, 소켓 경로 확인. |
| `info`에 멤버 `unknown` / 엔드포인트 `—` | 피어 아직 도달 불가. 양쪽 데이터 플레인 포트 개방 확인; DHT/가십 ~30초 내 수렴. |
| 멤버가 `unknown`에서 안 풀리고 **공개 노드**가 연결 안 됨 (특히 GUI로 만든 메쉬) | NAT 뒤 노드는 `meshd`를 `MESHD_DHT_BOOTSTRAP=<공인IP>:41001`로 띄우지 않으면 공개 피어를 자동으로 못 찾습니다. **GUI는 그 설정 없이 `meshd`를 띄우므로** 한 번 직접 지정: **Peers 탭 → `unknown` 멤버 → "set address" → `<공인IP>:41000`** (또는 Overview "Peer address" 카드). CLI 등가: `lattice raw '{"SetPeer":{"mesh":N,"member":M,"endpoint":"<공인IP>:41000"}}'`. 패킷 한 번 가면 reflexion + 가십이 이어받아 전원 수렴. **`MESHD_DHT_BOOTSTRAP`으로 띄운 CLI 클라이언트**는 이 단계가 불필요. |
| GUI/`info`에 **data plane DOWN** | 메쉬 UDP 포트를 다른 프로세스(낡은/두 번째 `meshd`)가 점유. `meshd`가 몇 초간 bind 재시도; 낡은 데몬 종료하면 복구(단일-인스턴스 가드가 새 데몬이 살아있는 걸 빼앗지 않게 함). |
| `cannot create pipe … (os error 5)` (Windows) | 다른 `meshd`가 파이프 점유. 먼저 종료(또는 리부트 — Lattice는 자동 시작 안 함). |
| 두 노드가 인터넷 너머로 연결 안 됨 | 둘 다 NAT 뒤·공개 경로 없음 — 공개 시드 노드를 추가하고 `MESHD_DHT_BOOTSTRAP` + `exit`을 거기로. |
| 재시작 후 메쉬 사라짐 | `MESHD_NO_PERSIST` 설정됨, 또는 `MESHD_STATE_DIR` 다름(root vs 사용자 `$HOME`). 데몬은 **실행 사용자의** `$HOME/.lattice/meshd`에 영속. |

원시 탈출구로 무엇이든 점검:

```sh
lattice raw '"ListMeshes"'
lattice raw '{"MeshInfo":{"mesh":1}}'
```
