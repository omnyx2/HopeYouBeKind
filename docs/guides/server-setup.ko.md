# 서버 설치 — Lattice 노드를 헤드리스로 운영

**항상 켜진 서버**(클라우드 VM, 집 서버, 라즈베리파이)에 **GUI 없이** 노드를 올리는
실전 빠른 시작 — 전부 터미널로 합니다. 서버는 보통 다른(NAT 뒤) 노드들이 찾아 들어오고
트래픽을 내보내는 **공개 출구 / DHT 시드** 역할을 합니다.

전체 명령/환경변수 레퍼런스는 [CLI 운영자 레퍼런스](cli-reference.ko.md)를 보세요.
이 문서는 "일단 돌게 만들기" 경로입니다.

---

## 0. TL;DR (명령 4줄로 서버 띄우기)

```sh
# 1. 데몬 빌드
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd

# 2. CLI를 PATH에 등록
sudo ./scripts/lattice install

# 3. 부팅 서비스로 시작(공개 출구/시드: 공인 IP 고정 + 포트 개방)
sudo lattice install-service --advertise <공인IP>:41000 --bind-port 41000 --dht-port 41001

# 4. 확인
lattice status
```

이걸로 부팅에도 살아남는 데몬이 돕니다. 이제 메쉬를 만들거나 가입하세요(§3).

> **서버에 Rust가 없다?** [Releases](https://github.com/omnyx2/HopeYouBeKind/releases)에서
> OS/arch에 맞는 **standalone `meshd`**(예: `meshd-Linux-X64`, `meshd-Linux-ARM64`)를
> 받아 `chmod +x` 후 CLI가 가리키게 하세요: `export LATTICE_MESHD=/경로/meshd`.
> 2~4단계는 동일합니다.

---

## 1. 사전 준비

- `install-service`는 **Linux(systemd)**. macOS는 `lattice up`으로 동작(GUI 서비스 없음).
- **Root** — 데몬이 TUN 장치를 만들고 라우트를 바꿉니다. CLI가 자동으로 `sudo`를 씁니다.
- **UDP 포트 개방** — 클라우드 보안 목록 **과** 호스트 방화벽 **양쪽**:
  - **41000** — 메쉬 데이터 플레인(`--bind-port`).
  - **41001** — DHT 랑데부(`--dht-port`), 이 노드가 디스커버리 시드가 되려면.
  - DHT 기본값은 `42900`이니 — 실제로 열어둔 포트로 고정하세요.
- 서버에서 빌드하려면 Rust(`rustup`, stable) 필요 — 또는 위의 prebuilt 바이너리 사용.

```sh
# Oracle Cloud / Ubuntu 예시 — 호스트 방화벽 개방(클라우드 보안 목록은 별도)
sudo ufw allow 41000/udp && sudo ufw allow 41001/udp
```

---

## 2. 데몬 실행

### 부팅 서비스로 (권장)

```sh
sudo lattice install-service --advertise <공인IP>:41000 --bind-port 41000 --dht-port 41001
```

`/etc/systemd/system/lattice-meshd.service`를 작성하고 `daemon-reload` + `enable --now`
까지 합니다. 이제 매 부팅마다 시작되고 죽으면 재시작됩니다.

| 관리 | 명령 |
|---|---|
| 한눈에 건강 | `lattice status`  (`--watch 2`로 실시간) |
| 로그 팔로우 | `lattice logs -f`  ·  `journalctl -u lattice-meshd -f` |
| 재시작 | `sudo lattice restart`  ·  `sudo systemctl restart lattice-meshd` |
| 중지 | `sudo systemctl stop lattice-meshd` |
| 서비스 제거 | `sudo lattice uninstall-service` |

> `lattice down`은 소켓 경유로 데몬을 깨끗이 끕니다(sudo 불필요). 단 서비스의 `Restart`
> 정책상 자동으로 다시 안 살아날 수 있으니 — 다시 띄울 땐 `systemctl restart` /
> `sudo lattice restart`를 쓰세요.

### 서비스 없이 (포그라운드 / 임시)

```sh
sudo lattice up --advertise <공인IP>:41000 --bind-port 41000 --dht-port 41001
#   --foreground 면 이 터미널에 띄움(Ctrl-C로 종료); 아니면 백그라운드.
lattice status
sudo lattice down        # 종료
```

`lattice up`은 `meshd` 바이너리를 자동 탐지(레포 빌드 디렉토리, 설치된 앱, 또는
`$LATTICE_MESHD`)하고, TUN 위해 `sudo`로 올린 뒤, 소켓이 응답할 때까지 기다립니다.

---

## 3. 메쉬 생성 또는 가입

### 이 서버가 메쉬를 만든다 (첫 노드)

```sh
lattice new corp --me seed         # 당신이 멤버 #1 "seed"
lattice serve-exit corp            # 이 서버를 메쉬의 인터넷 출구로
```

### 이 서버가 기존 메쉬에 가입한다

초대 흐름은 한 줄짜리 코드 2개입니다. 헤드리스에선 **SSH로 파이프**됩니다:

```sh
# 양쪽에 SSH 가능한 머신에서: 서버의 신원 코드를 받아 초대 발급
ssh server lattice id | lattice invite corp seed -
#   -> 초대 코드 출력; 서버에 되돌려줌:
ssh server lattice join <초대코드>
```

또는 단계별 수동(한 줄 코드를 터미널 사이로 복사):
`server: lattice id` → `host: lattice invite corp seed <id>` → `server: lattice join <초대>`.

연결 확인:

```sh
lattice info corp        # 모든 멤버가 'live'여야 함
lattice doctor           # 건강 점검 + (문제 시) 권장 조치
```

---

## 4. 클라이언트 노드(NAT 뒤)가 이 시드로 부트스트랩

각 클라이언트에서 DHT를 이 서버의 공인 주소로 가리키면, 나머지 피어를 자동으로 찾습니다
(가십 + reflexive STUN + DHT 랑데부):

```sh
sudo lattice up --dht-bootstrap <공인IP>:41001
```

그다음 초대/가입 흐름(§3). 초대자 주소만 받은 클라이언트도 시드를 통해 나머지를 재발견합니다.

---

## 5. 일상 운영

```sh
lattice ls                       # 이 노드의 메쉬
lattice status --watch 2         # 실시간 대시보드 (SSH 창에 띄워두기 좋음)
lattice info corp                # 멤버·생존성·엔드포인트·출구
lattice doctor                   # idle/건강 문제 진단
lattice traffic --detail         # 피어별 바이트 + 최근 흐름(누가 누구와 통신했나)
lattice flows corp --block 1.1.1.1   # SDN 라우팅 규칙(전 멤버에게 gossip)
lattice exit corp seed           # 출구가 될 멤버 지정
lattice recipher corp            # 키 교체(오프라인 멤버 축출)
lattice expel corp <member>      # 멤버 제거(메쉬의 추방 정책에 따라)
```

상태는 **실행 사용자의** 홈에 영속됩니다 — root 서비스면 `/root/.lattice/meshd`
(0700 디렉토리, 0600 JSON). 재시작 시 다시 로드되므로 재부팅·네트워크 변경에도 노드가
유지됩니다. 네트워크 변경(새 IP, 로밍)은 자동으로 자가치유됩니다 —
[DYNAMIC_NETWORK](../DYNAMIC_NETWORK.md) 참고.

---

## 6. 서버 업데이트

```sh
cd HopeYouBeKind && git pull
cargo build --release -p lattice-meshd        # 또는 새 standalone 바이너리 교체
sudo systemctl restart lattice-meshd          # 새 바이너리 적용
lattice status                                # 복귀 + 메쉬 재로드 확인
```

메쉬 상태는 재시작에도 보존됩니다(영속). 모든 노드를 호환 버전으로 유지하세요 —
roster/flow 가십과 와이어 포맷은 일치하는 `meshd`를 전제합니다.

---

## 트러블슈팅

| 증상 | 확인 |
|---|---|
| `meshd not reachable … Is the daemon running?` | `lattice status`; `systemctl status lattice-meshd`; `journalctl -u lattice-meshd -e`. |
| 피어가 `idle`/`live` 아님 | `lattice doctor`. 보통 UDP 포트가 양끝까지 안 열렸거나, 두 노드의 네트워크 id가 다름(split-brain). |
| `lattice status`에 `binary not found` | CLI가 `meshd`를 못 찾음. `export LATTICE_MESHD=/경로/meshd`. |
| 출구 트래픽이 안 나감 | 출구 노드는 ip-forwarding + NAT 필요(데이터 플레인 켜지면 자동) **그리고** 클라우드 방화벽이 forwarding/egress 허용해야 함. |
| 두 데몬이 포트 다툼 | 호스트당 `meshd` 하나만. `install-service` 전에 옛/수작업 유닛을 제거하세요. |
