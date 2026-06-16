# Lattice guides — 가이드

Beginner-friendly, hands-on guides for using Lattice (the serverless mesh VPN)
from the `lattice` command line. 초보자용 실습 가이드입니다.

## English

| Guide | What it covers |
|---|---|
| [Getting started](getting-started.en.md) | From zero to a working VPN: run the daemon, create a mesh, invite a machine, route all traffic through an exit. |
| [Feature cookbook](cookbook.en.md) | Short recipes per feature: private LAN, full-tunnel VPN, multiple meshes, ephemeral/self-destruct meshes, attack response, key rotation, cipher choice, invite secrecy, persistence, discovery. |

## 한국어

| 가이드 | 내용 |
|---|---|
| [시작하기](getting-started.ko.md) | 0에서 작동하는 VPN까지: 데몬 실행, 메쉬 생성, 컴퓨터 초대, 모든 트래픽을 출구로 라우팅. |
| [기능 쿡북](cookbook.ko.md) | 기능별 짧은 레시피: 사설 LAN, 풀터널 VPN, 여러 메쉬, 휘발성/자폭 메쉬, 공격 대응, 키 교체, 암호 선택, 초대 비밀성, 영속화, 디스커버리. |

## The CLI / CLI 도구

All guides use the `lattice` CLI at [`scripts/lattice`](../../scripts/lattice) —
a zero-dependency Python wrapper around the `meshd` daemon's socket. Run
`lattice --help` or `lattice <command> --help` for built-in help.

모든 가이드는 [`scripts/lattice`](../../scripts/lattice)의 `lattice` CLI를
사용합니다 — `meshd` 데몬 소켓을 감싼 의존성 없는 Python 래퍼입니다.
`lattice --help` 또는 `lattice <명령> --help`로 도움말을 볼 수 있습니다.

```sh
# put it on your PATH / PATH에 등록
sudo ln -sf "$PWD/scripts/lattice" /usr/local/bin/lattice
lattice --help
```
