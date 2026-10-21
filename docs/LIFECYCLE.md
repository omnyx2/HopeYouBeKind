# Lattice 설치·실행·삭제 수명주기 (Install / Run / Uninstall Lifecycle)

> 2026-10-21 설계. 문제의식: "배포가 너무 번잡하다" — 맥에는 /Applications 앱, loose 바이너리,
> DMG에서 뜬 앱, 수동 sudo 실행본이 뒤섞이고(2026-08-22 /Volumes 사고, 2026-09-19 lablinux
> state 소실 사고가 전부 이 번잡함에서 나옴), 데몬은 GUI가 띄우고 GUI가 죽이는 어정쩡한
> 소유권이라 "창을 닫으면 VPN이 죽는" 구조였다. 이 문서가 목표 모델과 전환 계획의 기준.

## 1. 목표 모델 (3 OS 공통)

```
┌─ OS 서비스 매니저 (launchd / systemd / Task Scheduler) ─┐
│   meshd  ← root 백그라운드 서비스. 부팅 시 자동 시작(옵션).│
│           유저가 직접 만지는 대상이 아님.                  │
└──────────────▲───────────────────────────────────────────┘
               │ IPC (unix socket / named pipe)
┌──────────────┴───────────────┐     ┌────────────────────┐
│  GUI (무권한 뷰어/컨트롤러)     │     │  lattice CLI        │
│  · 정보 표시 + 조작만          │     │  (서버/헤드리스 운영) │
│  · 데몬 없으면 "시작" 버튼      │     └────────────────────┘
│    → 권한 프롬프트 1회          │
│  · 창 닫기 = 트레이로 숨김      │
│  · 명시적 Quit 2종             │
└──────────────┬───────────────┘
        트레이/메뉴바 아이콘 (3 OS): 켜짐/꺼짐 + egress 상태 표시
```

원칙:
- **데몬 소유권은 OS 서비스 매니저에게.** GUI는 데몬을 "소유"하지 않는다 — 시작을 *요청*할
  수 있을 뿐. GUI 종료가 VPN을 죽이지 않는다 (기존 ExitRequested→Shutdown은 GUI-소유 모델의
  고아 방지책이었음 — 서비스 소유 모델에서는 "고아"가 곧 정상 상태다).
- **권한 프롬프트는 뚜렷한 행위에 1회씩**: 데몬 수동 시작 / 부팅 자동시작 켜기·끄기 / 제거.
- **트레이가 진실의 창**: 앱 창이 닫혀 있어도 Lattice가 켜져 있음을 OS 위젯바에서 항상 확인.
- **설치·삭제는 "전부 정리"가 기본**: 레거시 잔재(아래 §5 인벤토리)를 설치가 치우고, 제거는
  역순으로 전부 걷어낸다. 메쉬 state는 **물어보고** 보존/삭제(§4).

## 2. 데몬 서비스화 (per-OS)

| | 메커니즘 | 설치 주체 | 내용 |
|---|---|---|---|
| macOS | LaunchDaemon `/Library/LaunchDaemons/dev.lattice.meshd.plist` | GUI 토글(관리자 1회) 또는 install 스크립트 | `RunAtLoad` + `KeepAlive`; ProgramArguments = 앱 번들 안 `Contents/Resources/resources/meshd` + 소켓 경로, `DATA_PLANE=1`. 앱 업데이트 = 번들 교체로 바이너리도 교체(launchd가 재기동). |
| Linux | systemd `lattice-meshd.service` (기존 `lattice install-service` 유닛 그대로) | GUI 토글(pkexec) 또는 CLI | `Restart=always`; 이미 lablinux에서 검증된 모델. |
| Windows | Task Scheduler `\Lattice\meshd` (ONSTART, SYSTEM, highest) | GUI 토글(UAC) | 네이티브 서비스(SERVICE_MAIN)는 meshd 코드 작업이 필요해 2단계로 미룸 — 부팅 태스크가 실용 등가. |

- 부팅 자동시작이 **꺼진** 상태의 수동 시작은 기존 `launch_meshd_elevated` 경로 그대로
  (osascript/pkexec/RunAs) — 단, setup 자동 실행이 아니라 GUI의 "데몬 시작" 버튼이 주 경로.
- 소유권 충돌은 기존 **single-instance guard**가 그대로 처리(root DATA_PLANE 데몬이 무권한
  소유자를 supersede — docs/ERRORS.md 2026-08-07). 서비스와 수동 실행이 겹쳐도 하나만 남는다.

## 3. GUI: 트레이 + 수명주기 (이번 구현)

- **트레이 아이콘 (3 OS)**: 메뉴 = 상태줄(데몬/egress, 폴 틱마다 갱신) · `열기` ·
  `종료 (VPN 유지)` · `종료 + VPN 중지`. CI가 이미 libappindicator를 설치함(Linux 트레이 전제).
- **창 닫기 → 숨김** (`CloseRequested` → `prevent_close` + hide). 트레이의 `열기`로 복귀.
- **ExitRequested에서 무조건 Shutdown 제거.** `종료 + VPN 중지`만 Shutdown IPC를 보낸다.
  `종료 (VPN 유지)`가 기본 — 데몬은 서비스/백그라운드로 계속 돈다.
- **Settings 패널 신설**: 데몬 상태 + 시작 버튼 / "컴퓨터 켤 때 VPN 자동 시작"(= §2 서비스
  설치·해제 토글, 권한 프롬프트) / "로그인하면 Lattice 열기"(= GUI 자동시작: LaunchAgent /
  `~/.config/autostart/*.desktop` / HKCU Run — 무권한).
- 프론트는 폴 틱마다 `tray_status` invoke로 트레이 상태줄/툴팁을 갱신(데몬 지식은 프론트 폴이
  이미 가장 정확).

## 4. 설치·삭제와 메쉬 state

메쉬 state(멤버십+identity)는 **자격증명이다** — 2026-09-19 사고의 교훈: 백업 없이 지워지면
재가입뿐. 흐름:

```
설치/제거 시작
  └─ 기존 state 존재? (daemon의 persist dir에 mesh-*.json)
       ├─ 없음 → 그냥 진행
       └─ 있음 → 사용자에게 질문: [보존(기본)] / [완전 삭제]
            ├─ 보존 → 데몬 살아있으면 ExportState IPC → <tempdir>/lattice-mesh-backup.json
            │         (죽어있으면 mesh-*.json을 그대로 두거나 파일 복사로 stash)
            │         → 설치 → 새 meshd 첫 기동이 MESHD_IMPORT 백업을 자동 재로드(기존 기능)
            └─ 삭제 → state dir까지 제거 (identity 영구 소실임을 명시 경고)
```

기존 메커니즘 재사용: `ExportState`(IPC) ↔ 데몬 startup의 migration-backup import는 이미
구현·검증돼 있다(commit 8769137). 설치 플로우는 이를 **호출만** 하면 된다.

## 5. 레거시 잔재 인벤토리 (설치가 치우고, 제거가 걷어낼 것들)

| OS | 잔재 | 처리 |
|---|---|---|
| macOS | `/Applications/Lattice.app`(+`.prev` 백업), `/Volumes/Lattice`(DMG 마운트), 수동/osascript로 뜬 root meshd 프로세스, `/tmp/lattice-meshd.{sock,log}`, LaunchDaemon plist, 레포 `target/`에서 복사해 쓰던 loose meshd | install: 전부 teardown 후 교체. uninstall: 전부 제거 + (질문 후) state dir |
| Linux | systemd 유닛 + `/usr/lib/lattice/resources/meshd`(패키지), loose 실행본, `/root/.lattice/meshd` state, 구 GUI AppImage/deb | `lattice uninstall-service` + deb prerm(후속); uninstall 스크립트가 질문 후 state 처리 |
| Windows | `%LOCALAPPDATA%\Lattice\meshd.exe` + `C:\ProgramData\Lattice`(SYSTEM 태스크 카피) 런카피, 설치 디렉터리, 예약 태스크 `Lattice\meshd`, HKCU Run 키 | `scripts/uninstall-win.ps1`가 전부 제거(graceful Shutdown→태스크/런카피/NSIS·MSI); `install-win.ps1`은 그걸 먼저 돌리고 설치 |

## 6. 이번에 구현하는 것 (오프라인 검증 범위)

1. 트레이 + 창닫기-숨김 + 2종 Quit (src-tauri, 3 OS 공통 코드).
2. Tauri 커맨드: `daemon_status` / `daemon_start` / `get·set_daemon_boot`(§2 per-OS) /
   `get·set_gui_autostart` / `tray_status`.
3. GUI Settings 패널 (index.html + main.js).
4. `scripts/install-mac.sh` 전면 개편 + `scripts/uninstall-mac.sh` 신설 — §4 질문/보존 플로우
   + §5 macOS 잔재 정리 + LaunchDaemon(옵션) 설치.
5. ExitRequested의 무조건 Shutdown 제거(= Phase 4 라이브 항목이던 "창닫기=데몬사망" 해소).

검증: cargo check(src-tauri, stable) + eslint + vite build. **라이브 앱/데몬은 건드리지 않음**
— 실제 트레이/서비스 동작 검증은 다음 번들 설치 때(아래 §8 체크리스트).

## 7. 후속 (문서만, 별도 작업)

- Windows: install/uninstall/daemon-start는 `scripts/*-win.ps1`로 구현+라이브 검증(2026-10-21,
  박스 0.7.2→0.7.16 클린 재설치 + SYSTEM 태스크 데몬 + 메쉬 가입 e2e). 남은 것: NSIS installer
  자체에 설치-전 cleanup 내장(현재는 install-win.ps1이 대행), meshd 네이티브 Windows 서비스화
  (windows-service crate; 현재는 ONSTART 예약 태스크가 실용 등가).
- Linux: deb postinst/prerm에 유닛 설치·제거 연결(현재는 CLI 수동).
- 업데이트 배너의 "Update" 흐름을 §4 보존 플로우와 통합(이미 ExportState는 호출함).
- GUI의 데몬 버전 ↔ 앱 버전 불일치 경고(구 GUI가 신 데몬에 붙는 2026-09-19 패턴 감지).

## 8. 다음 라이브 설치 때 검증 체크리스트

- [ ] 트레이 아이콘 3 OS 표시 + 상태줄 갱신, 창 닫기 후 VPN 유지되는지 (`curl` egress 확인)
- [ ] `종료 + VPN 중지`만 데몬을 내리는지; `종료 (VPN 유지)` 후 재실행 시 소켓 재접속
- [ ] 부팅 토글 → 재부팅 → 데몬 자동 기동 + GUI 자동시작 토글
- [ ] install-mac.sh: 기존 설치 위에서 state 보존 경로 / 삭제 경로 각각
- [ ] uninstall-mac.sh 후 잔재 0 (ps, launchctl list, /tmp, /Applications)
