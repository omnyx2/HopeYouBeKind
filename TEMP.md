# TEMP.md — live working memory

## 리팩토링 로드맵 — 남은 단계 (Phase 0·1·2·3 + 4-오프라인 완료 → COMPLETE.md 2026-10-20/21)

2026-10-20 4-영역 감사 기반. 라이브 데몬 불가침 원칙 유지.
(보류 중: GUI 페이지 단위 분할(상태 설계 필요 — DOM-diff 재작업과 함께), 데몬 reason CODE.)

0. [ ] **수명주기 개편 — 남은 후속** (구현분 (a)~(d)는 COMPLETE.md 2026-10-21 / db04076):
   (e) Windows NSIS 커스텀 템플릿(설치 전 cleanup: 런카피/예약태스크 + 제거부) ·
   deb postinst/prerm에 systemd 유닛 연결 · Win 네이티브 서비스화(windows-service) ·
   GUI의 데몬↔앱 버전 불일치 경고 · 업데이트 배너와 state-질문 플로우 통합.
   라이브 검증(2026-10-21, v0.7.16 설치): ✅창닫기→트레이 생존+VPN 유지 ✅데몬 v0.7.16 기동
   ✅state/egress/full-tunnel 자동 복귀 ✅설치 스크립트(보존 플로우). 남은 §8: 트레이 메뉴
   육안(상태줄·열기·종료 2종), "종료+VPN 중지", 부팅 토글 재부팅 검증, GUI 자동시작,
   uninstall-mac.sh 실전. fleet: Mac=0.7.16, lablinux=0.7.15, oracle=0.7.13.
1. [ ] Phase 4 — 라이브/멀티노드 검증 필요 묶음(각각 단독 커밋 + 라이브 재검증, 스왑 절차 준수):
   - handle 내 lock 쥔 동기 shell-out(route/pfctl/powershell)을 PostAction으로 — 라우팅 복원과
     IPC 응답 순서가 바뀌는 의미 변화(kill-switch/SetCurrent{None} 경로).
   - DHT 재발견의 endpoint 무조건 덮어쓰기(meshd dht reconnect) — apply_gossip_table 불변식
     (fresh direct는 안 덮음) 적용. docs/DHT_RENDEZVOUS.md 펴놓고.
   - ~~창닫기=데몬사망 → 트레이~~ **구현됨**(db04076, feat/lifecycle) — 라이브 검증만 남음
     (LIFECYCLE.md §8; orphan 모델이 서비스 소유로 바뀐 점 유의).
   - quick-admit HashMap 비결정성(membership.rs grant_members) — roster-merge 의미 변화,
     혼합버전 페어 테스트 필요.
   참고: 다음 플릿 롤아웃 때 Phase 2~4 변경 전체의 라이브 검증 겸사(버전업 + 클린스왑).

## 상시 메모 (이전 세션에서 유지)

fleet: Mac v0.7.15(0ba7f44) + lablinux v0.7.15(e38ce57) + oracle v0.7.13(dab561f, 미업데이트).
- lablinux = #9 "lab" (100.80.1.9) secure-join, exit=#9, 데몬 v0.7.15 systemd 정상 (2026-09-19
  state 소실 사고 후 재가입 — 상세 docs/ERRORS.md 2026-09-19).
- ⚠️ Mac↔lablinux 오버레이 실패(양방향): 둘 다 캠퍼스 NAT 뒤, oracle relay 수렴 안 됨(문서화된
  symmetric-NAT 한계). lablinux 관리는 직접 ssh(캠퍼스 LAN).
- 구 0.7.13 GUI를 lablinux에서 실행 금지(데몬은 systemd가 돌림 — 사고 원인이었음).
- lablinux 업데이트 절차: 소스 rsync(브랜치 미push) → 네이티브 빌드(1.79) → systemd 바이너리
  스왑 → 오버레이 검증. 백업 meshd.v0713.bak.

열린 이슈:
- opsec (2026-10-21 처리): 팁의 COMPLETE.md 실 IP 11건 → 플레이스홀더 스크럽, opsec-scan 0 =
  CI 게이트 green. 미push 트리 전수 스캔 결과 **새 식별자 0** — 플래그된 값 전부 이미 origin에
  공개돼 있던 것(main COMPLETE.md 8건 + origin/feat 7건). 히스토리 rewrite는 이미 공개된 값이라
  실익 없음 — 필요해지면(인프라 교체 등) 그때 사용자 결정.
