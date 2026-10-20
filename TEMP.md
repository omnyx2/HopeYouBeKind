# TEMP.md — live working memory

## 리팩토링 로드맵 — 남은 단계 (Phase 0·1·2·3 + 4-오프라인 완료 → COMPLETE.md 2026-10-20/21)

2026-10-20 4-영역 감사 기반. 라이브 데몬 불가침 원칙 유지.
(보류 중: GUI 페이지 단위 분할(상태 설계 필요 — DOM-diff 재작업과 함께), 데몬 reason CODE.)

1. [ ] Phase 4 — 라이브/멀티노드 검증 필요 묶음(각각 단독 커밋 + 라이브 재검증, 스왑 절차 준수):
   - handle 내 lock 쥔 동기 shell-out(route/pfctl/powershell)을 PostAction으로 — 라우팅 복원과
     IPC 응답 순서가 바뀌는 의미 변화(kill-switch/SetCurrent{None} 경로).
   - DHT 재발견의 endpoint 무조건 덮어쓰기(meshd dht reconnect) — apply_gossip_table 불변식
     (fresh direct는 안 덮음) 적용. docs/DHT_RENDEZVOUS.md 펴놓고.
   - 창닫기=데몬사망 → 시스템 트레이(+명시적 "Quit & disconnect"). orphan-root-meshd 사고 이력
     주의(single-instance guard 테스트 필수).
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
- ⚠️ opsec: COMPLETE.md/ERRORS.md 등에 실제 인프라 IP 커밋됨(기존부터, 일부 main에 push).
  스크럽 필요 여부 사용자 확인.
- feat/extensions-meshd → main 머지 (v0.7.14/0.7.15 + Phase 0) 대기.
