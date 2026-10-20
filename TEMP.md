# TEMP.md — live working memory

## 리팩토링 로드맵 — 남은 단계 (Phase 0·1·2 완료 → COMPLETE.md 2026-10-20/21)

2026-10-20 4-영역 감사 기반. 각 단계는 별도 PR, 라이브 데몬 불가침 원칙 유지.
(Phase 2에서 안 한 것: persist.rs 내부의 write_json_secure/read_json_or_default dedup —
파일별 serializer 차이(to_vec vs to_vec_pretty) 보존 조건으로 Phase 3에 흡수.)

1. [ ] Phase 3 — handle() 뚱뚱한 arm 함수화(IPC enum 자체는 불가침) / persist write_json_secure
   dedup / meshrun run() 13-param→
   구조체 + select arm 추출 / GUI main.js 모듈 분할 + 단일 폴 스케줄러 + egressMode 헬퍼 4벌→1 /
   lattice doctor의 한국어 substring 매칭→reason code.
2. [ ] Phase 4 — 행동 변화(각각 단독 커밋+라이브 검증): handle 내 lock 쥔 동기 shell-out,
   meshrun eprintln→tracing(Windows 진단 복구), direct/relay 25s/30s skew 통일, 결정론적
   relay 선출, DHT endpoint 덮어쓰기 불변식, 창닫기=데몬사망→트레이.
   버그 후보 추가 검토: quick-admit HashMap 비결정성(membership.rs grant_members — 노드별
   로스터 분기 가능, 수정은 roster-merge semantics 변경이라 Phase와 별도로 신중히).

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
