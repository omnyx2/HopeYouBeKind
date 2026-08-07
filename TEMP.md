# TEMP.md — live working memory

## Current task: full-tunnel egress sticky (v0.7.14) — "자꾸 Default network로 감" 버그

원인: full-tunnel egress(`current`+`full_tunnel`)가 재시작에 persist 안 됨(split만 유지). 고침:
`egress.json` persist/load + 부팅 복원(exit 도달 후 divert, preflight 가드).

### 진행
1. [x] persist_egress/load_egress + SetCurrent/RemoveMesh/self-destruct 호출 + 부팅 복원
2. [x] restore_full_tunnel (exit 도달 대기 후 apply + kill-switch 재무장)
3. [x] 오프라인 검증: 빌드(1.79) + 단위테스트 7/7 + fmt + clippy(기존패턴) + startup 스모크
4. [x] 버전 0.7.14 범프 + CHANGELOG/ERRORS/SPLIT_TUNNEL 문서
5. [ ] 커밋 (feat/extensions-meshd)
6. [ ] **라이브 Mac 데몬 스왑은 사용자 합의 후** (clean teardown: off→shutdown→quit→relaunch) + fleet 배포 판단
