# TEMP.md — live working memory

## Current task: egress 3모드 명시화 (Off / Split / Full) — 개념/UI 정리

문제(설계 결함, 라우팅 버그 아님): "exit/egress"가 3군데서 다른 뜻 → topbar가 Default network를
full-tunnel의 peer 선택지처럼 노출. 자기 네트워크 = "메쉬 egress OFF"인데 그렇게 안 보임.
사용자 결정: **명시적 3모드 Off/Split/Full + Config exit 셀렉터의 `— none —` 제거**.

### 요구
1. [ ] Config "Egress & routing": exit 셀렉터에서 `— none —` 제거, 관문 멤버 기본값 지정
       (pinned/exitable 우선). "my exit" = "이 메쉬의 인터넷 관문"으로 프레이밍
2. [ ] 3모드 세그먼트 컨트롤(Off/Split/Full) — 현재 이 메쉬의 egress 모드 반영 + 전환
       Off→SetCurrent{None}, Split→SplitOn, Full→(exit 보장)→SetCurrent{Some}
3. [ ] topbar/plain 문구 리라벨: "Default network" → "직접 인터넷 (VPN 꺼짐/메쉬 egress off)",
       모드(Full/Split) 표시
4. [ ] 데몬: 최소 변경(가능하면 GUI-only). MeshInfo에 필요한 필드(per-member exitable,
       split 상태) 있는지 확인 후 필요시 추가
5. [ ] 오프라인 검증(빌드/테스트/fmt) + GUI 번들 sanity → 라이브 Mac 스왑은 사용자 합의 후
