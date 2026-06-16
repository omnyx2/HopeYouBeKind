# Lattice 목표 프로토콜 설계 — 통신 로직 · 생성 정보 · 암호화 지점

> 이 문서는 **사용자가 의도한 목표 설계**를 정리한 것. 현재 구현된 표면은
> [docs/CRYPTO_SURFACE.md](CRYPTO_SURFACE.md)에 있고, 이 문서는 "어디에 암호화가 필요한가 +
> 모든 통신 로직 + 생성되는 정보"를 캡처한다. §8은 구현 전에 풀어야 할 **엔지니어링 쟁점**.

---

## 0. 행위자 · 표기 / Actors & notation

| 기호 | 의미 |
|---|---|
| **A** / **a** | 최초 생성자 **컴퓨터** / **사람** (creator) |
| **B** / **b** | 가입자 **컴퓨터** / **사람** (joiner). 2번째 이후엔 기존 멤버 **B1**이 신규 **B2**를 초대 |
| **seed_X** | 각 노드 X가 가진 시드 (영구 신원 비밀) |
| **n** | 초대자가 고른 임의 정수 (키 스케줄 시작 인덱스) |
| **k** | 키 스케줄 스텝 크기 |
| **K(X,Y,i)** | X·Y 시드 + 인덱스 `i`로 유도한 대칭키. `i`는 `n → n+k → n+2k …`로 **전진** |

핵심: `K(·,·,i)`는 **단방향(one-way) 유도** — 나중 인덱스 키에서 과거 인덱스 키를 못 구함
(forward secrecy). [docs/CRYPTO_SURFACE.md §6의 "키 폐기 래칫"과 동일 원리]

---

## 1. 생성되는 정보 / Information artifacts

가입·운영 중 만들어지는 모든 데이터 조각:

| 정보 | 누가 생성 | 성격 | 비고 |
|---|---|---|---|
| **신원코드** identity code | 가입자 B | **time-expire**, 완전 랜덤 | 초대받기 위해 먼저 발행 |
| **초대코드** invite code | 초대자 A | 암호화 산출물 | `Enc_algo(신원코드 ; seed_A, seed_B, n)` |
| **seed** | 각 노드 | 영구 비밀 | 키 유도 입력 |
| **n, k** | 초대자 | 키 스케줄 파라미터 | n은 초대마다 임의 |
| **K(A,B,n+1k)** | 양측 유도 | 대칭키 | B→A 접속정보 봉인용 |
| **K(A,B,n+2k)** | 양측 유도 | 대칭키 | A→B iplookup 테이블 봉인용 |
| **접속정보** connection info | 각 노드 | live-paired | ip:port + 접근방식(직접/릴레이) + 접속시간 |
| **iplookup table** | 초대자 | 봉인 전송 | 가입자가 노드에 닿는 표 |
| **토폴로지** topology | n번째 가입 시 수합 | 전 노드 관점 통합 | 최단경로 형성용 |
| **헤더 키** | mesh_id + time | 시간 슬라이드 | §5, 본문과 별도 cipher |
| **헤더 배치 순열** | 메쉬 생성 시 확정 | per-mesh 비밀 | §6 안티-핑거프린트 |
| **DNS/DHCP 기억** | 각 노드 | 로컬 | 업데이트 불필요시 요청 안 보냄 |

---

## 2. 가입 플로우 — 최초 (A → B) / First join

각 화살표에 **[암호화 지점]** 표시.

1. **B → A: 신원코드.** B가 time-expire·완전랜덤 신원코드를 발행해 A에게 전달.
2. **A: 초대코드 생성. [암호화 ①]** A가 `초대코드 = Enc_algo(신원코드 ; seed_A, seed_B, n)`.
   입력 = A 시드 + B 시드 + A가 고른 정수 n.
3. **A → B: 초대코드.** 단, **암호화 알고리즘 자체는 알려주지 않음.** → b가 a에게 **사람 대 사람**으로
   알고리즘을 직접 물어봐야 함 (대역외 사회적 핸드셰이크).
4. **B: 초대코드 해석. [복호 ①]** b가 받은 알고리즘으로 해석.
   - **3회 이상 오해독을 초대자에게 보내면** → 전체 메쉬에 **잠금 대기(lock-wait)** + 전 참여자에게
     **공격 경보**. (§7)
5. **B → A: 접속정보 (A에 대한). [암호화 ②]** B가 A 접속정보를 `K(A,B,n+1k)`로 봉인해 전송. A가 검증.
6. **A → B: iplookup table. [암호화 ③]** A가 `K(A,B,n+2k)`로 봉인해 전송. B가 해석 → A 노드 접속정보 획득.
7. **연결 수립.** ip 수신 후 실제 연결. 이후 **랜덤성을 더한 주기적 통신**으로 live 확인 (keepalive).

---

## 3. 가입 플로우 — n번째 (B1 → B2) / Nth join + 토폴로지

§2와 동일하되 초대자 = 기존 멤버 B1, 입력 = `seed_A, seed_B1, seed_B2, n(B2 지정)`:

1. **B2 → B1: 신원코드** (time-expire 랜덤).
2. **B1: 초대코드 [암호화 ①].** `Enc_algo(신원코드 ; seed_A, seed_B1, seed_B2, n)`.
3. **B1 → B2: 초대코드** (알고리즘 비공개 → b2가 b1에게 직접 문의).
4. **B2: 해석 [복호 ①].** 3회 오해독 → 잠금 대기 + 공격 경보. **그리고 여기서 중요:**
   - 메쉬 참여자들이 **빠르게 공격 여부를 판단**. **단 한 명이라도 "공격"으로 판단하면 전체 메쉬가 파괴됨.**
   - 따라서 그 전에 **메쉬 생성자(A)가 "공격 아님"을 눌러 전원을 안심**시켜야 함. (§7 — 최대 쟁점)
5. **B2 → B1: 접속정보 [암호화 ②]** `K(B1,B2,n+1k)`. 검증.
6. **B1 → B2: iplookup table [암호화 ③]** `K(B1,B2,n+2k)`. 해석 → B1 접속정보 획득 → 연결 + keepalive.
7. **전체 토폴로지 수합.** B2가 B1에게 **모든 노드 접속정보**를 요구 → B1이 전달 + **모든 노드에게 각자가
   가진 접속정보(접속시간·각 노드 접근방식 직접/릴레이)를 요청**해 전부 수합.
8. **최단경로 형성.** B2가 모든 노드의 **모든 관점** 접속정보를 받아 전부 접근 시도 →
   기존보다 빠른 경로 발견 시 저장, 나머지는 기존 정보와 통합 → **상호 최단경로 토폴로지** 형성.
9. **GUI.** 직접 못 닿아 **릴레이로 가야 하는 분리된 망**은 그래프에서 **아래 영역의 분리된 원**으로 표시.
10. **로컬 기억.** 각 노드는 자기 DNS/DHCP를 기억. 참여 정보를 기억해 **업데이트 불필요하면 다른 노드에
    요청을 안 보냄** (불필요 트래픽 억제).

---

## 4. 암호화가 필요한 지점 / Where encryption is needed

| # | 지점 | 무엇을 | 키 / 방식 | 성질 |
|---|---|---|---|---|
| ① | 초대코드 생성·해석 | 신원코드 ↔ 초대코드 | `Enc_algo(seed들, n)` + **알고리즘 비공개** | 단방향, 대역외 알고리즘 공유 |
| ② | 가입자→초대자 접속정보 | connection info | `K(·,·,n+1k)` | forward-secure 인덱스 |
| ③ | 초대자→가입자 iplookup | iplookup table | `K(·,·,n+2k)` | forward-secure 인덱스 |
| ④ | 토폴로지 수합 | 전 노드 접속정보 | 멤버 대칭키(메쉬 secret 계열) | live-paired |
| ⑤ | 데이터 평면 **본문** | app payload | **드롭박스 선택 cipher** | 메쉬마다 교체 가능 |
| ⑥ | 데이터 평면 **헤더** | 라우팅 헤더 | `key = f(mesh_id, time)`, 2중 슬라이드 | 키 모르면 사실상 해독불능 |
| ⑦ | keepalive | live 신호 | 멤버 대칭키 + 랜덤 주기 | live-paired |

> 현재 코드(CRYPTO_SURFACE.md) 대비: ②③④⑤⑦은 `MeshSuite`/keydist 계열에 대응되지만, ①(알고리즘
> 비공개+초대코드)과 ⑥(헤더 별도 cipher)·§6(헤더 배치)은 **신규**. 본문/헤더 분리도 신규(현재는 헤더가
> AAD 평문).

---

## 5. 암호화 성질 / Encryption properties

1. **시드 기반 해독불가 (DECIDED).** "역해독 불가능" = **시드를 모르면 해독 불가** (계산적 안전).
   별도의 자기소멸이 아니라, 키 재료(시드/share)가 **live 노드에 있어야만** 존재 → §5-2와 결합되어
   "다 죽으면 복원 불가"가 성립.
2. **Live-paired 해석성.** 본인이 소유한 모든 정보는 **살아있는(live) 노드와 pair해야만 해석 가능.**
   → **모든 live가 죽으면** 관련 접속정보를 스스로 정리하고 **해당 메쉬는 자가 폐기.**
   (= 시간창 망각의 *공간판*: 도달 가능한 동료가 없으면 비밀 복원 불가. 구현 = threshold secret sharing,
   임계값 t는 §8-4)
3. **본문/헤더 분리 cipher.** 메쉬 생성 후 **드롭박스로 통신 암호화 방식 선택.**
   - **본문(body)** = 드롭박스 선택 방식.
   - **헤더(header)** = `mesh_id + time` 시드로 암호화. 정확한 키 모르면 사실상 해독 불능.
   - **time 스텝 경계에서 해독이 끊기는 경우 대비** → **2개 중첩 슬라이드(overlapping window)** 방식.
4. **메쉬별 cipher + 재암호화 거버넌스 (DECIDED).**
   - 메쉬마다 **완전히 다른 암호화 알고리즘** 채택 가능. **단 생성 시점에 확정.**
   - **생성 후 변경(re-cipher)** = **노드의 60% 이상이 online**일 때만 가능. (현재 charter의
     `RecipherTrigger::Quorum { k }`에 대응 — k = ⌈0.6·N⌉)
   - **변경 감지는 암묵적**: 각 노드는 *더 이상 해독이 안 되는 것*을 통해 바뀐 걸 알게 됨 (명시적 공지 없음).
   - **변경 시 꺼져 있던 컴퓨터는 그대로 메쉬에서 퇴출** (새 알고리즘/키를 못 받았으므로 따라잡기 불가 →
     재가입하려면 새 초대 필요).

---

## 6. 헤더 랜덤성 (안티-핑거프린트) / Header obfuscation

- 메쉬 **최초 생성 시** 헤더(필수 요소는 고정)를 **MTU의 어느 위치에 어떤 순서로 넣을지** 결정 가능.
- 목적: **lattice라는 프로그램의 존재를 알아도, 트래픽을 보고 lattice라고 절대 특정 못 하게.**
  데몬 설치 여부를 직접 확인하지 않는 한 식별 불가.
- 즉 헤더 배치는 **per-mesh 비밀 순열** → 외부 DPI/핑거프린팅 저항.

---

## 7. 공격 대응 / Abuse response (⚠️ 최대 설계 위험)

- **3회 오해독 → 메쉬 잠금 대기 + 전 참여자 공격 경보.**
- **단 한 명이라도 "공격"으로 판단 → 전체 메쉬 파괴 (one-veto self-destruct). (DECIDED)**
- **오판이어도 메쉬는 터진다** — 의도된 fail-deadly 설계. 거짓양성 위험을 감수하고 안전을 택함.
- **생성자(A)가 "공격 아님"을 눌러 전원 안심**시키면 파괴를 막음 → 생성자 override가 veto보다 우선.

→ DoS/오판 위험은 **수용된 트레이드오프**. (참고: 생성자 override와 veto의 타이밍 처리만 구현에서
명확히 — §8-2.)

---

## 8. 결정사항 · 남은 쟁점 / Decisions & remaining

**결정됨 (RESOLVED):**
1. **"역해독 불가능" = 시드 모르면 해독 불가** (계산적 안전). live-paired와 결합되어 "다 죽으면 복원 불가".
   (§5-1)
2. **One-veto self-destruct = 채택.** 오판이어도 메쉬 파괴. fail-deadly, 거짓양성 위험 수용. (§7)
3. **메쉬별 cipher, 생성 시 확정. 변경은 60% online 정족수. 오프라인 노드는 변경 시 자동 퇴출.**
   (§5-4)
4. **해독 실패의 두 의미 = 컨텍스트로 분리 (DECIDED).** **데이터평면** 프레임 해독 실패 → 조용히
   "재암호화됨, 나 퇴출" 처리(공격 카운트 X). **가입(초대코드)** 단계 해독 실패만 → 3-strike 공격 카운트.
   → 잠깐 끊긴 노드가 실수로 메쉬를 폭파시키는 사고 방지.
5. **Threshold t = 60% (DECIDED, 재암호화 정족수와 일치).** §5-2 live-paired 비밀 공유 임계값을 재암호화
   정족수와 같은 60%로 둠. (필요시 메쉬별 튜닝 여지만 남김.)

**남은 쟁점 (구현 시 명확히):**
6. **생성자 override vs veto 타이밍.** override(안심)와 veto(파괴)가 동시 발생 시 우선순위/윈도우 규칙.
   (생성자 서명 all-clear 우선.)
7. **헤더 배치 순열.** 필수 헤더 요소를 MTU 내 임의 위치로 흩으면 파싱·정렬 처리 필요 → 고정 슬롯 +
   per-mesh 순열 시드.

---

## 9. 현재 코드 대비 / vs current code
- 이미 있음: 멤버 대칭키 계열(②③④⑦ ≈ `MeshSuite`/keydist), 토폴로지 수합 ≈ discovery(P-D1~D4),
  keepalive ≈ 가십.
- **신규 필요:** ① 초대코드+알고리즘 비공개, ⑤⑥ 본문/헤더 분리 cipher + 드롭박스, §6 헤더 순열,
  §5-2 live-paired self-destruct(threshold), §7 공격 대응, ①의 time-expire 신원코드.

---

## 10. 구현 순서 / Build order

설계 잠금 후, 의존성·가치 순. 각 단계는 독립 배포 가능. / Design locked; by dependency + value.

| 단계 | 내용 | 기반 |
|---|---|---|
| **P-C1 본문 cipher seam** | 생성 시 메쉬별 cipher 확정 + `suite(name)` 실제 분기 + 두 번째 suite 등록. **연구용 시간창/manifold cipher가 여기 꽂힘.** | 이미 있는 `MeshSuite`/charter.initial_cipher |
| **P-C2 헤더/본문 분리** | 헤더 = `f(mesh_id,time)` 2중 슬라이드 cipher, 본문 = P-C1 선택. 현재 평문 헤더(AAD)를 봉인으로. | wire_v2 + P-C1 |
| **P-C3 재암호화 거버넌스** | 60% online 정족수 re-cipher, epoch 증가, 오프라인=암묵 퇴출(데이터평면 해독실패 처리). | charter `RecipherTrigger::Quorum` |
| **P-C4 live-paired 자폭** | threshold(60%) 비밀 공유: t개 미만 live → secret 복원 불가 → 자가 폐기. | keydist + share 분배 |
| **P-C5 헤더 순열** | 필수 헤더 요소를 per-mesh 비밀 순열로 MTU 내 배치 (안티-핑거프린트). | wire_v2 |
| **P-C6 초대코드 + 알고리즘 비공개** | time-expire 신원코드 → 초대코드(seed들+n), 대역외 알고리즘 공유. | 가입 플로우 재작업 |
| **P-C7 공격 대응** | 3-strike 잠금/경보, one-veto 자폭, 생성자 override. | P-C6 |

권장 시작 = **P-C1** (가장 작고, 이미 절반 구현됐고, 연구 cipher의 집).

## TL;DR (EN)
Target protocol: a joiner's time-expiring random **identity code** → inviter turns it into an
**invite code** via an algorithm kept secret (shared human-to-human), keyed by both seeds + an
integer n; a forward-stepping key schedule `K(X,Y,n+ik)` seals the connection-info and iplookup
exchanges; the nth joiner aggregates everyone's connection info from all viewpoints to build a
**shortest-path topology**. Crypto properties: one-way key derivation, **live-paired** custody
(all-dead ⇒ mesh self-destructs), **separate body cipher (dropbox-selectable) and header cipher
(mesh_id+time, overlapping windows)**, and per-mesh **header-position permutation** so traffic
is unidentifiable as Lattice. Open risks: one-veto self-destruct (DoS), algorithm-secrecy as a
layer not a foundation, and "irreversible" = key-erasure not undecryptable-ciphertext (§8).
