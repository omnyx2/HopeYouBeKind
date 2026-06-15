# Time-Window Cipher — design / 시간창 암호 설계

> **STATUS: PARKED (design only).** The mesh ships the simple default suite
> (`crates/mesh/src/crypto.rs`, the `MeshSuite` seam) for now; this scheme drops in
> later as a second `impl MeshSuite` without touching the data plane. Revisit once
> the construction (esp. §10.1–10.3) is settled — we are not yet sure how to make it
> flaw-free, so it stays out of the running code until then.
> / **상태: 보류(설계만).** 지금은 단순 기본 스위트를 사용. 이 방식은 나중에 `MeshSuite`
> 두 번째 구현으로 드롭인. §10.1–10.3이 확정되고 결함 없는 구성이 잡힐 때까지 실행 코드에
> 넣지 않는다.
>
> The project's **research contribution**: a per-mesh cipher whose data becomes
> **cryptographically unrecoverable** once a time window passes — not merely
> "rejected". A second `MeshCipher` suite (docs/MESH_V2.md §4) selected by a mesh's
> charter. Source of truth for the implementation; update this doc first.
>
> 프로젝트의 **연구 기여**: 시간창이 지나면 데이터가 (거부가 아니라) **암호학적으로
> 복구 불가**가 되는 per-mesh 암호. 헌장이 선택하는 두 번째 `MeshCipher` 스위트.
> 구현의 진실의 원본 — 코드 전에 이 문서를 먼저 고친다.

---

## 0. The test that *defines* success / 성공을 정의하는 테스트

**EN.** The whole design is judged by one loop:
1. `seal(m)` at time `T` → ciphertext `c`.
2. Advance time past the window (`> W`) and let every honest holder run its normal
   key-erasure step.
3. `open(c)` now **must fail for everyone, including a full node compromise** — the
   keys to decrypt `c` no longer exist anywhere. ("encrypt-now / decrypt-later-fails")

If a timestamp check is all that stands between an attacker and the plaintext, the
design has **failed** — because the attacker ignores the check.

**KO.** 설계의 합격 기준은 한 루프입니다: ① 시각 `T`에 `seal(m)`→`c`. ② 윈도우(`W`)를
지나도록 시간을 보내고 정직한 보유자들이 평소대로 키 소거 단계를 수행. ③ 이제
`open(c)`는 **노드를 통째로 털어도 전원에게 실패**해야 함 — `c`를 풀 키가 어디에도 없음.
타임스탬프 체크만으로 막는 거라면 **실패**(공격자는 체크를 무시하면 그만).

---

## 1. Why the v1 demo doesn't achieve it / v1 데모가 안 되는 이유

**EN.** `crates/crypto/src/custom.rs` (the bench demo) embeds an `issued_at` stamp
and `decrypt` refuses ciphertext older than `WINDOW`. But the **session key
persists**: anyone holding it recomputes the keystream and decrypts regardless of
the stamp. The window is a *policy gate*, not *erasure*. Old data is fully
recoverable on compromise → the property is not met. (The file itself says "DEMO …
replace with your scheme.")

**KO.** v1 데모는 `issued_at`를 박고 오래된 ciphertext를 `decrypt`가 거부하지만 **세션 키가
계속 남아** 있어 키 보유자는 스탬프와 무관하게 복호화 가능. 윈도우가 *정책 게이트*일 뿐
*소거*가 아님 → 탈취 시 과거 데이터 완전 복구 가능 → 속성 미충족.

---

## 2. Core principle — forward-secure key ERASURE / 핵심 — 전방안전 키 소거

**EN.** True unrecoverability requires that the decryption key be **destroyed and
not reconstructible**. The standard tool is a **forward-secure key ratchet**:

```
R_{t+1} = H(R_t)          H one-way (BLAKE2s); R_t deleted after use
K_t     = KDF(R_t, "aead")  the per-slot AEAD key
```

Once `R_t` is deleted, `H` being one-way means it **cannot be recomputed** from any
later `R_{t+k}` — so slot-`t` keys are gone forever and slot-`t` ciphertext is
unrecoverable. This is the same family as the Signal symmetric-key ratchet,
forward-secure logging, puncturable PRFs, and "self-destructing data" (Vanish) — a
**vetted** basis, not new primitives (mirroring the project's stance: design the
*usage*, not the primitive).

The window `W` is just **how many recent slots a node keeps before erasing**:
keep `{R_{t-W+1} … R_t}`, delete `R_{t-W}` and earlier.

**KO.** 진짜 복구불가 = 복호화 키를 **파괴하고 재구성 불가**로. 표준 도구는 **전방안전
키 래칫**: `R_{t+1}=H(R_t)`(H는 일방향, 사용 후 `R_t` 삭제), `K_t=KDF(R_t)`. `R_t`를
지우면 일방향성 때문에 이후 상태로부터 **역산 불가** → 그 슬롯 데이터 영구 소실. Signal
대칭 래칫·forward-secure logging·puncturable PRF·자가소멸 데이터(Vanish)와 같은 계열로
**검증된 토대**(새 프리미티브 발명이 아니라 *사용법*을 설계). 윈도우 `W`는 **노드가
지우기 전 유지하는 최근 슬롯 수**.

---

## 3. Construction — the time ratchet / 구성 — 시간 래칫

| field | meaning |
|---|---|
| `δ` (slot length) | wall-clock seconds per slot (charter param) |
| `t = ⌊now/δ⌋` | current slot index |
| `R_t` | ratchet state for slot `t` (32 bytes) |
| `W` | window = slots kept before erasure (charter param) |
| `K_t = BLAKE2s(R_t ‖ "aead" ‖ t)` | per-slot AEAD key |

- **Genesis:** `R_{t0}` = the mesh's epoch secret at the mesh's birth slot `t0`.
- **Advance (every `δ`):** `R_{t+1} = BLAKE2s(R_t ‖ "ratchet")`; **then erase**
  `R_{t-W}` (zeroize). A node holds at most `W` states.
- **Seal:** stamp the slot `t` in the clear (in the AEAD `aad`, so it's
  authenticated), key `K_t`, nonce = per-slot counter → `[slot(8) ‖ ChaChaPoly(K_t,
  ctr, m, aad)]`.
- **Open:** read `slot`; if `slot < t-W+1` (state erased) → **unrecoverable**, fail;
  else derive `K_slot` from the retained `R_slot`, AEAD-open.

**Rollback-proof:** the slot is in the `aad`, so a ciphertext can't be replayed into
a different slot's key.

**KO.** 슬롯 길이 `δ`, 현재 슬롯 `t=⌊now/δ⌋`, 슬롯 상태 `R_t`, 윈도우 `W`, 슬롯 키
`K_t=BLAKE2s(R_t‖"aead"‖t)`. 생성 시 `R_{t0}`=메쉬 epoch 시크릿. `δ`마다
`R_{t+1}=BLAKE2s(R_t‖"ratchet")` 후 `R_{t-W}` **소거**. seal은 슬롯을 평문(aad로 인증)에
박고 `K_t`로 암호화. open은 슬롯이 윈도우 밖이면 **복구불가 실패**, 안이면 `R_slot`에서
키 유도해 복호화. 슬롯이 aad라 다른 슬롯 키로 재생 불가.

---

## 4. The "manifold" framing / "manifold" 해석

**EN.** docs/MATHEMATICAL_MODEL.md models the multi-network world as a **sheaf over a
manifold/cell-complex `X`** glued from per-mesh **charts**; the node pubkey is a
constant global section. The time-window cipher extends this along a **time axis**:
the key schedule is a **section of a key-sheaf over `X × Time`**. Forward-secure
erasure is *deletion of the section's past fibres* — the manifold "forgets" its
history. A re-cipher (§7) is a new chart transition. *This is the research lens
(metaphor-level per the math doc's own caveat); the rigorous core is §2–§3.*

**KO.** 수학 모델은 멀티네트워크 세계를 차트(메쉬)들을 글루한 **manifold/셀복합체 `X` 위의
sheaf**로 봄. 시간창 암호는 이를 **시간축**으로 확장 — 키 스케줄은 **`X × Time` 위 키-sheaf의
section**이고, 전방안전 소거는 *section의 과거 fiber를 삭제*하는 것(매니폴드가 역사를
"망각"). 단 이건 연구적 *비유 수준*이고, 엄밀한 핵심은 §2–§3.

---

## 5. Mesh synchronization / 메쉬 동기화

**EN.** All members must ratchet in lockstep and erase together.
- **Shared start:** members share `R_{t0}` (delivered with the invite / mesh secret).
- **Clock-driven:** everyone derives `t` from wall-clock + `δ`. **Skew:** keep a
  ±1-slot overlap (`W ≥ 2`) so a sender one slot ahead is still readable.
- **Late joiner:** receives the *current* `R_t` only → **cannot read pre-join
  slots** (a feature, not a bug).
- **Churn / expel:** handled by the §7 re-cipher (fresh secret), not by the ratchet.

**KO.** 전원이 같은 박자로 래칫·소거. 시작 상태 `R_{t0}` 공유(초대/메쉬 시크릿에 실어
전달). 모두 벽시계+`δ`로 `t` 산출, **시계오차**는 ±1슬롯 겹침(`W≥2`)으로 흡수. **늦은
가입자**는 현재 `R_t`만 받아 **가입 전 슬롯 복호화 불가**(의도된 특성). 추방/이탈은 §7
re-cipher로.

---

## 6. Security model — honest scope / 보안 모델 — 정직한 범위

**EN.**
- **Guaranteed (post-window forward secrecy):** a node compromised at time `T` that
  **followed the protocol** holds nothing for slots erased before `T` → that data is
  unrecoverable. A device seized/stolen later is barren.
- **NOT guaranteed:** a **malicious member that hoarded keys** during the window can
  keep that slot's data. You cannot force deletion on an adversary who legitimately
  held the key — this is fundamental. In-window compromise is covered by **capture
  detection + re-cipher** (docs/MESH_V2.md §5), not by this cipher.
- **In scope:** confidentiality + integrity per slot (ChaChaPoly), rollback-proof
  slots, time-bounded recoverability under honest deletion.
- **Out of scope:** traffic analysis; a global adversary recording all ciphertext
  *and* all live keys.

**KO.**
- **보장(윈도우 후 전방안전):** 프로토콜을 따른 노드가 시각 `T`에 털려도, `T` 전에 소거된
  슬롯은 아무것도 없음 → 복구불가. 나중에 압수/도난된 기기는 빈 깡통.
- **미보장:** 윈도우 동안 **키를 쌓아둔 악성 멤버**는 그 슬롯 데이터를 보유 가능(키를 정당히
  가졌던 적에게 삭제를 강제할 수 없음 — 근본적 한계). 윈도우 내 침해는 이 암호가 아니라
  **탈취감지+re-cipher**가 담당.
- **범위 내:** 슬롯별 기밀·무결성, 슬롯 롤백 방지, 정직한 삭제 하의 시간제한 복구성.
- **범위 밖:** 트래픽 분석; 모든 ciphertext+라이브 키를 다 가진 전역 공격자.

---

## 7. Interplay with epochs, re-cipher, capture / epoch·re-cipher·탈취와의 관계

**EN.** Two orthogonal time axes:
- **Slots (this cipher):** fine-grained, automatic, forward-secure erasure within an
  epoch. No coordination — purely clock-driven.
- **Epochs (§5/§6):** coarse, *event*-driven (expel / compromise). A re-cipher seeds
  a **fresh `R`** for the new epoch (gossiped via the signed re-cipher record), which
  an expelled node never receives. The default suite already keys per epoch
  (`crates/mesh/src/crypto.rs`); the time-window suite keys per `(epoch, slot)`.

**KO.** 두 독립 시간축: **슬롯**(이 암호, 미세·자동·epoch 내 전방안전 소거, 시계 구동) +
**epoch**(§5/§6, 거시·이벤트 구동: 추방/침해 시 새 `R` 시드를 서명된 re-cipher 레코드로
배포, 추방 노드는 못 받음). 기본 스위트는 epoch별, 시간창 스위트는 `(epoch, slot)`별 키.

---

## 8. Integration — a MeshCipher suite / 통합 — MeshCipher 스위트

**EN.** A mesh's `charter.initial_cipher` selects the suite:
- `"noise-ik-chachapoly"` → the default `MeshCipher` (done).
- `"timewindow-chachapoly"` → this scheme: same AEAD, but the key is `K_t` from the
  ratchet instead of `BLAKE2s(secret ‖ epoch)`. Charter also carries `δ` and `W`.

API mirrors the default so the data plane is suite-agnostic:
`seal(slot_or_nonce, plaintext, aad)` / `open(...)` + a `tick()` that advances and
erases. The data plane stamps the slot; replay/nonce as in the default.

**KO.** 헌장의 `initial_cipher`로 스위트 선택. `"timewindow-chachapoly"`는 동일 AEAD에 키만
래칫의 `K_t` 사용, 헌장에 `δ`·`W` 추가. API는 기본과 동일(데이터 플레인이 스위트 무관),
+`tick()`(전진·소거).

---

## 9. Test plan / 테스트 계획

1. **round-trip in window:** seal at slot `t`, open at slot `t` → ok.
2. **the defining test:** seal at `t`; `tick()` past `W`; open → **fails** even with
   the full cipher state (states erased). ← the headline property.
3. **erasure is real:** after `tick()` past `W`, assert the old `R` is zeroized /
   absent (not just gated).
4. **skew:** sender at `t+1`, receiver at `t` (within `W`) → ok.
5. **slot binding:** a ciphertext's slot can't be opened under another slot's key.
6. **late joiner:** start from `R_t`; pre-`t` ciphertext → fails.

**KO.** ① 윈도우 내 왕복 ok ② **정의 테스트**: seal 후 `W` 넘게 `tick()` → open이 **전체
상태로도 실패**(소거됨) ← 핵심 ③ 소거 실증(옛 `R` zeroize 확인, 게이트 아님) ④ 시계오차
흡수 ⑤ 슬롯 바인딩 ⑥ 늦은 가입자 과거 복호화 실패.

---

## 10. Open research questions + decisions to confirm / 열린 연구 질문·결정

1. **Ratchet shape (the "manifold"):** linear hash chain (§3, simplest) vs a **tree /
   2-D ratchet** (time × member or time × topology) giving partial-erasure or
   per-direction windows. The 2-D form is where the "manifold" becomes load-bearing,
   not metaphor — **thesis surface.** / 래칫 구조: 선형 체인 vs 트리/2D 래칫(시간×멤버 등),
   2D에서 "manifold"가 비유 아닌 실체가 됨 — 논문 표면.
2. **Window semantics:** wall-clock slots (§3) vs message-count vs hybrid. /
   윈도우 의미: 벽시계 슬롯 vs 메시지 수 vs 혼합.
3. **`δ`, `W` defaults** (clock-skew vs storage vs forward-secrecy granularity). /
   `δ`·`W` 기본값.
4. **Erasure trust:** the honest-deletion assumption (§6) — can hardware (secure
   enclave / TPM-sealed `R`) strengthen it toward "even a careful in-window attacker
   loses it"? / 소거 신뢰: 정직삭제 가정을 enclave/TPM 봉인으로 강화 가능한가?
5. **Start-state delivery:** how `R_{t0}` reaches a joiner (invite payload vs derived
   from the cert chain). / 시작 상태 전달 방식.

> Confirm 1–3 before coding the suite; 4–5 can follow.
> 1–3은 스위트 코딩 전 확정, 4–5는 추후.
