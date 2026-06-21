# Exit node

An **exit node** routes another node's *general internet traffic* out through
itself — so the client appears on the internet as the exit node's IP (the
"NordVPN-style" use). This is different from normal mesh traffic, which only
covers the overlay range `100.64.0.0/10`.

> **§A is the v2 (meshd) full-tunnel** — what ships today. It **reuses the v1 OS
> plumbing** (`crates/{daemon,meshd}/src/exit.rs`) documented from "## Two roles"
> onward, so keep reading for the per-OS route/NAT details.
> / **§A는 v2(meshd) 풀터널**(현재 출하본). v1 OS 배선(`exit.rs`)을 **재사용**하므로
> OS별 라우트/NAT 세부는 "## Two roles" 이하를 그대로 참고.

## §A. v2 full-tunnel via meshd / v2 meshd 풀터널

In v2 the exit is **per-mesh, set by the client** (`SetExit{mesh, exit}`), and
**any data-plane node can serve as an exit** — meshd does the OS plumbing on top of
the data plane (`lattice_meshrun::run` already routes internet-bound packets to the
exit member; see DATA_PLANE.md §6). meshd's exit module is ported verbatim from
v1's `exit.rs`; the NAT source range `100.64.0.0/10` covers the meshd overlay
(`100.80.x`).

- **Bringup (every node).** When a mesh's data plane comes up, meshd enables
  `ip_forward` + NAT (`exit::enable_nat`, idempotent) so the node is *ready* to be an
  exit, and records the TUN interface name for later route diversion.
- **Make egress (client).** `SetCurrent{mesh}` on a mesh that has an exit set →
  `exit::route_through(tun, exit_ip)` diverts the host default route through the TUN
  (pinning a host route to the **exit's physical endpoint** — learned in `PeerLinks`
  — via the real gateway, so the underlay doesn't loop) and `exit::set_dns(1.1.1.1)`
  points DNS through the tunnel.
- **Stop / restore.** `SetCurrent{None}`, clearing the exit (`SetExit{..,None}`),
  and `RemoveMesh` all call `restore_routes` + `restore_dns`.

### Kill-switch watchdog / 킬스위치 워치독

Full tunnel diverts the host default route through the exit; if that path stops
carrying traffic the host is **stranded offline**. On make-egress meshd arms a
watchdog (`ArmKillSwitch`): every **~20 s** it probes the internet **through the
tunnel** (TCP connect `1.1.1.1:443`, 5 s timeout — the probe travels TUN → exit, so
success proves the exit forwards). The **first failed probe auto-reverts** to direct
internet (restore routes + DNS, clear egress), so a dead/flaky exit never cuts the
user off. Ported from v1 (commit `282d737`).

### QUIC / large-packet notes / QUIC·대용량 패킷 메모

- **Browsers + QUIC.** A site can be unreachable in a browser but fine via `curl`
  because the browser tries **HTTP/3 (QUIC over UDP 443)** first and QUIC often
  breaks across a tunnel. Forcing TCP fallback (reject forwarded UDP 443 at the
  exit) is the standard workaround — but blanket MSS-clamp / UDP-reject rules were
  observed to *break* otherwise-working sites here, so apply such rules surgically.
- **Datacenter-IP blocks.** Some destinations (e.g. xvideos' origin) refuse
  connections from the exit's **cloud/datacenter IP** while a CDN-fronted site
  (pornhub) accepts it — a property of the *destination*, not the mesh. A different
  exit (residential IP) is the only fix.

/ v2에선 exit가 **메쉬별, 클라이언트가 지정**(`SetExit{mesh,exit}`)하고 **데이터플레인
노드면 누구나 exit** 가능 — meshd가 데이터플레인 위에 OS 배선을 얹는다(`run`이 이미
인터넷행 패킷을 exit 멤버로 라우팅, DATA_PLANE.md §6). exit 모듈은 v1 `exit.rs`를 그대로
이식(NAT 범위 `100.64.0.0/10`이 meshd 오버레이 `100.80.x` 포함).
**기동(모든 노드)**: 데이터플레인이 뜨면 `ip_forward`+NAT(`enable_nat`, 멱등)로 exit 준비 +
TUN 이름 기록. **make egress(클라이언트)**: exit 설정된 메쉬에 `SetCurrent{mesh}` →
`route_through`로 기본 라우트를 TUN으로(엔드포인트는 `PeerLinks`에서, 실 게이트웨이로 우회해
루프 방지) + `set_dns(1.1.1.1)`로 DNS도 터널 경유. **중지/복구**: `SetCurrent{None}`·exit
해제·`RemoveMesh`가 `restore_routes`+`restore_dns`.
**킬스위치**: 풀터널은 기본 라우트를 exit로 돌리니 그 경로가 죽으면 **오프라인 고립**. make
egress 시 워치독을 무장 → **~20초마다** 터널 경유로 인터넷 프로브(`1.1.1.1:443` TCP, 5초
타임아웃; TUN→exit를 통과하므로 성공=exit 포워딩 증명). **첫 실패 시 자동 복구**(라우트+DNS
복원, egress 해제)로 죽은 exit가 사용자를 끊지 않게(v1 `282d737` 이식).
**QUIC/대용량**: 브라우저는 `curl`은 되는데 안 될 수 있음 — **HTTP/3(QUIC, UDP 443)** 먼저
시도하는데 터널에서 자주 깨짐. exit에서 forward UDP 443 차단해 TCP 폴백시키는 게 표준
해법이나, 무차별 MSS-clamp/UDP 차단이 멀쩡하던 사이트를 **깨뜨리는** 경우가 관찰돼 룰은
신중히 적용. **데이터센터 IP 차단**: 일부 목적지(예: xvideos 오리진)는 exit의 **클라우드
IP** 연결을 거부(CDN 앞단인 pornhub은 허용) — 메쉬가 아니라 *목적지* 특성, 다른(주거용 IP)
exit만이 해법.

## Two roles

- **Client** — "send my internet through peer X". The client's default route is
  diverted into the tunnel; everything except the path to X's physical endpoint
  goes to X.
- **Exit** — "let others go out through me". The exit enables IP forwarding and
  source-NAT (masquerade) so tunnelled packets leave via its real interface and
  replies come back.

## Using it from the GUI

On the **exit** machine:
1. Start the node, then turn on **"Act as exit node"**.

On the **client** machine:
1. Start the node and connect to the exit (same mesh).
2. In **"Exit through"**, pick the exit peer. Your internet now egresses there.
3. Set it back to **"Direct (no exit)"** to stop.

Verify from the client: `curl https://ifconfig.me` should show the **exit's**
public IP, not yours.

## What the daemon does (the OS plumbing)

Engine routing is done and tested (internet-bound packets tunnel to the exit;
the exit writes them to its TUN). The daemon then changes the OS so the kernel
actually feeds/forwards that traffic:

**Client** (`exit::route_through`) — saves the current default route, pins a host
route to the exit's physical endpoint via the real gateway (so the tunnel
doesn't loop), then points the default route at the tunnel interface. Reverted
by `restore_routes` on change-to-direct and on daemon shutdown.

**Exit** — Linux (`exit::enable_nat`):
```
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 100.64.0.0/10 -o <wan> -j MASQUERADE
iptables -I FORWARD 1 -s 100.64.0.0/10 -j ACCEPT   # -I, not -A: see gotcha below
iptables -I FORWARD 1 -d 100.64.0.0/10 -j ACCEPT
```
**macOS** (`exit::enable_nat`) — enables forwarding and loads a pf NAT rule,
saving/restoring pf state:
```
sysctl -w net.inet.ip.forwarding=1
pfctl -f /tmp/lattice-pf.conf   # nat on <wan> from 100.64.0.0/10 to any -> (<wan>)
pfctl -e
```
**Windows** (`exit::enable_nat`) — `Set-NetIPInterface -Forwarding Enabled` +
`New-NetNat -InternalIPInterfaceAddressPrefix 100.64.0.0/10` (WinNAT). The client
side adds 0.0.0.0/1 + 128.0.0.0/1 routes via the `Lattice` Wintun adapter.

## CLI

```
lattice exit allow            # volunteer as an exit (enable NAT). --off to stop.
lattice exit use <node-id>    # full-tunnel: divert default route through the exit.
lattice exit use <id> --split # split-tunnel: engine forwards, OS default UNTOUCHED.
lattice exit use --off        # back to direct.
lattice status                # shows exit-via / is-exit.
```

**Split tunnel** is the safe, non-disruptive mode: the engine forwards
internet-bound packets to the exit, but the host's default route is left alone —
only destinations you explicitly route into the TUN egress via the exit. Use it
for verification (it can never knock the host offline) and selective routing.

## Verifying a (client → exit) pair without cutting anyone off

Per pair, on the **exit** run `lattice exit allow` once. On a **Linux client**:
```
lattice exit use <EXIT_ID> --split
sudo ip route replace 1.1.1.1/32 dev <tun>       # route only the probe IP into the TUN
curl -s https://1.1.1.1/cdn-cgi/trace | grep ^ip # egress IP — should be the EXIT's
sudo ip route del 1.1.1.1/32 ; lattice exit use --off
```
DNS-free probes (so the test never depends on a private resolver across the exit):
`curl https://1.1.1.1/cdn-cgi/trace` and `dig +short myip.opendns.com @208.67.222.222`.

## The 4×4 matrix (client → exit)

Four nodes — Mac (macOS), Ubuntu (Linux), Windows, Oracle (Linux public anchor).
Diagonal = "direct" (a node doesn't exit through itself). Off-diagonal = route
that client's internet out through that exit; egress IP must equal the exit's.

| client ↓ \ exit → | Mac | Ubuntu | Windows | Oracle |
|---|---|---|---|---|
| **Mac**     | direct | ✅ 203.0.113.30 | ⚠️ Win | ✅ <PUBLIC_IP> |
| **Ubuntu**  | ✅ 203.0.113.20 | direct | ⚠️ Win | ✅ <PUBLIC_IP> |
| **Windows** | ⚠️ Win | ⚠️ Win | direct | ⚠️ Win |
| **Oracle**  | ✅ <CELLULAR_IP> | ✅ 203.0.113.30 | ⚠️ Win | direct |

✅ = verified live 2026-06-14. The whole **macOS + Linux 3-node sub-matrix
(Mac/Ubuntu/Oracle) is complete — all 6 cross cells pass**: each client's egress
IP becomes the exit's public IP. Probes were DNS-free (`1.1.1.1/cdn-cgi/trace`,
`dig @208.67.222.222`); Mac-client cells via full-tunnel, Linux-client cells via
split-tunnel. Mac↔Oracle was verified with Mac on cellular (egress <CELLULAR_IP>);
the rest on campus WiFi. Mac and Windows both NAT behind the campus gateway
(203.0.113.20), so those two exits share an egress IP — the `exit use <id>`
target disambiguates which node forwarded.

⚠️ **Win** = the 6 Windows cells are NOT yet passing. Findings: Windows
route_through now diverts correctly (`Find-NetRoute 1.1.1.1` → the `Lattice`
Wintun adapter, after fixing `WinTun::name()`), WinNAT is configured, and overlay
data flows (Win↔Ubuntu/Oracle ping OK) — BUT the engine doesn't forward a
*non-overlay* packet out the exit (the exit node's TUN sees 0 forwarded packets).
Likely a Wintun L3 on-link delivery quirk for the 0/1+128/1 routes (no ARP on
Wintun) — packets are dropped before reaching the daemon's receive ring. Needs
hands-on Windows debugging. Mac↔Windows also won't form a direct session on the
current campus WiFi (AP client-isolation) — those cells additionally need a path
(direct LAN or a relay both can reach).

## Gotchas found the hard way

- **RHEL/Oracle-Linux `FORWARD -j REJECT`**: those distros ship a default reject
  rule in FORWARD; an *appended* ACCEPT never runs. `enable_nat` now **inserts**
  (`-I FORWARD 1`) ahead of it. Symptom: exit NAT set up correctly but forwarded
  traffic silently dropped (egress times out).
- **macOS split-tunnel + scoped routing**: an unbound socket binds to the primary
  interface's scope and ignores a host route pointing at the TUN, so split-tunnel
  on a macOS *client* doesn't capture arbitrary apps. Full-tunnel works. (A macOS
  client verifies via full-tunnel; Linux clients verify via split.)
- **Overlay MTU over a relay**: a relayed overlay path adds encapsulation, so
  1500-byte TCP (e.g. ssh) stalls while ICMP is fine. Lower the TUN MTU or clamp
  MSS before relying on TCP across a relayed hop.
- **Run the headless anchor under systemd** (`lattice-anchor.service`), not
  nohup/setsid — over a flaky link a backgrounded launch doesn't survive the SSH
  drop; a unit does, and restart is one short command.

## ⚠️ Remaining cautions

- Full-tunnel changes the default route; if interrupted a host can be cut off.
  The daemon saves/restores and reverts on `--off` and on shutdown — prefer
  `--split` for tests. **Don't full-tunnel the host running your control session
  through an unverified exit** (you can lose your own connectivity).
- IPv6 is not diverted yet (IPv4 only) — check for IPv6 leaks if that matters.
