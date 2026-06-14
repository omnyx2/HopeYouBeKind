# Exit node

An **exit node** routes another node's *general internet traffic* out through
itself — so the client appears on the internet as the exit node's IP (the
"NordVPN-style" use). This is different from normal mesh traffic, which only
covers the overlay range `100.64.0.0/10`.

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
| **Mac**     | direct | ✅ 203.0.113.30 | ⚠️ Win | ✅ 203.0.113.10 |
| **Ubuntu**  | ✅ 203.0.113.20 | direct | ⚠️ Win | ✅ 203.0.113.10 |
| **Windows** | ⚠️ Win | ⚠️ Win | direct | ⚠️ Win |
| **Oracle**  | ✅ 118.235.x | ✅ 203.0.113.30 | ⚠️ Win | direct |

✅ = verified live 2026-06-14. The whole **macOS + Linux 3-node sub-matrix
(Mac/Ubuntu/Oracle) is complete — all 6 cross cells pass**: each client's egress
IP becomes the exit's public IP. Probes were DNS-free (`1.1.1.1/cdn-cgi/trace`,
`dig @208.67.222.222`); Mac-client cells via full-tunnel, Linux-client cells via
split-tunnel. Mac↔Oracle was verified with Mac on cellular (egress 118.235.x);
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
