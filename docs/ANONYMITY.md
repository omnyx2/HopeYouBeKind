# Origin Unlinkability at the Exit — L1 "Opaque Relay Circuits"

## Goal (the requirement)
Who originated a flow must be knowable **only inside the mesh**. From **outside**
the mesh — the destination site, and any underlay eavesdropper on a single relay
leg — the origin node must be unidentifiable. Responses must still route back to the
origin. The **exit** node may know the origin (it is a mesh-internal node).

This is **L1** (of L1/L2/L3): hide origin from outside only. L2 (onion multi-hop so
even the exit can't link) and L3 (cover traffic vs a global timing adversary) are
future. See [[lattice-exit-anonymity-L1]].

## What's already true (baseline)
- Destination sees only the exit's egress IP (exit source-NAT). ✅
- The exit's conntrack returns responses over the overlay to the origin. ✅

## The leak L1 closes
Today's relay frame is `[0xF0][dest_id:32][src_id:32][noise-ct]` — the **node ids are
plaintext**. A node id is a stable, cert-bound identity, so an underlay observer on
the origin↔relay leg can long-term-track the origin across IP changes, and link it to
the exit. L1 removes node ids from the wire, replacing them with **per-leg opaque
circuit ids (cid)** that differ on each hop.

## Wire format (new)
Replace the `0xF0` envelope with two frame types on the same relay socket:

```
DATA   : [0xF1][cid:16][noise-ct]
SETUP  : [0xF2][cid:16][enc_setup]        (origin→relay, one per circuit)
```
- `0xF1`/`0xF2` stay outside wire::MessageType (0x01..=0x05) for demux on the shared
  mesh socket (same trick as 0xF0).
- `cid` = 16 random bytes, **unique per leg** (origin picks cid_OR; relay picks
  cid_RP). No node id ever on the wire.
- `enc_setup` = the setup payload encrypted to the relay over the EXISTING origin↔relay
  Noise session (they're directly connected), so an observer can't read it.

### SETUP payload (plaintext, before Noise-sealing to the relay)
```
[target_id:32]      # the far endpoint P this circuit carries to (e.g. the exit)
[return_cid:16]     # cid the relay must stamp on frames it returns to us (= cid_OR)
```
The relay, on SETUP from origin O (arriving from O_addr):
1. resolves `target_id` → `P_addr` (it is connected to P; reuse the direct-session
   address — the `connected_addr`/`learn` table we already maintain).
2. picks `cid_RP` (random), installs a **circuit entry** (below), and—if P is itself
   a relay toward a further hop—forwards a SETUP onward. For our single-relay case P
   is the exit, so no onward SETUP; instead O also sends an end-to-end SETUP to P
   *through* the circuit (so P maps cid_RP→return). P installs an endpoint entry.

## Circuit table (per node)
```
struct Circuit {
    fwd_addr: SocketAddr,   // where DATA goes toward the far end
    fwd_cid:  [u8;16],      // cid to stamp on the forwarded DATA
    ret_addr: SocketAddr,   // where DATA goes back toward the origin
    ret_cid:  [u8;16],      // cid to stamp on the returned DATA
}
// keyed by the cid seen on an INCOMING frame:
//   incoming cid == this entry's "near" cid for that direction.
// relay R holds: cid_OR → {fwd:(P_addr,cid_RP), ret:(O_addr,cid_OR)}
//                cid_RP → {fwd:(O_addr,cid_OR), ret:(P_addr,cid_RP)}  (the reverse)
// endpoint P holds: cid_RP → unwrap-to-engine; reply path = (R_addr, cid_RP)
// origin  O holds: cid_OR → unwrap-to-engine (synthetic addr for P)
```
Forward (O→P): O sends `[0xF1][cid_OR][ct]`→R; R looks up cid_OR, rewrites to
`[0xF1][cid_RP][ct]`→P_addr. Return (P→O): P sends `[0xF1][cid_RP][ct]`→R; R rewrites
to `[0xF1][cid_OR][ct]`→O_addr. **Each hop holds only cid→(neighbor) maps — no node
id needed to route or to return.**

## How it folds into today's code
- `relay.rs`: the `fwd`(id→addr), `relay_path`(reply-via-received), `learn`, and
  `synth` mechanisms collapse into the circuit table. `synth` (per-peer 192.0.2.x
  fake addr to the engine) stays — it's how an unwrapped circuit surfaces to the
  engine as a "direct" peer; just key it by circuit instead of src_id.
- Circuit SETUP is triggered at the **auto-relay election** point (daemon directory
  consumer): when O elects relay R for target P, O runs the setup handshake over the
  O↔R Noise session, then feeds P to the engine via the circuit's synth addr.
- Wire format changes → ALL nodes redeploy (like the manifest-flows change). From the
  dorm, deploy to Linux nodes over the **overlay SSH** (Ubuntu 100.64.0.10, Oracle
  100.64.0.12) since campus LAN is unreachable.

## Protects / doesn't (be honest)
| observer | after L1 |
|---|---|
| destination site | exit IP only ✅ |
| underlay eavesdropper on one leg | sees O's *IP* + an opaque per-leg cid; **no node id, dest, or content** → no stable-identity tracking ✅ |
| the exit | knows origin — allowed (mesh-internal) ✅ |
| global observer (all legs) | per-leg cids raise the bar, but timing/volume correlation still links → that's L3 ⚠️ |

## Build order
1. `relay.rs`: `0xF1`/`0xF2` encode/decode + `Circuit` table + DATA forward/return by
   cid (unit test: O–R–P three transports, DATA round-trips, no node id on the wire).
2. SETUP handshake over the O↔R Noise session + endpoint (P) install.
3. daemon: drive SETUP from the election; feed P via circuit synth.
4. redeploy 3 nodes over overlay SSH; live re-verify Mac↔Oracle + a tcpdump showing
   the relay leg carries no node ids.
```
