# Mathematical model — the mesh as a network sheaf over a global identity space

The rigorous foundation under [SDN_DHT_ARCHITECTURE.md](SDN_DHT_ARCHITECTURE.md)
(authority + distribution) and [FLOW_TABLE.md](FLOW_TABLE.md) (programmable
forwarding). It answers one question precisely:

> **Why does a serverless mesh of many independent networks assemble into *one*
> coherent global network in which *everyone* has a unique, consistent place —
> with no coordination server?**

The short answer: model the multi-network world as a **network sheaf** over the
graph of nodes; "one coherent network including everyone" is a **global section**
(degree-0 cohomology `H⁰`); the obstruction to it existing/being unique is `H¹`;
and a **global, collision-free cryptographic identity (the node's public key)**
makes the sheaf *constant*, forcing `H¹ = 0` — so the unique global section
**always exists**. The admin's CA signature *selects* that section; the DHT
*distributes* it. That is the whole serverless-coherence theorem, made precise.

> Status: this is the architecture's mathematical model, written to be honest
> about what is rigorous (the sheaf/cohomology statements) vs. a guiding metaphor
> (the smooth-manifold picture). Informal where marked.

---

## 0. Dictionary (networking ↔ mathematics)

| Networking | Mathematics |
| --- | --- |
| global identity space (all possible node-ids) | the space `I = {0,1}²⁵⁶` (Ed25519 pubkeys) |
| one mesh network | a **chart** `(Uᵢ, φᵢ)` — a local patch with its own overlay coordinates |
| overlay VIP space (`100.64.0.0/10`) | the chart's **local coordinate** `φᵢ : Uᵢ → Vip` |
| a node in two meshes (multi-homed) | a point in a **chart overlap** `Uᵢ ∩ Uⱼ` |
| relay / gateway / exit between meshes | the **transition map** `φᵢⱼ = φⱼ∘φᵢ⁻¹` |
| the whole multi-network world | the **manifold / cell complex** `X` glued from charts |
| "is the global network consistent?" | the **cocycle / sheaf condition** |
| "one network including everyone, uniquely" | a **global section** `s ∈ H⁰(X; F)` |
| inconsistency / can't glue | nonzero **obstruction** `H¹(X; F) ≠ 0` |
| node identity = public key | a **global section of the identity sheaf** (constant) |
| admin CA signature | the act of **choosing** the unique global section |
| member certificate | a **restriction map** binding a node's local data to the global id |
| flow table (policy/routing) | a **sheaf morphism** programming the data plane |
| routing redundancy (many routes) | the **fundamental groupoid / `π₁`** (path classes) |
| the DHT (Kademlia) | the **atlas + coordinate transport** (an ultrametric id-space) |

---

## 1. Meshes as charts; multi-homing as transition maps

A manifold is built from local **charts** glued on their overlaps. Each mesh is a
chart: a set of nodes `Uᵢ` with a local coordinate system `φᵢ` (its overlay
addressing). A node that belongs to two meshes lives in the **overlap**, and the
**transition map** translates one mesh's coordinates into the other's — that node
*is* the glue.

```
        mesh A  (chart U_A)              mesh B  (chart U_B)
   ┌──────────────────────────┐    ┌──────────────────────────┐
   │   a1     a2               │    │              b1     b2    │
   │       a3        ┌─────────┼────┼─────────┐        b3       │
   │                 │    G    │    │    G    │                 │
   │       a4        └─────────┼────┼─────────┘        b4       │
   │   a5                      │    │              b5           │
   └──────────────────────────┘    └──────────────────────────┘
                    U_A ∩ U_B = { G }     ← multi-homed gateway
              transition  φ_AB : (G in A-coords) ↦ (G in B-coords)
```

In Lattice today, `G` is exactly a **relay / exit node** (e.g. the dual-homed
Ubuntu box, or the public Oracle anchor): a node reachable in two coordinate
patches that carries traffic between them. **Gateways are not a special case —
they are the transition functions of the atlas**, and the flow table's
`ToExit`/relay actions are how those transitions are programmed.

---

## 2. The cocycle condition — when *does* it glue?

Charts glue into a single consistent manifold only if the transition maps agree on
**triple overlaps** (the cocycle condition); for a fibre bundle the structure
functions `gᵢⱼ` must satisfy `gᵢₖ = gⱼₖ ∘ gᵢⱼ`:

```
                 U_A
                /   \
          φ_AB /     \ φ_AC
              /       \
            U_B ───────  U_C
                 φ_BC

   cocycle:   φ_AC  =  φ_BC ∘ φ_AB     on  U_A ∩ U_B ∩ U_C
              φ_ii = id ,  φ_ji = φ_ij⁻¹
```

**Networking meaning.** If node `X` is in meshes A, B, C, then "translate X's
identity A→B then B→C" must equal "translate A→C". If two meshes disagree about
who a node *is* — e.g. address collisions, or a node admitted under conflicting
identities — the cocycle **fails**, the charts **don't glue**, and there is **no
unique global network**. So:

> **Uniqueness of the global mesh is NOT automatic.** It is exactly the cocycle /
> sheaf-consistency condition. The interesting question is how to *guarantee* it.

---

## 3. The network sheaf (the precise, discrete model)

A smooth manifold is too much: the mesh is **discrete** (finite nodes, links). The
right object is a **cellular / network sheaf** `F` over the graph `X` of nodes and
links (Curry; Hansen–Ghrist; Robinson):

- a **stalk** `F(v)` on each node `v` — its local data (its ids / coordinates
  across the meshes it belongs to);
- a **stalk** `F(e)` on each link `e`, with **restriction maps** `F(v) → F(e)`;
- a **global section** `s` assigns `s(v) ∈ F(v)` to every node so that the two
  restrictions **agree on every link** (the consistency condition).

```
   F(u)            F(v)           F(w)        ← stalks (local id / coords)
    ●───────────────●───────────────●
    │    F(e₁)  ↘  ↙  F(e₂)         │         ← restriction maps onto links
    │              ●                 │
    │            F(...)              │
    ●────────────────────────────────●
         a GLOBAL SECTION s : choose s(v)∈F(v) ∀v, agreeing on every link

   H⁰(X; F)  =  { consistent global sections }     ← "one network, everyone in it"
   H¹(X; F)  =  { obstructions to gluing }          ← "the inconsistency"
```

This is the precise form of "include everyone consistently": a **global section of
the network sheaf**. Its existence/uniqueness is governed by `H⁰`; the obstruction
by `H¹` (sheaf cohomology = the measure of *local-data → global-structure*
obstructions — Hansen–Ghrist; Ghrist–Hiraoka for the network-coding case).

---

## 4. The theorem (informal): a global identity trivializes `H¹`

**Claim.** If every node carries one **globally unique, collision-free identity**
that is the *same in every mesh* — its public key in `I = {0,1}²⁵⁶` — then the
identity sheaf is **constant**, every restriction map is the **identity**, the
cocycle holds automatically, and therefore

```
        H¹(X; F_id) = 0   ⟹   a unique global section of identity ALWAYS exists
```

i.e. **the mesh can always be assembled uniquely, with everyone a consistent
resident.**

**Why (sketch).** A constant sheaf assigns the same stalk `I` to every cell with
identity restriction maps. A global section is then just a globally consistent
choice of identity per node; since each node's identity is fixed and global (`pkᵥ`),
the choice is forced and consistent on every overlap (`pk = pk`). There is nothing
for the transition maps to disagree about, so the cocycle is satisfied trivially
and the obstruction `H¹` vanishes. (For the connected identity component this is
the constant-sheaf cohomology `H⁰ = I`, `H¹` reflecting only graph topology, not
identity conflict.)

```
   generic sheaf                     identity sheaf (pubkey)
   ─────────────────                 ────────────────────────────
   F(v) varies per node              F(v) = { pk_v } ⊂ 2²⁵⁶   (global, constant)
   restrictions nontrivial           restrictions = identity   (pk = pk)
   H¹ may be ≠ 0  (may NOT glue)     H¹ = 0   ⟹  unique global section, always
```

**This is the serverless-coherence theorem.** It explains, mathematically, *why*
the SDN×DHT design produces one coherent network view without a server:

- the **public key as node-id** is what trivializes the obstruction (no two meshes
  can disagree about identity) — the foundation already in the codebase (cf.
  self-certifying identity, Mazières);
- the **admin CA signature** is the act of **selecting** the unique global section
  among the consistent ones (membership, VIPs, policy) — *authority = choosing the
  section*;
- the **DHT** is the dumb transport that **distributes** the chosen section; it can
  withhold or replay but never forge, because the section is signed.

Decentralized distribution, centralized authority — now with a reason it *works*.

---

## 5. Two levels: identity (unique) vs. paths (plural)

Your intuition "always uniquely constructible, yet infinitely many paths" splits
cleanly across **cohomological degree**:

```
   degree 0   H⁰  =  global sections   =  WHO is in the net, who each node is
              → UNIQUE   (pubkey trivializes the obstruction)

   degree 1   H¹ / π₁ =  cycles / path classes =  HOW you reach a node
              → PLURAL  (multi-homing & relays create independent routes)
```

> **Residents are unique; routes are infinite.**

`H⁰` pins the *destination* (one identity per node); `π₁` / `H¹` measures the
*routing freedom* — independent cycles in the topology are exactly redundant,
homotopy-distinct paths, i.e. **resilience**. A richer `π₁` is *good*: more
independent ways to reach the same unique resident (direct / relay / exit are
different path classes to one identity).

---

## 6. The geometric view (optional coordinate): hyperbolic embedding

The atlas needs *a* coordinate transport. Two realizations:

- **What Lattice uses now — the Kademlia ultrametric.** Node-ids live in
  `{0,1}²⁵⁶` with the XOR metric, an **ultrametric** (a tree / Cantor-set
  structure). The DHT *is* the atlas: it gives every node a global position and a
  routing structure, distributed peer-to-peer (Maymounkov–Mazières).
- **A continuous alternative — hyperbolic embedding.** Krioukov et al. show
  complex networks embed naturally in a **hyperbolic manifold** so that each node
  gets a **unique coordinate** and **greedy routing on local information alone**
  succeeds with near-optimal paths — *iff* the coordinate space is congruent with
  the underlying space. This is your "manifold with unique coordinates + paths"
  realized concretely, and a candidate future coordinate system for the mesh
  (greedy geometric routing instead of/alongside DHT lookup).

Both give the same thing the theorem needs: a **global coordinate** in which every
node sits once. The ultrametric (discrete) is what's built; the hyperbolic
(continuous) is the smooth-manifold realization of the same idea.

---

## 7. Correspondence to the implementation (the payoff)

```
   MATH                                IMPLEMENTATION (crate / artifact)
   ─────────────────────────────────────────────────────────────────────
   global identity space  I=2²⁵⁶       node-id = Ed25519 public key
   atlas + coordinate transport         Kademlia DHT  (crates/dht, XOR metric)
   chart  (U_i, φ_i)                    one mesh + its overlay VIP space (crates/overlay)
   transition map  φ_ij                 multi-homed relay / exit node (crates/net, exit.rs)
   network sheaf  F                     manifest + directory + endpoint records (crates/membership)
   CHOSEN global section  s ∈ H⁰        admin CA signature on the NetworkManifest
   restriction map (glue)               member certificate (binds local ↦ global id)
   sheaf morphism / "the program"       flow table (FLOW_TABLE.md) over the manifest
   π₁ / path classes                    routing redundancy: direct / relay / exit
   H¹ = 0 (no obstruction)              pubkey-id ⇒ one coherent mesh, no server
```

```
   ┌──────────────────────────────────────────────────────────────────┐
   │ AUTHORITY      admin CA  =  selects the unique global section s    │
   ├──────────────────────────────────────────────────────────────────┤
   │ SECTION        signed NetworkManifest + directory  =  s ∈ H⁰(X;F)  │
   ├──────────────────────────────────────────────────────────────────┤
   │ SHEAF / GLUE   member certs (restrictions) · pubkey-id (constant)  │
   │                ⇒ cocycle holds ⇒ H¹ = 0 ⇒ s exists & is unique     │
   ├──────────────────────────────────────────────────────────────────┤
   │ ATLAS          DHT (Kademlia ultrametric)  =  global coordinate     │
   ├──────────────────────────────────────────────────────────────────┤
   │ CHARTS         meshes (overlay VIP patches), glued at multi-homers  │
   ├──────────────────────────────────────────────────────────────────┤
   │ DATA PLANE     flow table programs transitions: ToPeer/ToExit/Drop  │
   └──────────────────────────────────────────────────────────────────┘
```

---

## 8. Link to the flow table and the crypto research

- **Flow table = the chosen section, made operational.** The admin's global
  section fixes *who exists and reaches whom*; the [flow table](FLOW_TABLE.md)
  `match → action` is the **sheaf morphism** that pushes that section into the data
  plane (route to peer, to exit, or `Drop`). Default-deny (`H⁰` says "not a
  permitted flow") is the kill-switch; app-authorization is a finer stalk
  (`src_uid`) in `F`.
- **Same manifold as the cipher.** The manifold-and-time-window cryptography
  (see [[crypto-research-goal-and-bench]]) lives on *this* space: the topology of
  communication and the geometry of the cipher share one substrate. A natural
  research thread: the time-window (data unrecoverable after a window) as a
  **time-varying sheaf** whose sections expire — `H⁰` nonempty now, empty later.

---

## 9. Open problems (this is where the contribution is)

The two pillars exist in the literature; **their synthesis here does not**:

1. **No paper** casts a P2P mesh VPN as a network sheaf whose gluing obstruction is
   *trivialized by a cryptographic global identity*, with the controller's
   signature selecting the global section. (Pillars: sheaf-on-networks — Hansen–
   Ghrist, Ghrist–Hiraoka; hyperbolic network geometry — Krioukov.) **This framing
   is the novel claim to make rigorous.**
2. **Make the theorem precise.** State `F`, `X`, the restriction maps, and prove
   `H¹(X; F_id) = 0` rigorously for the pubkey-identity sheaf; characterize what
   the admin section adds (VIP/policy as a *non*-constant sub-sheaf with its own
   cohomology — does admin-assigned VIP allocation have an obstruction?).
3. **`π₁` as a resilience invariant.** Quantify routing redundancy as the rank of
   `H¹` of the *connectivity* sheaf; relate to relay/exit placement.
4. **Coordinate choice.** Ultrametric (Kademlia) vs. hyperbolic embedding
   (Krioukov greedy routing): when is geometric routing congruent enough to
   replace DHT lookup?
5. **Time-varying sheaf** for the time-window cipher: sections that vanish after a
   window; tie `H⁰` collapse to key erasure.

---

## References

- J. Hansen, R. Ghrist, *Toward a Spectral Theory of Cellular Sheaves*, J. Applied
  & Computational Topology, 2019.
- R. Ghrist, Y. Hiraoka, *Applications of Sheaf Cohomology and Exact Sequences to
  Network Coding*, RIMS Kôkyûroku 1752, 2011.
- J. Curry, *Sheaves, Cosheaves and Applications*, PhD thesis, 2014.
- M. Robinson, *Topological Signal Processing*, Springer, 2014.
- *A Sheaf-Theoretic Characterization of Tasks in Distributed Systems*, arXiv:2503.02556, 2025.
- D. Krioukov, F. Papadopoulos, M. Kitsak, A. Vahdat, M. Boguñá, *Hyperbolic
  Geometry of Complex Networks*, Phys. Rev. E 82, 2010.
- R. Kleinberg, *Geographic Routing Using Hyperbolic Space*, INFOCOM 2007.
- P. Maymounkov, D. Mazières, *Kademlia: A Peer-to-peer Information System Based on
  the XOR Metric*, IPTPS 2002.
- D. Mazières et al., *Separating Key Management from File System Security* (SFS,
  self-certifying identity), SOSP 1999.
- M. Herlihy, D. Kozlov, S. Rajsbaum, *Distributed Computing Through Combinatorial
  Topology*, Morgan Kaufmann, 2013.
- R. Rivest, A. Shamir, D. Wagner, *Time-lock Puzzles and Timed-release Crypto*,
  MIT-LCS, 1996.
