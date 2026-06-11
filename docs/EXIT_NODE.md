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
iptables -A FORWARD -s 100.64.0.0/10 -j ACCEPT
iptables -A FORWARD -d 100.64.0.0/10 -j ACCEPT
```

macOS exit NAT needs a `pf` rule (the daemon only enables forwarding); add:
```
echo 'nat on en0 from 100.64.0.0/10 to any -> (en0)' | sudo pfctl -ef -
```

## ⚠️ Status & cautions

- **Engine + IPC + GUI**: implemented and tested.
- **OS plumbing**: implemented (Linux solid; macOS NAT needs the pf rule above)
  but **not yet verified across a full two-machine path** — changing the default
  route can cut a host off the network if interrupted. Test on a spare machine.
  The daemon saves/restores the route and reverts on exit, but verify before
  relying on it.
- IPv6 is not diverted yet (IPv4 only), so check for IPv6 leaks if that matters.
