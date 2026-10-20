//! Pure helpers: charter-policy parsers/formatters (expel, header-placement,
//! exit-policy), hex codecs, key fingerprints, and the ⌈0.6·n⌉ quorum floor.
//! No State access — everything here is directly unit-testable.
//! Pure code motion out of main.rs (Phase 2); behavior unchanged.

use crate::*;

/// ⌈0.6·n⌉ — the shared threshold: the re-cipher quorum (§5-4) and the live-paired
/// self-destruct floor (§5-2). Below this many live members the mesh secret is (by
/// the threshold-sharing model) unrecoverable, so the mesh self-destructs.
pub(crate) fn quorum_threshold(n: usize) -> usize {
    (3 * n + 4) / 5
}

/// 🟢 Short hex fingerprint of a public key (for display).
pub(crate) fn fp(pk: &PubKey) -> String {
    pk[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse the `expel` policy name (CreateMesh) into an [`ExpelPolicy`]. `None`/"" ⇒
/// `CreatorOnly` (the default); `quorum` ⇒ k=2, or `quorum:N` for an explicit threshold.
pub(crate) fn parse_expel(s: Option<&str>) -> Result<ExpelPolicy, String> {
    let s = s.map(|x| x.trim().to_ascii_lowercase()).unwrap_or_default();
    Ok(match s.as_str() {
        "" | "creator" | "creator-only" | "creatoronly" => ExpelPolicy::CreatorOnly,
        "inviter" | "inviter-chain" | "inviterchain" => ExpelPolicy::InviterChain,
        "none" | "no" | "never" => ExpelPolicy::None,
        "quorum" => ExpelPolicy::Quorum { k: 2 },
        other => match other
            .strip_prefix("quorum:")
            .and_then(|n| n.parse::<u8>().ok())
        {
            Some(0) => return Err("expel quorum k must be >= 1".into()),
            Some(k) => ExpelPolicy::Quorum { k },
            None => {
                return Err(format!(
                    "unknown expel policy '{other}' (creator|inviter|quorum[:k]|none)"
                ))
            }
        },
    })
}

/// Parse the `header` placement name (CreateMesh) into a [`HeaderPlacement`]. `None`/""
/// ⇒ `Random` (the secret-derived per-frame float, the secure default); `fixed:N` pins a
/// byte offset.
pub(crate) fn parse_header_placement(s: Option<&str>) -> Result<HeaderPlacement, String> {
    let s = s.map(|x| x.trim().to_ascii_lowercase()).unwrap_or_default();
    Ok(match s.as_str() {
        "" | "random" | "float" | "scramble" => HeaderPlacement::Random,
        "front" | "head" | "start" => HeaderPlacement::Front,
        "back" | "tail" | "end" => HeaderPlacement::Back,
        other => match other
            .strip_prefix("fixed:")
            .and_then(|n| n.parse::<u16>().ok())
        {
            Some(n) => HeaderPlacement::Fixed(n),
            None => {
                return Err(format!(
                    "unknown header placement '{other}' (random|front|back|fixed:N)"
                ))
            }
        },
    })
}

/// Parse the `exit_policy` name (CreateMesh) into an [`ExitPolicy`]. `None`/"" ⇒ `Isolate`
/// (forwarded traffic egresses the exit's real WAN — no chains/loops, the default).
pub(crate) fn parse_exit_policy(s: Option<&str>) -> Result<ExitPolicy, String> {
    let s = s.map(|x| x.trim().to_ascii_lowercase()).unwrap_or_default();
    Ok(match s.as_str() {
        "" | "isolate" | "isolated" | "direct" => ExitPolicy::Isolate,
        "chain" | "chained" | "onion" => ExitPolicy::Chain,
        other => {
            return Err(format!("unknown exit policy '{other}' (isolate|chain)"));
        }
    })
}

/// Human name of an exit-egress policy (MeshInfo display).
pub(crate) fn exit_policy_name(p: ExitPolicy) -> &'static str {
    match p {
        ExitPolicy::Isolate => "isolate (forwarded traffic → exit's real WAN)",
        ExitPolicy::Chain => "chain (forwarded traffic → exit's full-tunnel)",
    }
}

/// Human name of a header-placement policy (MeshInfo display).
pub(crate) fn header_placement_name(p: HeaderPlacement) -> String {
    match p {
        HeaderPlacement::Random => "random (P-C5 float)".into(),
        HeaderPlacement::Front => "front".into(),
        HeaderPlacement::Back => "back".into(),
        HeaderPlacement::Fixed(n) => format!("fixed:{n}"),
    }
}

/// Human name of an expel policy (MeshInfo display).
pub(crate) fn expel_name(p: ExpelPolicy) -> String {
    match p {
        ExpelPolicy::CreatorOnly => "creator-only".into(),
        ExpelPolicy::InviterChain => "inviter-chain".into(),
        ExpelPolicy::Quorum { k } => format!("quorum(k={k})"),
        ExpelPolicy::None => "none".into(),
    }
}

/// 🟢 Lowercase hex of bytes.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 🟢 Parse 64 hex chars into a 32-byte array; `None` if malformed.
pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
