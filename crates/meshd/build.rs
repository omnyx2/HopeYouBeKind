use std::process::Command;

fn main() {
    // Embed a short build identity (git short SHA) so a *running* meshd can report exactly
    // which build it is (startup log line in main). This is the antidote to "old build vs
    // new build got mixed up": the log says it outright. Best-effort — falls back to "nogit".
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nogit".to_string());
    println!("cargo:rustc-env=LATTICE_BUILD={sha}");
    // Re-stamp when HEAD moves so the embedded SHA never goes stale. `.git/logs/HEAD` is the
    // reliable trigger — it appends on every commit/checkout on the current branch, whereas
    // `.git/HEAD` only changes on a branch switch. (scripts/build-app.sh additionally touches
    // this file to force a re-stamp, so a release build never depends on this detection alone.)
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");

    // Windows: give meshd.exe a real VERSIONINFO resource. A bare, metadata-less binary is a
    // top trigger for Windows Defender ML false positives (Wacatac/Bearfoss/Sabsik/etc.) —
    // see BUILD.md. The GUI exe gets this from tauri.conf; the standalone meshd sidecar did
    // not, which is why meshd.exe specifically was flagged.
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "Lattice meshd")
            .set("FileDescription", "Lattice mesh VPN daemon (meshd)")
            .set("CompanyName", "omnyx2")
            .set(
                "LegalCopyright",
                "Copyright (c) omnyx2. Source-available, noncommercial.",
            )
            .set("OriginalFilename", "meshd.exe")
            .set("InternalName", "meshd");
        if let Err(e) = res.compile() {
            // Don't fail the build if the resource compiler is unavailable on some host;
            // just warn — the binary still builds, only without the metadata.
            println!("cargo:warning=winres failed (meshd.exe will lack VERSIONINFO): {e}");
        }
    }
}
