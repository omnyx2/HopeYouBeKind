# Lattice Windows installer (docs/LIFECYCLE.md §4-§5). Cleanly (re)installs the app:
# tear down any previous install + legacy remnants first (uninstall-win.ps1), then run
# the bundled installer silently. Mesh state is preserved by default.
#
#   powershell -ExecutionPolicy Bypass -File install-win.ps1 -Installer <path to .msi|-setup.exe> [-DeleteState]
#
# Run elevated (an admin SSH session already is). Does NOT launch meshd — the daemon
# comes up when the user opens the app (UAC) or via the "start at boot" toggle
# (Settings), which registers a SYSTEM scheduled task. For a headless test, start it
# explicitly with scripts/win-daemon-start.ps1.
param([Parameter(Mandatory=$true)][string]$Installer, [switch]$DeleteState)
$ErrorActionPreference = "Stop"
function Log($m) { Write-Host ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $m) }

if (-not (Test-Path $Installer)) { throw "installer not found: $Installer" }
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Log "== tear down any previous install =="
$un = Join-Path $here "uninstall-win.ps1"
if (Test-Path $un) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $un @(if ($DeleteState) {"-DeleteState"})
} else {
  Log "  (uninstall-win.ps1 not alongside — skipping teardown)"
}

Log "== install $Installer =="
$ext = [System.IO.Path]::GetExtension($Installer).ToLower()
if ($ext -eq ".msi") {
  Start-Process msiexec -ArgumentList "/i", "`"$Installer`"", "/qn", "/norestart" -Wait
} else {
  # NSIS: /S = silent.
  Start-Process $Installer -ArgumentList "/S" -Wait
}

Log "== verify =="
$exe = "C:\Program Files\Lattice\Lattice.exe"
if (Test-Path $exe) {
  $v = (Get-Item $exe).VersionInfo.ProductVersion
  Log "  installed Lattice.exe v$v"
} else {
  throw "install FAILED — $exe missing"
}
Log "== done =="
Log "Open the app to start the VPN (UAC prompt), or enable boot-start in Settings."
