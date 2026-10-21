# Lattice Windows uninstaller (docs/LIFECYCLE.md §5). Removes EVERYTHING the app put
# on this machine — the daemon (stopped gracefully so routes/DNS are restored), the
# boot scheduled task, the per-user run-copy, the installed app (NSIS or MSI), and
# stale pipes. Mesh state (membership + identity) is KEPT by default; delete it only
# with -DeleteState.
#
#   powershell -ExecutionPolicy Bypass -File uninstall-win.ps1 [-DeleteState]
#
# Run elevated (an admin SSH session already is). Best-effort throughout: a missing
# piece is not an error, so this is safe to run on a half-installed box.
param([switch]$DeleteState)
$ErrorActionPreference = "SilentlyContinue"
function Log($m) { Write-Host ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $m) }

$pipe  = "\\.\pipe\lattice-meshd"
$state = "$env:USERPROFILE\.lattice\meshd"

Log "== stop daemon (graceful: restores routes + DNS) =="
# World-writable pipe → the Shutdown IPC needs no elevation; it runs the clean
# teardown inside meshd. Fall back to taskkill if the pipe is unresponsive.
try {
  $c = New-Object System.IO.Pipes.NamedPipeClientStream(".", "lattice-meshd", [System.IO.Pipes.PipeDirection]::InOut)
  $c.Connect(2000)
  $w = New-Object System.IO.StreamWriter($c); $w.WriteLine('"Shutdown"'); $w.Flush()
  Start-Sleep 2; $c.Dispose()
  Log "  Shutdown sent"
} catch { Log "  (daemon not reachable — skipping graceful stop)" }
Stop-Process -Name meshd -Force -ErrorAction SilentlyContinue
Start-Sleep 1

Log "== boot service (scheduled task) =="
schtasks /Delete /TN "Lattice\meshd" /F 2>$null | Out-Null

Log "== GUI login autostart =="
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Lattice /f 2>$null | Out-Null
Stop-Process -Name Lattice -Force -ErrorAction SilentlyContinue

Log "== run-copy (%LOCALAPPDATA%\Lattice) =="
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Lattice" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\ProgramData\Lattice" -ErrorAction SilentlyContinue  # SYSTEM task copy

Log "== uninstall the installed app =="
$u = "C:\Program Files\Lattice\uninstall.exe"       # NSIS
if (Test-Path $u) { Start-Process $u -ArgumentList "/S" -Wait; Log "  NSIS uninstaller ran" }
# MSI installs: remove by product name too.
Get-CimInstance Win32_Product -Filter "Name LIKE 'Lattice%'" -ErrorAction SilentlyContinue | ForEach-Object {
  Log ("  msiexec /x {0}" -f $_.IdentifyingNumber)
  Start-Process msiexec -ArgumentList "/x", $_.IdentifyingNumber, "/qn" -Wait
}
Remove-Item -Recurse -Force "C:\Program Files\Lattice" -ErrorAction SilentlyContinue

Log "== mesh state =="
if (Test-Path $state) {
  if ($DeleteState) { Remove-Item -Recurse -Force $state; Log "  DELETED $state (identity gone)" }
  else { Log "  KEPT $state (reinstall rejoins automatically; -DeleteState to remove)" }
} else { Log "  none" }

Log "== done — Lattice removed =="
