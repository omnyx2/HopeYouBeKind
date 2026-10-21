# Start meshd as a SYSTEM background service on Windows, headless (docs/LIFECYCLE.md §2).
# Same path the GUI's "start at boot" toggle uses (a ProgramData copy run by a SYSTEM
# ONSTART scheduled task) — doubles as a test of that path and as a way to bring the
# daemon up on a headless box where no interactive UAC is available.
#
#   powershell -ExecutionPolicy Bypass -File win-daemon-start.ps1
#
# Run elevated. Idempotent: (re)registers the task from the installed meshd and runs it.
$ErrorActionPreference = 'Stop'
function Log($m) { Write-Host ((Get-Date -Format HH:mm:ss) + ' ' + $m) }

$src = 'C:\Program Files\Lattice\resources\meshd.exe'
if (-not (Test-Path $src)) { throw 'installed meshd not found — install first' }

$dir = 'C:\ProgramData\Lattice'
New-Item -ItemType Directory -Force $dir | Out-Null
$staged = Join-Path $dir 'meshd.exe'

# Windows can't overwrite a running exe; stop the task/process first so the copy refreshes.
schtasks /End /TN 'Lattice\meshd' 2>$null | Out-Null
Stop-Process -Name meshd -Force -ErrorAction SilentlyContinue
Start-Sleep 1
Copy-Item -Force $src $staged
Log ('staged meshd -> ' + $staged)

# --data-plane enables the TUN/NAT without an inherited env var; meshd falls back to its
# default pipe name (matches the GUI). Build /TR by concatenation (quote-safe).
$tr = '"' + $staged + '" --data-plane'
schtasks /Create /TN 'Lattice\meshd' /TR $tr /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null
Log 'registered SYSTEM ONSTART task Lattice\meshd'
schtasks /Run /TN 'Lattice\meshd' | Out-Null

$pipe = '\\.\pipe\lattice-meshd'
$ok = $false
foreach ($i in 1..30) {
  if (Test-Path $pipe) { $ok = $true; break }
  Start-Sleep 1
}
if ($ok) { Log 'PASS meshd pipe is up' }
else     { Log 'FAIL meshd pipe never appeared (see C:\ProgramData\Lattice and the task history)' }
