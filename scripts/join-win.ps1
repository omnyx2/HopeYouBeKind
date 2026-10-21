# Headless mesh join on Windows: decode a `lattice invite` base64 code → JoinMesh IPC.
param([string]$CodeFile = 'C:\lattice-test\invite.txt', [string]$Name = 'win2')
$ErrorActionPreference = 'Stop'

$code = (Get-Content $CodeFile -Raw).Trim().Replace('-','+').Replace('_','/')
$json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($code))
$inv  = $json | ConvertFrom-Json
$req  = @{ JoinMesh = @{ invite = $inv; name = $Name } } | ConvertTo-Json -Depth 60 -Compress

$p = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'lattice-meshd', [System.IO.Pipes.PipeDirection]::InOut)
$p.Connect(5000)
$w = New-Object System.IO.StreamWriter($p); $w.WriteLine($req); $w.Flush()
$r = New-Object System.IO.StreamReader($p)
Write-Host $r.ReadLine()
$p.Dispose()
