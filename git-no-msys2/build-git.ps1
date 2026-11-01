# Build native Git for Windows with Meson + MSVC, using busybox-w32 as the
# only Unix toolset at build time. MSYS2 and Git for Windows are hidden so the
# build cannot reach them.
param(
    [Parameter(Mandatory)] [string] $Source,
    [Parameter(Mandatory)] [string] $Prefix,
    [Parameter(Mandatory)] [string] $BusyboxUrl
)
$ErrorActionPreference = 'Stop'

$tools = Join-Path $env:RUNNER_TEMP 'bbtools'
New-Item -ItemType Directory -Force $tools | Out-Null
Invoke-WebRequest $BusyboxUrl -OutFile (Join-Path $tools 'busybox.exe')
# Meson looks these up by name; busybox-w32 picks the applet from argv[0].
foreach ($t in 'sh','sed','diff','tar','cat','cut','grep','sort','tr','uname','awk','mkdir','rm','cp','mv','ls','find','xargs','head','tail','wc','test','expr','printf','echo','touch','basename','dirname') {
    Copy-Item (Join-Path $tools 'busybox.exe') (Join-Path $tools "$t.exe")
}
& (Join-Path $tools 'busybox.exe') | Select-Object -First 2

# Hide every MSYS2-based install on the runner.
$hidden = @()
foreach ($d in 'C:\msys64', 'C:\Program Files\Git', 'C:\Strawberry', 'C:\cygwin64', 'C:\mingw64') {
    if (Test-Path $d) {
        try { Rename-Item $d "$d.hidden"; $hidden += $d; Write-Host "hid $d" }
        catch { Write-Host "::warning::could not hide $d : $_" }
    }
}
$hidden | Set-Content (Join-Path $env:RUNNER_TEMP 'hidden-dirs.txt')
$env:PATH = (($env:PATH -split ';') | Where-Object { $_ -and $_ -notmatch '(?i)\\Git\\|msys|mingw|Strawberry|cygwin' }) -join ';'
$env:PATH = "$tools;$env:PATH"
Write-Host "PATH=$env:PATH"
foreach ($p in 'sh','sed','git','perl','bash') {
    $c = Get-Command $p -ErrorAction SilentlyContinue
    Write-Host ("{0,-5} -> {1}" -f $p, ($c.Source ?? '<not found>'))
}
# C:\Windows\System32\bash.exe is the WSL launcher, not MSYS2.
$bash = (Get-Command bash -ErrorAction SilentlyContinue).Source
if ($bash -and $bash -notmatch '(?i)\\Windows\\system32\\') { throw "MSYS2-style bash still reachable: $bash" }

Push-Location $Source
try {
    $toolPath = $tools -replace '\\','/'
    meson setup build --vsenv `
        "--prefix=$($Prefix -replace '\\','/')" `
        -Dbuildtype=release `
        "-Dsane_tool_path=$toolPath" `
        -Druntime_prefix=true `
        -Dperl=disabled -Dpython=disabled -Drust=disabled `
        -Dgettext=disabled -Dgitk=disabled -Dgit_gui=disabled -Dgitweb=disabled `
        -Dcredential_helpers=wincred
    if ($LASTEXITCODE) { throw "meson setup failed ($LASTEXITCODE)" }
    meson compile -C build
    if ($LASTEXITCODE) { throw "meson compile failed ($LASTEXITCODE)" }
    meson install -C build --no-rebuild
    if ($LASTEXITCODE) { throw "meson install failed ($LASTEXITCODE)" }
    # Meson's Windows install leaves bin\git and the dashed builtins in
    # libexec\git-core as symlinks to extensionless names (e.g. "git"), which do
    # not resolve. Replace each with a real <name>.exe copy of its target.
    # Links can point at other links, so resolve in passes.
    $fixed = 0
    foreach ($pass in 1..4) {
    $links = @(Get-ChildItem -Recurse -Force $Prefix | Where-Object { $_.LinkType -eq 'SymbolicLink' })
    if (-not $links) { break }
    $links | ForEach-Object {
        $p = $_.FullName
        $target = $_.Target | Select-Object -First 1
        $abs = if ([IO.Path]::IsPathRooted($target)) { $target } else { Join-Path (Split-Path $p) $target }
        $src = @($abs, "$abs.exe") | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if (-not $src) {
            if ($pass -eq 4) { throw "cannot resolve link $p -> $target" }
            return
        }
        $dest = if ($p -match '(?i)\.exe$') { $p } else { "$p.exe" }
        Remove-Item -LiteralPath $p -Force
        Copy-Item -LiteralPath $src $dest -Force
        Write-Host "link $p -> $target  =>  $dest (copy of $src)"
        $fixed++
    }
    }
    Write-Host "replaced $fixed link(s) with real files"
} finally {
    Pop-Location
}
