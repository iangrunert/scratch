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
if (Get-Command bash -ErrorAction SilentlyContinue) { throw 'bash is still reachable' }

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
        -Ddocs=[] -Dcredential_helpers=wincred
    if ($LASTEXITCODE) { throw "meson setup failed ($LASTEXITCODE)" }
    meson compile -C build
    if ($LASTEXITCODE) { throw "meson compile failed ($LASTEXITCODE)" }
    meson install -C build --no-rebuild
    if ($LASTEXITCODE) { throw "meson install failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}
