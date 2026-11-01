# Build native Git for Windows with Meson + MSVC, using busybox-w32 as the
# only Unix toolset at build time. MSYS2 and Git for Windows are hidden so the
# build cannot reach them.
param(
    [Parameter(Mandatory)] [string] $Source,
    [Parameter(Mandatory)] [string] $Prefix,
    [Parameter(Mandatory)] [string] $BusyboxUrl,
    # compat/poll uses the user32 message pump, so every git binary imports
    # user32.dll and needs Win32k at load time. Delay-loading defers that until
    # poll() actually pumps messages.
    [switch] $DelayLoadUser32
)
$ErrorActionPreference = 'Stop'

$tools = Join-Path $env:RUNNER_TEMP 'bbtools'
New-Item -ItemType Directory -Force $tools | Out-Null
Invoke-WebRequest $BusyboxUrl -OutFile (Join-Path $tools 'busybox.exe') -MaximumRetryCount 5 -RetryIntervalSec 10
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
        -Dcredential_helpers=wincred `
        $(if ($DelayLoadUser32) { '-Dc_link_args=/DELAYLOAD:user32.dll delayimp.lib' })
    if ($LASTEXITCODE) { throw "meson setup failed ($LASTEXITCODE)" }
    meson compile -C build
    if ($LASTEXITCODE) { throw "meson compile failed ($LASTEXITCODE)" }
    meson install -C build --no-rebuild
    if ($LASTEXITCODE) { throw "meson install failed ($LASTEXITCODE)" }
    # Meson's Windows install leaves bin\git and the dashed builtins in
    # libexec\git-core as symlinks to extensionless names (e.g. "git"), which do
    # not resolve. Replace each with a real <name>.exe copy of its final target.
    function Resolve-GitLink([string] $dir, [string] $target, [int] $depth = 0) {
        if ($depth -gt 8) { throw "link chain too deep at $dir\$target" }
        $abs = if ([IO.Path]::IsPathRooted($target)) { $target } else { Join-Path $dir $target }
        foreach ($c in @($abs, "$abs.exe")) {
            $item = Get-Item -LiteralPath $c -Force -ErrorAction SilentlyContinue
            if (-not $item -or $item.PSIsContainer) { continue }
            if ($item.LinkType -eq 'SymbolicLink') {
                return Resolve-GitLink (Split-Path $item.FullName) ($item.Target | Select-Object -First 1) ($depth + 1)
            }
            return $item.FullName
        }
        throw "cannot resolve $abs"
    }
    $links = @(Get-ChildItem -Recurse -Force $Prefix | Where-Object { $_.LinkType -eq 'SymbolicLink' })
    $plan = foreach ($l in $links) {
        [pscustomobject]@{
            Link = $l.FullName
            Src  = Resolve-GitLink (Split-Path $l.FullName) ($l.Target | Select-Object -First 1)
            Dest = if ($l.FullName -match '(?i)\.exe$') { $l.FullName } else { "$($l.FullName).exe" }
        }
    }
    $links | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
    foreach ($e in $plan) {
        Copy-Item -LiteralPath $e.Src $e.Dest -Force
        Write-Host "link $($e.Link)  =>  $($e.Dest) (copy of $($e.Src))"
    }
    $fixed = $plan.Count
    Write-Host "replaced $fixed link(s) with real files"
    # Meson writes the build-time shell path into the shebang of the installed
    # shell scripts (git-submodule, git-filter-branch, ...). Git for Windows
    # resolves "#!/bin/sh" to "sh" on PATH, so use that instead.
    Get-ChildItem -File (Join-Path $Prefix 'libexec\git-core') | Where-Object { -not $_.Extension } | ForEach-Object {
        $text = [IO.File]::ReadAllText($_.FullName)
        if ($text -match '^#!(\S+)') {
            Write-Host "shebang $($_.Name): #!$($Matches[1]) -> #!/bin/sh"
            [IO.File]::WriteAllText($_.FullName, ($text -replace '^#!\S+', '#!/bin/sh'))
        }
    }
} finally {
    Pop-Location
}
