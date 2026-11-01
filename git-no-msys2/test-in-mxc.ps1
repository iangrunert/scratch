# Run native git and busybox-w32 inside an MXC ProcessContainer via wxc-exec.
param(
    [Parameter(Mandatory)] [string] $WxcExec,
    [string] $GitRoot,            # install prefix containing bin\git.exe (optional)
    [Parameter(Mandatory)] [string] $BusyboxExe,
    [Parameter(Mandatory)] [string] $OutDir,
    # The run is only meaningful on the native ProcessContainer (BaseContainer/PSEC) tier.
    [string] $RequireTier = 'base-container',
    # Run the git-only cases with Win32k blocked (the ProcessContainer default).
    [switch] $GitWithoutUi
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutDir | Out-Null

$sbx  = 'C:\sbx'
$bb   = "$sbx\bb"
$work = "$sbx\work"
$git  = "$sbx\git"
$outside = "$sbx\outside"
Remove-Item -Recurse -Force $sbx -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $bb, $work, "$work\home", "$work\tmp", $outside | Out-Null
Copy-Item $BusyboxExe "$bb\busybox.exe"
Copy-Item $BusyboxExe "$bb\sh.exe"     # git looks up "sh" on PATH
"secret" | Set-Content "$outside\secret.txt"
$haveGit = $GitRoot -and (Test-Path "$GitRoot\bin\git.exe")
if ($haveGit) { Copy-Item -Recurse $GitRoot $git }

$env:WXC_SCRATCH = $OutDir
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-Mxc {
    param(
        [string] $Name,
        [string] $CommandLine,
        [ValidateSet('pass','fail','info')] [string] $Expect = 'pass',
        [string] $MustContain,
        [switch] $Network,
        [switch] $HostLoopback,
        [switch] $Ui,
        [string] $Cwd = $work
    )
    $req = [ordered]@{
        version     = '1.0.0'
        containerId = "gitprobe-$($results.Count)"
        containment = 'processcontainer'
        process     = [ordered]@{
            commandLine       = $CommandLine
            cwd               = $Cwd
            timeout           = 120000
            inheritDefaultEnv = $true
            env = @(
                "PATH=$git\bin;$bb;C:\Windows\System32;C:\Windows",
                "HOME=$work\home", "USERPROFILE=$work\home",
                "TMP=$work\tmp", "TEMP=$work\tmp",
                'GIT_CONFIG_NOSYSTEM=1', 'GIT_AUTHOR_NAME=mxc', 'GIT_AUTHOR_EMAIL=mxc@example.com',
                'GIT_COMMITTER_NAME=mxc', 'GIT_COMMITTER_EMAIL=mxc@example.com'
            )
        }
        filesystem  = [ordered]@{
            readonlyPaths  = @(@($bb) + $(if ($haveGit) { @($git) } else { @() }) | Where-Object { -not $_.StartsWith("$work\") })
            readwritePaths = @($work)
        }
    }
    if ($Network) {
        $req.processContainer = @{ capabilities = @('internetClient') }
        $req.network = [ordered]@{
            egress  = @{ default = 'allow' }
            ingress = [ordered]@{ default = 'deny'; hostLoopback = $(if ($HostLoopback) { 'allow' } else { 'deny' }) }
        }
    }
    # busybox-w32 links user32; its DLL init fails when Win32k is blocked (the default).
    if ($Ui) { $req.ui = @{ disable = $false } }
    $cfg = Join-Path $OutDir "$Name.json"
    $req | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $cfg
    Write-Host "::group::$Name  [$CommandLine]"
    $out = & $WxcExec $cfg 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $text = $out -join "`n"
    Write-Host $text
    Write-Host "exit=$code"
    Write-Host '::endgroup::'
    $ok = switch ($Expect) {
        'pass' { $code -eq 0 -and (-not $MustContain -or $text -match $MustContain) }
        'fail' { $code -ne 0 -or ($MustContain -and $text -notmatch $MustContain) }
        'info' { $true }
    }
    $tail = (($out | Select-Object -Last 3) -join ' / ').Replace('|', '/')
    $results.Add([pscustomobject]@{ Name = $Name; Expect = $Expect; Exit = $code; Ok = $ok; Tail = $tail })
}

# --- Host capability -------------------------------------------------------
Write-Host '::group::wxc-exec --probe'
$probe = & $WxcExec --probe 2>&1 | Out-String
Write-Host $probe
Write-Host '::endgroup::'
$probe | Set-Content (Join-Path $OutDir 'probe.json')
$os = Get-CimInstance Win32_OperatingSystem
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
$osLine = "$($os.Caption) build $($os.BuildNumber).$ubr ($env:PROCESSOR_ARCHITECTURE)"
Write-Host "Host: $osLine"
$tier = $null
try { $tier = ($probe | ConvertFrom-Json).tier } catch { }
if ($RequireTier -and $tier -ne $RequireTier) {
    $msg = "ProcessContainer tier is '$($tier ?? '<none>')', not '$RequireTier', on $osLine. " +
           "Native PSEC needs Windows 11 24H2/25H2 build 26100.9278/26200.9278 or later (26H1: 28000.2804); " +
           "see mxc docs/backends/process-container/os-version-support.md."
    if ($env:GITHUB_STEP_SUMMARY) {
        @("### MXC ProcessContainer: $osLine", '', "**Not run:** $msg", '', '```json', $probe.Trim(), '```') -join "`n" |
            Add-Content $env:GITHUB_STEP_SUMMARY
    }
    Write-Host "::error::$msg"
    exit 1
}

# --- Baseline ---------------------------------------------------------------
Invoke-Mxc 'baseline-cmd' 'cmd.exe /c echo hello-from-container' -MustContain 'hello-from-container'
Invoke-Mxc 'containment-write-outside' "cmd.exe /c echo x> $outside\pwned.txt" -Expect fail
Invoke-Mxc 'containment-read-outside' "cmd.exe /c type $outside\secret.txt" -Expect info

# --- Executing tools from inside the container ----------------------------
# wxc-exec starts the top-level process itself; children are started by the
# contained process. Check whether a contained process may execute files from
# a readonlyPaths grant and from a readwritePaths grant.
New-Item -ItemType Directory -Force "$work\tools\bb" | Out-Null
Copy-Item "$bb\busybox.exe", "$bb\sh.exe" "$work\tools\bb"
Invoke-Mxc 'exec-child-from-readonly-path'  "cmd.exe /c $bb\busybox.exe echo child-ran" -Expect info -MustContain 'child-ran' -Ui
Invoke-Mxc 'exec-child-from-readwrite-path' "cmd.exe /c $work\tools\bb\busybox.exe echo child-ran" -Expect info -MustContain 'child-ran' -Ui
$roExec = ($results | Where-Object Name -eq 'exec-child-from-readonly-path').Exit -eq 0
$rwExec = ($results | Where-Object Name -eq 'exec-child-from-readwrite-path').Exit -eq 0
Write-Host "child exec from readonlyPaths: $roExec; from readwritePaths: $rwExec"
if (-not $roExec -and $rwExec) {
    # Run the remaining cases with the tools in the writable workspace, so the
    # results show what git and busybox do once they can start each other.
    Write-Host '::warning::Contained processes cannot execute files under readonlyPaths; relocating busybox and git into the readwrite workspace.'
    $bb = "$work\tools\bb"
    if ($haveGit) { Copy-Item -Recurse $git "$work\tools\git"; $git = "$work\tools\git" }
}

# --- busybox-w32 ------------------------------------------------------------
Invoke-Mxc 'bb-default-ui-policy' "$bb\busybox.exe --help" -Expect info
Invoke-Mxc 'bb-version'   "$bb\busybox.exe --help" -MustContain 'BusyBox' -Ui
Invoke-Mxc 'bb-sh-basic'  "$bb\busybox.exe sh -c `"echo hi; pwd; uname -a; echo `$((6*7))`"" -MustContain '42' -Ui
Invoke-Mxc 'bb-sh-pipes'  "$bb\busybox.exe sh -c `"seq 1 100 | awk '{s+=`$1} END {print s}' | sed 's/^/sum=/'`"" -MustContain 'sum=5050' -Ui
Invoke-Mxc 'bb-sh-files'  "$bb\busybox.exe sh -c `"mkdir -p d && echo abc > d/f && cat d/f | tr a-z A-Z && ls -l d && rm -r d`"" -MustContain 'ABC' -Ui
Invoke-Mxc 'bb-sh-subshell-func' "$bb\busybox.exe sh -c `"f() { echo fn:`$1; }; (f sub); x=`$(f cmd); echo `$x; for i in 1 2 3; do echo it`$i; done`"" -MustContain 'it3' -Ui
Invoke-Mxc 'bb-sh-spawn-native' "$bb\busybox.exe sh -c `"cmd.exe /c echo native-child; echo rc=`$?`"" -MustContain 'native-child' -Ui
Invoke-Mxc 'bb-sh-write-outside' "$bb\busybox.exe sh -c `"echo x > C:/sbx/outside/bb.txt`"" -Expect fail -Ui
Invoke-Mxc 'bb-as-sh.exe' "$bb\sh.exe -c `"echo via-sh-exe`"" -MustContain 'via-sh-exe' -Ui

# --- native git -------------------------------------------------------------
if ($haveGit) {
    $g = "$git\bin\git.exe"
    $gitUi = -not $GitWithoutUi
    Invoke-Mxc 'git-version' "$g --version --build-options" -MustContain 'git version' -Ui:$gitUi
    Invoke-Mxc 'git-init-commit-log' ("cmd.exe /c `"$g init -q r1 && cd r1 && echo hello> a.txt && $g add a.txt && " +
        "$g commit -q -m first && echo more>> a.txt && $g commit -q -am second && $g log --oneline && $g status --short && $g diff HEAD~1 --stat`"") -MustContain 'second' -Ui:$gitUi
    Invoke-Mxc 'git-branch-merge' ("cmd.exe /c `"cd r1 && $g switch -q -c topic && echo t> t.txt && $g add t.txt && $g commit -q -m topic && " +
        "$g switch -q master && $g merge -q --no-ff -m merged topic && $g log --graph --oneline -5`"") -MustContain 'merged' -Ui:$gitUi
    Invoke-Mxc 'git-clone-no-local' "$g clone -q --no-local r1 r2" -Ui:$gitUi  # spawns upload-pack
    Invoke-Mxc 'git-gc-fsck' "cmd.exe /c `"cd r2 && $g gc -q && $g fsck && $g count-objects -v`"" -MustContain 'count' -Ui:$gitUi
    Invoke-Mxc 'git-stash-rebase' ("cmd.exe /c `"cd r2 && echo w>> a.txt && $g stash -q && $g stash list && $g stash pop -q && $g checkout -q -- . && " +
        "$g rebase -q HEAD~1 && $g log --oneline -1`"") -Ui:$gitUi
    Invoke-Mxc 'git-write-outside' "$g init -q $outside\repo" -Expect fail -Ui:$gitUi

    # Features that need a POSIX shell, served by busybox sh.exe on PATH.
    Invoke-Mxc 'git-config-shell-alias' "$g -C r1 config alias.hi `"!echo alias-ran-in-sh `$((1+1))`"" -Ui
    Invoke-Mxc 'git-shell-alias' "$g -C r1 hi" -MustContain 'alias-ran-in-sh 2' -Ui
    Invoke-Mxc 'git-shell-alias-default-ui-policy' "$g -C r1 hi" -Expect info
    Invoke-Mxc 'git-hook' ("$bb\sh.exe -c `"cd r1 && printf '#!/bin/sh\necho hook-ran-from-busybox\n' > .git/hooks/pre-commit && " +
        "git commit -q --allow-empty -m hooked`"") -MustContain 'hook-ran-from-busybox' -Ui
    Invoke-Mxc 'git-sequence-editor' ("$bb\sh.exe -c `"cd r1 && GIT_SEQUENCE_EDITOR='sed -i 1s/^pick/reword/' GIT_EDITOR='sed -i 1s/.*/reworded-by-sed/' " +
        "git rebase -q -i HEAD~1 && git log -1 --format=%s`"") -MustContain 'reworded-by-sed' -Ui
    Invoke-Mxc 'git-filter-branch-sh-script' ("$bb\sh.exe -c `"cd r2 && FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --msg-filter 'sed s/^/fb:/' HEAD~1..HEAD && git log -1 --format=%s`"") -MustContain 'fb:' -Ui
    Invoke-Mxc 'git-difftool-extcmd' "$bb\sh.exe -c `"cd r1 && git difftool -y --extcmd='diff -u' HEAD~2 HEAD -- a.txt; echo rc=`$?`"" -MustContain 'more' -Ui
    Invoke-Mxc 'git-sh-scripts-in-busybox' "$bb\sh.exe -c `"cd r1 && . `$(git --exec-path)/git-sh-setup && echo top=`$(git rev-parse --show-toplevel)`"" -MustContain 'top=' -Ui
    Invoke-Mxc 'git-submodule-sh-wrapper' "$bb\sh.exe -c `"cd r1 && git -c protocol.file.allow=always submodule add -q C:/sbx/work/r2 sub && git submodule status`"" -MustContain ' sub' -Ui
    Invoke-Mxc 'git-https-ls-remote' "$g ls-remote https://github.com/git/git refs/heads/master" -Expect info -Network -Ui:$gitUi
    Invoke-Mxc 'git-https-ls-remote-schannel' "$g -c http.sslBackend=schannel ls-remote https://github.com/git/git refs/heads/master" -Expect info -Network -Ui:$gitUi
    Invoke-Mxc 'git-https-ls-remote-schannel-loopback' "$g -c http.sslBackend=schannel ls-remote https://github.com/git/git refs/heads/master" -Expect info -Network -HostLoopback -Ui:$gitUi
}

# --- Report -----------------------------------------------------------------
$results | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
$results | ConvertTo-Json | Set-Content (Join-Path $OutDir 'results.json')
$md = @("### MXC ProcessContainer: $osLine", '', '```json', $probe.Trim(), '```', '',
        '| Case | Expect | Exit | Result | Output tail |', '|---|---|---|---|---|')
foreach ($r in $results) {
    $md += "| $($r.Name) | $($r.Expect) | $($r.Exit) | $(if ($r.Ok) { 'ok' } else { '**FAIL**' }) | ``$($r.Tail)`` |"
}
if ($env:GITHUB_STEP_SUMMARY) { $md -join "`n" | Add-Content $env:GITHUB_STEP_SUMMARY }
$failed = @($results | Where-Object { -not $_.Ok })
if ($failed.Count) { Write-Host "::error::$($failed.Count) case(s) failed: $($failed.Name -join ', ')"; exit 1 }
