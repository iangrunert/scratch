# Run native git and busybox-w32 inside an MXC ProcessContainer via wxc-exec.
param(
    [Parameter(Mandatory)] [string] $WxcExec,
    [string] $GitRoot,            # install prefix containing bin\git.exe (optional)
    [Parameter(Mandatory)] [string] $BusyboxExe,
    [Parameter(Mandatory)] [string] $OutDir
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
            readonlyPaths  = @($bb) + $(if ($haveGit) { @($git) } else { @() })
            readwritePaths = @($work)
        }
    }
    if ($Network) { $req.processContainer = @{ capabilities = @('internetClient') } }
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

# --- Baseline ---------------------------------------------------------------
Invoke-Mxc 'baseline-cmd' 'cmd.exe /c echo hello-from-container' -MustContain 'hello-from-container'
Invoke-Mxc 'containment-write-outside' "cmd.exe /c echo x> $outside\pwned.txt" -Expect fail
Invoke-Mxc 'containment-read-outside' "cmd.exe /c type $outside\secret.txt" -Expect info

# --- busybox-w32 ------------------------------------------------------------
Invoke-Mxc 'bb-version'   "$bb\busybox.exe --help" -MustContain 'BusyBox'
Invoke-Mxc 'bb-sh-basic'  "$bb\busybox.exe sh -c `"echo hi; pwd; uname -a; echo `$((6*7))`"" -MustContain '42'
Invoke-Mxc 'bb-sh-pipes'  "$bb\busybox.exe sh -c `"seq 1 100 | awk '{s+=`$1} END {print s}' | sed 's/^/sum=/'`"" -MustContain 'sum=5050'
Invoke-Mxc 'bb-sh-files'  "$bb\busybox.exe sh -c `"mkdir -p d && echo abc > d/f && cat d/f | tr a-z A-Z && ls -l d && rm -r d`"" -MustContain 'ABC'
Invoke-Mxc 'bb-sh-subshell-func' "$bb\busybox.exe sh -c `"f() { echo fn:`$1; }; (f sub); x=`$(f cmd); echo `$x; for i in 1 2 3; do echo it`$i; done`"" -MustContain 'it3'
Invoke-Mxc 'bb-sh-spawn-native' "$bb\busybox.exe sh -c `"cmd.exe /c echo native-child; echo rc=`$?`"" -MustContain 'native-child'
Invoke-Mxc 'bb-sh-write-outside' "$bb\busybox.exe sh -c `"echo x > C:/sbx/outside/bb.txt`"" -Expect fail
Invoke-Mxc 'bb-as-sh.exe' "$bb\sh.exe -c `"echo via-sh-exe`"" -MustContain 'via-sh-exe'

# --- native git -------------------------------------------------------------
if ($haveGit) {
    $g = "$git\bin\git.exe"
    Invoke-Mxc 'git-version' "$g --version --build-options" -MustContain 'git version'
    Invoke-Mxc 'git-init-commit-log' ("cmd.exe /c `"$g init -q r1 && cd r1 && echo hello> a.txt && $g add a.txt && " +
        "$g commit -q -m first && echo more>> a.txt && $g commit -q -am second && $g log --oneline && $g status --short && $g diff HEAD~1 --stat`"") -MustContain 'second'
    Invoke-Mxc 'git-branch-merge' ("cmd.exe /c `"cd r1 && $g switch -q -c topic && echo t> t.txt && $g add t.txt && $g commit -q -m topic && " +
        "$g switch -q master && $g merge -q --no-ff -m merged topic && $g log --graph --oneline -5`"") -MustContain 'merged'
    Invoke-Mxc 'git-clone-no-local' "$g clone -q --no-local r1 r2" # spawns upload-pack
    Invoke-Mxc 'git-gc-fsck' "cmd.exe /c `"cd r2 && $g gc -q && $g fsck && $g count-objects -v`"" -MustContain 'count'
    Invoke-Mxc 'git-stash-rebase' ("cmd.exe /c `"cd r2 && echo w>> a.txt && $g stash -q && $g stash list && $g stash pop -q && $g checkout -q -- . && " +
        "$g rebase -q HEAD~1 && $g log --oneline -1`"")
    Invoke-Mxc 'git-write-outside' "$g init -q $outside\repo" -Expect fail

    # Features that need a POSIX shell, served by busybox sh.exe on PATH.
    Invoke-Mxc 'git-config-shell-alias' "$g -C r1 config alias.hi `"!echo alias-ran-in-sh `$((1+1))`""
    Invoke-Mxc 'git-shell-alias' "$g -C r1 hi" -MustContain 'alias-ran-in-sh 2'
    Invoke-Mxc 'git-hook' ("$bb\sh.exe -c `"cd r1 && printf '#!/bin/sh\necho hook-ran-from-busybox\n' > .git/hooks/pre-commit && " +
        "git commit -q --allow-empty -m hooked`"") -MustContain 'hook-ran-from-busybox'
    Invoke-Mxc 'git-sequence-editor' ("$bb\sh.exe -c `"cd r1 && GIT_SEQUENCE_EDITOR='sed -i 1s/^pick/reword/' GIT_EDITOR='sed -i 1s/.*/reworded-by-sed/' " +
        "git rebase -q -i HEAD~1 && git log -1 --format=%s`"") -MustContain 'reworded-by-sed'
    Invoke-Mxc 'git-filter-branch-sh-script' ("$bb\sh.exe -c `"cd r2 && FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --msg-filter 'sed s/^/fb:/' HEAD~1..HEAD && git log -1 --format=%s`"") -MustContain 'fb:'
    Invoke-Mxc 'git-difftool-extcmd' "$bb\sh.exe -c `"cd r1 && git difftool -y --extcmd='diff -u' HEAD~2 HEAD -- a.txt; echo rc=`$?`"" -MustContain 'more'
    Invoke-Mxc 'git-sh-scripts-in-busybox' "$bb\sh.exe -c `"cd r1 && . `$(git --exec-path)/git-sh-setup && echo top=`$(git rev-parse --show-toplevel)`"" -MustContain 'top='
    Invoke-Mxc 'git-https-ls-remote' "$g ls-remote https://github.com/git/git refs/heads/master" -Expect info -Network
    Invoke-Mxc 'git-https-ls-remote-schannel' "$g -c http.sslBackend=schannel ls-remote https://github.com/git/git refs/heads/master" -Expect info -Network
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
