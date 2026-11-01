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
$outside = "C:\sbx-outside"   # deliberately not under $sbx
Remove-Item -Recurse -Force $sbx, $outside -ErrorAction SilentlyContinue
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
        [string[]] $ExtraReadonly = @(),
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
                # Every launch is a new container identity, so files created by
                # an earlier launch fail git's ownership check.
                'GIT_PAGER=cat', 'PAGER=cat',
                'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=*',
                'GIT_COMMITTER_NAME=mxc', 'GIT_COMMITTER_EMAIL=mxc@example.com'
            )
        }
        filesystem  = [ordered]@{
            readonlyPaths  = @(@($bb) + $(if ($haveGit) { @($git) } else { @() }) + $ExtraReadonly + $script:ParentGrant |
                               Where-Object { $_ -and -not $_.StartsWith("$work\") } | Select-Object -Unique)
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
# contained process. Find out what a contained process needs to start a
# binary from a readonlyPaths or readwritePaths grant.
$script:ParentGrant = @()
New-Item -ItemType Directory -Force "$work\tools\bb" | Out-Null
Copy-Item "$bb\busybox.exe", "$bb\sh.exe" "$work\tools\bb"
Invoke-Mxc 'exec-cmd-child-system32'        "cmd.exe /c whoami.exe" -Expect info -Ui
Invoke-Mxc 'exec-cmd-child-readonly'        "cmd.exe /c $bb\busybox.exe echo child-ran" -Expect info -MustContain 'child-ran' -Ui
Invoke-Mxc 'exec-cmd-child-readwrite'       "cmd.exe /c $work\tools\bb\busybox.exe echo child-ran" -Expect info -MustContain 'child-ran' -Ui
Invoke-Mxc 'exec-bb-child-readonly'         "$bb\busybox.exe sh -c `"$($bb -replace '\\','/')/busybox.exe echo child-ran`"" -Expect info -MustContain 'child-ran' -Ui
Invoke-Mxc 'exec-bb-child-readwrite'        "$bb\busybox.exe sh -c `"$($work -replace '\\','/')/tools/bb/busybox.exe echo child-ran`"" -Expect info -MustContain 'child-ran' -Ui
Invoke-Mxc 'exec-cmd-child-readonly-parent-granted' "cmd.exe /c $bb\busybox.exe echo child-ran" -Expect info -MustContain 'child-ran' -Ui -ExtraReadonly $sbx
$ok = { param($n) [bool]($results | Where-Object { $_.Name -eq $n -and $_.Exit -eq 0 }) }
if (-not (& $ok 'exec-cmd-child-readonly') -and (& $ok 'exec-cmd-child-readonly-parent-granted')) {
    Write-Host '::warning::Contained cmd.exe could start a granted binary only after the parent C:\sbx was also granted read-only; granting it for the remaining cases.'
    $script:ParentGrant = @($sbx)
}

# --- busybox-w32 ------------------------------------------------------------
Invoke-Mxc 'bb-default-ui-policy' "$bb\busybox.exe --help" -Expect info
Invoke-Mxc 'bb-version'   "$bb\busybox.exe --help" -MustContain 'BusyBox' -Ui
Invoke-Mxc 'bb-sh-basic'  "$bb\busybox.exe sh -c `"echo hi; pwd; uname -a; echo `$((6*7))`"" -MustContain '42' -Ui
Invoke-Mxc 'bb-sh-pipes'  "$bb\busybox.exe sh -c `"seq 1 100 | awk '{s+=`$1} END {print s}' | sed 's/^/sum=/'`"" -MustContain 'sum=5050' -Ui
Invoke-Mxc 'bb-sh-files'  "$bb\busybox.exe sh -c `"mkdir -p d && echo abc > d/f && cat d/f | tr a-z A-Z && ls -l d && rm -r d`"" -MustContain 'ABC' -Ui
Invoke-Mxc 'bb-sh-subshell-func' "$bb\busybox.exe sh -c `"f() { echo fn:`$1; }; (f sub); x=`$(f cmd); echo `$x; for i in 1 2 3; do echo it`$i; done`"" -MustContain 'it3' -Ui
Invoke-Mxc 'bb-sh-spawn-native' "$bb\busybox.exe sh -c `"cmd.exe /c echo native-child; echo rc=`$?`"" -MustContain 'native-child' -Ui
Invoke-Mxc 'bb-sh-write-outside' "$bb\busybox.exe sh -c `"echo x > C:/sbx-outside/bb.txt`"" -Expect fail -Ui
Invoke-Mxc 'bb-as-sh.exe' "$bb\sh.exe -c `"echo via-sh-exe`"" -MustContain 'via-sh-exe' -Ui

# --- native git -------------------------------------------------------------
if ($haveGit) {
    $g = "$git\bin\git.exe"
    $gitUi = -not $GitWithoutUi
    $sh = "$bb\sh.exe"
    # Each case is a fresh container; the repositories persist in $work.
    # Direct launches: wxc-exec starts git, and git starts its own children
    # (upload-pack for clone, pack-objects/repack for gc).
    Invoke-Mxc 'git-version'        "$g --version --build-options" -MustContain 'git version' -Ui:$gitUi
    Invoke-Mxc 'git-init'           "$g init -q r1" -Ui:$gitUi
    Invoke-Mxc 'git-commit'         "$g -C r1 commit -q --allow-empty -m first" -Ui:$gitUi
    Invoke-Mxc 'git-switch-topic'   "$g -C r1 switch -q -c topic" -Ui:$gitUi
    Invoke-Mxc 'git-commit-topic'   "$g -C r1 commit -q --allow-empty -m topic" -Ui:$gitUi
    Invoke-Mxc 'git-switch-master'  "$g -C r1 switch -q master" -Ui:$gitUi
    Invoke-Mxc 'git-merge'          "$g -C r1 merge -q --no-ff -m merged topic" -Ui:$gitUi
    Invoke-Mxc 'git-log'            "$g -C r1 log --graph --oneline" -MustContain 'merged' -Ui:$gitUi
    Invoke-Mxc 'git-clone-no-local' "$g clone -q --no-local r1 r2" -Ui:$gitUi
    Invoke-Mxc 'git-gc'             "$g -C r2 gc" -Ui:$gitUi
    Invoke-Mxc 'git-fsck'           "$g -C r2 fsck" -Ui:$gitUi
    Invoke-Mxc 'git-count-objects'  "$g -C r2 count-objects -v" -MustContain 'in-pack' -Ui:$gitUi
    Invoke-Mxc 'git-write-outside'  "$g init -q $outside\repo" -Expect fail -Ui:$gitUi
    Invoke-Mxc 'git-https-ls-remote'                   "$g ls-remote https://github.com/git/git refs/heads/master" -Expect info -Network -Ui:$gitUi
    Invoke-Mxc 'git-https-ls-remote-loopback'          "$g ls-remote https://github.com/git/git refs/heads/master" -Expect info -Network -HostLoopback -Ui:$gitUi
    Invoke-Mxc 'git-https-ls-remote-schannel-loopback' "$g -c http.sslBackend=schannel ls-remote https://github.com/git/git refs/heads/master" -MustContain 'refs/heads/master' -Network -HostLoopback -Ui:$gitUi

    # busybox sh driving git, and git starting busybox sh (needs Win32k for busybox).
    # Output of the last external command in "sh -c" went missing in earlier runs.
    # Compare inside vs outside the container, and with a trailing builtin.
    $savedPath = $env:PATH; $env:PATH = "$git\bin;$bb;$env:SystemRoot\System32;$env:SystemRoot"
    $hostOut = & $sh -c 'cd C:/sbx; git --version' 2>&1 | Out-String
    $env:PATH = $savedPath
    Write-Host "host (no container) sh -c 'git --version' => [$($hostOut.Trim())]"
    $results.Add([pscustomobject]@{ Name = 'host-sh-last-external-output'; Expect = 'info'; Exit = $LASTEXITCODE; Ok = $true; Tail = $hostOut.Trim() })
    Invoke-Mxc 'sh-last-external-output'   "$sh -c `"git --version`"" -Expect info -MustContain 'git version' -Ui
    Invoke-Mxc 'sh-last-builtin-output'    "$sh -c `"git --version; echo end`"" -Expect info -MustContain 'git version' -Ui
    Invoke-Mxc 'sh-last-external-native'   "$sh -c `"cmd.exe /c echo from-cmd`"" -Expect info -MustContain 'from-cmd' -Ui
    Invoke-Mxc 'sh-starts-git'      "$sh -c `"git --version; echo rc=`$?`"" -MustContain 'rc=0' -Ui
    Invoke-Mxc 'sh-edit-diff-commit' ("$sh -c `"cd r1 && echo hello > a.txt && git add a.txt && git commit -q -m add-a && echo more >> a.txt && " +
        "git diff --stat && git commit -q -am more && git log --oneline -3; echo end=`$?`"") -MustContain 'more' -Ui
    Invoke-Mxc 'sh-stash'           "$sh -c `"cd r1 && echo w >> a.txt && git stash -q && git stash list && git stash pop -q && git checkout -q -- . && git status --short; echo end=`$?`"" -MustContain 'stash@' -Ui
    Invoke-Mxc 'git-config-shell-alias' "$g -C r1 config alias.hi `"!echo alias-ran-in-sh `$((1+1))`"" -Ui:$gitUi
    Invoke-Mxc 'git-shell-alias'    "$g -C r1 hi" -MustContain 'alias-ran-in-sh 2' -Ui
    Invoke-Mxc 'git-hook' ("$sh -c `"cd r1 && printf '#!/bin/sh\necho hook-ran-from-busybox\n' > .git/hooks/pre-commit && " +
        "git commit -q --allow-empty -m hooked; echo end=`$?`"") -MustContain 'hook-ran-from-busybox' -Ui
    Invoke-Mxc 'git-sequence-editor' ("$sh -c `"cd r1 && GIT_SEQUENCE_EDITOR='sed -i 1s/^pick/reword/' GIT_EDITOR='sed -i 1s/.*/reworded-by-sed/' " +
        "git rebase -q -i HEAD~1 && git log -1 --format=%s; echo end=`$?`"") -MustContain 'reworded-by-sed' -Ui
    Invoke-Mxc 'git-difftool-extcmd' "$sh -c `"cd r1 && git difftool -y --extcmd='diff -u' HEAD~3 HEAD -- a.txt; echo end=`$?`"" -MustContain 'more' -Ui
    Invoke-Mxc 'git-sh-setup'       "$sh -c `"cd r1 && . `$(git --exec-path)/git-sh-setup && echo top=`$(git rev-parse --show-toplevel)`"" -MustContain 'top=' -Ui
    Invoke-Mxc 'git-filter-branch'  "$sh -c `"cd r2 && FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --msg-filter 'sed s/^/fb:/' HEAD~1..HEAD && git log -1 --format=%s; echo end=`$?`"" -MustContain 'fb:' -Ui
    Invoke-Mxc 'git-submodule'      "$sh -c `"cd r1 && git -c protocol.file.allow=always submodule add -q C:/sbx/work/r2 sub && git submodule status; echo end=`$?`"" -MustContain ' sub' -Ui
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
