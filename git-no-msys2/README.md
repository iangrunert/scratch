# Git for Windows without MSYS2, inside MXC ProcessContainer

`.github/workflows/git-no-msys2.yml` builds upstream `git/git` for Windows with
Meson and MSVC, using no MSYS2 at build or run time. It then runs that git and
busybox-w32 inside an MXC ProcessContainer on the native BaseContainer (PSEC)
tier, and compares the results with the standard Git for Windows, which uses
MSYS2.

## What the workflow does

| Job | Runner | What it does |
|---|---|---|
| `build` | `windows-2025` (x64), `windows-11-arm` (arm64, plus a variant that delay-loads `user32.dll`) | `build-git.ps1`: hides `C:\msys64`, Git for Windows, Strawberry Perl and MinGW. Puts busybox-w32 on Meson's `sane_tool_path`, then builds and installs with `meson --vsenv`. `check_imports.py` fails the build if any PE file imports `msys-*.dll` or `cygwin1.dll`. |
| `build-mxc` | `windows-11-arm` | Builds `wxc-exec.exe` from `iangrunert/mxc` `main`. Current MXC has no AppContainer fallback tier. |
| `mxc` | `windows-11-arm` | `test-in-mxc.ps1`: stops unless `wxc-exec --probe` reports `tier: base-container`. Then runs each case as its own `wxc-exec` launch. |

Only `windows-11-arm` (Windows 11 build 26200) has the PSEC API set.
`windows-2025` is Windows Server: its probe reports
`baseContainerApiPresent: false`, so it cannot run the BaseContainer tier.
MXC 1.0.1 from npm silently falls back to AppContainer + DACL there.

## What git uses MSYS2 for

`git.exe` itself is a native Win32 program. Git for Windows uses MSYS2 for:

- **Building.** The MinGW-w64 toolchain, `make`, and Unix tools used to generate
  sources (`sh`, `sed`, `awk`, `tr`, `sort` and others). Meson + MSVC replaces
  the toolchain. Meson's `subprojects/` wraps build zlib, curl, OpenSSL, expat
  and PCRE2 statically, and busybox-w32 can supply all the generator tools.

- **A POSIX shell at run time.** git looks up `sh` on `PATH` for hooks, `!`
  aliases, editor, pager and credential-helper commands that contain shell
  syntax, `GIT_SEQUENCE_EDITOR`, and `difftool`/`mergetool` commands. It also
  needs `sh` for the commands still written as shell scripts: `git submodule`
  (a wrapper), `filter-branch`, `mergetool`, `difftool--helper`,
  `request-pull`, `quiltimport`, `web--browse`, `merge-octopus`,
  `merge-resolve`, `merge-one-file`, and `git-sh-setup` for third-party
  scripts. busybox-w32 `sh` (copied as `sh.exe` onto `PATH`) covers all the
  cases tested.

- **Perl.** `send-email`, `svn`, `cvsimport`/`cvsserver`/`cvsexportcommit`,
  `archimport` and `instaweb`. This build disables Perl, so those commands are
  absent.

- **Bundled programs.** `less` (default pager), `vi` (default editor), OpenSSH,
  GnuPG, Tcl/Tk for `gitk` and `git gui`, and `bash` for completion. None of
  these are in this build. Windows' built-in OpenSSH, or busybox's `less` and
  `vi`, can stand in.

## Results on `windows-11-arm`, BaseContainer tier

The `mxc` job also runs the same cases with the runner's Git for Windows
2.56.0.windows.3 (MinGW git plus the MSYS2 runtime and bash, used as `sh`).

| Case | This build, Win32k allowed | This build, `user32` delay-loaded, Win32k blocked for git launches (busybox cases still allowed) | Git for Windows, Win32k allowed | Git for Windows, Win32k blocked |
|---|---|---|---|---|
| `git --version`, init, commit, switch, merge, log | pass | pass | pass | fails at load (`STATUS_DLL_INIT_FAILED`) |
| `clone --no-local` (starts `upload-pack` through `sh`), then gc, fsck | pass | fails: busybox `sh` needs Win32k | fails: MSYS2 `sh` | fails at load |
| HTTPS `ls-remote` to github.com | pass (needs `hostLoopback: allow`) | pass (same) | pass, also without host loopback | fails at load |
| `sh` itself | busybox: pass | busybox: pass | MSYS2 bash: fails | MSYS2 bash: fails |
| Hook, `!` alias, `rebase -i` with `sed` editors, `difftool --extcmd`, `git-sh-setup`, `filter-branch`, `submodule add` | pass | pass, except `filter-branch` and `submodule add`, which need a clone | fail (need `sh`) | fail |
| Write outside `readwritePaths` | denied | denied | denied | fails at load |

In the container, every MSYS2 program dies at startup:

```
sh.exe: *** fatal error - NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0S5-…): 0xC0000022
```

The MSYS2 runtime (`msys-2.0.dll`, a Cygwin fork) creates a named-object
directory in `\BaseNamedObjects` for its shared memory. The container denies
that (`STATUS_ACCESS_DENIED`), whether or not Win32k is allowed. This takes out
`sh`/bash, the Unix tools in `usr\bin`, and every git feature that goes through
`sh`. git starts `upload-pack` for local and SSH remotes through `sh` (`connect.c`),
so `clone --no-local` fails too. Its MinGW `git.exe` imports `user32.dll` for the
same `poll()` reason as this build.

busybox-w32 works for the shell, pipes, awk/sed/tr, functions, subshells, file
I/O, and starting native programs.

## Constraints found

1. **Both binaries need Win32k.** busybox-w32 imports `user32.dll`, and so does
   every git binary, because git's `poll()` emulation (`compat/poll/poll.c`)
   pumps window messages. Under the default UI policy both fail at load with
   `STATUS_DLL_INIT_FAILED (0xC0000142)`.

   Linking git with `/DELAYLOAD:user32.dll` lets git start and run local
   commands and HTTPS with Win32k blocked. Commands that go through `sh` still
   fail there, because busybox-w32 needs Win32k. That includes `clone` and
   `fetch` from a local path or over SSH: `connect.c` runs `git-upload-pack
   '<path>'` through `sh`. A shell that does not import `user32.dll` would be
   needed to run fully under the default policy.

2. **HTTPS needs host loopback.** With `network.ingress.hostLoopback: deny`, curl
   fails with `getaddrinfo() thread failed to start`. Its resolver thread
   signals through a loopback socket pair. `hostLoopback: allow` fixes it.

3. **Each launch is a new container identity.** A repository created by one
   launch fails git's ownership check in the next one. The tests set
   `safe.directory=*` through `GIT_CONFIG_COUNT`.

4. **Contained `cmd.exe` cannot start busybox or this git.** It gets
   `Access is denied` for both, from `readonlyPaths` and `readwritePaths`, even
   with the parent folder granted and Win32k allowed. It can start System32's
   `whoami.exe` and MSYS2's `whoami.exe` from a granted path. Both binaries it
   fails on import `user32.dll`. busybox `sh` and git can start each other and
   their children, so the tests launch git directly or through busybox `sh`.

5. **Output of the last command in `sh -c` is lost inside the container.**
   `sh -c "git --version"` prints nothing in the container (exit code 0),
   but prints normally on the host. Adding a trailing builtin
   (`...; echo end=$?`) keeps the output.

6. **Meson's Windows install needs post-processing.** `build-git.ps1` does two
   fix-ups:

   - Meson installs `bin\git` and the dashed builtins as symlinks to names
     without `.exe`, which do not resolve. They are replaced with real `.exe`
     copies.

   - Meson substitutes the build-time shell path for `SHELL_PATH` in the
     installed scripts, with backslashes stripped (`C:a_tempbbtoolssh.exe`).
     It is rewritten to `sh`, which git resolves on `PATH`.

   Also, `git-imap-send.exe` links an OpenSSL DLL that is not installed.
