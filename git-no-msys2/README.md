# Git for Windows without MSYS2, inside MXC ProcessContainer

`.github/workflows/git-no-msys2.yml` builds upstream `git/git` for Windows with
Meson and MSVC, using no MSYS2 at build or run time. It then runs that git and
busybox-w32 inside an MXC ProcessContainer on the native BaseContainer (PSEC)
tier.

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

With `ui.disable: false` (Win32k allowed), every case passes. That covers:

- init, commit, switch, merge, log, `clone --no-local` (git starts
  `upload-pack`), gc (git starts `pack-objects`), fsck, count-objects, stash,
  diff.

- HTTPS `ls-remote` against github.com with OpenSSL and with Schannel.

- From busybox `sh`: a `pre-commit` hook, a `!` alias, `rebase -i` with `sed`
  as `GIT_SEQUENCE_EDITOR` and `GIT_EDITOR`, `difftool --extcmd`,
  `git-sh-setup`, `filter-branch`, and `submodule add`/`status`.

- Writes outside `readwritePaths` fail with `Permission denied` from git,
  busybox and `cmd.exe`.

busybox-w32 works for the shell, pipes, awk/sed/tr, functions, subshells, file
I/O, and starting native programs.

## Constraints found

1. **Both binaries need Win32k.** busybox-w32 imports `user32.dll`, and so does
   every git binary, because git's `poll()` emulation (`compat/poll/poll.c`)
   pumps window messages. Under the default UI policy both fail at load with
   `STATUS_DLL_INIT_FAILED (0xC0000142)`.

   Linking git with `/DELAYLOAD:user32.dll` lets git start with Win32k blocked.
   Local commands, HTTPS, hooks and aliases still work. Any command that starts
   a transport subprocess and polls its pipes (`clone`, `fetch` over `file://`,
   `submodule add`) fails. Running fully under the default policy would need
   git's `poll()` changed to wait without the message pump.

2. **HTTPS needs host loopback.** With `network.ingress.hostLoopback: deny`, curl
   fails with `getaddrinfo() thread failed to start`. Its resolver thread
   signals through a loopback socket pair. `hostLoopback: allow` fixes it.

3. **Each launch is a new container identity.** A repository created by one
   launch fails git's ownership check in the next one. The tests set
   `safe.directory=*` through `GIT_CONFIG_COUNT`.

4. **Contained `cmd.exe` cannot start binaries from granted paths.** It gets
   `Access is denied` for both `readonlyPaths` and `readwritePaths`, even with
   the parent folder granted. It can still start System32 tools. git and
   busybox can start each other from the same paths, so the tests launch git
   directly or through busybox `sh`.

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
