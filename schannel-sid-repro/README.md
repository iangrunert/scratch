# schantest — which Windows TLS dependency does my sandbox break?

"TLS doesn't work in the sandbox" has at least six distinct causes on Windows,
with different fixes. This walks them in dependency order and reports each
separately, so you stop guessing.

Windows TLS is not self-contained in the process:

- **SSPI → LSASS.** The SChannel provider and CNG key isolation live behind an
  ALPC boundary into `lsass.exe`.
- **crypt32 → HKLM.** Chain building reads
  `HKLM\SOFTWARE\Microsoft\SystemCertificates` and friends.
- **dnsapi → dnscache.** Name resolution is RPC to a service.

A restricting-SID token makes every access check *also* demand the restricting
SID on the object's DACL, and essentially none of those objects carry it. So a
restricted process can fail at any of those three boundaries, and the symptom
is the same vague network error.

## Build

MSVC, from an x64 Native Tools prompt:

```
build.bat
```

Or cross-build from Linux with `mingw-w64`:

```
sh build.sh
```

Both targets compile clean at `/W4` and `-Wall -Wextra`.

## Run

Get a baseline first, unsandboxed — you need to know what "working" prints on
this machine:

```
schantest.exe
```

Then the same binary under the token you're evaluating:

```
runrestricted.exe --restricted -- C:\path\to\schantest.exe
runrestricted.exe --deny-only  -- C:\path\to\schantest.exe
```

`--restricted` adds the RESTRICTED SID (S-1-5-12) as a restricting SID — the
mode that breaks SChannel. `--deny-only` uses deny-only groups and dropped
privileges with *no* restricting SIDs, which is weaker isolation on paper but
leaves SSPI working. Diffing those two runs is the whole experiment.

Useful flags on `schantest.exe`:

| Flag | Effect |
| --- | --- |
| `--validate` | let SChannel build the chain during the handshake instead of validating manually afterwards |
| `--no-handshake` | local probes only, no socket |
| `--quiet-token` | skip the token dump |
| `<host> <port>` | target something other than `www.microsoft.com:443` |

The default is **manual** validation, which is the point: it lets the handshake
succeed even when the certificate stores are unreadable, so you can tell a
broken transport apart from a broken trust store. Run it both ways.

### Two prerequisites that will waste your afternoon

1. **File ACLs.** Under a restricting SID the child cannot read its own image
   unless the file DACL grants that SID. Before the first run:

   ```
   icacls C:\path\to\dir /grant *S-1-5-12:(RX) /t
   ```

   Without this you get `ERROR_ACCESS_DENIED` from `CreateProcessAsUser`, which
   looks nothing like a TLS problem. The launcher prints this hint when it sees
   that error.

2. **The child may not start at all.** `runrestricted` grants the restricting
   SID access to the window station and thread desktop, since a lowbox or
   restricted child can die at DLL *initialisation* (`0xC0000142`) without
   that. But on the CI runner the actual failure is one step earlier:
   `0xC0000135` `STATUS_DLL_NOT_FOUND`, meaning the restricting SID is absent
   from the DACL of some DLL in the import graph, so loading fails before any
   code runs. Both statuses mean the same thing for interpretation: **no code
   ran, so the output says nothing about SSPI either way.** The launcher now
   prints the status in hex with its name, because the decimal forms are easy
   to confuse — `0xC0000135` is 3221225781 and `0xC0000142` is 3221225794, and
   mistaking one for the other sends you after the wrong cause.

## Reading the output

Each probe prints `[ OK ]`, `[FAIL]` with the raw status in hex plus its
`SEC_E_*`/`CERT_E_*` name, or `[skip]`. **The first failure is the diagnosis**
— everything after it is downstream noise.

| First failure | What it means | Where the fix lives |
| --- | --- | --- |
| `EnumerateSecurityPackages`, `QuerySecurityPackageInfo` | SSPI cannot cross ALPC into LSASS. The TLS provider is simply unreachable. | Nothing in-process can fix this. Change the sandbox primitive. |
| `AcquireCredentialsHandle` | Provider reachable, but credential handling / CNG key isolation is blocked. | Same — sandbox primitive. |
| `CertOpenSystemStore`, `HKLM SystemCertificates` | Trust anchors invisible. Note the handshake may still pass with manual validation. | Ship your own trust anchors, or grant the token registry read. |
| `getaddrinfo` | The dnscache RPC endpoint, not TLS at all. Easy to misattribute. | Sandbox primitive, or resolve in the broker. |
| `connect` | No outbound TCP. In an AppContainer this is a missing `internetClient` capability. | Capability or firewall, not TLS. |
| `InitializeSecurityContext` | The handshake proper. Check whether `--validate` changes it — if manual passes and `--validate` fails, it's trust, not transport. | Trust anchors. |
| `CertVerifyChainPolicy` only | Transport is fine; only chain validation fails. | Trust anchors. Revocation checking also wants network. |
| nothing | TLS works end to end under this token. | — |

The two shapes that matter:

- **Probes 1–3 fail** → restricting SIDs are the cause. No amount of
  re-ACLing fixes the LSASS port. Move to a different isolation primitive.
- **Probes 1–3 pass, 4–5 fail** → the sandbox is fine for TLS and you only
  need to get trust anchors in. That's a config problem, not an architecture
  one.

Probes 9–14 (`SECPKG_ATTR_*`, `EncryptMessage`/`DecryptMessage`) double as a
scope estimate: every attribute class printed there is one a hand-written SSPI
shim would have to answer correctly.

## Status

Both binaries cross-compile clean, but **have not been executed on Windows** —
they were written and built on Linux. Expect to fix something small on first
run.

---

# runappcontainer — AppContainer instead of a restricting SID

For tools with no option to switch TLS stacks — `nuget.exe`, `msbuild
-t:restore`, anything on .NET `SslStream` — a restricting SID is unfixable from
inside the process, because the LSA ALPC port that SSPI needs does not grant
restricting SIDs and cannot sensibly be re-ACLed. An AppContainer gets you
comparable isolation with that path intact: `System32`, the LSA port and
`HKLM\SOFTWARE\Microsoft\SystemCertificates` all grant ALL APPLICATION
PACKAGES, so SChannel keeps working.

The isolation model inverts. A lowbox token is granted access only where the
DACL names its **own package SID**, one of its **capability SIDs**, or ALL
APPLICATION PACKAGES — the user SID in the token is not sufficient. So the
default is a process that can read almost nothing of the user's profile, and
every `--grant` below is a deliberate hole you are choosing to open.

Network is denied at the WFP layer unless a capability says otherwise:

| Capability | SID | When you need it |
| --- | --- | --- |
| `internetClient` | S-1-15-3-1 | nuget.org, any public feed |
| `privateNetworkClientServer` | S-1-15-3-3 | **an internal feed** — Artifactory, ProGet, on-prem Azure DevOps |

That second row catches people out: an RFC1918 feed is not "internet", and
`internetClient` alone will not reach it.

## Step 1: confirm the premise

Before plumbing NuGet, point the probe at the sandbox and check that TLS
actually survives:

```
runappcontainer.exe --name tls-check --internet ^
  --grant-ro C:\path\to\schannel-sid-repro ^
  -- C:\path\to\schannel-sid-repro\schantest.exe
```

Probes 1–5 passing is the result that matters: SSPI reached LSASS and the
machine cert stores were readable. Compare against
`runrestricted.exe --restricted` on the same machine, which should fail at
probe 1 or 3. If probes 1–5 pass here, the rest is filesystem plumbing.

## Step 2: NuGet

```
runappcontainer.exe --name nuget-sandbox --internet --nuget-state ^
  --grant-ro "C:\tools\nuget" ^
  --grant-ro "%APPDATA%\NuGet" ^
  --grant-rw "C:\src\MySolution" ^
  -- C:\tools\nuget\nuget.exe restore C:\src\MySolution\MySolution.sln
```

What each piece is for:

- `--grant-ro` on the tool directory: the sandbox must read its own image.
  Anything under `Program Files` usually already grants ALL APPLICATION
  PACKAGES read+execute; a hand-placed `C:\tools` will not, and you get
  `ERROR_ACCESS_DENIED` from `CreateProcess` with no hint that it was the ACL.
- `--grant-ro` on `%APPDATA%\NuGet`: `NuGet.Config`. Machine-wide config under
  `%ProgramFiles(x86)%\NuGet\Config` is normally already readable.
- `--grant-rw` on the solution: `obj/`, `project.assets.json`,
  `packages.lock.json`, `bin/`. Restore writes into the tree, so this grant is
  unavoidable — the sandbox can write your source. That is the real limit of
  this approach for a hostile workload.
- `--nuget-state`: sets `NUGET_PACKAGES`, `NUGET_HTTP_CACHE_PATH`,
  `NUGET_PLUGINS_CACHE_PATH`, `TEMP` and `TMP` to directories inside the
  AppContainer profile, where the package SID already has full control. One
  grant instead of five scattered holes in the user profile.

**The global-package-cache tradeoff.** `--nuget-state` gives the sandbox its
own cache, so restores are cold and slower. To share the real one, drop
`--nuget-state` and `--grant-rw "%USERPROFILE%\.nuget\packages"` instead —
faster, but a compromised restore can then plant a package that your
unsandboxed builds will consume. Per-sandbox cache is the right default; share
it only if cold restores are genuinely too slow.

## Things that will bite

- **Loopback is blocked** for AppContainers regardless of capability. If your
  feed is on `localhost`, or you were planning to put a broker proxy there, you
  need an exemption:

  ```
  CheckNetIsolation LoopbackExempt -a -p=<package SID>
  ```

  Get the SID from `runappcontainer.exe --show-sid`. This is deliberately not
  automated here: the underlying API replaces the entire machine-global
  exemption list, so a careless call clobbers every other app's entry.

- **Credential providers.** An authenticated feed pulls in a plugin from
  `%USERPROFILE%\.nuget\plugins` (grant it read) and may need DPAPI to decrypt
  stored credentials. Whether `CryptUnprotectData` works for the user's own
  blobs inside a lowbox is worth testing before you rely on it.

- **Profiles are persistent machine state.** `CreateAppContainerProfile` writes
  HKCU state and a profile directory that outlive the process. Clean up with
  `--delete-profile`, and note the ACLs you granted stay on those paths until
  you remove them.

- **Console handles.** stdout and stderr are redirected through a pipe rather
  than inherited, because conhost does not reliably accept a lowbox token.
  That is why output appears under `--- child output ---` rather than
  interleaved live.

- **No package identity.** A bare lowbox has no package identity, so WinRT
  calls fail. Irrelevant for NuGet; relevant if you point this at something
  that expects to be a real packaged app.

## Verified results

From CI on `windows-latest`, run 4 (`ef77e50`), all steps green:

- **AppContainer: all 14 probes pass.** `EnumerateSecurityPackages` saw 12
  packages, `CertOpenSystemStore(ROOT)` 571 roots, `HKLM SystemCertificates`
  552 entries; the handshake negotiated TLS 1.2 with AES-256 and ECDHE,
  `CertVerifyChainPolicy` trusted the chain, and `EncryptMessage` /
  `DecryptMessage` moved a real HTTP request. The token dump confirms
  `AppContainer: yes`, `Restricting SIDs: 0`, low integrity. **SChannel works
  in a lowbox.**

- **`nuget.exe` works in the AppContainer, end to end.** It fetched
  `newtonsoft.json.13.0.3.nupkg` from `api.nuget.org` over TLS and installed it
  with a verified content hash. This is the actual claim this repo exists to
  support, and it holds.

- **Restricting SID: the premise is still not demonstrated.** The child exits
  `0xC0000135` (`STATUS_DLL_NOT_FOUND`) with no output — under the RESTRICTED
  SID it cannot load a DLL in its own import graph, so it never reaches
  `main`. Practically this is a *stronger* reason to reject restricting SIDs
  for a tool like `nuget.exe`: it cannot even start. But the mechanism claimed
  elsewhere in this README — SSPI being denied the LSASS ALPC port — remains
  **unverified**, because no code runs to exercise it. Treat it as reasoning,
  not as a measured result. Demonstrating it needs a different experiment:
  a binary whose imports the restricting SID *can* load.

### AppContainer tokens do not get ancestor traverse for free

The finding most likely to bite a real deployment. Reaching a granted
directory requires **every ancestor to be traversable by the package SID**, and
a lowbox token does not get this by default. `nuget.exe` failed with *Access to
the path 'C:\Users' is denied* until the chain from the drive root down to
`%APPDATA%` was opened with `--grant-x`.

`--grant-x` is a non-inheriting `FILE_TRAVERSE` ACE: it opens the path without
opening the contents, and without the spread an inheritable grant on
`C:\Users` would cause across every profile. The working grant set for NuGet,
as CI runs it:

```
--grant-x  C:\  C:\Users  C:\Users\<user>  ...\AppData  ...\AppData\Roaming
--grant-ro %APPDATA%\NuGet          # nuget reads this whatever -ConfigFile says
--grant-ro <tool dir>
--grant-rw <output or solution dir>
--nuget-state
```

The traverse ACE on `C:\` is redundant in practice (the root already allows
it) but harmless, and keeping the walk uniform avoids special cases.

Note that `-ConfigFile` does **not** stop `nuget.exe` reading the user-level
`%APPDATA%\NuGet\NuGet.Config`, so that directory needs read access
regardless.

### On trusting these results

Two bugs in earlier runs are worth knowing about, because both produced
confident output that was wrong:

1. The first run's assertions piped an `Out-String` blob to `Select-String`
   with a `^`-anchored pattern. That anchors at the start of the whole blob, so
   the per-line patterns never matched and the AppContainer check **could not
   fail**. It now captures lines and cross-checks the exit code, so no single
   text match is load-bearing.
2. The restricted child's exit code `3221225781` was read as `0xC0000142`
   (`STATUS_DLL_INIT_FAILED`) when it is `0xC0000135`
   (`STATUS_DLL_NOT_FOUND`) — the decimal forms differ by 13. That sent a fix
   after the window station, which was never the problem. The launcher now
   prints hex plus the NTSTATUS name.

---

# CI

`.github/workflows/windows-sandbox.yml` runs the whole comparison on a real
`windows-latest` runner, which is how the "not executed on Windows" caveats
above get retired. Four steps:

1. **Baseline, unsandboxed** — must pass. If it fails, the runner cannot reach
   the probe host and the rest of the comparison is meaningless.
2. **Restricting SID** — recorded as evidence, never fails the job. Its failure
   *is* the finding. The step distinguishes "SSPI unreachable" from "the
   process never started", which is why the launchers capture child output
   through a pipe rather than trusting console inheritance.
3. **AppContainer** — probes 1–5 must pass. This is the claim: SSPI reached
   LSASS and the machine certificate stores were readable.
4. **`nuget.exe install` inside the AppContainer** — the real workload, with
   `--nuget-state` and the two grants. Asserts the `.dll` actually landed.

Output from all four is attached as an artifact and rendered into the run
summary, so a failure is diagnosable without a local Windows box. The profiles
are deleted in an `always()` step, since `CreateAppContainerProfile` leaves
persistent HKCU state and a profile directory behind.

A separate Linux job cross-compiles all four translation units for x64 and
x86 under `-Wall -Wextra`, which is cheap and catches portability regressions
in the launcher code.
