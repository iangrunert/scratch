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

2. **Window station / desktop.** If the child dies instantly with exit code
   `0xC0000142`, that is DLL initialisation failing because the restricting SID
   has no access to `winsta0\default` — not a TLS result. Chromium's sandbox
   handles this by granting the sandbox an alternate desktop. For a quick
   experiment, grant access to the existing one or accept that this launcher is
   a diagnostic rather than a sandbox.

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

## Status

`runappcontainer.c` cross-compiles clean for x64 and x86 but, like the probe,
**has not been executed on Windows**.
