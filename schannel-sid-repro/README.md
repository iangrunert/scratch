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
