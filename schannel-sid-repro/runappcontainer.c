/*
 * runappcontainer.c -- Run a command in an AppContainer, with explicit
 * filesystem grants and network capabilities.
 *
 * Why this exists: tools that use SChannel with no option to switch TLS stacks
 * (nuget.exe, msbuild restore, anything on .NET SslStream) cannot work under a
 * restricting-SID token, because SSPI has to cross ALPC into LSASS and that
 * port does not grant restricting SIDs. An AppContainer gets you comparable
 * isolation while leaving that path intact: System32, the LSA port and the
 * machine certificate stores all grant ALL APPLICATION PACKAGES, so TLS keeps
 * working, while the user's files stay unreachable until you grant them.
 *
 * The isolation model is the inverse of a normal token. A lowbox token is
 * granted access only where the DACL names its own package SID, one of its
 * capability SIDs, or ALL APPLICATION PACKAGES. The user SID in the token is
 * not sufficient. So the default is "can read almost nothing of the profile",
 * and each --grant below is a deliberate hole.
 *
 * Network is denied at the WFP layer unless a capability says otherwise:
 *   internetClient             (S-1-15-3-1)  outbound to the internet
 *   privateNetworkClientServer (S-1-15-3-3)  outbound to the local network
 * Loopback is blocked regardless of capability; see README.md.
 *
 * Usage:
 *   runappcontainer.exe [options] -- <command> [args...]
 *
 *   --name <n>         AppContainer profile name (default nuget-sandbox)
 *   --internet         grant internetClient (default on)
 *   --private-net      grant privateNetworkClientServer, for an internal feed
 *   --no-internet      drop internetClient
 *   --grant-ro <path>  grant the package SID read+execute, inheritable
 *   --grant-rw <path>  grant the package SID modify, inheritable
 *   --nuget-state      point NUGET_PACKAGES / caches / TEMP at the profile dir
 *   --show-sid         print the package SID and exit
 *   --delete-profile   delete the profile and exit
 */

#define WIN32_LEAN_AND_MEAN

#include "childio.h"

#include <userenv.h>
#include <sddl.h>
#include <aclapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#endif

#define MAX_GRANTS 32

/* Well-known capability SIDs. Using the literals keeps this portable across
   SDKs; DeriveCapabilitySidsFromName would do the same job for custom ones. */
#define CAP_INTERNET_CLIENT   L"S-1-15-3-1"
#define CAP_PRIVATE_NETWORK   L"S-1-15-3-3"

typedef struct {
    wchar_t path[MAX_PATH];
    int     writable;
} grant;

static void usage(void)
{
    printf(
      "usage: runappcontainer.exe [options] -- <command> [args...]\n"
      "  --name <n>          profile name (default nuget-sandbox)\n"
      "  --internet          grant internetClient (default)\n"
      "  --no-internet       drop internetClient\n"
      "  --private-net       grant privateNetworkClientServer\n"
      "  --grant-ro <path>   package SID gets read+execute, inheritable\n"
      "  --grant-rw <path>   package SID gets modify, inheritable\n"
      "  --nuget-state       redirect NuGet caches and TEMP into the profile\n"
      "  --show-sid          print the package SID and exit\n"
      "  --delete-profile    delete the profile and exit\n");
}

/* ------------------------------------------------------------ the profile */

/* CreateAppContainerProfile is persistent and machine-registered: it makes
   HKCU state plus a profile directory, and fails with ERROR_ALREADY_EXISTS on
   a second run. That is the normal path -- derive the SID and carry on. */
static PSID ensure_profile(const wchar_t *name)
{
    PSID sid = NULL;
    HRESULT hr = CreateAppContainerProfile(name, name,
                                           L"Sandbox for SChannel-only tools",
                                           NULL, 0, &sid);
    if (SUCCEEDED(hr)) {
        printf("  created profile          %ls\n", name);
        return sid;
    }
    if (hr != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        sandbox_err("CreateAppContainerProfile", (DWORD)hr);
        return NULL;
    }
    hr = DeriveAppContainerSidFromAppContainerName(name, &sid);
    if (FAILED(hr)) {
        sandbox_err("DeriveAppContainerSid", (DWORD)hr);
        return NULL;
    }
    printf("  reusing profile          %ls\n", name);
    return sid;
}

/* ---------------------------------------------------------------- the ACLs */

/* Add one inheritable allow entry for the package SID, preserving whatever is
   already on the object. SetEntriesInAcl merges rather than replaces, so this
   is additive and idempotent -- re-running does not stack duplicates in any
   way that changes the effective rights. */
static int grant_path(const wchar_t *path, PSID sid, int writable)
{
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    EXPLICIT_ACCESSW ea;
    DWORD err;

    err = GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION, NULL, NULL,
                                &old_dacl, NULL, &sd);
    if (err != ERROR_SUCCESS) {
        sandbox_err("GetNamedSecurityInfo", err);
        printf("    path: %ls\n", path);
        return 0;
    }

    memset(&ea, 0, sizeof ea);
    ea.grfAccessPermissions = writable
        ? (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE)
        : (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = (LPWSTR)sid;

    err = SetEntriesInAclW(1, &ea, old_dacl, &new_dacl);
    if (err != ERROR_SUCCESS) {
        sandbox_err("SetEntriesInAcl", err);
        LocalFree(sd);
        return 0;
    }

    err = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION, NULL, NULL,
                                new_dacl, NULL);
    if (err != ERROR_SUCCESS) {
        sandbox_err("SetNamedSecurityInfo", err);
        printf("    path: %ls\n", path);
        LocalFree(new_dacl);
        LocalFree(sd);
        return 0;
    }

    printf("  granted %-3s              %ls\n", writable ? "rw" : "ro", path);
    LocalFree(new_dacl);
    LocalFree(sd);
    return 1;
}

/* ------------------------------------------------------- NuGet state paths */

/* NuGet writes to several places under the user profile by default. Rather
   than poking a hole in each, relocate the whole lot into the profile
   directory, where the package SID already has full control. One grant
   instead of five, and the sandbox cannot see the real package cache. */
static int redirect_nuget_state(PSID sid)
{
    LPWSTR sid_str = NULL, folder = NULL;
    wchar_t buf[MAX_PATH];
    HRESULT hr;

    if (!ConvertSidToStringSidW(sid, &sid_str)) {
        sandbox_err("ConvertSidToStringSid", GetLastError());
        return 0;
    }

    hr = GetAppContainerFolderPath(sid_str, &folder);
    LocalFree(sid_str);
    if (FAILED(hr) || !folder) {
        sandbox_err("GetAppContainerFolderPath", (DWORD)hr);
        return 0;
    }

    /* Each of these is read by NuGet at startup; see README.md for what else
       it may touch when a credential provider is in play. */
    struct { const wchar_t *var, *leaf; } map[] = {
        { L"NUGET_PACKAGES",           L"packages"     },
        { L"NUGET_HTTP_CACHE_PATH",    L"http-cache"   },
        { L"NUGET_PLUGINS_CACHE_PATH", L"plugins-cache"},
        { L"TEMP",                     L"temp"         },
        { L"TMP",                      L"temp"         },
    };

    for (size_t i = 0; i < sizeof map / sizeof *map; i++) {
        _snwprintf(buf, MAX_PATH, L"%s\\%s", folder, map[i].leaf);
        buf[MAX_PATH - 1] = L'\0';
        if (!CreateDirectoryW(buf, NULL) &&
            GetLastError() != ERROR_ALREADY_EXISTS) {
            sandbox_err("CreateDirectory", GetLastError());
            printf("    path: %ls\n", buf);
            CoTaskMemFree(folder);
            return 0;
        }
        /* Set in our own environment; the child inherits it because we pass
           NULL for lpEnvironment. */
        if (!SetEnvironmentVariableW(map[i].var, buf)) {
            sandbox_err("SetEnvironmentVariable", GetLastError());
            CoTaskMemFree(folder);
            return 0;
        }
        printf("  %-24ls %ls\n", map[i].var, buf);
    }

    CoTaskMemFree(folder);
    return 1;
}

/* --------------------------------------------------------- the command line */

static wchar_t *build_cmdline(int argc, char **argv, int from)
{
    size_t cap = 1;
    wchar_t *out;

    for (int i = from; i < argc; i++)
        cap += strlen(argv[i]) * 2 + 4;

    out = (wchar_t *)calloc(cap, sizeof(wchar_t));
    if (!out)
        return NULL;

    for (int i = from; i < argc; i++) {
        wchar_t wide[1024];
        int quote = strchr(argv[i], ' ') != NULL && argv[i][0] != '"';

        if (MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wide,
                                (int)(sizeof wide / sizeof *wide)) == 0) {
            free(out);
            return NULL;
        }
        if (i > from) wcscat(out, L" ");
        if (quote)    wcscat(out, L"\"");
        wcscat(out, wide);
        if (quote)    wcscat(out, L"\"");
    }
    return out;
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    const wchar_t *name = L"nuget-sandbox";
    wchar_t name_buf[64];
    int internet = 1, private_net = 0, nuget_state = 0;
    int show_sid = 0, del_profile = 0;
    grant grants[MAX_GRANTS];
    int grant_count = 0;
    int split = -1;

    PSID sid = NULL;
    PSID caps[2];
    DWORD cap_count = 0;
    wchar_t *cmdline = NULL;
    DWORD exit_code = 1;
    int rc = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { split = i + 1; break; }
        else if (strcmp(argv[i], "--internet") == 0)       internet = 1;
        else if (strcmp(argv[i], "--no-internet") == 0)    internet = 0;
        else if (strcmp(argv[i], "--private-net") == 0)    private_net = 1;
        else if (strcmp(argv[i], "--nuget-state") == 0)    nuget_state = 1;
        else if (strcmp(argv[i], "--show-sid") == 0)       show_sid = 1;
        else if (strcmp(argv[i], "--delete-profile") == 0) del_profile = 1;
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, name_buf, 64);
            name_buf[63] = L'\0';
            name = name_buf;
        }
        else if ((strcmp(argv[i], "--grant-ro") == 0 ||
                  strcmp(argv[i], "--grant-rw") == 0) && i + 1 < argc) {
            if (grant_count >= MAX_GRANTS) {
                printf("  too many grants (max %d)\n", MAX_GRANTS);
                return 2;
            }
            grants[grant_count].writable = (argv[i][9] == 'w');
            MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1,
                                grants[grant_count].path, MAX_PATH);
            grants[grant_count].path[MAX_PATH - 1] = L'\0';
            grant_count++;
        }
        else { usage(); return 2; }
    }

    if (del_profile) {
        HRESULT hr = DeleteAppContainerProfile(name);
        if (FAILED(hr)) {
            sandbox_err("DeleteAppContainerProfile", (DWORD)hr);
            return 1;
        }
        printf("  deleted profile %ls\n", name);
        return 0;
    }

    if (!show_sid && (split < 0 || split >= argc)) {
        usage();
        return 2;
    }

    printf("runappcontainer\n");

    sid = ensure_profile(name);
    if (!sid)
        return 1;

    {
        LPWSTR s = NULL;
        if (ConvertSidToStringSidW(sid, &s)) {
            printf("  package SID              %ls\n", s);
            if (show_sid) {
                printf("\n  loopback exemption (needs admin, machine-global):\n"
                       "    CheckNetIsolation LoopbackExempt -a -p=%ls\n", s);
            }
            LocalFree(s);
        }
    }
    if (show_sid) {
        FreeSid(sid);
        return 0;
    }

    if (internet && ConvertStringSidToSidW(CAP_INTERNET_CLIENT, &caps[cap_count])) {
        printf("  capability               internetClient\n");
        cap_count++;
    }
    if (private_net && ConvertStringSidToSidW(CAP_PRIVATE_NETWORK, &caps[cap_count])) {
        printf("  capability               privateNetworkClientServer\n");
        cap_count++;
    }
    if (!cap_count)
        printf("  capability               none (no network)\n");

    for (int i = 0; i < grant_count; i++) {
        if (!grant_path(grants[i].path, sid, grants[i].writable))
            goto out;
    }

    if (nuget_state && !redirect_nuget_state(sid))
        goto out;

    cmdline = build_cmdline(argc, argv, split);
    if (!cmdline) {
        printf("  could not build the command line\n");
        goto out;
    }

    {
        SECURITY_CAPABILITIES sc;
        SID_AND_ATTRIBUTES cap_attrs[2];
        child_opts opts;

        memset(&sc, 0, sizeof sc);
        sc.AppContainerSid = sid;
        sc.CapabilityCount = cap_count;
        for (DWORD i = 0; i < cap_count; i++) {
            cap_attrs[i].Sid = caps[i];
            cap_attrs[i].Attributes = SE_GROUP_ENABLED;
        }
        if (cap_count)
            sc.Capabilities = cap_attrs;

        memset(&opts, 0, sizeof opts);
        opts.caps = &sc;

        if (run_child_capture(cmdline, &opts, &exit_code)) {
            printf("\n  child exit code: %lu\n", (unsigned long)exit_code);
            rc = (int)exit_code;
        }
    }

out:
    free(cmdline);
    for (DWORD i = 0; i < cap_count; i++)
        LocalFree(caps[i]);
    FreeSid(sid);
    return rc;
}
