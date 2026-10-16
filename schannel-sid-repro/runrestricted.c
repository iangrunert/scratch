/*
 * runrestricted.c -- Run a command under a sandboxed token, for comparison.
 *
 * Builds a restricted token from this process's own primary token and launches
 * the given command with it. Because the new token is a restricted version of
 * the caller's own, CreateProcessAsUser is allowed without holding
 * SE_ASSIGNPRIMARYTOKEN_NAME.
 *
 * The modes exist so you can separate the two things people mean by "sandbox":
 *
 *   --restricted  add the RESTRICTED SID (S-1-5-12) as a restricting SID.
 *                 Every access check now also demands that SID on the
 *                 object's DACL. This is the mode that breaks SChannel.
 *   --null        restricting SID is the NULL SID (S-1-0-0), which almost
 *                 nothing grants. Strictest, and breaks correspondingly more.
 *   --deny-only   no restricting SIDs at all: deny-only groups plus dropped
 *                 privileges. Much weaker isolation on paper, but leaves SSPI
 *                 and the certificate stores working.
 *   --low         additionally drop the token to low integrity. Composes with
 *                 any of the above.
 *
 * Usage: runrestricted.exe [mode...] -- <command> [args...]
 */

#define WIN32_LEAN_AND_MEAN

#include "childio.h"

#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

static void usage(void)
{
    printf("usage: runrestricted.exe [--restricted|--null|--deny-only] [--low] "
           "-- <command> [args...]\n");
}

/* Join the remaining argv into one command line, quoting what needs it. The
   quoting here is deliberately simple -- enough for a path and plain flags. */
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
        int need_quotes = strchr(argv[i], ' ') != NULL && argv[i][0] != '"';

        if (MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wide,
                                (int)(sizeof wide / sizeof *wide)) == 0) {
            free(out);
            return NULL;
        }
        if (i > from)
            wcscat(out, L" ");
        if (need_quotes)
            wcscat(out, L"\"");
        wcscat(out, wide);
        if (need_quotes)
            wcscat(out, L"\"");
    }
    return out;
}

static int set_low_integrity(HANDLE tok)
{
    TOKEN_MANDATORY_LABEL tml;
    PSID low = NULL;
    int ok;

    if (!ConvertStringSidToSidW(L"S-1-16-4096", &low)) {
        sandbox_err("ConvertStringSidToSid(low integrity)", GetLastError());
        return 0;
    }
    memset(&tml, 0, sizeof tml);
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = low;

    ok = SetTokenInformation(tok, TokenIntegrityLevel, &tml,
                             (DWORD)(sizeof tml + GetLengthSid(low)));
    if (!ok)
        sandbox_err("SetTokenInformation(TokenIntegrityLevel)", GetLastError());
    LocalFree(low);
    return ok;
}

/* Grant a SID access to the window station and desktop.
 *
 * Without this a restricted-token child dies at DLL init with 0xC0000142
 * before executing a single instruction, because something in its import
 * graph touches user32 and the lowbox/restricted token has no access to
 * winsta0 or its default desktop. That failure looks like nothing at all:
 * no output, no probe results. Chromium's sandbox solves it by handing the
 * sandbox an alternate desktop; for a diagnostic, widening the existing one
 * is enough.
 *
 * The window station needs two ACEs with different inheritance -- one
 * inherit-only entry for the desktops it contains, one non-propagating entry
 * for the station itself. This is the shape the Windows SDK sample uses.
 */
#define WINSTA_WANTED (WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | \
                       WINSTA_ACCESSCLIPBOARD | WINSTA_CREATEDESKTOP | \
                       WINSTA_WRITEATTRIBUTES | WINSTA_ACCESSGLOBALATOMS | \
                       WINSTA_EXITWINDOWS | WINSTA_ENUMERATE | \
                       WINSTA_READSCREEN | STANDARD_RIGHTS_REQUIRED)

#define DESKTOP_WANTED (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | \
                        DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL | \
                        DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | \
                        DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | \
                        DESKTOP_SWITCHDESKTOP | STANDARD_RIGHTS_REQUIRED)

static int grant_object(HANDLE obj, EXPLICIT_ACCESSW *ea, ULONG n,
                        const char *what)
{
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD err;

    err = GetSecurityInfo(obj, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                          NULL, NULL, &old_dacl, NULL, &sd);
    if (err != ERROR_SUCCESS) {
        sandbox_err(what, err);
        return 0;
    }

    err = SetEntriesInAclW(n, ea, old_dacl, &new_dacl);
    if (err != ERROR_SUCCESS) {
        sandbox_err("SetEntriesInAcl", err);
        LocalFree(sd);
        return 0;
    }

    err = SetSecurityInfo(obj, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                          NULL, NULL, new_dacl, NULL);
    if (err != ERROR_SUCCESS)
        sandbox_err(what, err);

    LocalFree(new_dacl);
    LocalFree(sd);
    return err == ERROR_SUCCESS;
}

static void fill_ea(EXPLICIT_ACCESSW *ea, PSID sid, DWORD access, DWORD inherit)
{
    memset(ea, 0, sizeof *ea);
    ea->grfAccessPermissions = access;
    ea->grfAccessMode = GRANT_ACCESS;
    ea->grfInheritance = inherit;
    ea->Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea->Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea->Trustee.ptstrName = (LPWSTR)sid;
}

static void grant_station_and_desktop(PSID sid)
{
    HWINSTA ws = GetProcessWindowStation();
    HDESK   dk = GetThreadDesktop(GetCurrentThreadId());
    EXPLICIT_ACCESSW ea[2];

    if (ws) {
        fill_ea(&ea[0], sid, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE |
                             GENERIC_ALL,
                CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE);
        fill_ea(&ea[1], sid, WINSTA_WANTED, NO_PROPAGATE_INHERIT_ACE);
        if (grant_object(ws, ea, 2, "window station DACL"))
            printf("  granted window station\n");
    }
    if (dk) {
        fill_ea(&ea[0], sid, DESKTOP_WANTED, 0);
        if (grant_object(dk, ea, 1, "desktop DACL"))
            printf("  granted desktop\n");
    }
}

int main(int argc, char **argv)
{
    const wchar_t *restrict_sid = L"S-1-5-12";   /* RESTRICTED */
    int deny_only = 0;
    int low = 0;
    int split = -1;

    HANDLE self = NULL, tok = NULL;
    SID_AND_ATTRIBUTES restricting[1];
    SID_AND_ATTRIBUTES deny[1];
    PSID rsid = NULL, dsid = NULL;
    wchar_t *cmdline = NULL;
    DWORD exit_code = 1;
    int rc = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0)                { split = i + 1; break; }
        else if (strcmp(argv[i], "--restricted") == 0) restrict_sid = L"S-1-5-12";
        else if (strcmp(argv[i], "--null") == 0)       restrict_sid = L"S-1-0-0";
        else if (strcmp(argv[i], "--deny-only") == 0)  deny_only = 1;
        else if (strcmp(argv[i], "--low") == 0)        low = 1;
        else { usage(); return 2; }
    }
    if (split < 0 || split >= argc) {
        usage();
        return 2;
    }

    cmdline = build_cmdline(argc, argv, split);
    if (!cmdline) {
        printf("  could not build the command line\n");
        return 2;
    }

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                          &self)) {
        sandbox_err("OpenProcessToken", GetLastError());
        goto out;
    }

    if (deny_only) {
        /* Deny-only on Administrators, plus drop every privilege we can. No
           restricting SIDs, so access checks stay single-pass. */
        if (!ConvertStringSidToSidW(L"S-1-5-32-544", &dsid)) {
            sandbox_err("ConvertStringSidToSid(Administrators)", GetLastError());
            goto out;
        }
        deny[0].Sid = dsid;
        deny[0].Attributes = 0;
        printf("  mode: deny-only (Administrators), privileges dropped%s\n",
               low ? ", low integrity" : "");
        if (!CreateRestrictedToken(self, DISABLE_MAX_PRIVILEGE,
                                   1, deny, 0, NULL, 0, NULL, &tok)) {
            sandbox_err("CreateRestrictedToken", GetLastError());
            goto out;
        }
    } else {
        if (!ConvertStringSidToSidW(restrict_sid, &rsid)) {
            sandbox_err("ConvertStringSidToSid(restricting SID)", GetLastError());
            goto out;
        }
        restricting[0].Sid = rsid;
        restricting[0].Attributes = 0;
        printf("  mode: restricting SID %ls, privileges dropped%s\n",
               restrict_sid, low ? ", low integrity" : "");
        if (!CreateRestrictedToken(self, DISABLE_MAX_PRIVILEGE,
                                   0, NULL, 0, NULL, 1, restricting, &tok)) {
            sandbox_err("CreateRestrictedToken", GetLastError());
            goto out;
        }
    }

    if (low && !set_low_integrity(tok))
        goto out;

    /* The child cannot initialise at all without this; see the comment on
       grant_station_and_desktop. */
    grant_station_and_desktop(deny_only ? dsid : rsid);

    printf("  launching: %ls\n", cmdline);

    {
        child_opts opts;
        memset(&opts, 0, sizeof opts);
        opts.token = tok;
        if (!run_child_capture(cmdline, &opts, &exit_code)) {
            printf("\n  Under a restricting SID the image's DACL must grant\n"
                   "  that SID too:  icacls <dir> /grant *%ls:(RX) /t\n",
                   restrict_sid);
            goto out;
        }
    }

    printf("\n  child exit code: %lu", (unsigned long)exit_code);
    if (exit_code == 0xC0000142)
        printf("  (DLL init failed -- usually the window station/desktop DACL,\n"
               "   see the note in README.md)");
    printf("\n");
    rc = (int)exit_code;

out:
    free(cmdline);
    if (rsid) LocalFree(rsid);
    if (dsid) LocalFree(dsid);
    if (tok)  CloseHandle(tok);
    if (self) CloseHandle(self);
    return rc;
}
