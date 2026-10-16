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
