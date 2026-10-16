#include "childio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sandbox_err(const char *what, DWORD code)
{
    char msg[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                             FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, code, 0, msg, sizeof msg, NULL);
    while (n && (msg[n - 1] == '\n' || msg[n - 1] == '\r'))
        msg[--n] = '\0';
    printf("  %-28s failed: 0x%08lX %s\n", what, (unsigned long)code,
           n ? msg : "");
}

int run_child_capture(wchar_t *cmdline, const child_opts *opts, DWORD *exit_code)
{
    STARTUPINFOEXW six;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL, nul = INVALID_HANDLE_VALUE;
    HANDLE inherit[2];
    SIZE_T attr_size = 0;
    DWORD attr_count = opts->caps ? 2 : 1;
    int attr_ready = 0;
    int ok = 0;

    memset(&six, 0, sizeof six);
    memset(&pi, 0, sizeof pi);
    memset(&sa, 0, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        sandbox_err("CreatePipe", GetLastError());
        return 0;
    }
    /* Our read end must not leak into the child, or we never see EOF. */
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      &sa, OPEN_EXISTING, 0, NULL);
    if (nul == INVALID_HANDLE_VALUE) {
        sandbox_err("CreateFile(NUL)", GetLastError());
        goto out;
    }

    six.StartupInfo.cb = sizeof six;
    six.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    six.StartupInfo.hStdInput  = nul;
    six.StartupInfo.hStdOutput = wr;
    six.StartupInfo.hStdError  = wr;

    InitializeProcThreadAttributeList(NULL, attr_count, 0, &attr_size);
    six.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
    if (!six.lpAttributeList) {
        sandbox_err("malloc(attribute list)", ERROR_OUTOFMEMORY);
        goto out;
    }
    if (!InitializeProcThreadAttributeList(six.lpAttributeList, attr_count,
                                           0, &attr_size)) {
        sandbox_err("InitializeProcThreadAttributeList", GetLastError());
        goto out;
    }
    attr_ready = 1;

    if (opts->caps &&
        !UpdateProcThreadAttribute(six.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   opts->caps, sizeof *opts->caps, NULL, NULL)) {
        sandbox_err("UpdateProcThreadAttribute(caps)", GetLastError());
        goto out;
    }

    /* Only these two handles reach the child. stdout and stderr share one. */
    inherit[0] = nul;
    inherit[1] = wr;
    if (!UpdateProcThreadAttribute(six.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherit, sizeof inherit, NULL, NULL)) {
        sandbox_err("UpdateProcThreadAttribute(handles)", GetLastError());
        goto out;
    }

    if (opts->token) {
        ok = CreateProcessAsUserW(opts->token, NULL, cmdline, NULL, NULL, TRUE,
                                  EXTENDED_STARTUPINFO_PRESENT |
                                  CREATE_UNICODE_ENVIRONMENT,
                                  NULL, NULL, &six.StartupInfo, &pi);
    } else {
        ok = CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
                            EXTENDED_STARTUPINFO_PRESENT |
                            CREATE_UNICODE_ENVIRONMENT,
                            NULL, NULL, &six.StartupInfo, &pi);
    }

    if (!ok) {
        DWORD e = GetLastError();
        sandbox_err(opts->token ? "CreateProcessAsUser" : "CreateProcess", e);
        if (e == ERROR_ACCESS_DENIED)
            printf("\n  The sandbox cannot read the command's own image. Its\n"
                   "  directory DACL must grant the sandbox SID read+execute.\n");
        goto out;
    }

    /* Drop our copies of the write ends, or the read loop never terminates. */
    CloseHandle(wr);
    wr = NULL;
    CloseHandle(nul);
    nul = INVALID_HANDLE_VALUE;

    printf("\n--- child output ---\n");
    fflush(stdout);
    for (;;) {
        char buf[4096];
        DWORD n = 0;
        if (!ReadFile(rd, buf, sizeof buf, &n, NULL) || n == 0)
            break;
        fwrite(buf, 1, n, stdout);
        fflush(stdout);
    }
    printf("--- end child output ---\n");

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ok = 1;

out:
    if (attr_ready)
        DeleteProcThreadAttributeList(six.lpAttributeList);
    free(six.lpAttributeList);
    if (rd) CloseHandle(rd);
    if (wr) CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    return ok;
}
