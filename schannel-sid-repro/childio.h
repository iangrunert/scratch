/*
 * childio.h -- launch a sandboxed child and capture its output.
 *
 * Both launchers need this and neither can rely on console inheritance: a
 * restricted or lowbox token may be refused by conhost, and the child then
 * produces no output at all. That failure is indistinguishable from "the
 * process started and every probe failed", which is precisely the distinction
 * these tools exist to make. So stdout and stderr always go through a pipe.
 */

#ifndef CHILDIO_H
#define CHILDIO_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef struct {
    /* NULL launches with CreateProcessW; otherwise CreateProcessAsUserW. */
    HANDLE token;
    /* NULL adds no lowbox attribute; otherwise the child is an AppContainer. */
    SECURITY_CAPABILITIES *caps;
} child_opts;

/* Print a Windows error code with its system message. */
void sandbox_err(const char *what, DWORD code);

/* Run cmdline, streaming the child's merged stdout/stderr to our stdout.
   Returns 1 if the child ran to completion (exit_code is then set), 0 if the
   launch itself failed. cmdline is mutated by CreateProcess, as documented. */
int run_child_capture(wchar_t *cmdline, const child_opts *opts, DWORD *exit_code);

#endif
