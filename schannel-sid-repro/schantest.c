/*
 * schantest.c -- Find out which Windows TLS dependency a sandboxed token breaks.
 *
 * Windows TLS is not self-contained in the process. SSPI reaches LSASS over
 * ALPC for the SChannel provider itself, and crypt32 reads the machine
 * certificate stores out of HKLM. A restricting-SID token makes every access
 * check demand the restricting SID on the object's DACL, and essentially none
 * of those objects carry it -- so "TLS is broken" can mean any of six
 * different denials. This walks them in dependency order and reports each one
 * separately, so you know whether to fix the sandbox, the cert story, or both.
 *
 * Run it once unsandboxed to get a baseline, then again under whatever token
 * you are evaluating (see runrestricted.c) and diff the output.
 *
 * Usage: schantest.exe [host] [port] [options]
 *   --validate       let SChannel build and check the chain during the
 *                    handshake instead of validating manually afterwards
 *   --no-handshake   stop after the local probes; no socket is opened
 *   --quiet-token    skip the token dump
 *
 * Defaults to www.microsoft.com:443.
 */

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* MSVC picks these up here; the mingw build passes them on the command line. */
#ifdef _MSC_VER
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

#define IO_BUF (32 * 1024)

static int g_failures = 0;
static int g_probe = 0;

/* ------------------------------------------------------------------ output */

/* FormatMessage knows most SEC_E_* codes, but not reliably on every build and
   not under every UI language, so the ones that matter here are spelled out. */
static const char *sec_name(SECURITY_STATUS s)
{
    switch (s) {
    case SEC_E_OK:                      return "SEC_E_OK";
    case SEC_I_CONTINUE_NEEDED:         return "SEC_I_CONTINUE_NEEDED";
    case SEC_I_COMPLETE_NEEDED:         return "SEC_I_COMPLETE_NEEDED";
    case SEC_I_COMPLETE_AND_CONTINUE:   return "SEC_I_COMPLETE_AND_CONTINUE";
    case SEC_I_INCOMPLETE_CREDENTIALS:  return "SEC_I_INCOMPLETE_CREDENTIALS";
    case SEC_I_RENEGOTIATE:             return "SEC_I_RENEGOTIATE";
    case SEC_I_CONTEXT_EXPIRED:         return "SEC_I_CONTEXT_EXPIRED";
    case SEC_E_INCOMPLETE_MESSAGE:      return "SEC_E_INCOMPLETE_MESSAGE";
    case SEC_E_INSUFFICIENT_MEMORY:     return "SEC_E_INSUFFICIENT_MEMORY";
    case SEC_E_INTERNAL_ERROR:          return "SEC_E_INTERNAL_ERROR";
    case SEC_E_INVALID_HANDLE:          return "SEC_E_INVALID_HANDLE";
    case SEC_E_INVALID_TOKEN:           return "SEC_E_INVALID_TOKEN";
    case SEC_E_LOGON_DENIED:            return "SEC_E_LOGON_DENIED";
    case SEC_E_NO_AUTHENTICATING_AUTHORITY: return "SEC_E_NO_AUTHENTICATING_AUTHORITY";
    case SEC_E_NO_CREDENTIALS:          return "SEC_E_NO_CREDENTIALS";
    case SEC_E_SECPKG_NOT_FOUND:        return "SEC_E_SECPKG_NOT_FOUND";
    case SEC_E_UNSUPPORTED_FUNCTION:    return "SEC_E_UNSUPPORTED_FUNCTION";
    case SEC_E_UNTRUSTED_ROOT:          return "SEC_E_UNTRUSTED_ROOT";
    case SEC_E_CERT_EXPIRED:            return "SEC_E_CERT_EXPIRED";
    case SEC_E_WRONG_PRINCIPAL:         return "SEC_E_WRONG_PRINCIPAL";
    case SEC_E_ILLEGAL_MESSAGE:         return "SEC_E_ILLEGAL_MESSAGE";
    case SEC_E_ALGORITHM_MISMATCH:      return "SEC_E_ALGORITHM_MISMATCH";
    case SEC_E_BUFFER_TOO_SMALL:        return "SEC_E_BUFFER_TOO_SMALL";
    case SEC_E_CONTEXT_EXPIRED:         return "SEC_E_CONTEXT_EXPIRED";
    case CRYPT_E_NO_REVOCATION_CHECK:   return "CRYPT_E_NO_REVOCATION_CHECK";
    case CRYPT_E_REVOCATION_OFFLINE:    return "CRYPT_E_REVOCATION_OFFLINE";
    case CERT_E_UNTRUSTEDROOT:          return "CERT_E_UNTRUSTEDROOT";
    case CERT_E_CN_NO_MATCH:            return "CERT_E_CN_NO_MATCH";
    case CERT_E_EXPIRED:                return "CERT_E_EXPIRED";
    case CERT_E_CHAINING:               return "CERT_E_CHAINING";
    default:                            return NULL;
    }
}

static void print_code(long code)
{
    const char *n = sec_name((SECURITY_STATUS)code);
    if (n) {
        printf("0x%08lX %s", (unsigned long)code, n);
        return;
    }
    {
        char msg[256];
        DWORD len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                                   FORMAT_MESSAGE_IGNORE_INSERTS,
                                   NULL, (DWORD)code, 0, msg, sizeof msg, NULL);
        while (len && (msg[len - 1] == '\n' || msg[len - 1] == '\r'))
            msg[--len] = '\0';
        printf("0x%08lX %s", (unsigned long)code, len ? msg : "(no description)");
    }
}

static void pass(const char *name, const char *fmt, ...)
{
    va_list ap;
    printf("[ OK ] %d. %-26s ", ++g_probe, name);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void fail(const char *name, long code, const char *fmt, ...)
{
    va_list ap;
    g_failures++;
    printf("[FAIL] %d. %-26s ", ++g_probe, name);
    print_code(code);
    printf("\n                                     ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void skip(const char *name, const char *why)
{
    printf("[skip] %d. %-26s %s\n", ++g_probe, name, why);
}

/* ------------------------------------------------------- probe 0: the token */

static void dump_token(void)
{
    HANDLE tok = NULL;
    DWORD need = 0;

    printf("--- token ---\n");
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        printf("  OpenProcessToken failed: %lu\n\n", GetLastError());
        return;
    }

    printf("  IsTokenRestricted:  %s\n", IsTokenRestricted(tok) ? "yes" : "no");

    /* Integrity level lives in the last subauthority of the mandatory label. */
    if (!GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &need) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        TOKEN_MANDATORY_LABEL *label = (TOKEN_MANDATORY_LABEL *)malloc(need);
        if (label && GetTokenInformation(tok, TokenIntegrityLevel, label, need, &need)) {
            UCHAR  n   = *GetSidSubAuthorityCount(label->Label.Sid);
            DWORD  rid = *GetSidSubAuthority(label->Label.Sid, n - 1);
            const char *word =
                rid >= SECURITY_MANDATORY_SYSTEM_RID ? "system" :
                rid >= SECURITY_MANDATORY_HIGH_RID   ? "high"   :
                rid >= SECURITY_MANDATORY_MEDIUM_RID ? "medium" :
                rid >= SECURITY_MANDATORY_LOW_RID    ? "low"    : "untrusted";
            printf("  Integrity level:    %s (0x%lX)\n", word, (unsigned long)rid);
        }
        free(label);
    }

    {   /* TokenIsAppContainer is 0 for a classic token, 1 for a lowbox. */
        DWORD is_ac = 0, got = 0;
        if (GetTokenInformation(tok, TokenIsAppContainer, &is_ac, sizeof is_ac, &got))
            printf("  AppContainer:       %s\n", is_ac ? "yes" : "no");
    }

    need = 0;
    if (!GetTokenInformation(tok, TokenRestrictedSids, NULL, 0, &need) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        TOKEN_GROUPS *g = (TOKEN_GROUPS *)malloc(need);
        if (g && GetTokenInformation(tok, TokenRestrictedSids, g, need, &need)) {
            printf("  Restricting SIDs:   %lu\n", (unsigned long)g->GroupCount);
            for (DWORD i = 0; i < g->GroupCount; i++) {
                LPSTR s = NULL;
                if (ConvertSidToStringSidA(g->Groups[i].Sid, &s)) {
                    printf("                      %s\n", s);
                    LocalFree(s);
                }
            }
        }
        free(g);
    }

    CloseHandle(tok);
    printf("\n");
}

/* --------------------------------------------- probes 1-2: SSPI reaches LSA */

/* Enumerating packages is the cheapest question that still crosses the ALPC
   boundary into LSASS. If this fails, nothing downstream can work and the
   sandbox token is the whole story. */
static int probe_sspi_reachable(void)
{
    ULONG count = 0;
    SecPkgInfoW *pkgs = NULL;
    SECURITY_STATUS ss = EnumerateSecurityPackagesW(&count, &pkgs);

    if (ss != SEC_E_OK) {
        fail("EnumerateSecurityPackages", ss,
             "SSPI cannot reach LSASS; the TLS provider is unreachable.");
        return 0;
    }
    pass("EnumerateSecurityPackages", "%lu packages visible", (unsigned long)count);
    FreeContextBuffer(pkgs);

    {
        SecPkgInfoW *info = NULL;
        ss = QuerySecurityPackageInfoW((SEC_WCHAR *)UNISP_NAME_W, &info);
        if (ss != SEC_E_OK) {
            fail("QuerySecurityPackageInfo", ss, "SChannel (%ls) not available.",
                 UNISP_NAME_W);
            return 0;
        }
        pass("QuerySecurityPackageInfo", "SChannel present, max token %lu bytes",
             (unsigned long)info->cbMaxToken);
        FreeContextBuffer(info);
    }
    return 1;
}

/* ------------------------------------- probe 3: credentials (needs key iso) */

static int probe_acquire_cred(CredHandle *cred, int let_schannel_validate)
{
    SCHANNEL_CRED sc;
    SECURITY_STATUS ss;
    TimeStamp expiry;

    memset(&sc, 0, sizeof sc);
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    /* No client cert, and let the OS choose protocol versions -- we are
       probing reachability, not pinning a policy. */
    sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    sc.dwFlags |= let_schannel_validate ? SCH_CRED_AUTO_CRED_VALIDATION
                                        : SCH_CRED_MANUAL_CRED_VALIDATION;

    ss = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W,
                                   SECPKG_CRED_OUTBOUND, NULL, &sc,
                                   NULL, NULL, cred, &expiry);
    if (ss != SEC_E_OK) {
        fail("AcquireCredentialsHandle", ss,
             "Credential acquisition is where LSASS/CNG key isolation is first hit.");
        return 0;
    }
    pass("AcquireCredentialsHandle", "outbound SChannel creds (%s validation)",
         let_schannel_validate ? "schannel" : "manual");
    return 1;
}

/* ---------------------------- probes 4-5: the crypt32 / HKLM cert machinery */

/* Deliberately split from the handshake. Under restricting SIDs the handshake
   can succeed with manual validation while this fails, and the fix for each is
   different: the first needs a different sandbox primitive, the second needs
   you to ship a trust anchor. */
static void probe_cert_stores(void)
{
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) {
        fail("CertOpenSystemStore(ROOT)", (long)GetLastError(),
             "Machine root store unreadable; chain building cannot work.");
    } else {
        int n = 0;
        PCCERT_CONTEXT c = NULL;
        while ((c = CertEnumCertificatesInStore(store, c)) != NULL)
            n++;
        if (n == 0)
            fail("CertOpenSystemStore(ROOT)", 0,
                 "Store opened but is empty -- trust anchors are not visible.");
        else
            pass("CertOpenSystemStore(ROOT)", "%d root certificates", n);
        CertCloseStore(store, 0);
    }

    {   /* The registry key the store is backed by, read directly, so a denial
           shows up as a plain ACL error rather than an empty store. */
        HKEY k = NULL;
        LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates",
            0, KEY_READ, &k);
        if (st != ERROR_SUCCESS) {
            fail("HKLM SystemCertificates", (long)st,
                 "The ACL on the backing registry key denies this token.");
        } else {
            DWORD subkeys = 0;
            RegQueryInfoKeyW(k, NULL, NULL, NULL, &subkeys, NULL, NULL,
                             NULL, NULL, NULL, NULL, NULL);
            pass("HKLM SystemCertificates", "%lu entries", (unsigned long)subkeys);
            RegCloseKey(k);
        }
    }
}

/* ----------------------------------------------- probes 6-7: DNS and TCP */

/* DNS is here because dnsapi talks to the dnscache service over RPC, which
   fails under restricting SIDs in exactly the same way -- and then presents as
   a generic "network is broken", which is easy to misattribute to TLS. */
static int probe_dns(const wchar_t *host, const char *port, struct addrinfo **out)
{
    struct addrinfo hints;
    char hostA[256];
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    WideCharToMultiByte(CP_UTF8, 0, host, -1, hostA, sizeof hostA, NULL, NULL);

    rc = getaddrinfo(hostA, port, &hints, out);
    if (rc != 0) {
        fail("getaddrinfo", (long)rc,
             "Name resolution via the dnscache RPC endpoint failed.");
        return 0;
    }
    {
        char ip[INET6_ADDRSTRLEN] = "?";
        struct addrinfo *ai = *out;
        DWORD len = sizeof ip;
        WSAAddressToStringA(ai->ai_addr, (DWORD)ai->ai_addrlen, NULL, ip, &len);
        pass("getaddrinfo", "%s -> %s", hostA, ip);
    }
    return 1;
}

static SOCKET probe_connect(struct addrinfo *ai)
{
    SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
        fail("socket", (long)WSAGetLastError(), "Could not create a TCP socket.");
        return INVALID_SOCKET;
    }
    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
        fail("connect", (long)WSAGetLastError(),
             "Outbound TCP refused. In an AppContainer this means the "
             "internetClient capability is missing.");
        closesocket(s);
        return INVALID_SOCKET;
    }
    pass("connect", "TCP established");
    return s;
}

/* ------------------------------------------------- probe 8: the handshake */

typedef struct {
    SOCKET sock;
    unsigned char buf[IO_BUF];
    DWORD len;
} conn;

static int conn_fill(conn *c)
{
    int n;
    if (c->len >= sizeof c->buf) {
        printf("       receive buffer full with an incomplete record\n");
        return -1;
    }
    n = recv(c->sock, (char *)c->buf + c->len, (int)(sizeof c->buf - c->len), 0);
    if (n <= 0)
        return n;
    c->len += (DWORD)n;
    return n;
}

static int send_all(SOCKET s, const unsigned char *p, DWORD n)
{
    while (n) {
        int sent = send(s, (const char *)p, (int)n, 0);
        if (sent <= 0)
            return 0;
        p += sent;
        n -= (DWORD)sent;
    }
    return 1;
}

/* The classic SChannel client loop. Two details carry all the pain in a real
   implementation and both are exercised here: SEC_E_INCOMPLETE_MESSAGE means
   "I need more bytes, keep what you have", and a SECBUFFER_EXTRA on output
   means the tail of the buffer belongs to the next record. */
static SECURITY_STATUS do_handshake(conn *c, CredHandle *cred,
                                    const wchar_t *host, CtxtHandle *ctxt,
                                    DWORD req_flags)
{
    SecBuffer out[1], in[2];
    SecBufferDesc od, id;
    DWORD out_flags = 0;
    SECURITY_STATUS ss;
    int have_ctxt = 0;
    int rounds = 0;

    out[0].pvBuffer = NULL;
    out[0].cbBuffer = 0;
    out[0].BufferType = SECBUFFER_TOKEN;
    od.ulVersion = SECBUFFER_VERSION;
    od.cBuffers = 1;
    od.pBuffers = out;

    ss = InitializeSecurityContextW(cred, NULL, (SEC_WCHAR *)host, req_flags,
                                    0, 0, NULL, 0, ctxt, &od, &out_flags, NULL);
    if (ss != SEC_I_CONTINUE_NEEDED)
        return ss;
    have_ctxt = 1;

    if (out[0].cbBuffer && out[0].pvBuffer) {
        if (!send_all(c->sock, (unsigned char *)out[0].pvBuffer, out[0].cbBuffer)) {
            FreeContextBuffer(out[0].pvBuffer);
            return SEC_E_INTERNAL_ERROR;
        }
        FreeContextBuffer(out[0].pvBuffer);
        out[0].pvBuffer = NULL;
    }

    for (;;) {
        if (++rounds > 32)
            return SEC_E_INTERNAL_ERROR;

        if (c->len == 0) {
            int n = conn_fill(c);
            if (n < 0)
                return SEC_E_INTERNAL_ERROR;
            if (n == 0) {
                printf("       peer closed during handshake after %d round(s)\n",
                       rounds);
                return SEC_E_INTERNAL_ERROR;
            }
        }

        in[0].pvBuffer   = c->buf;
        in[0].cbBuffer   = c->len;
        in[0].BufferType = SECBUFFER_TOKEN;
        in[1].pvBuffer   = NULL;
        in[1].cbBuffer   = 0;
        in[1].BufferType = SECBUFFER_EMPTY;
        id.ulVersion = SECBUFFER_VERSION;
        id.cBuffers  = 2;
        id.pBuffers  = in;

        out[0].pvBuffer   = NULL;
        out[0].cbBuffer   = 0;
        out[0].BufferType = SECBUFFER_TOKEN;

        ss = InitializeSecurityContextW(cred, have_ctxt ? ctxt : NULL,
                                        (SEC_WCHAR *)host, req_flags, 0, 0,
                                        &id, 0, ctxt, &od, &out_flags, NULL);

        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            if (conn_fill(c) <= 0)
                return SEC_E_INTERNAL_ERROR;
            continue;
        }

        if (out[0].cbBuffer && out[0].pvBuffer) {
            int ok = send_all(c->sock, (unsigned char *)out[0].pvBuffer,
                              out[0].cbBuffer);
            FreeContextBuffer(out[0].pvBuffer);
            out[0].pvBuffer = NULL;
            if (!ok)
                return SEC_E_INTERNAL_ERROR;
        }

        /* Carry any leftover bytes to the front for the next record. */
        if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer) {
            memmove(c->buf, c->buf + (c->len - in[1].cbBuffer), in[1].cbBuffer);
            c->len = in[1].cbBuffer;
        } else if (ss != SEC_E_INCOMPLETE_MESSAGE) {
            c->len = 0;
        }

        if (ss == SEC_E_OK)
            return SEC_E_OK;
        if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE ||
            ss == SEC_I_COMPLETE_NEEDED)
            continue;
        return ss;
    }
}

/* --------------------------- probe 9: what the context will tell you about */

/* Every one of these is an attribute class a hand-written SSPI shim would have
   to answer. Printing them here is partly diagnosis and partly a scope
   estimate for that idea. */
static void probe_context_attrs(CtxtHandle *ctxt, SecPkgContext_StreamSizes *sizes)
{
    SECURITY_STATUS ss = QueryContextAttributesW(ctxt, SECPKG_ATTR_STREAM_SIZES,
                                                 sizes);
    if (ss != SEC_E_OK)
        fail("SECPKG_ATTR_STREAM_SIZES", ss, "Cannot size the record framing.");
    else
        pass("SECPKG_ATTR_STREAM_SIZES", "header %lu, trailer %lu, max msg %lu",
             (unsigned long)sizes->cbHeader, (unsigned long)sizes->cbTrailer,
             (unsigned long)sizes->cbMaximumMessage);

    {
        SecPkgContext_ConnectionInfo ci;
        memset(&ci, 0, sizeof ci);
        ss = QueryContextAttributesW(ctxt, SECPKG_ATTR_CONNECTION_INFO, &ci);
        if (ss != SEC_E_OK)
            fail("SECPKG_ATTR_CONNECTION_INFO", ss, "No negotiated-protocol detail.");
        else
            pass("SECPKG_ATTR_CONNECTION_INFO",
                 "proto 0x%lX, cipher 0x%lX/%lu bits, exch 0x%lX",
                 (unsigned long)ci.dwProtocol, (unsigned long)ci.aiCipher,
                 (unsigned long)ci.dwCipherStrength,
                 (unsigned long)ci.aiExch);
    }
}

/* Manual validation, run after a handshake that skipped it. This is the step
   that needs crypt32 plus the machine stores, and it is the one that a
   bring-your-own-TLS design has to replace with a shipped CA bundle. */
static void probe_manual_validation(CtxtHandle *ctxt, const wchar_t *host)
{
    PCCERT_CONTEXT cert = NULL;
    SECURITY_STATUS ss = QueryContextAttributesW(ctxt,
                             SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert);
    if (ss != SEC_E_OK || !cert) {
        fail("REMOTE_CERT_CONTEXT", ss, "Cannot retrieve the peer certificate.");
        return;
    }
    pass("REMOTE_CERT_CONTEXT", "peer cert, %lu bytes encoded",
         (unsigned long)cert->cbCertEncoded);

    {
        CERT_CHAIN_PARA para;
        PCCERT_CHAIN_CONTEXT chain = NULL;
        LPSTR usage[] = { (LPSTR)szOID_PKIX_KP_SERVER_AUTH };

        memset(&para, 0, sizeof para);
        para.cbSize = sizeof para;
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        para.RequestedUsage.Usage.cUsageIdentifier = 1;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = usage;

        if (!CertGetCertificateChain(NULL, cert, NULL, cert->hCertStore,
                                     &para, 0, NULL, &chain)) {
            fail("CertGetCertificateChain", (long)GetLastError(),
                 "Chain building failed -- this is the crypt32/HKLM dependency.");
        } else {
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl;
            CERT_CHAIN_POLICY_PARA  pp;
            CERT_CHAIN_POLICY_STATUS st;

            memset(&ssl, 0, sizeof ssl);
            ssl.cbSize = sizeof ssl;
            ssl.dwAuthType = AUTHTYPE_SERVER;
            ssl.pwszServerName = (WCHAR *)host;

            memset(&pp, 0, sizeof pp);
            pp.cbSize = sizeof pp;
            pp.pvExtraPolicyPara = &ssl;

            memset(&st, 0, sizeof st);
            st.cbSize = sizeof st;

            if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
                                                  &pp, &st)) {
                fail("CertVerifyChainPolicy", (long)GetLastError(),
                     "Policy check could not run.");
            } else if (st.dwError != 0) {
                fail("CertVerifyChainPolicy", (long)st.dwError,
                     "Chain built but did not satisfy SSL server policy.");
            } else {
                pass("CertVerifyChainPolicy", "chain trusted for %ls", host);
            }
            CertFreeCertificateChain(chain);
        }
    }
    CertFreeCertificateContext(cert);
}

/* ------------------------------- probe 10: records actually move both ways */

static void probe_record_io(conn *c, CtxtHandle *ctxt,
                            SecPkgContext_StreamSizes *sizes,
                            const wchar_t *host)
{
    char req[512];
    char hostA[256];
    unsigned char *msg;
    SecBuffer b[4];
    SecBufferDesc d;
    SECURITY_STATUS ss;
    int req_len;

    if (sizes->cbHeader == 0 && sizes->cbTrailer == 0) {
        skip("EncryptMessage", "stream sizes unavailable");
        return;
    }

    WideCharToMultiByte(CP_UTF8, 0, host, -1, hostA, sizeof hostA, NULL, NULL);
    req_len = snprintf(req, sizeof req,
                        "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                        "User-Agent: schantest\r\n\r\n", hostA);
    if (req_len < 0)
        req_len = (int)strlen(req);

    msg = (unsigned char *)malloc(sizes->cbHeader + (size_t)req_len + sizes->cbTrailer);
    if (!msg) {
        skip("EncryptMessage", "out of memory");
        return;
    }
    memcpy(msg + sizes->cbHeader, req, (size_t)req_len);

    b[0].pvBuffer = msg;                            b[0].cbBuffer = sizes->cbHeader;
    b[0].BufferType = SECBUFFER_STREAM_HEADER;
    b[1].pvBuffer = msg + sizes->cbHeader;          b[1].cbBuffer = (DWORD)req_len;
    b[1].BufferType = SECBUFFER_DATA;
    b[2].pvBuffer = msg + sizes->cbHeader + req_len; b[2].cbBuffer = sizes->cbTrailer;
    b[2].BufferType = SECBUFFER_STREAM_TRAILER;
    b[3].pvBuffer = NULL;                           b[3].cbBuffer = 0;
    b[3].BufferType = SECBUFFER_EMPTY;
    d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = b;

    ss = EncryptMessage(ctxt, 0, &d, 0);
    if (ss != SEC_E_OK) {
        fail("EncryptMessage", ss, "Could not encrypt an application record.");
        free(msg);
        return;
    }
    if (!send_all(c->sock, msg, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer)) {
        fail("EncryptMessage", (long)WSAGetLastError(), "Send failed.");
        free(msg);
        return;
    }
    pass("EncryptMessage", "%d byte request sent", req_len);
    free(msg);

    for (;;) {
        if (c->len == 0) {
            int n = conn_fill(c);
            if (n < 0 || (n == 0 && c->len == 0)) {
                fail("DecryptMessage", 0, "Peer closed before any plaintext.");
                return;
            }
        }

        b[0].pvBuffer = c->buf; b[0].cbBuffer = c->len; b[0].BufferType = SECBUFFER_DATA;
        b[1].pvBuffer = NULL; b[1].cbBuffer = 0; b[1].BufferType = SECBUFFER_EMPTY;
        b[2].pvBuffer = NULL; b[2].cbBuffer = 0; b[2].BufferType = SECBUFFER_EMPTY;
        b[3].pvBuffer = NULL; b[3].cbBuffer = 0; b[3].BufferType = SECBUFFER_EMPTY;
        d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = b;

        ss = DecryptMessage(ctxt, &d, 0, NULL);
        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            if (conn_fill(c) <= 0) {
                fail("DecryptMessage", 0, "Truncated record.");
                return;
            }
            continue;
        }
        if (ss == SEC_I_CONTEXT_EXPIRED) {
            fail("DecryptMessage", ss, "Peer sent close_notify before data.");
            return;
        }
        if (ss != SEC_E_OK) {
            fail("DecryptMessage", ss, "Could not decrypt the response.");
            return;
        }

        for (int i = 0; i < 4; i++) {
            if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer) {
                char line[128];
                DWORD n = b[i].cbBuffer < sizeof line - 1
                            ? b[i].cbBuffer : (DWORD)(sizeof line - 1);
                memcpy(line, b[i].pvBuffer, n);
                line[n] = '\0';
                for (char *p = line; *p; p++)
                    if (*p == '\r' || *p == '\n') { *p = '\0'; break; }
                pass("DecryptMessage", "%lu bytes plaintext: \"%s\"",
                     (unsigned long)b[i].cbBuffer, line);
                return;
            }
        }
        c->len = 0;
    }
}

/* ------------------------------------------------------------------- main */

static void usage(void)
{
    printf("usage: schantest.exe [host] [port] "
           "[--validate] [--no-handshake] [--quiet-token]\n");
}

int main(int argc, char **argv)
{
    const char *host = "www.microsoft.com";
    const char *port = "443";
    int let_schannel_validate = 0;
    int do_net = 1;
    int show_token = 1;
    int positional = 0;

    wchar_t hostW[256];
    WSADATA wsa;
    CredHandle cred;
    CtxtHandle ctxt;
    struct addrinfo *ai = NULL;
    conn c;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--validate") == 0)          let_schannel_validate = 1;
        else if (strcmp(argv[i], "--no-handshake") == 0) do_net = 0;
        else if (strcmp(argv[i], "--quiet-token") == 0)  show_token = 0;
        else if (strcmp(argv[i], "--help") == 0)         { usage(); return 0; }
        else if (argv[i][0] == '-')                      { usage(); return 2; }
        else if (positional++ == 0)                      host = argv[i];
        else                                             port = argv[i];
    }

    MultiByteToWideChar(CP_UTF8, 0, host, -1, hostW, 256);

    printf("schantest -- Windows TLS dependency probe\n");
    printf("target %s:%s, %s certificate validation\n\n", host, port,
           let_schannel_validate ? "schannel" : "manual");

    if (show_token)
        dump_token();

    printf("--- probes ---\n");

    if (!probe_sspi_reachable())
        goto done;

    SecInvalidateHandle(&cred);
    SecInvalidateHandle(&ctxt);

    if (!probe_acquire_cred(&cred, let_schannel_validate))
        goto done;

    probe_cert_stores();

    if (!do_net) {
        skip("getaddrinfo", "--no-handshake");
        goto cleanup_cred;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fail("WSAStartup", (long)WSAGetLastError(), "Winsock unavailable.");
        goto cleanup_cred;
    }

    if (!probe_dns(hostW, port, &ai))
        goto cleanup_wsa;

    memset(&c, 0, sizeof c);
    c.sock = probe_connect(ai);
    if (c.sock == INVALID_SOCKET)
        goto cleanup_ai;

    {
        DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                      ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                      ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
        SECURITY_STATUS ss;

        if (!let_schannel_validate)
            flags |= ISC_REQ_MANUAL_CRED_VALIDATION;

        ss = do_handshake(&c, &cred, hostW, &ctxt, flags);
        if (ss != SEC_E_OK) {
            fail("InitializeSecurityContext", ss, "Handshake did not complete.");
            goto cleanup_sock;
        }
        pass("InitializeSecurityContext", "handshake complete");
    }

    {
        SecPkgContext_StreamSizes sizes;
        memset(&sizes, 0, sizeof sizes);
        probe_context_attrs(&ctxt, &sizes);
        if (let_schannel_validate)
            skip("CertVerifyChainPolicy", "schannel validated during handshake");
        else
            probe_manual_validation(&ctxt, hostW);
        probe_record_io(&c, &ctxt, &sizes, hostW);
    }

    DeleteSecurityContext(&ctxt);
cleanup_sock:
    closesocket(c.sock);
cleanup_ai:
    freeaddrinfo(ai);
cleanup_wsa:
    WSACleanup();
cleanup_cred:
    FreeCredentialsHandle(&cred);
done:
    printf("\n--- summary ---\n");
    printf("  %d probe(s), %d failure(s)\n", g_probe, g_failures);
    if (g_failures == 0)
        printf("  TLS works end to end under this token.\n");
    return g_failures ? 1 : 0;
}
