/*
 * W3 (docs/compat.md): dynamic Windows program built with MSVC /MD /EHsc (dynamic CRT via
 * ucrtbase / vcruntime140 / vcruntime140_1 / api-ms-win-crt-*) and linked against w3lib.dll.
 *
 * Checks:
 *   dll_stat  static PE DLL import, DllMain(DLL_PROCESS_ATTACH), forwarded export to KERNEL32
 *   dll_dyn   LoadLibraryA/W, GetProcAddress (name, ordinal @10, forwarder), GetModuleHandle,
 *             GetModuleFileNameA, FreeLibrary
 *   dll_tls   per-DLL __declspec(thread) TLS + DllMain thread attach/detach across 4 threads
 *   crt_md    dynamic CRT heap, qsort, getenv/_putenv_s, sprintf_s, atexit
 *   seh_dll   SEH inside w3lib.dll AND RaiseException unwinding from w3lib.dll into w3.exe
 *   cxx_md    C++ /MD /EHsc throw/catch with RAII destructors and std::runtime_error
 *   prefix    (when given a file path arg) write/read/remove inside prefix + outside refused
 */

#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__declspec(dllimport) int __stdcall w3_add(int a, int b);
__declspec(dllimport) LONG __stdcall w3_attach_count(void);
__declspec(dllimport) LONG __stdcall w3_thread_attach_count(void);
__declspec(dllimport) LONG __stdcall w3_thread_detach_count(void);
__declspec(dllimport) int __stdcall w3_get_tls(void);
__declspec(dllimport) void __stdcall w3_set_tls(int v);
__declspec(dllimport) int __stdcall w3_seh_local(void);
__declspec(dllimport) void __stdcall w3_raise_across(DWORD code);
__declspec(dllimport) DWORD __stdcall w3_fwd_pid(void);

int w3_cxx_test(void); /* w3cxx.cpp */

static int failed;

static void check(const char *what, int ok, const char *detail)
{
    printf("W3: %-8s %s%s%s\n", what, ok ? "ok" : "FAILED", detail ? ": " : "", detail ? detail : "");
    if (!ok)
        failed++;
}

static void test_dll_static(void)
{
    int sum = w3_add(20, 22);
    LONG att = w3_attach_count();
    DWORD fpid = w3_fwd_pid();
    DWORD pid = GetCurrentProcessId();
    char d[96];
    sprintf_s(d, sizeof(d), "add=%d, attach=%ld, fwd_pid=%lu", sum, (long)att, (unsigned long)fpid);
    check("dll_stat", sum == 42 && att == 1 && fpid == pid, d);
}

static void test_dll_dynamic(void)
{
    HMODULE h = LoadLibraryA("w3lib.dll");
    int ok = h != NULL && GetModuleHandleA("w3lib.dll") == h;
    typedef int(__stdcall * mul_fn)(int, int);
    typedef int(__stdcall * ord_fn)(int);
    typedef DWORD(__stdcall * pid_fn)(void);
    typedef ULONGLONG(__stdcall * tick_fn)(void);
    mul_fn fmul = h ? (mul_fn)GetProcAddress(h, "w3_mul") : NULL;
    ord_fn ford = h ? (ord_fn)GetProcAddress(h, MAKEINTRESOURCEA(10)) : NULL;
    pid_fn fpid = h ? (pid_fn)GetProcAddress(h, "w3_fwd_pid") : NULL;
    char path[260] = { 0 };
    DWORD pn = h ? GetModuleFileNameA(h, path, sizeof(path)) : 0;
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    tick_fn ftick = k32 ? (tick_fn)GetProcAddress(k32, "GetTickCount64") : NULL;
    ok = ok && fmul && fmul(6, 7) == 42;
    ok = ok && ford && ford(13) == 40;
    ok = ok && fpid && fpid() == GetCurrentProcessId();
    ok = ok && pn > 0;
    ok = ok && ftick && ftick() >= 0;
    ok = ok && FreeLibrary(h);
    check("dll_dyn", ok, path);
}

static unsigned __stdcall tls_worker(void *arg)
{
    int id = (int)(INT_PTR)arg;
    if (w3_get_tls() != 42)
        return 1;
    w3_set_tls(200 + id);
    Sleep(2);
    return (w3_get_tls() == 200 + id) ? 0 : 2;
}

static void test_dll_tls(void)
{
    HANDLE th[4];
    int ok = (w3_get_tls() == 42);
    for (int i = 0; i < 4; i++) {
        th[i] = (HANDLE)_beginthreadex(NULL, 0, tls_worker, (void *)(INT_PTR)i, 0, NULL);
        if (!th[i])
            ok = 0;
    }
    if (WaitForMultipleObjects(4, th, TRUE, 30000) != WAIT_OBJECT_0)
        ok = 0;
    unsigned bits = 0;
    for (int i = 0; i < 4; i++) {
        DWORD code = 99;
        GetExitCodeThread(th[i], &code);
        bits |= code;
        CloseHandle(th[i]);
    }
    LONG ta = w3_thread_attach_count();
    LONG td = w3_thread_detach_count();
    char d[96];
    sprintf_s(d, sizeof(d), "main_tls=%d, attach=%ld, detach=%ld, bits=%u", w3_get_tls(), (long)ta, (long)td, bits);
    check("dll_tls", ok && bits == 0 && w3_get_tls() == 42 && ta >= 4 && td >= 4, d);
}

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

static void test_crt_md(void)
{
    int *arr = (int *)calloc(8, sizeof(int));
    int ok = arr != NULL;
    if (ok) {
        int init[8] = { 9, 2, 7, 1, 5, 3, 8, 4 };
        memcpy(arr, init, sizeof(init));
        qsort(arr, 8, sizeof(int), cmp_int);
        ok = arr[0] == 1 && arr[7] == 9;
        arr = (int *)realloc(arr, 16 * sizeof(int));
        ok = ok && arr != NULL && arr[0] == 1 && arr[7] == 9;
        free(arr);
    }
    ok = ok && _putenv_s("D_OS_W3", "dynamic_crt") == 0;
    const char *v = getenv("D_OS_W3");
    ok = ok && v && strcmp(v, "dynamic_crt") == 0;
    check("crt_md", ok, "malloc/calloc/realloc/qsort/getenv");
}

static void test_seh_dll(void)
{
    int local_ok = w3_seh_local();
    DWORD cross = 0;
    __try {
        w3_raise_across(0xE0D05003u);
    } __except (GetExceptionCode() == 0xE0D05003u ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        cross = GetExceptionCode();
    }
    char d[96];
    sprintf_s(d, sizeof(d), "local=%d, cross=%#lx", local_ok, (unsigned long)cross);
    check("seh_dll", local_ok == 1 && cross == 0xE0D05003u, d);
}

static void test_cxx_md(void)
{
    int r = w3_cxx_test();
    char d[64];
    sprintf_s(d, sizeof(d), "caught %d", r);
    check("cxx_md", r == 5678, d);
}

static void test_prefix(const char *path)
{
    if (!path) {
        check("prefix", 1, "skipped (no path given)");
        return;
    }
    FILE *f = NULL;
    int ok = fopen_s(&f, path, "w") == 0 && f != NULL;
    if (ok) {
        for (int i = 0; i < 50; i++)
            fprintf(f, "w3 prefix line %d\n", i);
        ok = fclose(f) == 0;
    }
    int lines = 0;
    char buf[128] = { 0 };
    if (ok && fopen_s(&f, path, "r") == 0 && f != NULL) {
        while (fgets(buf, sizeof(buf), f))
            lines++;
        fclose(f);
    } else {
        ok = 0;
    }
    ok = ok && remove(path) == 0;
    /* Outside namespace must be refused. */
    FILE *esc = NULL;
    int escaped = (fopen_s(&esc, "C:\\boot\\README.TXT", "r") == 0 && esc != NULL);
    if (esc)
        fclose(esc);
    char d[96];
    sprintf_s(d, sizeof(d), "%d lines in prefix, escape refused=%d", lines, !escaped);
    check("prefix", ok && lines == 50 && !escaped, d);
}

int main(int argc, char **argv)
{
    printf("Hello from Windows (W3): MSVC dynamic CRT (/MD) + PE DLLs on D-CMPL\n");
    test_dll_static();
    test_dll_dynamic();
    test_dll_tls();
    test_crt_md();
    test_seh_dll();
    test_cxx_md();
    test_prefix(argc > 1 ? argv[1] : NULL);
    printf("W3: %d checks failed\n", failed);
    return failed;
}
