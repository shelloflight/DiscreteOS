/*
 * W2 (docs/compat.md): an ordinary Windows console program built with MSVC and the static C
 * runtime (/MT): the CRT's own startup (heap, locks, TLS, FLS, command line, environment, stdio)
 * runs unchanged on D-CMPL's kernel32. Built by build.ps1 (cl /MT /EHsc /O2, Windows SDK);
 * run on D-OS with `dcmpl win w2.exe <args>` or `run w2.exe <args>` in the shell.
 *
 * Each check prints one line; the exit code is the number of failed checks (0 = all good).
 *   heap        malloc/realloc/free and calloc patterns, HeapAlloc statistics
 *   threads     4 threads (_beginthreadex) bump a shared counter under a CRITICAL_SECTION
 *   tls         __declspec(thread) (the image's TLS directory), TlsAlloc and FlsAlloc per thread
 *   args        argv from the command line (the program is started with "alpha beta")
 *   env         an environment variable set and read back (SetEnvironmentVariable / getenv)
 *   files       fopen/fprintf/fread/remove in the directory given as argv[3] (if present)
 *   seh         __try/__except around a write to NULL and around RaiseException,
 *               __try/__finally run on the way out, a C++ exception thrown and caught
 *   time        GetSystemTimeAsFileTime is after 2000 (D-OS time starts there without a clock),
 *               QueryPerformanceCounter advances
 *
 * Mode "fault" (argv[1]): an access violation nobody handles (D-CMPL reports it and the program
 * ends with the native fault exit code, as on Windows).
 */

#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failed;

static void check(const char *what, int ok, const char *detail)
{
    printf("W2: %-8s %s%s%s\n", what, ok ? "ok" : "FAILED", detail ? ": " : "", detail ? detail : "");
    if (!ok)
        failed++;
}

/* ---- heap ------------------------------------------------------------------------------------ */
static void test_heap(void)
{
    int ok = 1;
    char *blocks[64];
    for (int i = 0; i < 64; i++) {
        blocks[i] = malloc((size_t)(i + 1) * 97);
        if (!blocks[i]) {
            ok = 0;
            break;
        }
        memset(blocks[i], i, (size_t)(i + 1) * 97);
    }
    for (int i = 0; ok && i < 64; i++) {
        char *p = realloc(blocks[i], (size_t)(i + 1) * 211);
        if (!p || p[(i + 1) * 97 - 1] != (char)i)
            ok = 0;
        else
            blocks[i] = p;
    }
    for (int i = 0; i < 64; i++)
        free(blocks[i]);
    int *z = calloc(1000, sizeof(int));
    for (int i = 0; ok && z && i < 1000; i++)
        if (z[i])
            ok = 0;
    free(z);
    void *big = malloc(3 << 20); /* larger than any heap segment: its own mapping */
    if (!big)
        ok = 0;
    else
        memset(big, 0x5A, 3 << 20);
    free(big);
    HANDLE h = GetProcessHeap();
    void *x = HeapAlloc(h, HEAP_ZERO_MEMORY, 4096);
    ok = ok && x && ((char *)x)[4095] == 0 && HeapSize(h, 0, x) >= 4096 && HeapFree(h, 0, x);
    check("heap", ok && z, NULL);
}

/* ---- threads and TLS --------------------------------------------------------------------------- */
static CRITICAL_SECTION lock;
static volatile long counter;
static long atomic_counter;
static __declspec(thread) int tls_value = 7;
static __declspec(thread) char tls_buf[64];
static DWORD tls_slot, fls_slot;
static volatile LONG fls_destroyed;

static void WINAPI fls_cleanup(void *p)
{
    if (p)
        InterlockedIncrement(&fls_destroyed);
}

static unsigned __stdcall worker(void *arg)
{
    int id = (int)(INT_PTR)arg;
    unsigned bad = 0;
    if (tls_value != 7) /* every thread starts with the initial value */
        bad |= 1;
    tls_value = 100 + id;
    sprintf_s(tls_buf, sizeof(tls_buf), "thread %d", id);
    TlsSetValue(tls_slot, (void *)(INT_PTR)(id + 1));
    FlsSetValue(fls_slot, (void *)(INT_PTR)(id + 1));
    for (int i = 0; i < 2000; i++) {
        EnterCriticalSection(&lock);
        counter++;
        LeaveCriticalSection(&lock);
        InterlockedIncrement(&atomic_counter);
        if ((i & 255) == 0)
            Sleep(0);
    }
    char want[64];
    sprintf_s(want, sizeof(want), "thread %d", id);
    if (tls_value != 100 + id || strcmp(tls_buf, want) != 0)
        bad |= 2;
    if (TlsGetValue(tls_slot) != (void *)(INT_PTR)(id + 1) || FlsGetValue(fls_slot) != (void *)(INT_PTR)(id + 1))
        bad |= 4;
    return bad;
}

static void test_threads(void)
{
    InitializeCriticalSection(&lock);
    tls_slot = TlsAlloc();
    fls_slot = FlsAlloc(fls_cleanup);
    HANDLE t[4];
    int ok = tls_slot != TLS_OUT_OF_INDEXES && fls_slot != FLS_OUT_OF_INDEXES;
    for (int i = 0; i < 4; i++) {
        t[i] = (HANDLE)_beginthreadex(NULL, 0, worker, (void *)(INT_PTR)i, 0, NULL);
        if (!t[i])
            ok = 0;
    }
    DWORD w = WaitForMultipleObjects(4, t, TRUE, 30000);
    ok = ok && w == WAIT_OBJECT_0;
    unsigned bits = 0;
    for (int i = 0; i < 4; i++) {
        DWORD code = 99;
        if (!GetExitCodeThread(t[i], &code))
            ok = 0;
        bits |= code;
        CloseHandle(t[i]);
    }
    char d[96];
    sprintf_s(d, sizeof(d), "counter %ld, atomic %ld, worker bits %u", counter, atomic_counter, bits);
    check("threads", ok && counter == 8000 && atomic_counter == 8000, d);
    sprintf_s(d, sizeof(d), "main tls_value %d, %ld FLS callbacks", tls_value, (long)fls_destroyed);
    check("tls", bits == 0 && tls_value == 7 && TlsGetValue(tls_slot) == NULL && fls_destroyed == 4, d);
    DeleteCriticalSection(&lock);
}

/* ---- command line, environment ----------------------------------------------------------------- */
static void test_args(int argc, char **argv)
{
    char d[160];
    sprintf_s(d, sizeof(d), "argc %d, argv[0] '%s', argv[1] '%s', argv[2] '%s'", argc, argv[0],
              argc > 1 ? argv[1] : "", argc > 2 ? argv[2] : "");
    check("args", argc >= 3 && strcmp(argv[1], "alpha") == 0 && strcmp(argv[2], "beta") == 0, d);
}

static void test_env(void)
{
    int ok = SetEnvironmentVariableA("D_OS_W2", "discrete") != 0;
    char buf[32];
    DWORD n = GetEnvironmentVariableA("D_OS_W2", buf, sizeof(buf));
    ok = ok && n == 8 && strcmp(buf, "discrete") == 0;
    _putenv_s("D_OS_W2_CRT", "yes");
    const char *v = getenv("D_OS_W2_CRT");
    ok = ok && v && strcmp(v, "yes") == 0;
    check("env", ok, NULL);
}

/* ---- files ----------------------------------------------------------------------------------- */
static void test_files(const char *dir)
{
    if (!dir) {
        check("files", 1, "skipped (no directory given)");
        return;
    }
    char path[260];
    sprintf_s(path, sizeof(path), "%s\\w2-test.txt", dir);
    FILE *f = NULL;
    int ok = fopen_s(&f, path, "w") == 0 && f;
    if (ok) {
        for (int i = 0; i < 100; i++)
            fprintf(f, "line %d of the W2 file test\n", i);
        ok = fclose(f) == 0;
    }
    char line[128] = { 0 };
    int lines = 0;
    if (ok && fopen_s(&f, path, "r") == 0 && f) {
        while (fgets(line, sizeof(line), f))
            lines++;
        fclose(f);
    } else {
        ok = 0;
    }
    WIN32_FILE_ATTRIBUTE_DATA a;
    ok = ok && GetFileAttributesExA(path, GetFileExInfoStandard, &a) && a.nFileSizeLow > 2000;
    ok = ok && remove(path) == 0 && GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
    char d[96];
    sprintf_s(d, sizeof(d), "%d lines read back, last '%.20s'", lines, line);
    check("files", ok && lines == 100, d);
}

/* ---- SEH, C++ exceptions --------------------------------------------------------------------- */
static int finally_ran;

static int filter(unsigned code, unsigned want) { return code == want ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH; }

static __declspec(noinline) void inner_fault(volatile int *p)
{
    __try {
        *p = 42;
    } __finally {
        finally_ran++;
    }
}

static __declspec(noinline) int raise_custom(void)
{
    RaiseException(0xE0D05001u, 0, 0, NULL);
    return 1;
}

static void test_seh(void)
{
    unsigned got = 0;
    __try {
        inner_fault(NULL);
    } __except (got = GetExceptionCode(), filter(got, EXCEPTION_ACCESS_VIOLATION)) {
        got |= 0x10000000;
    }
    unsigned got2 = 0;
    __try {
        raise_custom();
    } __except (filter(GetExceptionCode(), 0xE0D05001u)) {
        got2 = GetExceptionCode();
    }
    int zero = 0;
    unsigned got3 = 0;
    __try {
        volatile int q = 10 / *(volatile int *)&zero;
        (void)q;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        got3 = GetExceptionCode();
    }
    char d[128];
    sprintf_s(d, sizeof(d), "access violation %#x, finally %d, raised %#x, divide %#x", got & 0x0FFFFFFF, finally_ran, got2, got3);
    check("seh", got == (0x10000000 | EXCEPTION_ACCESS_VIOLATION) && finally_ran == 1 && got2 == 0xE0D05001u &&
                     got3 == EXCEPTION_INT_DIVIDE_BY_ZERO, d);
}

int cxx_throw_catch(void); /* w2cxx.cpp */

static void test_cxx(void)
{
    int r = cxx_throw_catch();
    char d[64];
    sprintf_s(d, sizeof(d), "caught %d", r);
    check("c++", r == 1234, d);
}

/* ---- time ------------------------------------------------------------------------------------ */
static void test_time(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULONGLONG t = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    LARGE_INTEGER a, b, f;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    Sleep(2);
    QueryPerformanceCounter(&b);
    SYSTEMTIME st;
    GetSystemTime(&st);
    char d[96];
    sprintf_s(d, sizeof(d), "%04u-%02u-%02u, %lld ticks in Sleep(2)", st.wYear, st.wMonth, st.wDay, b.QuadPart - a.QuadPart);
    /* 2000-01-01 as a FILETIME: 125911584000000000 */
    check("time", t >= 125911584000000000ull && f.QuadPart > 0 && b.QuadPart > a.QuadPart && st.wYear >= 2000, d);
}

int main(int argc, char **argv)
{
    printf("Hello from Windows (W2): MSVC static CRT on D-CMPL\n");
    if (argc > 1 && strcmp(argv[1], "fault") == 0) {
        printf("W2: writing to address 0 with no handler\n");
        fflush(stdout);
        *(volatile int *)0 = 1;
        return 99;
    }
    test_heap();
    test_threads();
    test_args(argc, argv);
    test_env();
    test_files(argc > 3 ? argv[3] : NULL);
    test_seh();
    test_cxx();
    test_time();
    printf("W2: %d checks failed\n", failed);
    return failed;
}
