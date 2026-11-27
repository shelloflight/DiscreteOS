/*
 * W3 helper DLL (docs/compat.md): real PE32+ DLL built with MSVC /MD /LD, exporting functions by
 * name, by ordinal, and via a forwarded export to KERNEL32.dll, with DllMain attach/detach
 * tracking, its own __declspec(thread) TLS variable, and cross-module SEH.
 */

#include <windows.h>

static volatile LONG process_attaches;
static volatile LONG thread_attaches;
static volatile LONG thread_detaches;
static __declspec(thread) int dll_tls_val = 42;

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst;
    (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        InterlockedIncrement(&process_attaches);
        break;
    case DLL_THREAD_ATTACH:
        InterlockedIncrement(&thread_attaches);
        break;
    case DLL_THREAD_DETACH:
        InterlockedIncrement(&thread_detaches);
        break;
    default:
        break;
    }
    return TRUE;
}

__declspec(dllexport) int __stdcall w3_add(int a, int b)
{
    return a + b;
}

__declspec(dllexport) int __stdcall w3_mul(int a, int b)
{
    return a * b;
}

__declspec(dllexport) int __stdcall w3_ord_fn(int x)
{
    return x * 3 + 1;
}

__declspec(dllexport) LONG __stdcall w3_attach_count(void)
{
    return process_attaches;
}

__declspec(dllexport) LONG __stdcall w3_thread_attach_count(void)
{
    return thread_attaches;
}

__declspec(dllexport) LONG __stdcall w3_thread_detach_count(void)
{
    return thread_detaches;
}

__declspec(dllexport) int __stdcall w3_get_tls(void)
{
    return dll_tls_val;
}

__declspec(dllexport) void __stdcall w3_set_tls(int v)
{
    dll_tls_val = v;
}

static volatile int dll_finally_ran;

__declspec(dllexport) int __stdcall w3_seh_local(void)
{
    int caught = 0;
    dll_finally_ran = 0;
    __try {
        __try {
            volatile int *p = NULL;
            *p = 7;
        } __finally {
            dll_finally_ran = 1;
        }
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        caught = 1;
    }
    return (caught && dll_finally_ran == 1) ? 1 : 0;
}

__declspec(dllexport) void __stdcall w3_raise_across(DWORD code)
{
    RaiseException(code, 0, 0, NULL);
}
