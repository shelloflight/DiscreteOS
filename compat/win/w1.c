/*
 * W1 (docs/compat.md): a Windows console Hello World without a C runtime. Built by build.ps1
 * with MSVC (cl /GS- /Zl, link /NODEFAULTLIB /ENTRY:w1_main /Brepro) against import libraries
 * made from kernel32.def, so the build needs no Windows SDK and is reproducible. Run on D-OS by
 * D-CMPL's PE loader (user/dcmpl, `dcmpl win w1.exe`).
 *
 * Besides printing, it checks what the loader promises a Windows program: the TEB at GS
 * (gs:[0x30] points to itself) and the PEB's ImageBaseAddress (gs:[0x60] + 0x10) is where the
 * image was loaded. Exit code 0 = all good.
 *
 * Variants (same file, /D): W1_FAULT writes to NULL after printing (the fault must be reported
 * like a native one); W1_BAD also imports USER32.dll!MessageBoxA (the loader must refuse it,
 * naming the DLL and function).
 */

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD std_handle);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE h, const void *buf, DWORD len, DWORD *written, void *overlapped);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned code);
#ifdef W1_BAD
__declspec(dllimport) int __stdcall MessageBoxA(HANDLE wnd, const char *text, const char *caption, unsigned type);
#endif

unsigned __int64 __readgsqword(unsigned long offset);
#pragma intrinsic(__readgsqword)

extern char __ImageBase;                  /* the linker's symbol for this image's load address */

#define STD_OUTPUT_HANDLE ((DWORD)-11)

static DWORD put(HANDLE out, const char *s, DWORD n)
{
    DWORD written = 0;
    if (!WriteFile(out, s, n, &written, 0))
        return 0;
    return written;
}

void __stdcall w1_main(void)
{
    static const char hello[] = "Hello, world from Windows (W1)\r\n";
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    unsigned code = 0;

    if (put(out, hello, sizeof(hello) - 1) != sizeof(hello) - 1)
        code |= 1;
    unsigned __int64 teb = __readgsqword(0x30);
    if (teb == 0 || *(unsigned __int64 *)(teb + 0x30) != teb)
        code |= 2;
    unsigned __int64 peb = __readgsqword(0x60);
    if (peb == 0 || *(unsigned __int64 *)(peb + 0x10) != (unsigned __int64)&__ImageBase)
        code |= 4;
    if (code == 0) {
        static const char ok[] = "W1: TEB at GS, PEB image base matches, kernel32 bound\r\n";
        put(out, ok, sizeof(ok) - 1);
    }
#ifdef W1_FAULT
    static const char boom[] = "W1: writing to address 0 (must be reported like a native fault)\r\n";
    put(out, boom, sizeof(boom) - 1);
    *(volatile int *)0 = 0x57;
#endif
#ifdef W1_BAD
    MessageBoxA(0, hello, hello, 0);
#endif
    ExitProcess(code);
}
