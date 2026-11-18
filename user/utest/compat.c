/*
 * utest (`utest compat`, test case `compat`): the D-CMPL proofs, run through the
 * dcmpl program (user/dcmpl) on real foreign binaries (compat/):
 *   - the START exception (ABI addition of 10b): a supervisor stops a new process before its first
 *     instruction and can change its memory and registers, or kill it;
 *   - W1: the MSVC-built w1.exe runs through the PE loader and minimal kernel32 (exit 0), an
 *     unsupported import is refused naming DLL and function, a fault in W1 is reported like a
 *     native one, a non-PE is refused by its header;
 *   - L1: the static Linux l1 runs under the Linux server (exit 0), an unsupported syscall gets
 *     -ENOSYS, a fault is reported and kills it, a non-ELF is refused;
 *   - W2: w2.exe, built with MSVC's static C runtime, runs its checks (heap, threads, TLS, FLS,
 *     command line, environment, SEH, C++ exceptions, time) with exit code 0; an access violation
 *     nobody handles ends it like a native fault;
 *   - L2: the static Linux l2 runs its checks (mmap/brk, clone threads with TLS and a futex lock,
 *     futex timeouts, signal handlers, time, fork refused) with exit code 0;
 *   - benchmarks (PE load, forwarded Linux syscall) and PE parser fuzzing.
 */

#include "utest.h"

#define S30 30000000000ull

static int64_t spawn_start(const char *args, uint32_t flags, dos_handle_t *ch)
{
    struct dos_spawn s = {
        .parent = self_proc, .image = my_image(),
        .name = (uint64_t)(uintptr_t)"utest.child", .name_len = 11,
        .args = (uint64_t)(uintptr_t)args, .args_len = strlen(args),
        .flags = flags, .exception_channel = (uint64_t)(uintptr_t)ch,
    };
    return dos_spawn(&s);
}

static int64_t read_exc(dos_handle_t ch, struct dos_exception_msg *m, dos_handle_t *exc)
{
    struct dos_msg msg = { (uint64_t)(uintptr_t)m, sizeof(*m), 1, (uint64_t)(uintptr_t)exc };
    int64_t r = dos_channel_read(ch, &msg, S30);
    if (r == 0 && (msg.len != sizeof(*m) || msg.nhandles != 1))
        return -100;
    return r;
}

static void test_start_exception(void)
{
    dos_handle_t ch = 0;
    EXPECT(spawn_start("exit 7", DOS_SPAWN_START_EXCEPTION, &ch), DOS_ERR_INVALID_ARGS);   /* no supervisor */

    /* Stopped before its first instruction: RIP at the entry, RDI = RSP = startup block. The
     * supervisor rewrites the child's arguments ("exit 7" -> "exit 9") before anything ran. */
    int64_t p = spawn_start("exit 7", DOS_SPAWN_EXCEPTION_CHANNEL | DOS_SPAWN_START_EXCEPTION, &ch);
    CHECK(p > 0 && ch != 0);
    struct dos_exception_msg m;
    dos_handle_t exc = 0;
    EXPECT(read_exc(ch, &m, &exc), 0);
    CHECK(m.kind == DOS_EXC_START && m.regs.rdi != 0 && m.regs.rsp == m.regs.rdi && m.regs.rip != 0);
    uint64_t args = 0;
    EXPECT(dos_process_read_memory((dos_handle_t)p, m.regs.rdi + 16, &args, 8), 8);
    char nine = '9';
    EXPECT(dos_process_write_memory((dos_handle_t)p, args + 5, &nine, 1), 1);
    struct dos_regs r;
    EXPECT(dos_exception_get_regs(exc, &r), 0);
    CHECK(r.rip == m.regs.rip);
    EXPECT(dos_exception_set_regs(exc, &r), 0);
    EXPECT(dos_exception_resume(exc, DOS_EXC_RESUME, 0), 0);
    dos_handle_close(exc);
    EXPECT(wait_exit(p, S30), 9);
    dos_handle_close(ch);

    /* Killed at the start: nothing ever ran. */
    p = spawn_start("exit 7", DOS_SPAWN_EXCEPTION_CHANNEL | DOS_SPAWN_START_EXCEPTION, &ch);
    EXPECT(read_exc(ch, &m, &exc), 0);
    CHECK(m.kind == DOS_EXC_START);
    EXPECT(dos_exception_resume(exc, DOS_EXC_KILL, 33), 0);
    dos_handle_close(exc);
    EXPECT(wait_exit(p, S30), 33);
    dos_handle_close(ch);

    /* The supervisor goes away before it answers: the process is killed (fail closed). */
    p = spawn_start("exit 7", DOS_SPAWN_EXCEPTION_CHANNEL | DOS_SPAWN_START_EXCEPTION, &ch);
    EXPECT(read_exc(ch, &m, &exc), 0);
    dos_handle_close(exc);
    EXPECT(wait_exit(p, S30), DOS_EXIT_FAULT);
    dos_handle_close(ch);
    /* ABI v10 (the Linux server's mmap and clone): a process's root VMAR; a stopped thread needs
     * someone to start it (the process's exception channel). */
    int64_t v = dos_process_vmar(self_proc);
    CHECK(v > 0);
    if (v > 0)
        dos_handle_close((dos_handle_t)v);
    EXPECT(dos_process_vmar(0x7FFFFFF0u), DOS_ERR_BAD_HANDLE);
    EXPECT(dos_thread_create_stopped(self_proc, 0x400000, 0x400000, 0), DOS_ERR_BAD_STATE);
    dos_printf("utest: compat: start exception (stopped before the first instruction, memory and "
               "registers set, kill, unresolved = kill); process_vmar, thread_create_stopped\n");
}

/* Run "dcmpl <args>" as a process named `pname`, with the log, VMEX and every program image (as
 * init gives them to programs it trusts). Returns its exit code. */
static int64_t run_dcmpl(const char *pname, const char *args)
{
    struct dos_spawn_handle hs[64];   /* the log, VMEX and every program (31 today) */
    uint32_t nh = 0;
    dos_handle_t image = 0;
    char buf[32];
    int64_t l = dos_handle_duplicate(log_h, DOS_RIGHTS_SAME);
    if (l > 0)
        hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)l, DOS_RIGHTS_SAME, DOS_TAG_LOG, 0 };
    int64_t vx = dos_handle_duplicate(dos_startup_handle(DOS_TAG_VMEX), DOS_RIGHTS_SAME);
    if (vx > 0)
        hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)vx, DOS_RIGHTS_SAME, DOS_TAG_VMEX, 0 };
    for (uint32_t i = 0; i < dos_start->nhandles && nh < 64; i++) {
        dos_handle_t h = dos_start->handles[i].handle;
        if (dos_start->handles[i].tag != DOS_TAG_PROGRAM)
            continue;
        if (dos_object_name(h, buf, sizeof(buf)) == 8 && strncmp(buf, "dcmpl.dx", 8) == 0)
            image = h;
        int64_t d = dos_handle_duplicate(h, DOS_RIGHTS_SAME);
        if (d > 0)
            hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)d, DOS_RIGHTS_SAME, DOS_TAG_PROGRAM, 0 };
    }
    struct dos_limits limits = { 48u << 20, 512, 8 };
    struct dos_spawn s = {
        .parent = self_proc, .image = image,
        .name = (uint64_t)(uintptr_t)pname, .name_len = strlen(pname),
        .args = (uint64_t)(uintptr_t)args, .args_len = strlen(args),
        .handles = (uint64_t)(uintptr_t)hs, .nhandles = nh,
        .limits = (uint64_t)(uintptr_t)&limits,
    };
    int64_t code = wait_exit(dos_spawn(&s), S30);
    dos_printf("utest: compat: dcmpl %s -> exit code %ld\n", args, code);
    return code;
}

#define REFUSED 2                           /* dcmpl's exit code for a refused program */
#define USAGE   3

void test_compat(void)
{
    dos_printf("utest: compat: D-CMPL proofs\n");
    test_start_exception();

    /* W1: Windows, in-process PE loader + kernel32. */
    EXPECT(run_dcmpl("w1.exe", "win w1.exe"), 0);
    EXPECT(run_dcmpl("w1bad.exe", "win w1bad.exe"), REFUSED);
    EXPECT(run_dcmpl("w1fault.exe", "win w1fault.exe"), DOS_EXIT_FAULT);
    EXPECT(run_dcmpl("dcmpl", "win l1"), REFUSED);          /* an ELF is not a PE (by its header) */
    EXPECT(run_dcmpl("dcmpl", "win nosuch.exe"), USAGE);

    /* L1: Linux, FORWARD process served by the Linux server. */
    EXPECT(run_dcmpl("l1", "linux l1"), 0);
    EXPECT(run_dcmpl("l1", "linux l1 enosys"), 0);
    EXPECT(run_dcmpl("l1", "linux l1 fault"), DOS_EXIT_FAULT);
    EXPECT(run_dcmpl("l1", "linux w1.exe"), REFUSED);       /* a PE is not an ELF */
    EXPECT(run_dcmpl("l1", "linux l1 bench 5000"), 0);

    /* W2 and L2: programs on their runtimes (files are tested from the shell, which has disks). */
    EXPECT(run_dcmpl("w2.exe", "win w2.exe alpha beta"), 0);
    EXPECT(run_dcmpl("w2.exe", "win w2.exe fault"), DOS_EXIT_FAULT);
    EXPECT(run_dcmpl("l2", "linux l2"), 0);

    /* The PE parser against mutated images. */
    EXPECT(run_dcmpl("dcmpl", "pefuzz 20000"), 0);
    dos_printf("utest: compat: %s (%u failures)\n", failures ? "FAILED" : "PASSED", failures);
}
