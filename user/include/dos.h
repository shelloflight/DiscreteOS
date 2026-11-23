/*
 * D-OS user ABI, version 7 (C binding). Reference: docs/abi.md. A program built for version N runs
 * on any kernel whose version is at least N (syscall numbers and structures never change meaning).
 *
 * Every syscall: `syscall` with the number in RAX, arguments in RDI, RSI, RDX, R10, R8, R9.
 * Result in RAX: >= 0 is a value (handle, size, address, count), < 0 a DOS_ERR_* status.
 * RCX and R11 are clobbered; every other register is preserved.
 * A program reaches kernel objects only through the handles it was given at start (struct
 * dos_startup) and the ones it creates: there is no global namespace and no ambient authority.
 */
#ifndef DOS_ABI_H
#define DOS_ABI_H

#include <stddef.h>
#include <stdint.h>

#define DOS_ABI_VERSION 16

typedef uint32_t dos_handle_t;
#define DOS_HANDLE_INVALID 0u

/* ---- status codes ------------------------------------------------------------------------ */
#define DOS_OK               0
#define DOS_ERR_NO_MEMORY    (-1)
#define DOS_ERR_INVALID_ARGS (-2)
#define DOS_ERR_BAD_HANDLE   (-3)
#define DOS_ERR_WRONG_TYPE   (-4)
#define DOS_ERR_ACCESS_DENIED (-5)
#define DOS_ERR_NO_RESOURCES (-6)    /* a quota would be exceeded */
#define DOS_ERR_OUT_OF_RANGE (-7)
#define DOS_ERR_TIMED_OUT    (-8)
#define DOS_ERR_BAD_STATE    (-9)
#define DOS_ERR_NO_SPACE     (-10)
#define DOS_ERR_BAD_ADDRESS  (-11)   /* a pointer argument is not valid user memory */
#define DOS_ERR_NOT_SUPPORTED (-12)  /* unknown syscall */
#define DOS_ERR_SHOULD_WAIT  (-13)   /* nothing to do now (empty channel, full queue): wait, retry */
#define DOS_ERR_BUFFER_TOO_SMALL (-14) /* the sizes needed are written back */
#define DOS_ERR_PEER_CLOSED  (-15)   /* the other end of the channel is gone */
#define DOS_ERR_BAD_SIGNATURE (-16)  /* ABI v4: a .dsig does not match the content or the D-OS key */
#define DOS_ERR_NOT_SIGNED   (-17)   /* ABI v4: spawn of an image neither signed nor allowed unsigned */

/* ---- rights ------------------------------------------------------------------------------ */
#define DOS_RIGHT_DUPLICATE (1u << 0)
#define DOS_RIGHT_TRANSFER  (1u << 1)
#define DOS_RIGHT_READ      (1u << 2)
#define DOS_RIGHT_WRITE     (1u << 3)
#define DOS_RIGHT_EXECUTE   (1u << 4)
#define DOS_RIGHT_MAP       (1u << 5)
#define DOS_RIGHT_SIGNAL    (1u << 6)
#define DOS_RIGHT_WAIT      (1u << 7)
#define DOS_RIGHT_INSPECT   (1u << 8)
#define DOS_RIGHT_MANAGE    (1u << 9)
#define DOS_RIGHTS_SAME     (1u << 31)

/* ---- object types and signals --------------------------------------------------------------- */
#define DOS_OBJ_PROCESS 1
#define DOS_OBJ_THREAD  2
#define DOS_OBJ_VMO     3
#define DOS_OBJ_VMAR    4
#define DOS_OBJ_EVENT   5
#define DOS_OBJ_TIMER   6
#define DOS_OBJ_LOG     7
#define DOS_OBJ_CHANNEL 8
#define DOS_OBJ_PORT    9
#define DOS_OBJ_EXCEPTION 10
#define DOS_OBJ_RESOURCE  11
#define DOS_OBJ_DEVICE    12     /* ABI v3 */
#define DOS_OBJ_INTERRUPT 13
#define DOS_OBJ_PIN       14

#define DOS_SIGNALED    (1u << 0)     /* event set; timer fired */
#define DOS_TERMINATED  (1u << 1)     /* process / thread ended */
#define DOS_READABLE    (1u << 2)     /* channel: a message waits; port: a completion waits */
#define DOS_WRITABLE    (1u << 3)     /* channel: the peer's queue has room */
#define DOS_PEER_CLOSED (1u << 4)     /* channel: the other end is gone */

#define DOS_WAIT_FOREVER UINT64_MAX
#define DOS_ANY          UINT64_MAX     /* vmar_map / vmar_allocate: kernel picks the address */

/* Exit codes the kernel gives a process it ended. */
#define DOS_EXIT_KILLED  ((int32_t)0x80000001)
#define DOS_EXIT_FAULT   ((int32_t)0x80000002)

/* ---- syscall numbers ------------------------------------------------------------------------- */
enum {
    DOS_SYS_ABI_VERSION = 0, DOS_SYS_LOG_WRITE, DOS_SYS_HANDLE_CLOSE, DOS_SYS_HANDLE_DUPLICATE,
    DOS_SYS_HANDLE_REPLACE, DOS_SYS_HANDLE_GRANT, DOS_SYS_OBJECT_INFO, DOS_SYS_OBJECT_NAME,
    DOS_SYS_OBJECT_WAIT, DOS_SYS_EVENT_CREATE, DOS_SYS_EVENT_SIGNAL, DOS_SYS_TIMER_CREATE,
    DOS_SYS_TIMER_SET, DOS_SYS_TIMER_CANCEL, DOS_SYS_VMO_CREATE, DOS_SYS_VMO_READ,
    DOS_SYS_VMO_WRITE, DOS_SYS_VMO_SIZE, DOS_SYS_VMAR_MAP, DOS_SYS_VMAR_UNMAP,
    DOS_SYS_VMAR_ALLOCATE, DOS_SYS_PROCESS_CREATE, DOS_SYS_PROCESS_KILL, DOS_SYS_PROCESS_EXIT,
    DOS_SYS_PROCESS_QUOTA, DOS_SYS_PROCESS_EXIT_CODE, DOS_SYS_THREAD_CREATE, DOS_SYS_THREAD_EXIT,
    DOS_SYS_THREAD_EXIT_CODE, DOS_SYS_SPAWN, DOS_SYS_CLOCK_NS, DOS_SYS_YIELD,
    /* ABI v2 */
    DOS_SYS_CHANNEL_CREATE, DOS_SYS_CHANNEL_WRITE, DOS_SYS_CHANNEL_READ, DOS_SYS_CHANNEL_CALL,
    DOS_SYS_PORT_CREATE, DOS_SYS_PORT_ENTER, DOS_SYS_OBJECT_WAIT_ASYNC, DOS_SYS_PORT_CANCEL,
    DOS_SYS_PROCESS_EXCEPTION_CHANNEL, DOS_SYS_EXCEPTION_GET_REGS, DOS_SYS_EXCEPTION_SET_REGS,
    DOS_SYS_EXCEPTION_RESUME, DOS_SYS_THREAD_SET_EXCEPTION_HANDLER, DOS_SYS_EXCEPTION_RETURN,
    DOS_SYS_THREAD_SET_BASE, DOS_SYS_THREAD_GET_BASE, DOS_SYS_VMO_MAKE_EXECUTABLE,
    DOS_SYS_PROCESS_READ_MEMORY, DOS_SYS_PROCESS_WRITE_MEMORY,
    /* ABI v3: devices for user-space drivers */
    DOS_SYS_DEVICE_INFO, DOS_SYS_DEVICE_CONFIG_READ, DOS_SYS_DEVICE_CONFIG_WRITE, DOS_SYS_DEVICE_MAP_BAR,
    DOS_SYS_DEVICE_IO_READ, DOS_SYS_DEVICE_IO_WRITE, DOS_SYS_DEVICE_INTERRUPT, DOS_SYS_INTERRUPT_ACK,
    DOS_SYS_DEVICE_DMA_MAP,
    /* ABI v4: code signing */
    DOS_SYS_VMO_VERIFY, DOS_SYS_VMO_ALLOW_UNSIGNED,
    /* ABI v5: remote attestation */
    DOS_SYS_ATTEST,
    /* ABI v6: power control */
    DOS_SYS_SYSTEM_POWER,
    /* ABI v7: service manager decisions in the measurement log */
    DOS_SYS_MEASURE,
    /* ABI v8: the log service */
    DOS_SYS_KLOG_READ, DOS_SYS_LOG_RECORD,
    /* ABI v9: the terminal and the shell */
    DOS_SYS_DISPLAY_INFO, DOS_SYS_PROCESS_HANDLES,
    /* ABI v10: D-CMPL's Linux server (mmap, clone) */
    DOS_SYS_PROCESS_VMAR, DOS_SYS_THREAD_CREATE_STOPPED,
    /* ABI v12: hardware-rooted attestation */
    DOS_SYS_ATTEST_ACTIVATE,
    /* ABI v13: demand paging and child VMAR destruction */
    DOS_SYS_VMAR_DESTROY,
    /* ABI v14: kernel ChaCha20 CSPRNG */
    DOS_SYS_GET_RANDOM,
    /* ABI v15: physical base address of a device memory BAR */
    DOS_SYS_DEVICE_BAR_ADDR,
    /* ABI v16: TPM 2.0 credential sealing */
    DOS_SYS_TPM_SEAL, DOS_SYS_TPM_UNSEAL,
    DOS_SYS_COUNT,
    DOS_SYS_KTEST_SMAP = 0xF000,     /* test kernels only */
    DOS_SYS_KTEST_SMEP = 0xF001,
};

/* ---- structures (all little-endian, no padding) ------------------------------------------------ */
struct dos_info   { uint32_t type, rights; uint64_t koid; };
struct dos_limits { uint64_t memory, handles, threads; };      /* bytes, handles, threads */
struct dos_quota  { struct dos_limits limits, used; };

struct dos_spawn_handle {
    dos_handle_t handle;     /* moved into the new process (needs TRANSFER) */
    uint32_t     rights;     /* a subset of the handle's rights, or DOS_RIGHTS_SAME */
    uint32_t     tag;        /* how the child finds it (struct dos_startup) */
    uint32_t     reserved;
};

#define DOS_SPAWN_MAX_HANDLES       256u      /* handles one spawn may pass */
#define DOS_SPAWN_EXCEPTION_CHANNEL (1u << 0)   /* give the spawner the child's exception channel */
#define DOS_SPAWN_FORWARD           (1u << 1)   /* every syscall goes to the supervisor (needs the above) */
#define DOS_SPAWN_START_EXCEPTION   (1u << 2)   /* stop before the first instruction (needs a channel) */

struct dos_spawn {
    dos_handle_t parent;     /* process (MANAGE) whose quota the child is carved from */
    dos_handle_t image;      /* VMO (READ) holding the ELF executable */
    uint64_t     name, name_len;
    uint64_t     args, args_len;            /* bytes, at most 4096 */
    uint64_t     handles;                   /* struct dos_spawn_handle[], at most DOS_SPAWN_MAX_HANDLES */
    uint32_t     nhandles, flags;           /* flags: DOS_SPAWN_* */
    uint64_t     limits;                    /* struct dos_limits *, 0 = defaults */
    uint64_t     exception_channel;         /* DOS_SPAWN_EXCEPTION_CHANNEL: dos_handle_t * (out) */
};

/* ---- channels (ABI v2) ---------------------------------------------------------------------- */
#define DOS_CHANNEL_MAX_BYTES   65536u
#define DOS_CHANNEL_MAX_HANDLES 64u
#define DOS_CHANNEL_MAX_QUEUE   256u

struct dos_msg_handle { dos_handle_t handle; uint32_t rights; };   /* rights: subset or DOS_RIGHTS_SAME */
/* write: data/len and handles (struct dos_msg_handle[nhandles]) to send.
 * read:  buffers (data: len bytes, handles: dos_handle_t[nhandles]); the sizes received (or, on
 *        BUFFER_TOO_SMALL, needed) are written back into len and nhandles. */
struct dos_msg { uint64_t data; uint32_t len, nhandles; uint64_t handles; };

/* ---- ports (ABI v2): shared-memory rings ----------------------------------------------------- */
struct dos_port_header {
    uint32_t sq_head, sq_tail, sq_mask;     /* kernel advances sq_head; you write sq_tail */
    uint32_t cq_head, cq_tail, cq_mask;     /* you advance cq_head; kernel writes cq_tail */
    uint32_t overflow, flags;               /* completions waiting in the kernel for room */
    uint64_t sq_off, cq_off;                /* offsets of the rings in the VMO */
};
struct dos_sqe { uint32_t op, flags; uint64_t user_data; uint64_t args[6]; };   /* op: DOS_SYS_* */
struct dos_cqe { uint64_t user_data; int64_t result; };

/* ---- exceptions (ABI v2) -------------------------------------------------------------------- */
struct dos_regs {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags, fs_base, gs_base;
};
#define DOS_EXC_FAULT   1     /* a CPU exception; vector = its number */
#define DOS_EXC_SYSCALL 2     /* a syscall of a FORWARD process; error = its number (RAX) */
#define DOS_EXC_START   3     /* DOS_SPAWN_START_EXCEPTION: the first thread, before its first instruction */
#define DOS_EXC_RESUME  0
#define DOS_EXC_KILL    1     /* kill the process with the given exit code */
#define DOS_EXC_EXIT_THREAD 2 /* ABI v10: end only the stopped thread, with the given exit code */

/* In-process handler: RDI points at this, on the handler stack; resume with dos_exception_return. */
struct dos_exception_record {
    uint32_t kind, vector;
    uint64_t error, cr2;
    struct dos_regs regs;
    uint64_t reserved;
};
/* Exception channel message; it carries one handle: the exception (READ, WRITE). */
struct dos_exception_msg {
    uint32_t txid, kind, vector, reserved;
    uint64_t error, cr2, pid, tid;          /* pid, tid: koids */
    struct dos_regs regs;
};

/* Startup block: RDI at the entry point points at it (top of the initial stack). */
#define DOS_STARTUP_MAGIC 0x53534F44u     /* "DOSS" */
#define DOS_TAG_PROC_SELF   1
#define DOS_TAG_THREAD_SELF 2
#define DOS_TAG_VMAR_ROOT   3
#define DOS_TAG_LOG         4
#define DOS_TAG_PROGRAM     5             /* an executable image VMO (name: object_name) */
#define DOS_TAG_VMEX        6             /* resource: may make sealed VMOs executable */
#define DOS_TAG_DEVICE      7             /* a device (ABI v3): init gets all, devmgr what init passes */
#define DOS_TAG_POWER       8             /* resource (ABI v6): may switch the machine off or reset it */
#define DOS_TAG_MEASURE     9             /* resource (ABI v7): may record decisions in PCR 10 (init) */
#define DOS_TAG_MANIFEST    10            /* ABI v7: an embedded service manifest <name>.dman (init) */
#define DOS_TAG_KLOG        11            /* resource (ABI v8): may read the kernel log (init; the log service) */
#define DOS_TAG_BOOT_TIME   12            /* ABI v8: the wall-clock time the loader read (32-byte VMO; UEFI only) */
#define DOS_TAG_POWER_BUTTON 13           /* ABI v11: event signaled on each power-button press (init) */
#define DOS_TAG_TPM_SEAL    14            /* resource (ABI v16): TPM 2.0 credential sealing (init; identity) */
#define DOS_TAG_USER        0x10000       /* first tag for handles a spawner passes */

struct dos_startup_handle { dos_handle_t handle; uint32_t tag; };
struct dos_startup {
    uint32_t magic, abi_version, nhandles, args_len;
    uint64_t args;                          /* argument bytes (NUL-terminated copy) */
    uint64_t image_base;                    /* load bias of the executable */
    uint64_t stack_base, stack_size;
    struct dos_startup_handle handles[];
};

/* ---- devices (ABI v3) ---------------------------------------------------------------------- */
#define DOS_DEVICE_PCI      1
#define DOS_DEVICE_PLATFORM 2
#define DOS_DEVICE_IOMMU    (1u << 0)     /* flags: DMA is confined by an IOMMU */
#define DOS_DEVICE_MSI      (1u << 1)
#define DOS_DEVICE_MSIX     (1u << 2)
#define DOS_BAR_NONE   0
#define DOS_BAR_MEMORY 1
#define DOS_BAR_IO     2
#define DOS_DMA_DEVICE_READ  (1u << 0)    /* device_dma_map: the device may read the pages */
#define DOS_DMA_DEVICE_WRITE (1u << 1)    /*                 the device may write them */
struct dos_device_info {
    uint32_t kind, flags;                   /* DOS_DEVICE_* */
    uint16_t vendor, device;                /* PCI ids (0 for platform devices) */
    uint8_t  class_code, subclass, progif, revision;
    uint8_t  bus, dev, func, reserved0;
    uint16_t irqs, config_size;             /* interrupt sources; config space bytes */
    uint64_t dma_faults;                    /* DMA the IOMMU blocked for this device */
    uint64_t bar_size[6];                   /* platform: I/O windows */
    uint8_t  bar_kind[6], reserved1[2];     /* DOS_BAR_* */
    char     name[16];
};

_Static_assert(sizeof(struct dos_device_info) == 104, "struct dos_device_info layout");

/* ---- raw syscalls ------------------------------------------------------------------------------ */
static inline int64_t dos_syscall6(uint64_t n, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f)
{
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    int64_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
#ifdef __clang_analyzer__
/* Static analysis (build.ps1 test, case static): the kernel writes through pointer arguments,
 * which the analyzer cannot see through inline assembly. An undefined function stands in for
 * the syscall instruction: the analyzer then assumes, as it should, that every pointer passed may
 * have been written. Never compiled into a program. */
int64_t dos_syscall_analyzed(uint64_t n, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5);
#define DOS_SC(n, a, b, c, d, e, f) dos_syscall_analyzed((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), (uint64_t)(d), (uint64_t)(e), (uint64_t)(f))
#else
#define DOS_SC(n, a, b, c, d, e, f) dos_syscall6((n), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c), (uint64_t)(d), (uint64_t)(e), (uint64_t)(f))
#endif

static inline int64_t dos_abi_version(void) { return DOS_SC(DOS_SYS_ABI_VERSION, 0, 0, 0, 0, 0, 0); }
static inline int64_t dos_log_write(dos_handle_t log, const void *s, size_t n) { return DOS_SC(DOS_SYS_LOG_WRITE, log, s, n, 0, 0, 0); }
static inline int64_t dos_handle_close(dos_handle_t h) { return DOS_SC(DOS_SYS_HANDLE_CLOSE, h, 0, 0, 0, 0, 0); }
static inline int64_t dos_handle_duplicate(dos_handle_t h, uint32_t rights) { return DOS_SC(DOS_SYS_HANDLE_DUPLICATE, h, rights, 0, 0, 0, 0); }
static inline int64_t dos_handle_replace(dos_handle_t h, uint32_t rights) { return DOS_SC(DOS_SYS_HANDLE_REPLACE, h, rights, 0, 0, 0, 0); }
static inline int64_t dos_handle_grant(dos_handle_t h, uint32_t rights, dos_handle_t proc) { return DOS_SC(DOS_SYS_HANDLE_GRANT, h, rights, proc, 0, 0, 0); }
static inline int64_t dos_object_info(dos_handle_t h, struct dos_info *out) { return DOS_SC(DOS_SYS_OBJECT_INFO, h, out, 0, 0, 0, 0); }
static inline int64_t dos_object_name(dos_handle_t h, char *buf, size_t n) { return DOS_SC(DOS_SYS_OBJECT_NAME, h, buf, n, 0, 0, 0); }
static inline int64_t dos_object_wait(dos_handle_t h, uint32_t mask, uint64_t timeout_ns) { return DOS_SC(DOS_SYS_OBJECT_WAIT, h, mask, timeout_ns, 0, 0, 0); }
static inline int64_t dos_event_create(void) { return DOS_SC(DOS_SYS_EVENT_CREATE, 0, 0, 0, 0, 0, 0); }
static inline int64_t dos_event_signal(dos_handle_t h, uint32_t clear, uint32_t set) { return DOS_SC(DOS_SYS_EVENT_SIGNAL, h, clear, set, 0, 0, 0); }
static inline int64_t dos_timer_create(void) { return DOS_SC(DOS_SYS_TIMER_CREATE, 0, 0, 0, 0, 0, 0); }
static inline int64_t dos_timer_set(dos_handle_t h, uint64_t delay_ns) { return DOS_SC(DOS_SYS_TIMER_SET, h, delay_ns, 0, 0, 0, 0); }
static inline int64_t dos_timer_cancel(dos_handle_t h) { return DOS_SC(DOS_SYS_TIMER_CANCEL, h, 0, 0, 0, 0, 0); }
static inline int64_t dos_vmo_create(uint64_t size) { return DOS_SC(DOS_SYS_VMO_CREATE, size, 0, 0, 0, 0, 0); }
static inline int64_t dos_vmo_read(dos_handle_t h, uint64_t off, void *buf, uint64_t n) { return DOS_SC(DOS_SYS_VMO_READ, h, off, buf, n, 0, 0); }
static inline int64_t dos_vmo_write(dos_handle_t h, uint64_t off, const void *buf, uint64_t n) { return DOS_SC(DOS_SYS_VMO_WRITE, h, off, buf, n, 0, 0); }
static inline int64_t dos_vmo_size(dos_handle_t h) { return DOS_SC(DOS_SYS_VMO_SIZE, h, 0, 0, 0, 0, 0); }
static inline int64_t dos_vmar_map(dos_handle_t vmar, uint64_t offset, dos_handle_t vmo, uint64_t vmo_off, uint64_t len, uint32_t perms)
{ return DOS_SC(DOS_SYS_VMAR_MAP, vmar, offset, vmo, vmo_off, len, perms); }
static inline int64_t dos_vmar_unmap(dos_handle_t vmar, uint64_t addr, uint64_t len) { return DOS_SC(DOS_SYS_VMAR_UNMAP, vmar, addr, len, 0, 0, 0); }
static inline int64_t dos_vmar_allocate(dos_handle_t vmar, uint64_t offset, uint64_t len, uint32_t rights, uint64_t *base)
{ return DOS_SC(DOS_SYS_VMAR_ALLOCATE, vmar, offset, len, rights, base, 0); }
static inline int64_t dos_vmar_destroy(dos_handle_t vmar)
{ return DOS_SC(DOS_SYS_VMAR_DESTROY, vmar, 0, 0, 0, 0, 0); }
static inline int64_t dos_process_create(dos_handle_t parent, const char *name, size_t n, const struct dos_limits *l, dos_handle_t *vmar)
{ return DOS_SC(DOS_SYS_PROCESS_CREATE, parent, name, n, l, vmar, 0); }
static inline int64_t dos_process_kill(dos_handle_t h) { return DOS_SC(DOS_SYS_PROCESS_KILL, h, 0, 0, 0, 0, 0); }
static inline __attribute__((noreturn)) void dos_process_exit(int32_t code)
{
    DOS_SC(DOS_SYS_PROCESS_EXIT, (uint64_t)(int64_t)code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
static inline int64_t dos_process_quota(dos_handle_t h, struct dos_quota *q) { return DOS_SC(DOS_SYS_PROCESS_QUOTA, h, q, 0, 0, 0, 0); }
static inline int64_t dos_process_exit_code(dos_handle_t h) { return DOS_SC(DOS_SYS_PROCESS_EXIT_CODE, h, 0, 0, 0, 0, 0); }
static inline int64_t dos_thread_create(dos_handle_t proc, void (*entry)(uint64_t), void *stack_top, uint64_t arg)
{ return DOS_SC(DOS_SYS_THREAD_CREATE, proc, entry, stack_top, arg, 0, 0); }
static inline __attribute__((noreturn)) void dos_thread_exit(int32_t code)
{
    DOS_SC(DOS_SYS_THREAD_EXIT, (uint64_t)(int64_t)code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
static inline int64_t dos_thread_exit_code(dos_handle_t h) { return DOS_SC(DOS_SYS_THREAD_EXIT_CODE, h, 0, 0, 0, 0, 0); }
static inline int64_t dos_spawn(const struct dos_spawn *s) { return DOS_SC(DOS_SYS_SPAWN, s, 0, 0, 0, 0, 0); }
static inline uint64_t dos_clock_ns(void) { return (uint64_t)DOS_SC(DOS_SYS_CLOCK_NS, 0, 0, 0, 0, 0, 0); }
static inline int64_t dos_yield(void) { return DOS_SC(DOS_SYS_YIELD, 0, 0, 0, 0, 0, 0); }
/* ABI v2 */
static inline int64_t dos_channel_create(dos_handle_t *other) { return DOS_SC(DOS_SYS_CHANNEL_CREATE, other, 0, 0, 0, 0, 0); }
static inline int64_t dos_channel_write(dos_handle_t ch, const struct dos_msg *m) { return DOS_SC(DOS_SYS_CHANNEL_WRITE, ch, m, 0, 0, 0, 0); }
static inline int64_t dos_channel_read(dos_handle_t ch, struct dos_msg *m, uint64_t timeout_ns) { return DOS_SC(DOS_SYS_CHANNEL_READ, ch, m, 0, timeout_ns, 0, 0); }
static inline int64_t dos_channel_call(dos_handle_t ch, const struct dos_msg *wr, struct dos_msg *rd, uint64_t timeout_ns)
{ return DOS_SC(DOS_SYS_CHANNEL_CALL, ch, wr, rd, timeout_ns, 0, 0); }
static inline int64_t dos_port_create(uint32_t entries, dos_handle_t *vmo) { return DOS_SC(DOS_SYS_PORT_CREATE, entries, vmo, 0, 0, 0, 0); }
static inline int64_t dos_port_enter(dos_handle_t port, uint32_t submit, uint32_t min_complete, uint64_t timeout_ns)
{ return DOS_SC(DOS_SYS_PORT_ENTER, port, submit, min_complete, timeout_ns, 0, 0); }
static inline int64_t dos_object_wait_async(dos_handle_t h, uint32_t mask, dos_handle_t port, uint64_t key)
{ return DOS_SC(DOS_SYS_OBJECT_WAIT_ASYNC, h, mask, port, key, 0, 0); }
static inline int64_t dos_port_cancel(dos_handle_t port, dos_handle_t h, uint64_t key) { return DOS_SC(DOS_SYS_PORT_CANCEL, port, h, key, 0, 0, 0); }
static inline int64_t dos_process_exception_channel(dos_handle_t proc) { return DOS_SC(DOS_SYS_PROCESS_EXCEPTION_CHANNEL, proc, 0, 0, 0, 0, 0); }
static inline int64_t dos_exception_get_regs(dos_handle_t e, struct dos_regs *r) { return DOS_SC(DOS_SYS_EXCEPTION_GET_REGS, e, r, 0, 0, 0, 0); }
static inline int64_t dos_exception_set_regs(dos_handle_t e, const struct dos_regs *r) { return DOS_SC(DOS_SYS_EXCEPTION_SET_REGS, e, r, 0, 0, 0, 0); }
static inline int64_t dos_exception_resume(dos_handle_t e, uint32_t action, int32_t code)
{ return DOS_SC(DOS_SYS_EXCEPTION_RESUME, e, action, (uint64_t)(int64_t)code, 0, 0, 0); }
static inline int64_t dos_thread_set_exception_handler(void (*entry)(struct dos_exception_record *), void *stack_top)
{ return DOS_SC(DOS_SYS_THREAD_SET_EXCEPTION_HANDLER, entry, stack_top, 0, 0, 0, 0); }
static inline __attribute__((noreturn)) void dos_exception_return(const struct dos_exception_record *r)
{
    DOS_SC(DOS_SYS_EXCEPTION_RETURN, r, 0, 0, 0, 0, 0);
    __builtin_trap();                       /* only reached if the record was refused */
}
#define DOS_BASE_FS 0
#define DOS_BASE_GS 1
static inline int64_t dos_thread_set_base(uint32_t which, uint64_t v) { return DOS_SC(DOS_SYS_THREAD_SET_BASE, which, v, 0, 0, 0, 0); }
static inline int64_t dos_thread_get_base(uint32_t which) { return DOS_SC(DOS_SYS_THREAD_GET_BASE, which, 0, 0, 0, 0, 0); }
static inline int64_t dos_vmo_make_executable(dos_handle_t vmo, dos_handle_t vmex) { return DOS_SC(DOS_SYS_VMO_MAKE_EXECUTABLE, vmo, vmex, 0, 0, 0, 0); }
static inline int64_t dos_process_read_memory(dos_handle_t proc, uint64_t addr, void *buf, uint64_t n)
{ return DOS_SC(DOS_SYS_PROCESS_READ_MEMORY, proc, addr, buf, n, 0, 0); }
static inline int64_t dos_process_write_memory(dos_handle_t proc, uint64_t addr, const void *buf, uint64_t n)
{ return DOS_SC(DOS_SYS_PROCESS_WRITE_MEMORY, proc, addr, buf, n, 0, 0); }

/* ABI v3 */
static inline int64_t dos_device_info(dos_handle_t d, struct dos_device_info *i) { return DOS_SC(DOS_SYS_DEVICE_INFO, d, i, 0, 0, 0, 0); }
static inline int64_t dos_device_config_read(dos_handle_t d, uint32_t off, uint32_t size) { return DOS_SC(DOS_SYS_DEVICE_CONFIG_READ, d, off, size, 0, 0, 0); }
static inline int64_t dos_device_config_write(dos_handle_t d, uint32_t off, uint32_t size, uint32_t v)
{ return DOS_SC(DOS_SYS_DEVICE_CONFIG_WRITE, d, off, size, v, 0, 0); }
static inline int64_t dos_device_map_bar(dos_handle_t d, uint32_t bar) { return DOS_SC(DOS_SYS_DEVICE_MAP_BAR, d, bar, 0, 0, 0, 0); }
static inline int64_t dos_device_io_read(dos_handle_t d, uint32_t bar, uint32_t off, uint32_t size)
{ return DOS_SC(DOS_SYS_DEVICE_IO_READ, d, bar, off, size, 0, 0); }
static inline int64_t dos_device_io_write(dos_handle_t d, uint32_t bar, uint32_t off, uint32_t size, uint32_t v)
{ return DOS_SC(DOS_SYS_DEVICE_IO_WRITE, d, bar, off, size, v, 0); }
static inline int64_t dos_device_interrupt(dos_handle_t d, uint32_t index, uint32_t flags) { return DOS_SC(DOS_SYS_DEVICE_INTERRUPT, d, index, flags, 0, 0, 0); }
static inline int64_t dos_interrupt_ack(dos_handle_t irq) { return DOS_SC(DOS_SYS_INTERRUPT_ACK, irq, 0, 0, 0, 0, 0); }
static inline int64_t dos_device_dma_map(dos_handle_t d, dos_handle_t vmo, uint64_t off, uint64_t len, uint32_t flags, uint64_t *addrs)
{ return DOS_SC(DOS_SYS_DEVICE_DMA_MAP, d, vmo, off, len, flags, addrs); }
/* ABI v4: code signing. vmo_verify seals the program VMO and checks the .dsig (the first
 * 256 bytes of `dsig`) against the D-OS key; vmo_allow_unsigned (needs the VMEX resource) lets
 * unsigned code run. spawn refuses any other image (DOS_ERR_NOT_SIGNED). Both are measured (PCR 10). */
static inline int64_t dos_vmo_verify(dos_handle_t vmo, dos_handle_t dsig) { return DOS_SC(DOS_SYS_VMO_VERIFY, vmo, dsig, 0, 0, 0, 0); }
static inline int64_t dos_vmo_allow_unsigned(dos_handle_t vmo, dos_handle_t vmex) { return DOS_SC(DOS_SYS_VMO_ALLOW_UNSIGNED, vmo, vmex, 0, 0, 0, 0); }

/* ---- remote attestation (ABI v5; docs/attestation.md) ------------------------------------------ */
#define DOS_ATTEST_MAX 26624u   /* the largest report (a full 256-event log, TPM evidence) */
#define DOS_ATTEST_CHALLENGE 328u /* a TPM credential challenge: blob (70 bytes), then secret (258) */
/* A signed report of what this machine runs, for a remote party's 32-byte nonce. Returns its
 * length, or DOS_ERR_BUFFER_TOO_SMALL (cap < length; nothing written). */
#define DOS_POWER_OFF     1
#define DOS_POWER_REBOOT  2
#define DOS_POWER_SUSPEND 3
/* With the POWER resource: switch off, reset, or suspend to ACPI S3 (returns DOS_ERR_NOT_SUPPORTED if unavailable). */
static inline int64_t dos_system_power(dos_handle_t power, uint64_t action) { return DOS_SC(DOS_SYS_SYSTEM_POWER, power, action, 0, 0, 0, 0); }
/* ABI v7, with the MEASURE resource: extend PCR 10 with digest, logged as "svc <text>" (printable
 * ASCII, at most 52 bytes). */
static inline int64_t dos_measure(dos_handle_t measure, const uint8_t digest[32], const char *text, uint64_t len) { return DOS_SC(DOS_SYS_MEASURE, measure, digest, text, len, 0, 0); }

/* ABI v8: log levels, a record in the kernel log with a level (log_write is DOS_LOG_INFO). */
enum { DOS_LOG_ERROR = 0, DOS_LOG_WARN = 1, DOS_LOG_INFO = 2, DOS_LOG_DEBUG = 3 };
static inline int64_t dos_log_record(dos_handle_t log, int level, const void *s, size_t n) { return DOS_SC(DOS_SYS_LOG_RECORD, log, level, s, n, 0, 0); }

/* ABI v8, with the KLOG resource: kernel log records with sequence >= seq, at most 64, into buf
 * (cap bytes). Returns how many. Kernel addresses in the text read "[kaddr]". */
#define DOS_KLOG_TEXT 120
#define DOS_KLOG_SOURCE 24
enum { DOS_KLOG_ORIGIN_KERNEL = 0, DOS_KLOG_ORIGIN_PROGRAM = 1 };
#define DOS_KLOG_CONTINUES 1                  /* flags: no newline at the end */
struct dos_klog_entry {
    uint64_t seq;
    uint64_t time_us;                         /* monotonic, since kernel entry */
    uint8_t  level, len, origin, flags;
    uint32_t koid;                            /* program records: the writing process */
    char     source[DOS_KLOG_SOURCE];         /* program records: its name (set by the kernel) */
    char     text[DOS_KLOG_TEXT];             /* len bytes, not NUL-terminated */
    uint8_t  reserved[8];
};
_Static_assert(sizeof(struct dos_klog_entry) == 176, "dos_klog_entry layout");
static inline int64_t dos_klog_read(dos_handle_t klog, uint64_t seq, struct dos_klog_entry *buf, uint64_t cap) { return DOS_SC(DOS_SYS_KLOG_READ, klog, seq, buf, cap, 0, 0); }

/* ABI v9: the display device (a platform device named "display"): its memory window is BAR 0
 * (mapped write-combining; mapping it takes the screen from the kernel console). VGA text also
 * has the CRT controller's index/data ports (0x3D4-0x3D5) as I/O window 1. */
enum { DOS_DISPLAY_RGB32 = 1, DOS_DISPLAY_VGA_TEXT = 2 };
struct dos_display_info {
    uint32_t kind;                            /* DOS_DISPLAY_* */
    uint32_t width, height;                   /* pixels (RGB32) or cells (VGA text) */
    uint32_t pitch;                           /* bytes per line */
    uint64_t size;                            /* bytes of BAR 0 */
    uint8_t  red_shift, green_shift, blue_shift, reserved[5];
};
_Static_assert(sizeof(struct dos_display_info) == 32, "dos_display_info layout");
static inline int64_t dos_display_info(dos_handle_t dev, struct dos_display_info *i) { return DOS_SC(DOS_SYS_DISPLAY_INFO, dev, i, 0, 0, 0, 0); }

/* ABI v9, INSPECT on the process: the handles it holds (at most cap entries, at most 256 per
 * call); returns how many it holds. Handle values are never returned. */
struct dos_handle_entry {
    uint32_t type, rights;
    uint64_t koid;
    char     name[32];                        /* NUL-terminated; empty for unnamed objects */
};
_Static_assert(sizeof(struct dos_handle_entry) == 48, "dos_handle_entry layout");
static inline int64_t dos_process_handles(dos_handle_t proc, struct dos_handle_entry *buf, uint64_t cap) { return DOS_SC(DOS_SYS_PROCESS_HANDLES, proc, buf, cap, 0, 0, 0); }

/* ABI v10, MANAGE on the process: its root VMAR (a supervisor maps memory into it). */
static inline int64_t dos_process_vmar(dos_handle_t proc) { return DOS_SC(DOS_SYS_PROCESS_VMAR, proc, 0, 0, 0, 0, 0); }
/* ABI v10, MANAGE on the process: like dos_thread_create, but the thread stops with a START
 * exception before its first instruction (its supervisor sets every register). BAD_STATE if the
 * process has no exception channel. */
static inline int64_t dos_thread_create_stopped(dos_handle_t proc, uint64_t entry, uint64_t stack_top, uint64_t arg) { return DOS_SC(DOS_SYS_THREAD_CREATE_STOPPED, proc, entry, stack_top, arg, 0, 0); }

/* ABI v8: the boot-time record (DOS_TAG_BOOT_TIME). */
struct dos_boot_time {
    uint32_t magic;                           /* "DTIM" */
    uint32_t source;                          /* 1: UEFI GetTime */
    uint16_t year;
    uint8_t  month, day, hour, minute, second, pad;
    uint32_t nanosecond;
    int16_t  time_zone;                       /* minutes from UTC; 2047: unspecified */
    uint16_t pad2;
    int64_t  mono_ns;                         /* the monotonic clock at that moment (< 0: before the kernel) */
};
_Static_assert(sizeof(struct dos_boot_time) == 32, "dos_boot_time layout");
static inline int64_t dos_attest(const uint8_t nonce[32], void *buf, uint64_t cap) { return DOS_SC(DOS_SYS_ATTEST, nonce, buf, cap, 0, 0, 0); }
/* ABI v12: answer a verifier's TPM credential challenge (DOS_ATTEST_CHALLENGE bytes): 32 bytes to
 * out. DOS_ERR_NOT_SUPPORTED without a TPM, DOS_ERR_ACCESS_DENIED when the TPM refuses. */
static inline int64_t dos_attest_activate(const uint8_t *challenge, uint8_t out[32]) { return DOS_SC(DOS_SYS_ATTEST_ACTIVATE, challenge, out, 0, 0, 0, 0); }
/* ABI v14: fill buf (up to 4096 bytes per call) from the kernel's ChaCha20 CSPRNG. */
#define DOS_RANDOM_STRICT (1u << 0)
static inline int64_t dos_get_random(void *buf, uint64_t len, uint64_t flags) { return DOS_SC(DOS_SYS_GET_RANDOM, buf, len, flags, 0, 0, 0); }
/* ABI v15: physical base address of memory BAR `bar` (INSPECT on device). */
static inline int64_t dos_device_bar_addr(dos_handle_t dev, uint32_t bar) { return DOS_SC(DOS_SYS_DEVICE_BAR_ADDR, dev, bar, 0, 0, 0, 0); }
/* ABI v16: TPM 2.0 credential sealing under the owner SRK (needs DOS_TAG_TPM_SEAL). */
struct dos_tpm_seal_args {
    uint64_t auth, auth_len;
    uint64_t input, input_len;
    uint64_t output, output_cap;
};
_Static_assert(sizeof(struct dos_tpm_seal_args) == 48, "dos_tpm_seal_args layout");
static inline int64_t dos_tpm_seal(dos_handle_t res, const struct dos_tpm_seal_args *args) { return DOS_SC(DOS_SYS_TPM_SEAL, res, args, 0, 0, 0, 0); }
static inline int64_t dos_tpm_unseal(dos_handle_t res, const struct dos_tpm_seal_args *args) { return DOS_SC(DOS_SYS_TPM_UNSEAL, res, args, 0, 0, 0, 0); }

/* ---- storage (docs/storage.md; mirrors user/lib/libd/src/fs.rs) ---------------------------
 * Service messages start with a 32-byte header; VOLUME carries a channel to a volume's root. */
struct dos_fs_header { uint32_t txid, op; int32_t status; uint32_t reserved; uint64_t a, b; };
#define DOS_TAG_CONTROL     (DOS_TAG_USER + 0)       /* a service's control channel */
#define DOS_TAG_DISKS       (DOS_TAG_USER + 0x10)    /* storaged: disks from devmgr */
#define DOS_TAG_STORAGE     (DOS_TAG_USER + 0x11)    /* devmgr: disks to storaged */
#define DOS_TAG_NS_NAMES    (DOS_TAG_USER + 0xFF)    /* namespace: VMO of NUL-ended paths */
#define DOS_TAG_NS          (DOS_TAG_USER + 0x100)   /* namespace entry i: DOS_TAG_NS + i */
#define DOS_FS_VOLUME       102
#define DOS_FS_VOLUMES_DONE 103
#define DOS_FS_DISKS_LINK   104

/* ---- tiny runtime (user/lib/dos.c) -------------------------------------------------------------- */
extern const struct dos_startup *dos_start;   /* the startup block */
dos_handle_t dos_startup_handle(uint32_t tag); /* first handle with this tag, or 0 */
const char  *dos_args(void);                   /* NUL-terminated arguments */
void         dos_set_log(dos_handle_t log);    /* where dos_printf goes (default: DOS_TAG_LOG) */
void         dos_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
const char  *dos_status(int64_t r);            /* "NO_MEMORY", ... */
int          main(void);                       /* the program; its result is the exit code */

size_t strlen(const char *s);
int    strcmp(const char *a, const char *b);
int    strncmp(const char *a, const char *b, size_t n);
void  *memcpy(void *d, const void *s, size_t n);
void  *memset(void *d, int c, size_t n);
int    memcmp(const void *a, const void *b, size_t n);

#endif
