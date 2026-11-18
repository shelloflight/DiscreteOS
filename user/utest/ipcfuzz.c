/*
 * IPC fuzzer: channels and ports with hostile messages, between two
 * processes at a time.
 *
 * The parent creates a channel pair and starts two children ("ipcchild <seed> <n>"), one end each.
 * Each child keeps a pool of handles (its end of the shared channel, channels it creates, handles
 * it receives, events, VMOs) and runs <n> random operations on them:
 *   - writes: lengths around the limits, 0..66 handles (live, closed, invalid, the channel itself
 *     or its peer, the same handle twice), random rights, bad data/handle pointers;
 *   - reads with buffers too small for the data or the handles, calls with short timeouts;
 *   - handle duplication with fewer rights, closing, new channel pairs;
 *   - a port with random submissions (channel reads/writes, waits, null operations), cancels.
 * Handles sent across move between the processes. A channel's own end may be offered to it (the
 * kernel refuses it); other channel ends are sent too, closing cycles the kernel must collect
 * when the children exit (pick_for). Nothing may crash a child (every pointer it passes is either its own or one the
 * kernel must refuse), and every child must end with code 0. The kernel checks afterwards that no
 * object leaked (ktest fuzz: ktest_after_init).
 */

#include "utest.h"

#define TAG_PEER (DOS_TAG_USER + 7)

static uint64_t s;
static uint64_t rn(void)
{
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

static uint8_t wbuf[DOS_CHANNEL_MAX_BYTES + 64] __attribute__((aligned(64)));
static uint8_t rbuf[DOS_CHANNEL_MAX_BYTES + 64] __attribute__((aligned(64)));

#define POOL 96
static dos_handle_t pool[POOL];
static unsigned npool;

static void add(dos_handle_t h)
{
    if (npool < POOL)
        pool[npool++] = h;
    else
        pool[1 + rn() % (POOL - 1)] = h;      /* pool[0] (the shared channel) stays */
}


static dos_handle_t pick(void)
{
    switch (rn() % 10) {
    case 0: return DOS_HANDLE_INVALID;
    case 1: return (dos_handle_t)rn();
    default: return pool[rn() % npool];
    }
}

/* A handle to put in a message sent through `ch`: any handle, other channel ends included. A
 * channel end travelling through another channel can close a cycle (A's end queued in B, B's in A)
 * that nobody can drain; the kernel breaks such cycles when a process exits, and the
 * strict leak check afterwards proves it. Sending `ch` itself (or its peer) must be refused. */
static dos_handle_t pick_for(dos_handle_t ch)
{
    (void)ch;
    return pick();
}

static uint32_t rlen(void)
{
    switch (rn() % 8) {
    case 0: return 0;
    case 1: return DOS_CHANNEL_MAX_BYTES;
    case 2: return DOS_CHANNEL_MAX_BYTES + 1 + rn() % 32;
    case 3: return (uint32_t)rn();
    case 4: return 1 + rn() % 4096;
    default: return rn() % 256;
    }
}

static uint64_t rptr(void *good)
{
    switch (rn() % 16) {
    case 0: return KERNEL_ADDR + rn() % 0x1000;
    case 1: return UNMAPPED;
    case 2: return NONCANON;
    case 3: return 0;
    default: return (uint64_t)(uintptr_t)good;
    }
}

static void op_write(void)
{
    struct dos_msg_handle hs[DOS_CHANNEL_MAX_HANDLES + 3];
    uint32_t nh = rn() % 4 ? rn() % 3 : rn() % (DOS_CHANNEL_MAX_HANDLES + 3);
    dos_handle_t ch = rn() % 2 ? pool[0] : pick();
    for (uint32_t i = 0; i < nh; i++) {
        dos_handle_t h = rn() % 6 == 0 ? ch : pick_for(ch);
        if (i && rn() % 8 == 0)
            h = hs[0].handle;                 /* the same handle twice in one message */
        hs[i].handle = h;
        hs[i].rights = rn() % 3 ? DOS_RIGHTS_SAME : (uint32_t)rn() & 0x3FF;
    }
    uint32_t len = rlen();
    if (len <= sizeof(wbuf))
        for (uint32_t i = 0; i < len && i < 64; i++)
            wbuf[i] = (uint8_t)rn();
    struct dos_msg m = { rptr(wbuf), len, nh, rptr(hs) };
    dos_channel_write(ch, &m);                /* any status; moved handles are gone from us */
}

static void op_read(void)
{
    dos_handle_t got[DOS_CHANNEL_MAX_HANDLES] = { 0 };
    struct dos_msg m = { rptr(rbuf), rn() % 2 ? sizeof(rbuf) : rn() % 128, rn() % 2 ? DOS_CHANNEL_MAX_HANDLES : rn() % 3,
                         rptr(got) };
    if (m.len > sizeof(rbuf))
        m.len = sizeof(rbuf);
    dos_handle_t ch = rn() % 2 ? pool[0] : pick();
    int64_t r = dos_channel_read(ch, &m, rn() % 4 ? 0 : rn() % 200000);
    if (r >= 0 && m.handles == (uint64_t)(uintptr_t)got)
        for (uint32_t i = 0; i < m.nhandles && i < DOS_CHANNEL_MAX_HANDLES; i++)
            add(got[i]);
}

static void op_call(void)
{
    dos_handle_t ch = rn() % 2 ? pool[0] : pick();
    struct dos_msg_handle hs[2] = { { pick_for(ch), DOS_RIGHTS_SAME }, { pick_for(ch), DOS_RIGHTS_SAME } };
    dos_handle_t got[4] = { 0 };
    uint32_t len = rn() % 2 ? 8 + rn() % 64 : rlen();
    if (len >= 4 && len <= sizeof(wbuf))
        memcpy(wbuf, &(uint32_t){ (uint32_t)rn() }, 4);   /* a transaction id the peer may echo */
    struct dos_msg wr = { rptr(wbuf), len, rn() % 3, rptr(hs) };
    struct dos_msg rd = { (uint64_t)(uintptr_t)rbuf, rn() % 2 ? sizeof(rbuf) : rn() % 16, rn() % 5, rptr(got) };
    if (rd.len > sizeof(rbuf))
        rd.len = sizeof(rbuf);
    int64_t r = dos_channel_call(ch, &wr, &rd, rn() % 300000);
    if (r >= 0 && rd.handles == (uint64_t)(uintptr_t)got)
        for (uint32_t i = 0; i < rd.nhandles && i < 4; i++)
            add(got[i]);
}

/* ---- ports ------------------------------------------------------------------------------------ */

static dos_handle_t port_h;
static struct dos_port_header *port_hdr;
static struct dos_sqe *port_sq;
static struct dos_cqe *port_cq;

static void port_setup(void)
{
    dos_handle_t v = 0;
    int64_t h = dos_port_create(8, &v);
    if (h < 0)
        return;
    uint64_t size = (4096 + 8 * 64ull + 8 * 32ull + 4095) & ~4095ull;
    int64_t a = dos_vmar_map(self_vmar, DOS_ANY, v, 0, size, DOS_RIGHT_READ | DOS_RIGHT_WRITE);
    dos_handle_close(v);
    if (a < 0)
        return;
    port_h = (dos_handle_t)h;
    port_hdr = (struct dos_port_header *)(uintptr_t)a;
    port_sq = (struct dos_sqe *)(uintptr_t)(a + port_hdr->sq_off);
    port_cq = (struct dos_cqe *)(uintptr_t)(a + port_hdr->cq_off);
    add(port_h);
}

static struct dos_msg port_msgs[8];

static void op_port(void)
{
    if (!port_hdr)
        return;
    uint32_t n = rn() % 5;
    static const uint32_t ops[] = { DOS_SYS_CHANNEL_WRITE, DOS_SYS_CHANNEL_READ, DOS_SYS_OBJECT_WAIT, DOS_SYS_ABI_VERSION,
                                    DOS_SYS_CHANNEL_CALL, DOS_SYS_HANDLE_CLOSE };
    for (uint32_t i = 0; i < n; i++) {
        uint32_t t = port_hdr->sq_tail;
        struct dos_msg *m = &port_msgs[t & 7];
        *m = (struct dos_msg){ (uint64_t)(uintptr_t)wbuf, rn() % 128, 0, 0 };
        uint32_t op = rn() % 8 == 0 ? (uint32_t)rn() : ops[rn() % (sizeof(ops) / sizeof(ops[0]))];
        uint64_t a1 = rn() % 4 ? (uint64_t)(uintptr_t)m : rptr(m);
        port_sq[t & port_hdr->sq_mask] =
            (struct dos_sqe){ op, (uint32_t)(rn() % 3), rn(), { pick(), a1, rn() % 8, rn() % 100000, 0, 0 } };
        __atomic_store_n(&port_hdr->sq_tail, t + 1, __ATOMIC_RELEASE);
    }
    if (rn() % 4 == 0)
        port_hdr->sq_tail += (uint32_t)rn() % 40;    /* a lying tail: the kernel must bound it */
    dos_port_enter(port_h, (uint32_t)(rn() % 12), (uint32_t)(rn() % 2), rn() % 100000);
    uint32_t h = port_hdr->cq_head, tail = __atomic_load_n(&port_hdr->cq_tail, __ATOMIC_ACQUIRE);
    for (uint32_t i = h; i != tail && i - h <= port_hdr->cq_mask; i++)
        if (port_cq[i & port_hdr->cq_mask].result > 0 && rn() % 4 == 0)
            add((dos_handle_t)port_cq[i & port_hdr->cq_mask].result);   /* maybe a handle, maybe not */
    __atomic_store_n(&port_hdr->cq_head, rn() % 8 ? tail : h + (uint32_t)rn() % 16, __ATOMIC_RELEASE);
    if (rn() % 8 == 0)
        dos_port_cancel(port_h, pick(), rn());
}

int ipc_fuzz_child(uint64_t seed, uint64_t n)
{
    s = seed | 1;
    dos_handle_t peer = dos_startup_handle(TAG_PEER);
    if (!peer)
        return 2;
    pool[npool++] = peer;
    pool[npool++] = (dos_handle_t)dos_event_create();
    pool[npool++] = (dos_handle_t)dos_vmo_create(4096);
    port_setup();
    for (uint64_t i = 0; i < n; i++) {
        switch (rn() % 16) {
        case 0: case 1: case 2: case 3: case 4: op_write(); break;
        case 5: case 6: case 7: case 8: op_read(); break;
        case 9: op_call(); break;
        case 10: case 11: op_port(); break;
        case 12: {
            dos_handle_t other;
            int64_t a = dos_channel_create(&other);
            if (a > 0) {
                add((dos_handle_t)a);
                add(other);
            }
            break;
        }
        case 13: {
            int64_t d = dos_handle_duplicate(pick(), (uint32_t)rn() & 0x3FF);
            if (d > 0)
                add((dos_handle_t)d);
            break;
        }
        case 14:
            if (npool > 1) {
                unsigned k = 1 + rn() % (npool - 1);
                dos_handle_close(pool[k]);
            }
            break;
        default:
            dos_object_wait(pick(), (uint32_t)rn(), rn() % 50000);
            break;
        }
    }
    return 0;                                 /* everything left is closed by the exit */
}

/* Decimal digits of v and a space at p; returns the end. */
static char *put_u(char *p, uint64_t v)
{
    char d[24];
    int n = 0;
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n)
        *p++ = d[--n];
    *p++ = ' ';
    return p;
}

/* Parent: pairs of children over one channel. */
void ipc_fuzz(uint64_t total)
{
    uint64_t per = 1000, done = 0, pairs = 0, ok = 0;
    struct dos_limits lim = { 16u << 20, 512, 8 };
    uint64_t seed = rdtsc();
    while (done < total) {
        dos_handle_t b;
        int64_t a = dos_channel_create(&b);
        if (a < 0) {
            dos_printf("utest: FAIL ipc fuzz: channel_create %ld\n", a);
            failures++;
            return;
        }
        int64_t procs[2];
        uint64_t seeds[2];
        for (int k = 0; k < 2; k++) {
            seeds[k] = seed + (pairs * 2 + k) * 0x9E3779B97F4A7C15ull;
            char args[64] = "ipcchild ";
            char *p = put_u(put_u(args + 9, seeds[k]), per);
            p[-1] = 0;
            struct dos_spawn_handle hs[1] = { { k ? b : (dos_handle_t)a, DOS_RIGHTS_SAME, TAG_PEER, 0 } };
            struct dos_spawn sp = {
                .parent = self_proc, .image = my_image(),
                .name = (uint64_t)(uintptr_t)"utest.ipc", .name_len = 9,
                .args = (uint64_t)(uintptr_t)args, .args_len = strlen(args),
                .handles = (uint64_t)(uintptr_t)hs, .nhandles = 1,
                .limits = (uint64_t)(uintptr_t)&lim,
            };
            procs[k] = dos_spawn(&sp);
        }
        for (int k = 0; k < 2; k++) {
            int64_t code = wait_exit(procs[k], 60000000000ull);
            if (code == 0)
                ok++;
            else {
                dos_printf("utest: FAIL ipc fuzz child (seed %lu) ended with %ld (%s)\n", seeds[k], code, dos_status(code));
                failures++;
            }
        }
        done += 2 * per;
        pairs++;
    }
    struct dos_quota q;
    dos_process_quota(self_proc, &q);
    CHECK(q.used.threads == 1);
    dos_printf("utest: ipc fuzz: %lu operations in %lu process pairs (%lu children finished cleanly), kernel OK\n",
               done, pairs, ok);
}
