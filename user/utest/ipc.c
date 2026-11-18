/*
 * utest: channels (messages, handle transfer, limits, peer death, calls), IPC between
 * processes (zero-copy VMO sharing), ports (submission/completion rings, async waits, overflow),
 * exceptions (in-process handlers, supervisors, FORWARD syscalls, process memory), FS/GS bases,
 * VMO sealing (W^X for user-space loaders), XSAVE/AVX state, and the IPC benchmarks.
 *
 * Child modes ("p10 <mode>", spawned by the tests): echo, handlerfault, badreturn, null, ud2ret,
 * forward, fwdbench <n>, avx <seed>.
 */

#include "utest.h"

#define R  DOS_RIGHT_READ
#define W  DOS_RIGHT_WRITE
#define X  DOS_RIGHT_EXECUTE
#define S10 10000000000ull                 /* 10 s: never reached in a passing run */

/* ---- helpers ----------------------------------------------------------------------------------- */

static int64_t spawn_ex(const char *args, const struct dos_spawn_handle *extra, uint32_t nextra, uint32_t flags,
                        dos_handle_t *exc)
{
    struct dos_spawn_handle hs[8];
    uint32_t nh = 0;
    int64_t l = dos_handle_duplicate(log_h, DOS_RIGHTS_SAME);
    if (l > 0)
        hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)l, DOS_RIGHTS_SAME, DOS_TAG_LOG, 0 };
    for (uint32_t i = 0; i < nextra && nh < 8; i++)
        hs[nh++] = extra[i];
    struct dos_spawn s = {
        .parent = self_proc, .image = my_image(),
        .name = (uint64_t)(uintptr_t)"utest.child", .name_len = 11,
        .args = (uint64_t)(uintptr_t)args, .args_len = strlen(args),
        .handles = (uint64_t)(uintptr_t)hs, .nhandles = nh,
        .flags = flags, .exception_channel = (uint64_t)(uintptr_t)exc,
    };
    return dos_spawn(&s);
}

static int64_t ch_send(dos_handle_t ch, const void *d, uint32_t n, const struct dos_msg_handle *hs, uint32_t nh)
{
    struct dos_msg m = { (uint64_t)(uintptr_t)d, n, nh, (uint64_t)(uintptr_t)hs };
    return dos_channel_write(ch, &m);
}

static int64_t ch_recv(dos_handle_t ch, void *d, uint32_t cap, dos_handle_t *hs, uint32_t hcap, uint64_t timeout,
                       uint32_t *len, uint32_t *nh)
{
    struct dos_msg m = { (uint64_t)(uintptr_t)d, cap, hcap, (uint64_t)(uintptr_t)hs };
    int64_t r = dos_channel_read(ch, &m, timeout);
    if (len)
        *len = m.len;
    if (nh)
        *nh = m.nhandles;
    return r;
}

static int64_t ch_call(dos_handle_t ch, const void *wd, uint32_t wn, void *rd, uint32_t rcap, uint32_t *rlen, uint64_t timeout)
{
    struct dos_msg w = { (uint64_t)(uintptr_t)wd, wn, 0, 0 };
    struct dos_msg r = { (uint64_t)(uintptr_t)rd, rcap, 0, 0 };
    int64_t res = dos_channel_call(ch, &w, &r, timeout);
    if (rlen)
        *rlen = r.len;
    return res;
}

static uint8_t big[DOS_CHANNEL_MAX_BYTES];

/* ---- channels ---------------------------------------------------------------------------------- */

void test_channels(void)
{
    dos_handle_t b;
    int64_t ra = dos_channel_create(&b);
    CHECK(ra > 0 && b != 0);
    dos_handle_t a = (dos_handle_t)ra;
    struct dos_info info;
    EXPECT(dos_object_info(a, &info), 0);
    CHECK(info.type == DOS_OBJ_CHANNEL);
    EXPECT(dos_object_wait(a, DOS_WRITABLE, 0), DOS_WRITABLE);
    EXPECT(dos_object_wait(b, DOS_READABLE, 0), DOS_ERR_TIMED_OUT);

    /* Bytes, buffer too small (the message stays), empty queue, timeout. */
    char buf[64];
    uint32_t len = 0, nh = 0;
    EXPECT(ch_send(a, "hello", 5, 0, 0), 0);
    CHECK(dos_object_wait(b, DOS_READABLE, 0) & DOS_READABLE);
    EXPECT(ch_recv(b, buf, 2, 0, 0, 0, &len, &nh), DOS_ERR_BUFFER_TOO_SMALL);
    CHECK(len == 5 && nh == 0);
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), 0);
    CHECK(len == 5 && memcmp(buf, "hello", 5) == 0);
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), DOS_ERR_SHOULD_WAIT);
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 1000000, &len, &nh), DOS_ERR_TIMED_OUT);
    EXPECT(ch_send(a, "", 0, 0, 0), 0);                       /* empty messages are fine */
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), 0);
    CHECK(len == 0);

    /* Handle transfer: rights only shrink; a refused write consumes nothing. */
    int64_t ev = dos_event_create();
    int64_t evd = dos_handle_duplicate((dos_handle_t)ev, DOS_RIGHT_SIGNAL | DOS_RIGHT_WAIT | DOS_RIGHT_TRANSFER);
    struct dos_msg_handle mh = { (dos_handle_t)evd, DOS_RIGHT_SIGNAL | DOS_RIGHT_DUPLICATE };
    EXPECT(ch_send(a, "h", 1, &mh, 1), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_object_info((dos_handle_t)evd, &info), 0);     /* still ours */
    mh.rights = DOS_RIGHT_SIGNAL;
    EXPECT(ch_send(a, "h", 1, &mh, 1), 0);
    EXPECT(dos_object_info((dos_handle_t)evd, &info), DOS_ERR_BAD_HANDLE);   /* moved */
    dos_handle_t got = 0;
    EXPECT(ch_recv(b, buf, sizeof(buf), &got, 0, 0, &len, &nh), DOS_ERR_BUFFER_TOO_SMALL);
    CHECK(nh == 1);
    EXPECT(ch_recv(b, buf, sizeof(buf), &got, 1, 0, &len, &nh), 0);
    CHECK(nh == 1 && got != 0);
    EXPECT(dos_object_info(got, &info), 0);
    CHECK(info.type == DOS_OBJ_EVENT && info.rights == DOS_RIGHT_SIGNAL);
    EXPECT(dos_event_signal(got, 0, DOS_SIGNALED), 0);
    EXPECT(dos_object_wait((dos_handle_t)ev, DOS_SIGNALED, 0), DOS_SIGNALED);
    int64_t nt = dos_handle_duplicate((dos_handle_t)ev, DOS_RIGHT_WAIT);   /* no TRANSFER */
    mh = (struct dos_msg_handle){ (dos_handle_t)nt, DOS_RIGHTS_SAME };
    EXPECT(ch_send(a, "x", 1, &mh, 1), DOS_ERR_ACCESS_DENIED);
    mh = (struct dos_msg_handle){ a, DOS_RIGHTS_SAME };        /* its own end */
    EXPECT(ch_send(a, "x", 1, &mh, 1), DOS_ERR_NOT_SUPPORTED);
    mh = (struct dos_msg_handle){ b, DOS_RIGHTS_SAME };        /* its peer */
    EXPECT(ch_send(a, "x", 1, &mh, 1), DOS_ERR_NOT_SUPPORTED);
    struct dos_msg_handle two[2] = { { (dos_handle_t)ev, DOS_RIGHTS_SAME }, { (dos_handle_t)ev, DOS_RIGHTS_SAME } };
    EXPECT(ch_send(a, "x", 1, two, 2), DOS_ERR_INVALID_ARGS);
    EXPECT(ch_send(a, buf, DOS_CHANNEL_MAX_BYTES + 1, 0, 0), DOS_ERR_INVALID_ARGS);
    EXPECT(ch_send(a, buf, 1, two, DOS_CHANNEL_MAX_HANDLES + 1), DOS_ERR_INVALID_ARGS);
    EXPECT(ch_send(a, big, DOS_CHANNEL_MAX_BYTES, 0, 0), 0);  /* the largest message */
    EXPECT(ch_recv(b, big, sizeof(big), 0, 0, 0, &len, &nh), 0);
    CHECK(len == DOS_CHANNEL_MAX_BYTES);

    /* Bad pointers never crash anything. */
    EXPECT(dos_channel_write(a, (const struct dos_msg *)KERNEL_ADDR), DOS_ERR_BAD_ADDRESS);
    EXPECT(ch_send(a, (const void *)KERNEL_ADDR, 16, 0, 0), DOS_ERR_BAD_ADDRESS);
    EXPECT(ch_send(a, "x", 1, (const struct dos_msg_handle *)UNMAPPED, 1), DOS_ERR_BAD_ADDRESS);
    EXPECT(ch_send(a, "ok", 2, 0, 0), 0);
    EXPECT(ch_recv(b, (void *)KERNEL_ADDR, 16, 0, 0, 0, &len, &nh), DOS_ERR_BAD_ADDRESS);
    EXPECT(ch_recv(b, (void *)UNMAPPED, 16, 0, 0, 0, &len, &nh), DOS_ERR_BAD_ADDRESS);   /* fails mid-copy */
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), 0);   /* the message was kept */
    CHECK(len == 2);

    /* Queue limit and WRITABLE. */
    int full = 0;
    for (uint32_t i = 0; i < DOS_CHANNEL_MAX_QUEUE; i++)
        full += ch_send(a, &i, 4, 0, 0) == 0;
    CHECK(full == DOS_CHANNEL_MAX_QUEUE);
    EXPECT(ch_send(a, "x", 1, 0, 0), DOS_ERR_SHOULD_WAIT);
    EXPECT(dos_object_wait(a, DOS_WRITABLE, 0), DOS_ERR_TIMED_OUT);
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), 0);
    CHECK(dos_object_wait(a, DOS_WRITABLE, 0) & DOS_WRITABLE);
    int order = 1;
    for (uint32_t i = 1; i < DOS_CHANNEL_MAX_QUEUE; i++) {
        uint32_t v = 0;
        if (ch_recv(b, &v, 4, 0, 0, 0, &len, &nh) != 0 || v != i)
            order = 0;
    }
    CHECK(order);

    /* A call nobody answers times out; its request stays queued with a kernel transaction id. */
    uint8_t req[8] = { 0, 0, 0, 0, 'q' };
    EXPECT(ch_call(a, req, 8, buf, sizeof(buf), &len, 2000000), DOS_ERR_TIMED_OUT);
    EXPECT(ch_call(a, req, 3, buf, sizeof(buf), &len, 0), DOS_ERR_INVALID_ARGS);   /* < 4 bytes */
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), 0);
    CHECK(len == 8 && ((uint8_t)buf[3] & 0x80) && buf[4] == 'q');

    /* Peer death: the queue drains, then PEER_CLOSED; writes fail at once. */
    EXPECT(ch_send(a, "last", 4, 0, 0), 0);
    int64_t ev4 = dos_event_create();
    mh = (struct dos_msg_handle){ (dos_handle_t)ev4, DOS_RIGHTS_SAME };
    EXPECT(ch_send(a, "h", 1, &mh, 1), 0);
    EXPECT(dos_handle_close(a), 0);
    CHECK(dos_object_wait(b, DOS_PEER_CLOSED, 0) & DOS_PEER_CLOSED);
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), 0);
    CHECK(len == 4 && memcmp(buf, "last", 4) == 0);
    EXPECT(ch_send(b, "x", 1, 0, 0), DOS_ERR_PEER_CLOSED);
    dos_handle_t h2 = 0;
    EXPECT(ch_recv(b, buf, sizeof(buf), &h2, 1, 0, &len, &nh), 0);
    EXPECT(dos_handle_close(h2), 0);
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, 0, &len, &nh), DOS_ERR_PEER_CLOSED);
    EXPECT(ch_recv(b, buf, sizeof(buf), 0, 0, DOS_WAIT_FOREVER, &len, &nh), DOS_ERR_PEER_CLOSED);

    /* A closed channel with handles still queued releases them (no leak, no crash). */
    dos_handle_t c2, d2;
    d2 = (dos_handle_t)dos_channel_create(&c2);
    for (int i = 0; i < 8; i++) {
        int64_t e = dos_event_create();
        struct dos_msg_handle m1 = { (dos_handle_t)e, DOS_RIGHTS_SAME };
        ch_send(d2, "e", 1, &m1, 1);
    }
    struct dos_quota q0, q1;
    dos_process_quota(self_proc, &q0);
    EXPECT(dos_handle_close(c2), 0);
    EXPECT(dos_handle_close(d2), 0);
    dos_process_quota(self_proc, &q1);
    CHECK(q1.used.handles + 2 == q0.used.handles && q1.used.memory <= q0.used.memory);

    /* Fuzzed messages: random sizes, random handle lists (mostly invalid), all read back. */
    dos_handle_t fb;
    dos_handle_t fa = (dos_handle_t)dos_channel_create(&fb);
    uint64_t seed = rdtsc() | 1;
    int sent = 0, ok = 1;
    for (int i = 0; i < 3000; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        uint32_t n = (uint32_t)(seed % (DOS_CHANNEL_MAX_BYTES + 512));
        struct dos_msg_handle hl[3] = { { (dos_handle_t)(seed >> 8), (uint32_t)(seed >> 40) },
                                        { fa, DOS_RIGHTS_SAME }, { (dos_handle_t)seed, DOS_RIGHTS_SAME } };
        uint32_t k = (uint32_t)((seed >> 20) % 4);
        int64_t r = ch_send(fa, big, n, hl, k);
        if (r == 0)
            sent++;
        else if (r != DOS_ERR_INVALID_ARGS && r != DOS_ERR_BAD_HANDLE && r != DOS_ERR_ACCESS_DENIED &&
                 r != DOS_ERR_NOT_SUPPORTED && r != DOS_ERR_SHOULD_WAIT)
            ok = 0;
        if (i % 64 == 0)
            while (ch_recv(fb, big, sizeof(big), 0, 0, 0, &len, &nh) == 0)
                sent--;
    }
    while (ch_recv(fb, big, sizeof(big), 0, 0, 0, &len, &nh) == 0)
        sent--;
    CHECK(ok && sent == 0);
    dos_handle_close(fa);
    dos_handle_close(fb);
    dos_handle_close(b);
    dos_handle_close((dos_handle_t)ev);
    dos_handle_close((dos_handle_t)nt);
    dos_handle_close(got);
    dos_printf("utest: channels: messages, handle transfer (rights only shrink), queue limit, calls, peer closed, "
               "bad pointers, 3000 fuzzed messages\n");
}

/* Echo server (child "p10 echo"): replies with the request; 'd' = drop, 'm' = map the VMO it
 * carries and fill it with 0xAB. Ends when the channel's peer is gone. */
static int echo_server(void)
{
    dos_handle_t ch = dos_startup_handle(DOS_TAG_USER);
    for (;;) {
        dos_handle_t hs[4];
        uint32_t len, nh;
        int64_t r = ch_recv(ch, big, sizeof(big), hs, 4, DOS_WAIT_FOREVER, &len, &nh);
        if (r == DOS_ERR_PEER_CLOSED)
            return 0;
        if (r < 0)
            return 10;
        if (len >= 5 && big[4] == 'd')
            continue;
        if (len >= 5 && big[4] == 'm' && nh == 1) {
            int64_t a = dos_vmar_map(self_vmar, DOS_ANY, hs[0], 0, 4096, R | W);
            if (a > 0)
                memset((void *)(uintptr_t)a, 0xAB, 4096);
        }
        for (uint32_t i = 0; i < nh; i++)
            dos_handle_close(hs[i]);
        ch_send(ch, big, len, 0, 0);
    }
}

void test_ipc_processes(void)
{
    dos_handle_t b;
    dos_handle_t a = (dos_handle_t)dos_channel_create(&b);
    struct dos_spawn_handle h = { b, DOS_RIGHTS_SAME, DOS_TAG_USER, 0 };
    int64_t p = spawn_ex("p10 echo", &h, 1, 0, 0);
    CHECK(p > 0);
    uint8_t req[16], rep[16];
    uint32_t len = 0;
    int ok = 1;
    for (uint32_t i = 0; i < 500; i++) {
        memset(req, 0, sizeof(req));
        req[4] = 'e';
        memcpy(req + 8, &i, 4);
        if (ch_call(a, req, 12, rep, sizeof(rep), &len, S10) != 0 || len != 12 || memcmp(rep + 8, &i, 4) != 0)
            ok = 0;
    }
    CHECK(ok);

    /* Shared memory, zero-copy: the server maps our VMO and fills it; we see it in place. */
    dos_handle_t v;
    uint8_t *mem = map_new(4096, &v);
    CHECK(mem != 0);
    int64_t vd = dos_handle_duplicate(v, R | W | DOS_RIGHT_MAP | DOS_RIGHT_TRANSFER);
    struct dos_msg_handle mh = { (dos_handle_t)vd, DOS_RIGHTS_SAME };
    req[4] = 'm';
    struct dos_msg w = { (uint64_t)(uintptr_t)req, 8, 1, (uint64_t)(uintptr_t)&mh };
    struct dos_msg r = { (uint64_t)(uintptr_t)rep, sizeof(rep), 0, 0 };
    EXPECT(dos_channel_call(a, &w, &r, S10), 0);
    CHECK(mem && mem[0] == 0xAB && mem[4095] == 0xAB);

    /* Reply too big for the caller's buffer: BUFFER_TOO_SMALL with the size. */
    req[4] = 'e';
    EXPECT(ch_call(a, req, 12, rep, 6, &len, S10), DOS_ERR_BUFFER_TOO_SMALL);
    CHECK(len == 12);

    /* Peer death: the server's end goes with its process. */
    EXPECT(dos_process_kill((dos_handle_t)p), 0);
    EXPECT(wait_exit(p, S10), DOS_EXIT_KILLED);
    EXPECT(ch_call(a, req, 12, rep, sizeof(rep), &len, S10), DOS_ERR_PEER_CLOSED);
    CHECK(dos_object_wait(a, DOS_PEER_CLOSED, 0) & DOS_PEER_CLOSED);
    dos_handle_close(a);
    dos_handle_close(v);
    dos_printf("utest: ipc: 500 calls to another process, a VMO shared zero-copy through a channel, peer death\n");
}

/* An address the fault tests dereference on purpose (0); volatile, so neither the compiler nor the
 * static analyzer treats the deliberate NULL access as a mistake. */
static volatile uintptr_t fault_addr = 0;

/* ---- ports ------------------------------------------------------------------------------------- */

struct port {
    dos_handle_t h;
    struct dos_port_header *hdr;
    struct dos_sqe *sq;
    struct dos_cqe *cq;
};

static int port_open(struct port *p, uint32_t entries)
{
    dos_handle_t v = 0;
    int64_t h = dos_port_create(entries, &v);
    if (h < 0)
        return 0;
    uint64_t size = (4096 + entries * 64ull + entries * 32ull + 4095) & ~4095ull;
    int64_t a = dos_vmar_map(self_vmar, DOS_ANY, v, 0, size, R | W);
    dos_handle_close(v);
    if (a < 0)
        return 0;
    p->h = (dos_handle_t)h;
    p->hdr = (struct dos_port_header *)(uintptr_t)a;
    p->sq = (struct dos_sqe *)(uintptr_t)(a + p->hdr->sq_off);
    p->cq = (struct dos_cqe *)(uintptr_t)(a + p->hdr->cq_off);
    return 1;
}

static void sq_push(struct port *p, uint32_t op, uint64_t ud, uint64_t a0, uint64_t a1, uint64_t a2)
{
    uint32_t t = p->hdr->sq_tail;
    p->sq[t & p->hdr->sq_mask] = (struct dos_sqe){ op, 0, ud, { a0, a1, a2, 0, 0, 0 } };
    __atomic_store_n(&p->hdr->sq_tail, t + 1, __ATOMIC_RELEASE);
}

static int cq_pop(struct port *p, struct dos_cqe *out)
{
    uint32_t h = p->hdr->cq_head;
    if (h == __atomic_load_n(&p->hdr->cq_tail, __ATOMIC_ACQUIRE))
        return 0;
    *out = p->cq[h & p->hdr->cq_mask];
    __atomic_store_n(&p->hdr->cq_head, h + 1, __ATOMIC_RELEASE);
    return 1;
}

void test_ports(void)
{
    struct port p;
    dos_handle_t v;
    EXPECT(dos_port_create(3, &v), DOS_ERR_INVALID_ARGS);     /* not a power of two */
    EXPECT(dos_port_create(0, &v), DOS_ERR_INVALID_ARGS);
    if (!port_open(&p, 8)) {                                   /* (found by the static analyzer: */
        CHECK(!"port_open");                                   /* the test went on with p unset) */
        return;
    }
    CHECK(p.hdr->sq_mask == 7 && p.hdr->cq_mask == 15);
    struct dos_info info;
    EXPECT(dos_object_info(p.h, &info), 0);
    CHECK(info.type == DOS_OBJ_PORT);

    /* Submission: a batch of syscalls in one port_enter; refused ops complete with an error. */
    sq_push(&p, DOS_SYS_ABI_VERSION, 1, 0, 0, 0);
    sq_push(&p, DOS_SYS_EVENT_CREATE, 2, 0, 0, 0);
    sq_push(&p, DOS_SYS_YIELD, 3, 0, 0, 0);                   /* may block: not from a port */
    sq_push(&p, 9999, 4, 0, 0, 0);
    sq_push(&p, DOS_SYS_CLOCK_NS, 5, 0, 0, 0);
    EXPECT(dos_port_enter(p.h, 5, 0, 0), 5);
    struct dos_cqe c[8] = { 0 };
    int n = 0;
    while (n < 8 && cq_pop(&p, &c[n]))
        n++;
    CHECK(n == 5);
    CHECK(c[0].user_data == 1 && c[0].result == DOS_ABI_VERSION);
    CHECK(c[1].user_data == 2 && c[1].result > 0);
    CHECK(c[2].user_data == 3 && c[2].result == DOS_ERR_NOT_SUPPORTED);
    CHECK(c[3].user_data == 4 && c[3].result == DOS_ERR_NOT_SUPPORTED);
    CHECK(c[4].user_data == 5 && c[4].result > 0);
    dos_handle_t ev = (dos_handle_t)c[1].result;

    /* Async wait: the completion appears in shared memory, no syscall needed to see it. */
    EXPECT(dos_object_wait_async(ev, DOS_SIGNALED, p.h, 42), 0);
    struct dos_cqe one;
    CHECK(!cq_pop(&p, &one));
    EXPECT(dos_event_signal(ev, 0, DOS_SIGNALED), 0);
    CHECK(cq_pop(&p, &one) && one.user_data == 42 && (one.result & DOS_SIGNALED));

    /* A wait set: whichever fires first; the other is cancelled. */
    int64_t t = dos_timer_create();
    int64_t ev2 = dos_event_create();
    EXPECT(dos_object_wait_async((dos_handle_t)t, DOS_SIGNALED, p.h, 7), 0);
    EXPECT(dos_object_wait_async((dos_handle_t)ev2, DOS_SIGNALED, p.h, 8), 0);
    EXPECT(dos_timer_set((dos_handle_t)t, 2000000), 0);
    EXPECT(dos_port_enter(p.h, 0, 1, DOS_WAIT_FOREVER), 0);
    CHECK(cq_pop(&p, &one) && one.user_data == 7);
    EXPECT(dos_port_cancel(p.h, (dos_handle_t)ev2, 8), 1);
    EXPECT(dos_port_cancel(p.h, (dos_handle_t)ev2, 8), 0);
    EXPECT(dos_event_signal((dos_handle_t)ev2, 0, DOS_SIGNALED), 0);
    EXPECT(dos_port_enter(p.h, 0, 1, 2000000), 0);            /* times out: nothing came */
    CHECK(!cq_pop(&p, &one));

    /* Overflow: 20 completions for a 16-entry CQ; 4 wait in the kernel, none is lost. */
    for (int i = 0; i < 20; i++)
        EXPECT(dos_object_wait_async(ev, DOS_SIGNALED, p.h, 100 + (uint64_t)i), 0);   /* ev is signaled */
    CHECK(p.hdr->overflow == 4);
    int got = 0, inorder = 1;
    while (cq_pop(&p, &one)) {
        inorder &= one.user_data == 100 + (uint64_t)got;
        got++;
    }
    CHECK(got == 16);
    EXPECT(dos_port_enter(p.h, 0, 0, 0), 0);                  /* flushes the overflow */
    while (cq_pop(&p, &one)) {
        inorder &= one.user_data == 100 + (uint64_t)got;
        got++;
    }
    CHECK(got == 20 && inorder && p.hdr->overflow == 0);

    /* Channel readable through a port. */
    dos_handle_t cb;
    dos_handle_t ca = (dos_handle_t)dos_channel_create(&cb);
    EXPECT(dos_object_wait_async(cb, DOS_READABLE | DOS_PEER_CLOSED, p.h, 99), 0);
    EXPECT(ch_send(ca, "x", 1, 0, 0), 0);
    CHECK(cq_pop(&p, &one) && one.user_data == 99 && (one.result & DOS_READABLE));

    /* Rules: no waiting on a port through a port; WAIT needed; mask checked; corrupted header. */
    EXPECT(dos_object_wait_async(p.h, DOS_READABLE, p.h, 1), DOS_ERR_WRONG_TYPE);
    int64_t nw = dos_handle_duplicate(ev, DOS_RIGHT_SIGNAL);
    EXPECT(dos_object_wait_async((dos_handle_t)nw, DOS_SIGNALED, p.h, 1), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_object_wait_async(ev, 0, p.h, 1), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_object_wait_async(ev, 1u << 30, p.h, 1), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_object_wait_async(self_vmar, DOS_SIGNALED, p.h, 1), DOS_ERR_WRONG_TYPE);
    uint32_t tail = p.hdr->sq_tail;
    p.hdr->sq_tail = tail + 1000;
    EXPECT(dos_port_enter(p.h, 1, 0, 0), DOS_ERR_BAD_STATE);
    p.hdr->sq_tail = tail;
    p.hdr->cq_head += 12345;                                  /* a lying head: treated as full */
    sq_push(&p, DOS_SYS_ABI_VERSION, 1, 0, 0, 0);
    EXPECT(dos_port_enter(p.h, 1, 0, 0), 0);
    p.hdr->cq_head -= 12345;
    EXPECT(dos_port_enter(p.h, 1, 0, 0), 1);
    CHECK(cq_pop(&p, &one) && one.result == DOS_ABI_VERSION);

    /* Waits on objects that go away are cancelled silently. */
    int64_t ev3 = dos_event_create();
    EXPECT(dos_object_wait_async((dos_handle_t)ev3, DOS_SIGNALED, p.h, 5), 0);
    EXPECT(dos_handle_close((dos_handle_t)ev3), 0);
    EXPECT(dos_handle_close(p.h), 0);                         /* the port goes with nothing pending */
    dos_handle_close(ca);
    dos_handle_close(cb);
    dos_handle_close(ev);
    dos_handle_close((dos_handle_t)ev2);
    dos_handle_close((dos_handle_t)t);
    dos_handle_close((dos_handle_t)nw);
    dos_printf("utest: ports: batched submission, async waits (wait set, cancel), overflow kept in order, "
               "hostile header\n");
}

/* ---- in-process exceptions --------------------------------------------------------------------- */

static uint8_t hstack[16384] __attribute__((aligned(16)));
static volatile uint32_t hcount, hvector;
static volatile uint64_t hcr2;

static void handler(struct dos_exception_record *r)
{
    hcount++;
    hvector = r->vector;
    hcr2 = r->cr2;
    if (r->vector == 6)
        r->regs.rip += 2;                     /* ud2 */
    else if (r->vector == 14) {
        r->regs.rip += 3;                     /* mov (%rax), %rbx */
        r->regs.rbx = 0x1234;
    }
    dos_exception_return(r);                  /* #BP (int3) is a trap: RIP is past it already */
}

static void handler_faults(struct dos_exception_record *r)
{
    (void)r;
    __asm__ volatile("ud2");                  /* a fault inside the handler: the process dies */
}

static void handler_badreturn(struct dos_exception_record *r)
{
    r->regs.rip = KERNEL_ADDR;
    dos_exception_return(r);                  /* refused (INVALID_ARGS): traps inside the handler */
}

void test_exceptions(void)
{
    struct dos_exception_record rec = { 0 };
    EXPECT(DOS_SC(DOS_SYS_EXCEPTION_RETURN, &rec, 0, 0, 0, 0, 0), DOS_ERR_BAD_STATE);   /* not in a handler */
    EXPECT(dos_thread_set_exception_handler(handler, (void *)KERNEL_ADDR), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_thread_set_exception_handler((void (*)(struct dos_exception_record *))KERNEL_ADDR, hstack + 64),
           DOS_ERR_INVALID_ARGS);
    EXPECT(dos_thread_set_exception_handler(handler, hstack + sizeof(hstack)), 0);
    __asm__ volatile("ud2" ::: "memory");
    CHECK(hcount == 1 && hvector == 6);
    uint64_t rbx;
    __asm__ volatile("mov (%%rax), %%rbx" : "=b"(rbx) : "a"(0x10ull) : "memory");
    CHECK(hcount == 2 && hvector == 14 && hcr2 == 0x10 && rbx == 0x1234);
    __asm__ volatile("int3" ::: "memory");
    CHECK(hcount == 3 && hvector == 3);
    uint64_t in = 0x5A5A5A5A12345678ull, out = 0;
    __asm__ volatile("mov %1, %%r12\n\tud2\n\tmov %%r12, %0" : "=r"(out) : "r"(in) : "r12", "memory");
    CHECK(out == in && hcount == 4);          /* every other register comes back exactly */
    EXPECT(dos_thread_set_exception_handler(0, 0), 0);
    EXPECT(wait_exit(spawn_ex("p10 handlerfault", 0, 0, 0, 0), S10), DOS_EXIT_FAULT);
    EXPECT(wait_exit(spawn_ex("p10 badreturn", 0, 0, 0, 0), S10), DOS_EXIT_FAULT);
    dos_printf("utest: exceptions: in-process handler (#UD, #PF, #BP), registers resumed exactly, "
               "a fault in the handler or a bad return kills\n");
}

/* ---- supervisors and FORWARD ------------------------------------------------------------------- */

static int64_t exc_read(dos_handle_t ch, struct dos_exception_msg *m, dos_handle_t *exc)
{
    uint32_t len = 0, nh = 0;
    int64_t r = ch_recv(ch, m, sizeof(*m), exc, 1, S10, &len, &nh);
    if (r == 0 && (len != sizeof(*m) || nh != 1))
        return -100;
    return r;
}

static uint64_t koid_of(dos_handle_t h)
{
    struct dos_info info = { 0 };
    dos_object_info(h, &info);
    return info.koid;
}

/* Serve a FORWARD child: returns the syscalls served, or -1 on a protocol error. */
static int64_t serve_forward(dos_handle_t ch, dos_handle_t proc, int quiet)
{
    int64_t served = 0;
    for (;;) {
        struct dos_exception_msg m;
        dos_handle_t exc = 0;
        if (exc_read(ch, &m, &exc) != 0 || m.kind != DOS_EXC_SYSCALL)
            return -1;
        struct dos_regs r;
        if (dos_exception_get_regs(exc, &r) != 0 || r.rax != m.error)
            return -1;
        served++;
        switch (m.error) {
        case 1000:                            /* add */
            r.rax = r.rdi + r.rsi + r.rdx;
            break;
        case 1001: {                          /* write(buf, len): read the child's memory */
            char s[64];
            uint64_t n = r.rsi < sizeof(s) ? r.rsi : sizeof(s);
            int64_t got = dos_process_read_memory(proc, r.rdi, s, n);
            r.rax = (got == (int64_t)n && !quiet && strncmp(s, "hello from a forwarded process", n) == 0) ? n : (uint64_t)-5;
            if (quiet)
                r.rax = n;
            break;
        }
        case 1002: {                          /* fill(ptr): write the child's memory */
            uint64_t v = 0x1122334455667788ull;
            r.rax = (uint64_t)dos_process_write_memory(proc, r.rdi, &v, 8);
            break;
        }
        case 1003:                            /* arch_prctl(SET_FS, addr) */
            r.fs_base = r.rdi;
            r.rax = 0;
            break;
        case 60:                              /* exit(code) */
            dos_exception_resume(exc, DOS_EXC_KILL, (int32_t)r.rdi);
            dos_handle_close(exc);
            return served;
        default:
            r.rax = (uint64_t)-38;            /* ENOSYS */
            break;
        }
        if (dos_exception_set_regs(exc, &r) != 0 || dos_exception_resume(exc, DOS_EXC_RESUME, 0) != 0)
            return -1;
        dos_handle_close(exc);
    }
}

void test_supervisor(void)
{
    /* A fault goes to the supervisor; it kills with its own exit code. */
    dos_handle_t ch = 0;
    int64_t p = spawn_ex("p10 null", 0, 0, DOS_SPAWN_EXCEPTION_CHANNEL, &ch);
    CHECK(p > 0 && ch != 0);
    struct dos_exception_msg m;
    dos_handle_t exc = 0;
    EXPECT(exc_read(ch, &m, &exc), 0);
    CHECK(m.kind == DOS_EXC_FAULT && m.vector == 14 && m.cr2 == 0 && m.pid == koid_of((dos_handle_t)p));
    struct dos_info info;
    EXPECT(dos_object_info(exc, &info), 0);
    CHECK(info.type == DOS_OBJ_EXCEPTION);
    struct dos_regs r;
    EXPECT(dos_exception_get_regs(exc, &r), 0);
    CHECK(r.rip == m.regs.rip && r.rip != 0);
    EXPECT(dos_exception_resume(exc, 7, 0), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_exception_resume(exc, DOS_EXC_KILL, 77), 0);
    EXPECT(dos_exception_resume(exc, DOS_EXC_KILL, 78), DOS_ERR_BAD_STATE);
    EXPECT(dos_exception_get_regs(exc, &r), DOS_ERR_BAD_STATE);
    EXPECT(wait_exit(p, S10), 77);
    dos_handle_close(exc);
    dos_handle_close(ch);

    /* Resume: the supervisor skips the faulting instruction; registers are validated. */
    p = spawn_ex("p10 ud2ret", 0, 0, DOS_SPAWN_EXCEPTION_CHANNEL, &ch);
    EXPECT(exc_read(ch, &m, &exc), 0);
    CHECK(m.kind == DOS_EXC_FAULT && m.vector == 6);
    EXPECT(dos_exception_get_regs(exc, &r), 0);
    struct dos_regs bad = r;
    bad.rip = KERNEL_ADDR;
    EXPECT(dos_exception_set_regs(exc, &bad), DOS_ERR_INVALID_ARGS);
    bad = r;
    bad.fs_base = NONCANON;
    EXPECT(dos_exception_set_regs(exc, &bad), DOS_ERR_INVALID_ARGS);
    r.rip += 2;
    EXPECT(dos_exception_set_regs(exc, &r), 0);
    EXPECT(dos_exception_resume(exc, DOS_EXC_RESUME, 0), 0);
    EXPECT(wait_exit(p, S10), 5);
    dos_handle_close(exc);
    dos_handle_close(ch);

    /* An exception handle closed unresolved kills the process (fail closed). */
    p = spawn_ex("p10 null", 0, 0, DOS_SPAWN_EXCEPTION_CHANNEL, &ch);
    EXPECT(exc_read(ch, &m, &exc), 0);
    EXPECT(dos_handle_close(exc), 0);
    EXPECT(wait_exit(p, S10), DOS_EXIT_FAULT);
    dos_handle_close(ch);

    /* The supervisor is gone before the fault: the usual crash report and kill. */
    p = spawn_ex("p10 null", 0, 0, DOS_SPAWN_EXCEPTION_CHANNEL, &ch);
    EXPECT(dos_handle_close(ch), 0);
    EXPECT(wait_exit(p, S10), DOS_EXIT_FAULT);

    /* One supervisor per process; process_exception_channel for an existing process. */
    dos_handle_t cv;
    int64_t cp = dos_process_create(self_proc, "nothreads", 9, 0, &cv);
    int64_t e1 = dos_process_exception_channel((dos_handle_t)cp);
    CHECK(e1 > 0);
    EXPECT(dos_process_exception_channel((dos_handle_t)cp), DOS_ERR_BAD_STATE);
    EXPECT(dos_handle_close((dos_handle_t)e1), 0);
    int64_t e2 = dos_process_exception_channel((dos_handle_t)cp);
    CHECK(e2 > 0);
    EXPECT(dos_process_kill((dos_handle_t)cp), 0);
    CHECK(dos_object_wait((dos_handle_t)e2, DOS_PEER_CLOSED, S10) & DOS_PEER_CLOSED);
    dos_handle_close((dos_handle_t)e2);
    dos_handle_close((dos_handle_t)cp);
    dos_handle_close(cv);

    /* FORWARD: every syscall of the child is served here, with its memory and FS base. */
    EXPECT(spawn_ex("p10 forward", 0, 0, DOS_SPAWN_FORWARD, &ch), DOS_ERR_INVALID_ARGS);   /* no supervisor */
    p = spawn_ex("p10 forward", 0, 0, DOS_SPAWN_EXCEPTION_CHANNEL | DOS_SPAWN_FORWARD, &ch);
    CHECK(p > 0);
    EXPECT(serve_forward(ch, (dos_handle_t)p, 0), 6);
    EXPECT(wait_exit(p, S10), 42);
    dos_handle_close(ch);
    dos_printf("utest: supervisor: faults to the exception channel (kill, resume, validated registers, "
               "unresolved = kill, supervisor gone), FORWARD syscalls with process memory and FS base\n");
}

/* Child "p10 forward": every syscall below is served by the supervisor. */
static int forward_child(void)
{
    if (DOS_SC(1000, 1, 2, 3, 0, 0, 0) != 6)
        DOS_SC(60, 101, 0, 0, 0, 0, 0);
    static const char msg[] = "hello from a forwarded process";
    if (DOS_SC(1001, msg, sizeof(msg) - 1, 0, 0, 0, 0) != (int64_t)(sizeof(msg) - 1))
        DOS_SC(60, 102, 0, 0, 0, 0, 0);
    static volatile uint64_t slot;
    if (DOS_SC(1002, &slot, 0, 0, 0, 0, 0) != 8 || slot != 0x1122334455667788ull)
        DOS_SC(60, 103, 0, 0, 0, 0, 0);
    static uint64_t tls = 0xFEEDFACEull;
    uint64_t f = 0;
    DOS_SC(1003, &tls, 0, 0, 0, 0, 0);
    __asm__ volatile("mov %%fs:0, %0" : "=r"(f));
    if (f != 0xFEEDFACEull)
        DOS_SC(60, 104, 0, 0, 0, 0, 0);
    if (dos_abi_version() != -38)             /* a D-OS syscall too goes to the supervisor */
        DOS_SC(60, 105, 0, 0, 0, 0, 0);
    DOS_SC(60, 42, 0, 0, 0, 0, 0);
    return 99;
}

/* ---- FS / GS bases ----------------------------------------------------------------------------- */

static uint64_t tls_slots[5];

static int check_bases(uint32_t i, int rounds)
{
    tls_slots[i] = 0xC0DE0000ull + i;
    dos_thread_set_base(DOS_BASE_FS, (uint64_t)(uintptr_t)&tls_slots[i]);
    dos_thread_set_base(DOS_BASE_GS, (uint64_t)(uintptr_t)&tls_slots[i]);
    int bad = 0;
    for (int k = 0; k < rounds; k++) {
        uint64_t f, g;
        __asm__ volatile("mov %%fs:0, %0" : "=r"(f));
        __asm__ volatile("mov %%gs:0, %0" : "=r"(g));
        bad += f != tls_slots[i] || g != tls_slots[i];
        dos_yield();
    }
    return bad;
}

static void base_worker(uint64_t i)
{
    dos_thread_exit(check_bases((uint32_t)i, 300));
}

void test_bases(void)
{
    EXPECT(dos_thread_get_base(DOS_BASE_FS), 0);
    EXPECT(dos_thread_set_base(DOS_BASE_FS, KERNEL_ADDR), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_thread_set_base(DOS_BASE_GS, NONCANON), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_thread_set_base(2, 0), DOS_ERR_INVALID_ARGS);
    int64_t th[4];
    for (uint32_t i = 0; i < 4; i++) {
        uint8_t *stack = map_new(16384, 0);
        th[i] = dos_thread_create(self_proc, base_worker, stack + 16384, i);
        CHECK(th[i] > 0);
    }
    EXPECT(check_bases(4, 300), 0);
    EXPECT(dos_thread_get_base(DOS_BASE_FS), (int64_t)(uintptr_t)&tls_slots[4]);
    for (int i = 0; i < 4; i++) {
        dos_object_wait((dos_handle_t)th[i], DOS_TERMINATED, S10);
        EXPECT(dos_thread_exit_code((dos_handle_t)th[i]), 0);
        dos_handle_close((dos_handle_t)th[i]);
    }
    dos_thread_set_base(DOS_BASE_FS, 0);
    dos_thread_set_base(DOS_BASE_GS, 0);
    dos_printf("utest: bases: FS and GS base per thread, kept across switches on all CPUs, validated\n");
}

/* ---- sealing: W^X for user-space loaders ------------------------------------------------------- */

void test_sealing(void)
{
    dos_handle_t vmex = dos_startup_handle(DOS_TAG_VMEX);
    CHECK(vmex != 0);
    static const uint8_t code[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };   /* mov eax, 42; ret */
    int64_t v = dos_vmo_create(4096);
    EXPECT(dos_vmo_write((dos_handle_t)v, 0, code, sizeof(code)), 0);
    int64_t alias = dos_handle_duplicate((dos_handle_t)v, DOS_RIGHTS_SAME);   /* keeps WRITE */
    int64_t rw = dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)v, 0, 4096, R | W);
    CHECK(rw > 0);
    EXPECT(dos_vmo_make_executable((dos_handle_t)v, vmex), DOS_ERR_BAD_STATE);   /* mapped writable */
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)v, 0, 4096, R | X), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_vmar_unmap(self_vmar, (uint64_t)rw, 4096), 1);
    EXPECT(dos_vmo_make_executable((dos_handle_t)v, self_proc), DOS_ERR_WRONG_TYPE);   /* not VMEX */
    int64_t x = dos_vmo_make_executable((dos_handle_t)v, vmex);
    CHECK(x > 0);
    struct dos_info info;
    EXPECT(dos_object_info((dos_handle_t)v, &info), DOS_ERR_BAD_HANDLE);   /* replaced */
    EXPECT(dos_object_info((dos_handle_t)x, &info), 0);
    CHECK((info.rights & X) && !(info.rights & W));
    EXPECT(dos_vmo_write((dos_handle_t)alias, 0, code, 1), DOS_ERR_ACCESS_DENIED);   /* sealed, any alias */
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)alias, 0, 4096, R | W), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)x, 0, 4096, R | W | X), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)x, 0, 4096, R | W), DOS_ERR_ACCESS_DENIED);
    int64_t xa = dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)x, 0, 4096, R | X);
    CHECK(xa > 0);
    int (*fn)(void) = (int (*)(void))(uintptr_t)xa;
    CHECK(xa > 0 && fn() == 42);
    EXPECT(dos_process_write_memory(self_proc, (uint64_t)xa, code, 1), DOS_ERR_ACCESS_DENIED);
    uint8_t back[6] = { 0 };
    EXPECT(dos_process_read_memory(self_proc, (uint64_t)xa, back, 6), 6);
    CHECK(memcmp(back, code, 6) == 0);
    EXPECT(dos_process_read_memory(self_proc, UNMAPPED, back, 6), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_process_read_memory(self_proc, (uint64_t)xa, (void *)KERNEL_ADDR, 6), DOS_ERR_BAD_ADDRESS);
    /* A writable VMO the loader is still filling cannot be sealed under it (no writer race). */
    dos_vmar_unmap(self_vmar, (uint64_t)xa, 4096);
    dos_handle_close((dos_handle_t)x);
    dos_handle_close((dos_handle_t)alias);
    dos_printf("utest: sealing: executable only after sealing (VMEX), no writable alias or mapping, "
               "W^X kept for user-space loaders\n");
}

/* ---- AVX (XSAVE) ------------------------------------------------------------------------------- */

static int has_avx(void)
{
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    if (!(c & (1u << 27)) || !(c & (1u << 28)))
        return 0;                             /* OSXSAVE (set by the kernel) and AVX */
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return (lo & 6) == 6;
}

__attribute__((target("avx"))) static int avx_work(uint64_t seed)
{
    uint64_t in[4] = { seed, seed * 3, seed * 5, seed * 7 }, out[4];
    __asm__ volatile("vmovdqu %0, %%ymm7" : : "m"(in) : "xmm7");
    for (int i = 0; i < 200; i++)
        dos_yield();
    __asm__ volatile("vmovdqu %%ymm7, %0" : "=m"(out) : : "memory");
    return memcmp(in, out, sizeof(in)) == 0 ? 0 : 1;
}

void test_avx(void)
{
    if (!has_avx()) {
        dos_printf("utest: avx: no AVX on this CPU (XSAVE state still kept)\n");
        return;
    }
    int64_t p[3];
    for (int i = 0; i < 3; i++) {
        char args[16] = "p10 avx 1";
        args[8] = (char)('3' + i);
        p[i] = spawn_ex(args, 0, 0, 0, 0);
    }
    EXPECT(avx_work(0x1111111111111111ull), 0);
    for (int i = 0; i < 3; i++)
        EXPECT(wait_exit(p[i], S10), 0);
    dos_printf("utest: avx: YMM registers kept per thread across switches (XSAVE)\n");
}

/* ---- benchmarks -------------------------------------------------------------------------------- */

void bench_ipc(void)
{
    enum { N = 10000 };
    dos_handle_t b;
    dos_handle_t a = (dos_handle_t)dos_channel_create(&b);
    uint8_t msg[64] = { 0 }, rep[64];
    uint32_t len;
    uint64_t t0 = rdtsc();
    for (int i = 0; i < N; i++) {
        ch_send(a, msg, 64, 0, 0);
        ch_recv(b, rep, 64, 0, 0, 0, &len, 0);
    }
    uint64_t local = (rdtsc() - t0) / N;
    dos_handle_close(a);
    dos_handle_close(b);

    a = (dos_handle_t)dos_channel_create(&b);
    struct dos_spawn_handle h = { b, DOS_RIGHTS_SAME, DOS_TAG_USER, 0 };
    int64_t p = spawn_ex("p10 echo", &h, 1, 0, 0);
    msg[4] = 'e';
    for (int i = 0; i < 200; i++)
        ch_call(a, msg, 16, rep, 64, &len, S10);
    t0 = rdtsc();
    for (int i = 0; i < N; i++)
        ch_call(a, msg, 16, rep, 64, &len, S10);
    uint64_t call = (rdtsc() - t0) / N;

    /* Throughput: 64 KiB messages to the other process (dropped there), then one call to sync. */
    big[4] = 'd';
    uint64_t ns0 = dos_clock_ns();
    int sent = 0;
    while (sent < 400) {
        int64_t r = ch_send(a, big, sizeof(big), 0, 0);
        if (r == 0)
            sent++;
        else if (r == DOS_ERR_SHOULD_WAIT)
            dos_object_wait(a, DOS_WRITABLE, S10);
        else
            break;
    }
    ch_call(a, msg, 16, rep, 64, &len, S10);
    uint64_t ns = dos_clock_ns() - ns0;
    uint64_t mbs = ns ? (uint64_t)sent * sizeof(big) * 1000 / ns : 0;   /* bytes/ns * 1000 = MB/s */
    dos_handle_close(a);
    wait_exit(p, S10);

    /* Port: 64 null ops per port_enter. */
    struct port pt;
    uint64_t batch = 0;
    if (port_open(&pt, 64)) {
        struct dos_cqe c;
        t0 = rdtsc();
        for (int k = 0; k < 100; k++) {
            for (int i = 0; i < 64; i++)
                sq_push(&pt, DOS_SYS_ABI_VERSION, (uint64_t)i, 0, 0, 0);
            dos_port_enter(pt.h, 64, 0, 0);
            while (cq_pop(&pt, &c))
                ;
        }
        batch = (rdtsc() - t0) / (100 * 64);
        dos_handle_close(pt.h);
    }

    /* Forwarded syscall round trip (FORWARD child, supervisor here). */
    dos_handle_t ch = 0;
    p = spawn_ex("p10 fwdbench 3000", 0, 0, DOS_SPAWN_EXCEPTION_CHANNEL | DOS_SPAWN_FORWARD, &ch);
    t0 = rdtsc();
    int64_t served = serve_forward(ch, (dos_handle_t)p, 1);
    uint64_t fwd = served > 0 ? (rdtsc() - t0) / (uint64_t)served : 0;
    CHECK(served == 3001);
    EXPECT(wait_exit(p, S10), 0);
    dos_handle_close(ch);

    dos_printf("BENCH user: channel write+read 64 B (same process, 2 syscalls): %lu cycles\n", local);
    dos_printf("BENCH user: channel call round trip to another process: %lu cycles\n", call);
    dos_printf("BENCH user: channel throughput, 64 KiB messages to another process: %lu MB/s\n", mbs);
    dos_printf("BENCH user: port batch of 64 null ops (1 port_enter): %lu cycles per op\n", batch);
    dos_printf("BENCH user: forwarded syscall round trip (FORWARD, supervisor process): %lu cycles\n", fwd);
}

/* ---- child modes ------------------------------------------------------------------------------- */

int ipc_child(const char *a)
{
    if (!strcmp(a, "echo"))
        return echo_server();
    if (!strcmp(a, "handlerfault")) {
        dos_thread_set_exception_handler(handler_faults, hstack + sizeof(hstack));
        __asm__ volatile("ud2");
        return 1;
    }
    if (!strcmp(a, "badreturn")) {
        dos_thread_set_exception_handler(handler_badreturn, hstack + sizeof(hstack));
        __asm__ volatile("ud2");
        return 1;
    }
    if (!strcmp(a, "null"))
        return *(volatile int *)(uintptr_t)fault_addr;        /* 0, on purpose (the fault test) */
    if (!strcmp(a, "ud2ret")) {
        __asm__ volatile("ud2");              /* the supervisor moves RIP past it */
        return 5;
    }
    if (!strcmp(a, "forward"))
        return forward_child();
    if (!strncmp(a, "fwdbench ", 9)) {
        uint64_t n = parse_u(word(a, 1));
        for (uint64_t i = 0; i < n; i++)
            DOS_SC(1000, i, 1, 2, 0, 0, 0);
        DOS_SC(60, 0, 0, 0, 0, 0, 0);
        return 99;
    }
    if (!strncmp(a, "avx ", 4))
        return avx_work(parse_u(word(a, 1)) * 0x0101010101010101ull);
    return 98;
}
