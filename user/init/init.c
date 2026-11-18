/*
 * init: the first user process. Started by the kernel with its own process, thread and root
 * VMAR, the debug log, one read-only VMO per embedded program and the VMEX resource, and nothing
 * else.
 *
 * Arguments:
 *   (none)              check the ABI, list the programs, start the storage service (storaged.dx)
 *                       and the device manager (devmgr.dx, with every device and driver), linked
 *                       so disks reach storaged; collect the volumes storaged announces; supervise
 *                       the device manager (restart it, relinked, if it dies). Disks are
 *                       read-only (docs/hardware.md): safe to boot on a real machine
 *   devmgr [args]       run the device manager with [args] once (no storage), exit with its exit
 *                       code (tests)
 *   run <prog> [args]   spawn <prog>.dx with [args], passing it the log, copies of the program
 *                       VMOs and the VMEX resource (today every program init runs is a test
 *                       or a loader), wait for it, exit with its exit code
 *   storage test        start storaged (with its test hooks) and devmgr with writable disks, then
 *                       run fstest.dx with every volume in its namespace (/<volume name>), exit
 *                       with its exit code
 *   storage readonly    the default storage setup (read-only), with storaged checking that every
 *                       driver refuses a raw write; then `fstest readonly`
 *   power off|reboot    switch the machine off or reset it with the POWER resource (tests)
 *   bench               the hardware benchmark image (docs/benchmarks.md): the default read-only
 *                       storage setup, then `utest bench` and `fstest bench`; exits with 0 only
 *                       if both did (the kernel then shows the results screen)
 */

#include "dos.h"

#define MAX_VOLS 16

static dos_handle_t find_program(const char *name, size_t n)
{
    char buf[32];
    for (uint32_t i = 0; i < dos_start->nhandles; i++) {
        if (dos_start->handles[i].tag != DOS_TAG_PROGRAM)
            continue;
        int64_t len = dos_object_name(dos_start->handles[i].handle, buf, sizeof(buf));
        if (len == (int64_t)n + 3 && strncmp(buf, name, n) == 0 && strncmp(buf + n, ".dx", 3) == 0)
            return dos_start->handles[i].handle;
    }
    return DOS_HANDLE_INVALID;
}

/* Volumes storaged announced: name and a channel to the root (every right). */
static struct { char name[33]; dos_handle_t root; } vols[MAX_VOLS];
static uint32_t nvols;

static int64_t spawn(const char *name, size_t n, dos_handle_t image, const char *args, struct dos_spawn_handle *hs,
                     uint32_t nh)
{
    struct dos_limits limits = { 96u << 20, 2048, 48 };
    struct dos_spawn s = {
        .parent = dos_startup_handle(DOS_TAG_PROC_SELF),
        .image = image,
        .name = (uint64_t)(uintptr_t)name, .name_len = n,
        .args = (uint64_t)(uintptr_t)args, .args_len = strlen(args),
        .handles = (uint64_t)(uintptr_t)hs, .nhandles = nh,
        .limits = (uint64_t)(uintptr_t)&limits,
    };
    return dos_spawn(&s);
}

/* The log, the VMEX resource and copies of the program VMOs (to spawn copies of itself). */
static uint32_t common_handles(struct dos_spawn_handle *hs, uint32_t max)
{
    uint32_t nh = 0;
    int64_t log = dos_handle_duplicate(dos_startup_handle(DOS_TAG_LOG), DOS_RIGHTS_SAME);
    if (log > 0)
        hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)log, DOS_RIGHTS_SAME, DOS_TAG_LOG, 0 };
    int64_t vmex = dos_handle_duplicate(dos_startup_handle(DOS_TAG_VMEX), DOS_RIGHTS_SAME);
    if (vmex > 0)
        hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)vmex, DOS_RIGHTS_SAME, DOS_TAG_VMEX, 0 };
    for (uint32_t i = 0; i < dos_start->nhandles && nh < max; i++) {
        if (dos_start->handles[i].tag != DOS_TAG_PROGRAM)
            continue;
        int64_t d = dos_handle_duplicate(dos_start->handles[i].handle, DOS_RIGHTS_SAME);
        if (d > 0)
            hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)d, DOS_RIGHTS_SAME, DOS_TAG_PROGRAM, 0 };
    }
    return nh;
}

static int wait_exit(int64_t child, const char *what)
{
    dos_object_wait((dos_handle_t)child, DOS_TERMINATED, DOS_WAIT_FOREVER);
    int64_t code = dos_process_exit_code((dos_handle_t)child);
    dos_printf("init: %s exited with code %d\n", what, (int)code);
    dos_handle_close((dos_handle_t)child);
    return (int)code;
}

/* With `with_ns`, the child's namespace holds every volume as /<name> (moved: init's copies are
 * used up). */
static int run(const char *cmd, int with_ns)
{
    const char *sp = cmd;
    while (*sp && *sp != ' ')
        sp++;
    size_t n = (size_t)(sp - cmd);
    const char *args = *sp ? sp + 1 : sp;
    dos_handle_t image = find_program(cmd, n);
    if (!image) {
        dos_printf("init: no program '%s'\n", cmd);
        return 1;
    }
    struct dos_spawn_handle hs[DOS_SPAWN_MAX_HANDLES];
    uint32_t nh = common_handles(hs, DOS_SPAWN_MAX_HANDLES - 24);
    if (with_ns && nvols) {
        char names[MAX_VOLS * 34];
        size_t len = 0;
        for (uint32_t i = 0; i < nvols; i++) {
            names[len++] = '/';
            size_t k = strlen(vols[i].name);
            memcpy(names + len, vols[i].name, k);
            len += k;
            names[len++] = 0;
        }
        int64_t v = dos_vmo_create(len);
        if (v > 0 && dos_vmo_write((dos_handle_t)v, 0, names, len) == 0)
            hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)v, DOS_RIGHT_READ, DOS_TAG_NS_NAMES, 0 };
        for (uint32_t i = 0; i < nvols && nh < DOS_SPAWN_MAX_HANDLES; i++) {
            hs[nh++] = (struct dos_spawn_handle){ vols[i].root, DOS_RIGHTS_SAME, DOS_TAG_NS + i, 0 };
            vols[i].root = 0;
        }
    }
    int64_t child = spawn(cmd, n, image, args, hs, nh);
    if (child < 0) {
        dos_printf("init: spawn %s failed: %s\n", cmd, dos_status(child));
        return 1;
    }
    return wait_exit(child, cmd);
}

/* The device manager gets the log, every DEVICE handle, the driver programs (*.ddrv) as copies
 * (init keeps its own to start it again) and, if given, the channel its disks go to storaged on. */
static int64_t start_devmgr(const char *args, dos_handle_t storage)
{
    dos_handle_t image = find_program("devmgr", 6);
    if (!image) {
        dos_printf("init: no devmgr program\n");
        return -1;
    }
    struct dos_spawn_handle hs[DOS_SPAWN_MAX_HANDLES];
    uint32_t nh = 0, ndev = 0, skipped = 0;
    int64_t log = dos_handle_duplicate(dos_startup_handle(DOS_TAG_LOG), DOS_RIGHTS_SAME);
    if (log > 0)
        hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)log, DOS_RIGHTS_SAME, DOS_TAG_LOG, 0 };
    if (storage)
        hs[nh++] = (struct dos_spawn_handle){ storage, DOS_RIGHTS_SAME, DOS_TAG_STORAGE, 0 };
    char buf[32];
    for (uint32_t i = 0; i < dos_start->nhandles; i++) {
        uint32_t tag = dos_start->handles[i].tag;
        dos_handle_t h = dos_start->handles[i].handle;
        if (tag == DOS_TAG_PROGRAM) {
            int64_t len = dos_object_name(h, buf, sizeof(buf));
            if (len < 5 || len > (int64_t)sizeof(buf) || strncmp(buf + len - 5, ".ddrv", 5) != 0)
                continue;
        } else if (tag != DOS_TAG_DEVICE) {
            continue;
        }
        if (nh == DOS_SPAWN_MAX_HANDLES) {
            skipped++;                    /* never silently: reported below */
            continue;
        }
        int64_t d = dos_handle_duplicate(h, DOS_RIGHTS_SAME);
        if (d > 0) {
            hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)d, DOS_RIGHTS_SAME, tag, 0 };
            ndev += tag == DOS_TAG_DEVICE;
        }
    }
    if (skipped)
        dos_printf("init: %u devices/drivers left out: devmgr takes at most %u handles\n", skipped, DOS_SPAWN_MAX_HANDLES);
    int64_t child = spawn("devmgr", 6, image, args, hs, nh);
    if (child < 0)
        dos_printf("init: spawn devmgr failed: %s\n", dos_status(child));
    else
        dos_printf("init: started devmgr with %u devices\n", ndev);
    return child;
}

/* storaged gets the log, its control channel (to init) and the disks channel (from devmgr). */
static int64_t start_storaged(const char *args, dos_handle_t ctl, dos_handle_t disks)
{
    dos_handle_t image = find_program("storaged", 8);
    if (!image) {
        dos_printf("init: no storaged program\n");
        return -1;
    }
    struct dos_spawn_handle hs[4];
    uint32_t nh = 0;
    int64_t log = dos_handle_duplicate(dos_startup_handle(DOS_TAG_LOG), DOS_RIGHTS_SAME);
    if (log > 0)
        hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)log, DOS_RIGHTS_SAME, DOS_TAG_LOG, 0 };
    hs[nh++] = (struct dos_spawn_handle){ ctl, DOS_RIGHTS_SAME, DOS_TAG_CONTROL, 0 };
    hs[nh++] = (struct dos_spawn_handle){ disks, DOS_RIGHTS_SAME, DOS_TAG_DISKS, 0 };
    int64_t child = spawn("storaged", 8, image, args, hs, nh);
    if (child < 0)
        dos_printf("init: spawn storaged failed: %s\n", dos_status(child));
    return child;
}

/* Collect VOLUME announcements until VOLUMES_DONE (or a timeout). */
static void collect_volumes(dos_handle_t ctl, uint64_t timeout_ns)
{
    uint64_t deadline = dos_clock_ns() + timeout_ns;
    for (;;) {
        uint64_t now = dos_clock_ns();
        if (now >= deadline) {
            dos_printf("init: storaged did not report its volumes in time\n");
            return;
        }
        char buf[sizeof(struct dos_fs_header) + 64];
        dos_handle_t h[1] = { 0 };
        struct dos_msg m = { (uint64_t)(uintptr_t)buf, sizeof(buf), 1, (uint64_t)(uintptr_t)h };
        if (dos_channel_read(ctl, &m, deadline - now) < 0)
            continue;
        if (m.len < sizeof(struct dos_fs_header))
            continue;
        struct dos_fs_header hd;
        memcpy(&hd, buf, sizeof(hd));
        if (hd.op == DOS_FS_VOLUMES_DONE)
            break;
        if (hd.op != DOS_FS_VOLUME || m.nhandles != 1) {
            if (m.nhandles)
                dos_handle_close(h[0]);
            continue;
        }
        if (nvols == MAX_VOLS) {
            dos_handle_close(h[0]);
            continue;
        }
        size_t n = m.len - sizeof(hd);
        if (n > 32)
            n = 32;
        memcpy(vols[nvols].name, buf + sizeof(hd), n);
        vols[nvols].name[n] = 0;
        vols[nvols].root = h[0];
        nvols++;
    }
    char list[MAX_VOLS * 34 + 1];
    size_t len = 0;
    for (uint32_t i = 0; i < nvols; i++) {
        list[len++] = ' ';
        size_t k = strlen(vols[i].name);
        memcpy(list + len, vols[i].name, k);
        len += k;
    }
    list[len] = 0;
    dos_printf("init: %u volume(s):%s\n", nvols, list);
}

/* Start storaged and devmgr linked by a disks channel. Returns devmgr; *ctl_out is init's end
 * of storaged's control channel. */
static int64_t start_storage(const char *storaged_args, dos_handle_t *ctl_out)
{
    dos_handle_t ctl_peer = 0, disks_peer = 0;
    int64_t ctl = dos_channel_create(&ctl_peer);
    int64_t disks = dos_channel_create(&disks_peer);
    if (ctl < 0 || disks < 0) {
        dos_printf("init: cannot create the storage channels\n");
        return -1;
    }
    if (start_storaged(storaged_args, ctl_peer, disks_peer) < 0)
        return -1;
    *ctl_out = (dos_handle_t)ctl;
    /* Disks are writable only for the storage tests (docs/hardware.md). */
    return start_devmgr(strcmp(storaged_args, "test") == 0 ? "rw" : "", (dos_handle_t)disks);
}

int main(void)
{
    int64_t v = dos_abi_version();
    struct dos_info self;
    if (v < DOS_ABI_VERSION || dos_object_info(dos_startup_handle(DOS_TAG_PROC_SELF), &self) != 0 ||
        self.type != DOS_OBJ_PROCESS) {
        dos_printf("init: ABI mismatch (kernel ABI %d, init built for %d)\n", (int)v, DOS_ABI_VERSION);
        return 1;
    }
    dos_printf("init: running in ring 3, ABI v%d, process koid %lu, %u startup handles\n", (int)v,
               self.koid, dos_start->nhandles);

    const char *a = dos_args();
    if (strncmp(a, "run ", 4) == 0)
        return run(a + 4, 0);
    if (strncmp(a, "devmgr", 6) == 0 && (a[6] == ' ' || a[6] == 0)) {
        int64_t c = start_devmgr(a[6] ? a + 7 : "", 0);
        return c < 0 ? 1 : wait_exit(c, "devmgr");
    }
    if (strcmp(a, "storage test") == 0) {
        dos_handle_t ctl = 0;
        if (start_storage("test", &ctl) < 0)
            return 1;
        collect_volumes(ctl, 30000000000ull);
        return run("fstest", 1);
    }
    if (strcmp(a, "power off") == 0 || strcmp(a, "power reboot") == 0) {
        dos_handle_t pw = dos_startup_handle(DOS_TAG_POWER);
        uint64_t action = a[6] == 'o' ? DOS_POWER_OFF : DOS_POWER_REBOOT;
        /* A program without the resource is refused first. */
        int64_t denied = dos_system_power(dos_startup_handle(DOS_TAG_VMEX), action);
        dos_printf("init: power: the VMEX resource is refused (%d); asking with POWER\n", (int)denied);
        if (denied != DOS_ERR_ACCESS_DENIED)
            return 1;
        int64_t r = dos_system_power(pw, action);
        dos_printf("init: power: system_power returned %d\n", (int)r);
        return 1;
    }
    if (strcmp(a, "bench") == 0) {
        dos_handle_t ctl = 0;
        if (start_storage("", &ctl) < 0)
            return 1;
        collect_volumes(ctl, 30000000000ull);
        int u = run("utest bench", 0);
        int f = run("fstest bench", 1);
        return u || f;
    }
    if (strcmp(a, "storage readonly") == 0) {
        dos_handle_t ctl = 0;
        if (start_storage("rocheck", &ctl) < 0)
            return 1;
        collect_volumes(ctl, 30000000000ull);
        return run("fstest readonly", 1);
    }

    char list[256];
    size_t len = 0;
    for (uint32_t i = 0; i < dos_start->nhandles; i++) {
        if (dos_start->handles[i].tag != DOS_TAG_PROGRAM || len + 34 > sizeof(list))
            continue;
        list[len++] = ' ';
        int64_t n = dos_object_name(dos_start->handles[i].handle, list + len, 31);
        if (n > 0)
            len += (size_t)(n < 31 ? n : 31);
    }
    list[len] = '\0';
    dos_printf("init: programs:%s\n", list);
    dos_handle_t ctl = 0;
    int64_t c = start_storage("", &ctl);
    if (c >= 0)
        collect_volumes(ctl, 30000000000ull);
    /* Supervise the device manager: start it again if it ends (a few times; no shell yet), with
     * a fresh disks channel whose other end goes to storaged. */
    for (int tries = 0; c >= 0 && tries < 3; tries++) {
        wait_exit(c, "devmgr");
        dos_handle_t peer = 0;
        int64_t disks = dos_channel_create(&peer);
        if (disks < 0)
            break;
        struct dos_fs_header hd = { 0, DOS_FS_DISKS_LINK, 0, 0, 0, 0 };
        struct dos_msg_handle mh = { peer, DOS_RIGHTS_SAME };
        struct dos_msg m = { (uint64_t)(uintptr_t)&hd, sizeof(hd), 1, (uint64_t)(uintptr_t)&mh };
        if (ctl)
            dos_channel_write(ctl, &m);
        c = start_devmgr("", (dos_handle_t)disks);
    }
    dos_printf("init: devmgr keeps failing, idle\n");
    for (;;)
        dos_object_wait(dos_startup_handle(DOS_TAG_PROC_SELF), DOS_TERMINATED, DOS_WAIT_FOREVER);
}
