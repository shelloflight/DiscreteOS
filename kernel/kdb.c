/*
 * kdb: kernel inspection commands on the boot console (kmain's line loop, until user space has a
 * shell). Read-only: they print state, they never change it.
 *   help      list the commands
 *   threads   every thread: state, CPU, priority, switches, run time, kernel or user
 *   cpus      per-CPU state: current thread, run queue, switches, interrupts, TLB flushes
 *   objects   live kernel objects per type
 *   measure   the measurement log (measured boot) and the PCRs it touched
 *   mem       physical memory, kernel page tables, heap
 *   prof [ms] sample every CPU at 1 kHz for ms (default 1000), then print the profile and the
 *             latency histograms (syscalls, wake-ups, interrupts)
 *   lat       the latency histograms of the last profiling session
 */

#include <stdbool.h>
#include "kdb.h"
#include "mm.h"
#include "printf.h"
#include "profile.h"
#include "power.h"
#include "rust.h"
#include "string.h"
#include "thread.h"

bool kdb_command(const char *line)
{
    if (strcmp(line, "help") == 0) {
        kprintf("kdb: commands: help, threads, cpus, objects, measure, mem, prof [ms], lat, poweroff, reboot\n");
    } else if (memcmp(line, "prof", 4) == 0 && (line[4] == '\0' || line[4] == ' ')) {
        uint64_t ms = 0;
        for (const char *p = line + 4; *p == ' ' || (*p >= '0' && *p <= '9'); p++)
            if (*p != ' ')
                ms = ms * 10 + (uint64_t)(*p - '0');
        if (!ms || ms > 60000)
            ms = 1000;
        kprintf("kdb: profiling all CPUs at 1000 Hz for %llu ms\n", (unsigned long long)ms);
        profile_start(1000);
        thread_sleep_ns(ms * NS_PER_MS);
        profile_stop();
        profile_print(10);
        lat_print_all();
    } else if (strcmp(line, "poweroff") == 0) {
        power_off();
    } else if (strcmp(line, "reboot") == 0) {
        power_reboot();
    } else if (strcmp(line, "lat") == 0) {
        lat_print_all();
    } else if (strcmp(line, "threads") == 0) {
        kprintf("kdb: threads\n");
        sched_dump_threads(false);
    } else if (strcmp(line, "cpus") == 0) {
        kprintf("kdb: cpus\n");
        sched_dump_cpus();
    } else if (strcmp(line, "measure") == 0) {
        dkrnl_measure_print();
    } else if (strcmp(line, "objects") == 0) {
        dkrnl_objects_print();
    } else if (strcmp(line, "mem") == 0) {
        pmm_print();
        vmm_print();
        heap_print();
    } else {
        return false;
    }
    return true;
}
