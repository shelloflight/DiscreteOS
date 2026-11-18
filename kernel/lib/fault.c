/* Fault injection for test builds (see fault.h). The state lives in the current thread. */

#ifdef KTEST

#include "fault.h"
#include "percpu.h"
#include "thread.h"

void fault_inject_arm(uint32_t kinds, uint64_t nth)
{
    struct thread *t = current_thread();
    t->fault_fired = false;
    t->fault_countdown = nth;
    t->fault_kinds = kinds;
}

bool fault_inject_disarm(void)
{
    struct thread *t = current_thread();
    t->fault_kinds = 0;
    t->fault_countdown = 0;
    return t->fault_fired;
}

bool fault_should_fail(uint32_t kind)
{
    if (percpu_irq_depth())
        return false;                  /* interrupt handlers run on the thread's CPU, not for it */
    struct thread *t = current_thread();
    if (!t || !(t->fault_kinds & kind))
        return false;
    if (--t->fault_countdown)
        return false;
    t->fault_kinds = 0;                /* one-shot */
    t->fault_fired = true;
    return true;
}

#else
typedef int fault_c_is_empty_in_release_builds;
#endif
