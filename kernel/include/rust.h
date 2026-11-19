/*
 * Entry points implemented in Rust (kernel/rust). Hand-written header: the surface is small.
 * Everything else the Rust side exports is declared next to its C API (klog.h, ...).
 */
#ifndef DOS_RUST_H
#define DOS_RUST_H

#include <stdbool.h>
#include <stdint.h>

struct interrupt_frame;

void dkrnl_init(void);            /* after heap + time: verifies the allocator, sets up objects */
/* ACPI (kernel/rust/src/dev/acpi.rs): run \_TTS(state) and \_PTS(state) before sleeping or switching
 * off, when the AML namespace is loaded and the caller may block; otherwise nothing. */
void dkrnl_acpi_prepare_sleep(uint32_t state);
/* ACPI wake (dev/acpi.rs): run \_PIC(1), \_WAK(state), \_TTS(0) and re-enable SCI events. */
void dkrnl_acpi_wake(uint32_t state);
/* PCI suspend/resume (dev/pci.rs): save and restore PCI configuration headers across S3. */
void dkrnl_pci_suspend(void);
void dkrnl_pci_resume(void);
/* IOMMU resume (dev/iommu): restore VT-d / AMD-Vi DMA + interrupt remapping after S3 wake. */
void dkrnl_iommu_resume(void);
/* TPM resume (security/measure.rs): issue TPM2_Startup(TPM_SU_STATE) if a TPM is attached. */
void dkrnl_tpm_resume(void);
void dkrnl_objects_print(void);   /* live kernel objects per type (inspection) */
/* Verified-boot report, PCR 8 measurement, TPM discovery (after dkrnl_init: needs ACPI) */
void dkrnl_security_init(uint32_t firmware, uint32_t flags, const uint8_t *kernel_dsig);
void dkrnl_measure_print(void);   /* the measurement log and the PCRs it touched (kdb) */

/* User mode (kernel/rust/src/user/) */
void dkrnl_start_init(const char *args, uint64_t len);  /* spawn init (embedded) with these arguments */
void dkrnl_uthread_finish(void *user, int code);        /* uthread_exit: drop a user thread's state */
void dkrnl_user_print_current(void);                    /* "user fault: process 'x' (koid n)" */
void dkrnl_user_kill_current(int code);                 /* kill the current thread's process */
/* Hand a ring-3 fault to the thread's handler or the supervisor; true = resume. */
bool dkrnl_user_exception(struct interrupt_frame *f, uint64_t cr2);
/* Resolve a not-present fault on a demand-paged user mapping; true = page mapped, resume. */
bool dkrnl_demand_page(uint64_t cr2, uint64_t error);

#ifdef KTEST
uint32_t rust_selftest(void);     /* KTEST_SELFTEST: returns the number of failures */
void rust_ktest_panic(void);      /* KTEST_RUSTPANIC: fails a kassert! */
void rust_bench_box(void *ctx);   /* KTEST_BENCH */
void rust_bench_spinlock(void *ctx);
void rust_bench_klog(void *ctx);
void channel_call_stats(uint64_t *calls, uint64_t *moved);   /* channel calls since boot; how many changed CPU */
void rust_bench_spawn(void *ctx);
uint32_t rust_objects_test(void); /* KTEST_OBJECTS: returns the number of failures */
void rust_bench_objects_init(void);
void rust_bench_handle_lookup(void *ctx);
void rust_bench_handle_dup_close(void *ctx);
void rust_bench_event_signal_wait(void *ctx);
void rust_bench_vmo_create_close(void *ctx);
uint64_t rust_objects_live(void);  /* KTEST_SOAK */
uint32_t rust_elf_fuzz(void);      /* KTEST_FUZZ: returns the number of failures */
uint32_t rust_acpi_fuzz(void);     /* KTEST_FUZZ: MADT/MCFG/DMAR/TPM2 parsers; failures */
void     rust_objects_snapshot(void);   /* ktest: live objects now ... */
uint64_t rust_channels_collected(void); /* channel ends freed by cycle collection */
uint32_t rust_objects_leaked(void);     /* ... and types with more of them later (printed) */
_Bool rust_soak_objects(uint64_t seed);
#endif

#endif
