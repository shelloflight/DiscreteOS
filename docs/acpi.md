# ACPI and AML

Firmware describes the machine in **AML** byte code (the DSDT and the SSDTs): its devices, how to
change power states, and what to run when something happens (the power button, a lid, a
temperature limit). D-OS has its own AML interpreter, written for the kernel, and runs it in one
kernel thread.

**Code:** `kernel/aml/` (the interpreter, `no_std` + `alloc`, no `unsafe`, host-testable),
`kernel/rust/src/dev/acpi.rs` (the kernel side: tables, hardware access, the SCI, the power button),
`kernel/arch/x86_64/acpi.c` (table discovery), `kernel/arch/x86_64/power.c` (S5, `acpi_mmio_map`).

## The interpreter (`kernel/aml`)

- `load_table` runs a table's top level: names, scopes, devices, processors, power resources,
  thermal zones, methods (kept as byte ranges, parsed when called), operation regions and fields.
  The DSDT and every SSDT share one namespace.
- `evaluate` runs a method or reads a named object; `initialize` runs `_REG` for SystemMemory,
  SystemIO and PCI_Config regions, `\_SB._INI`, then walks the devices: `_STA`, `_INI` if present,
  children if present or functional (ACPI 6.5, 6.5.1).
- Opcodes: the ACPI 6.5 set firmware uses: data objects, names and scopes, control flow (If/Else,
  While, Break, Continue, Return), integer and logical operators, conversions (ToBuffer,
  ToInteger, ToString, ToHexString, ToDecimalString, BCD), strings and buffers (Concatenate,
  ConcatenateResTemplate, Mid, SizeOf), packages (Index, DerefOf, Match), buffer fields,
  references (RefOf, CondRefOf), CopyObject, ObjectType, mutexes and events, Notify, Sleep, Stall,
  Timer, Fatal. Load, LoadTable and Unload fail cleanly.
- Fields: SystemMemory, SystemIO, PCI_Config (device from `_ADR`, segment and bus from the host
  bridge's `_SEG`/`_BBN`, secondary buses of the bridges in between), EmbeddedControl (through the
  handler; none yet), IndexField, BankField; access widths, Preserve/WriteAsOnes/WriteAsZeros,
  the global lock for `Lock` fields.
- Integers are 32 bits in revision 1 tables (QEMU's DSDT), 64 bits otherwise.
- `_OSI` answers true for the Windows versions and the feature strings ACPICA answers;
  `\_OS` is `Microsoft Windows NT`, `\_REV` 2. Firmware is tested against Windows and picks its
  code paths from these.

All hardware access goes through the `Handler` trait (ports, physical memory, PCI configuration,
embedded controller, delays, the global lock, Notify), so the same code runs in the kernel and in
`cargo test`.

### Fail closed

- Every byte is bounds-checked; malformed code, a missing name or a type error ends only the
  method being evaluated (`Error` with the table offset).
- Budgets per evaluation (`Limits`): 2 million steps (a loop polling hardware ends), 48 nested
  calls, 48 nested expressions, 1 MiB per buffer or string, 64 Ki package elements, 256 Ki
  namespace nodes, packages nested at most 8 deep when stored into packages.
- The handler is asked before every nesting level whether there is stack left (`stack_ok`).
- Loading: a definition that fails is skipped with its own length (a scope or device body), so
  one bad definition does not lose the rest of the table; duplicates keep the first definition.
- Each opcode group runs in its own non-inlined function, so one level of nesting costs only the
  frame of the operation at that level (real firmware: 20 KiB of stack at the deepest point,
  measured on the host over every method of a desktop's tables).

## In the kernel (`dev/acpi.rs`)

At the end of device discovery the kernel starts thread `acpi` and waits (up to 20 s) until it
has:

1. switched to a private 128 KiB stack (heap pages between unmapped guard pages; kernel stacks are
   16 KiB and the interpreter recurses);
2. loaded the DSDT (FADT `X_DSDT`/`DSDT`) and every SSDT;
3. run `\_PIC(1)` (APIC mode) and `initialize`;
4. evaluated `\_S5` and handed it to the power code (`power_set_s5`; a method works too);
5. read the first present processor's `_CST`, `_CPC` and `_PSS`/`_PCT` (`aml::processor`) and
   configured idle states and performance control on every CPU ([power.md](power.md));
6. set up the SCI (below).

```
ACPI: AML: DSDT + 0 SSDT(s), 8 KiB, 280 objects in 4 ms; 0 definition(s) skipped
ACPI: AML: 41 devices (41 present), 0 _INI and 0 _REG run, 0 failed, 3 ms
ACPI: AML stack: deepest use 13 KiB of 128 KiB
ACPI: SCI on IRQ 9; power button: fixed; 2 GPE(s) enabled, 0 wake-only
```

Then it serves requests and events for ever. Before power-off, `power_off` asks it to run
`\_TTS(5)` and `\_PTS(5)` (bounded wait; skipped in contexts that must not block, such as kdb).

### What firmware code may touch

AML runs in ring 0, so the handler limits it:

- **Memory:** only outside usable RAM (MMIO, reserved, ACPI NVS) and inside the direct map; a page
  the kernel already maps differently (read-only firmware tables) is refused, never remapped.
- **I/O ports:** the DMA controllers, PICs, PITs, RTC/CMOS (the clock service owns it), ELCR and
  the PCI configuration ports 0xCF8-0xCFF are ignored (reads give 0, writes are dropped): ACPICA's
  list, which Windows enforces too. Each refusal is logged (the first 16).
- **PCI configuration:** segment 0, aligned, inside the function's configuration space, through
  the kernel's own accessors.

### SCI, GPEs and the power button

The SCI (FADT `SCI_INT`, level-triggered active-low unless the MADT overrides it) arrives on the
boot CPU. The interrupt handler only disables the events that fired (PM1 fixed events, GPE enable
bits) and wakes the thread, which:

- for the **fixed power button** (FADT `PWR_BUTTON` clear): clears `PWRBTN_STS` and signals the
  power-button event;
- for a **GPE** with an `_Lxx` (level) or `_Exx` (edge) method under `\_GPE`: clears the status
  (before the method for edge, after it for level), runs the method, handles the `Notify`s it
  made, and re-enables it. A GPE that fires more than 200 times in a second stays disabled (an
  interrupt storm cannot take a CPU);
- `Notify(<PNP0C0C device>, 0x80)` (a control-method power button) signals the power-button event
  too; other notifications are logged.

The thread also runs the **TPM start method** for the TPM driver: firmware TPMs whose ACPI `TPM2`
table names start method 2 or 8 (AMD's) start each command through the TPM device's `_DSM`
(MSFT0101, UUID 6BBF6CAB-5463-4714-B7CD-F0203C0368D4, function 1). The CRB start register is
set as well: the `_DSM` only signals the firmware, which clears the register once the response is
ready.

GPEs listed in a `_PRW` (wake events) are not enabled at run time. Hardware-reduced ACPI (no SCI,
GPIO events) is not supported yet.

The **power-button event** is given to init (startup tag `POWER_BUTTON`, ABI v11). init clears it
and does what the shell's `power off` does: every service stops in reverse order, storaged makes
the volumes durable, then `system_power`.

## Tests

- `aml-host` (host, `cargo test` in `kernel/aml`): unit tests on byte code built in the test (no
  ASL compiler needed); a mutation fuzzer (every truncation and 30 000 mutations of a built table);
  and, on Windows, the build machine's own DSDT and SSDTs (dumped from `HKLM\HARDWARE\ACPI` into
  `build\host\acpi`, never committed): loaded with no error, initialised, `\_S5`, the power button
  and TPM devices found, the TPM start `_DSM` listing and running function 1, every method run
  against simulated hardware (each one returns or fails cleanly), its processors' `_CST`, `_CPC`
  and `_PSS` read, and its SSDTs mutated on top of its DSDT. Processor objects are also read from
  built byte code shaped like a desktop's, and malformed ones read as absent.
- `boot`, `uefi`: QEMU's tables (SeaBIOS and OVMF) load with nothing skipped, initialisation has no
  failure, the SCI is set up.
- `powerbutton`: QEMU's `system_powerdown` reaches init through the SCI; clean shutdown and
  power-off.
- `poweroff`, `poweroff-uefi`: power-off with `\_PTS`.
- `static`: clippy over `kernel/aml` and the kernel.

## Limitations

- No EmbeddedControl handler yet (laptops: battery, lid, many thermal zones), no SMBus, GPIO or
  GenericSerialBus regions, no dynamic table loading.
- S3 sleep, wake events and device power states (`_PSx`, power resources) are not used yet.
- `_OSC`/`_PDC` are not run: firmware that loads processor tables only after them (some Intel
  machines) shows no `_CST`.
- `_PRT` interrupt routing is not used: devices use MSI/MSI-X.
- The AML thread serialises all evaluation; a method that sleeps delays the next event.
