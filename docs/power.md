# Power control

D-KRNL can switch the machine off (ACPI S5) and reset it. Power-off needs nothing from AML on
most machines; when the AML namespace is loaded ([acpi.md](acpi.md)) it supplies `\_S5` (also as
a method) and `\_TTS`/`\_PTS` run first.

**Code:** `kernel/arch/x86_64/power.c`, `kernel/include/power.h`; syscall `system_power`
([abi.md](abi.md)).

## At boot

`power_init` reads the **FADT** (PM1a/PM1b control blocks, SMI command port, reset register, 8042
flag, hardware-reduced sleep register) and finds the `\_S5` package in the **DSDT** with a small
scanner (`power_parse_s5`) that decodes SLP_TYPa/b. It prints, for example:

```
Power: power-off by ACPI S5 (SLP_TYP 0/0, PM1a port 0x604); reset by reset register (port 0xcf9 = 0xf)
```

If `\_S5` is a method rather than a data package, the scanner finds nothing; the AML interpreter
evaluates it a moment later and hands the values over (`power_set_s5`, printed as
`Power: \_S5 from AML: ...` when they differ). Without `\_S5` or a PM1 control block, power-off is
reported as unavailable; reset still works.

## Switching off

`power_off` runs `\_TTS(5)` and `\_PTS(5)` on the ACPI thread (when the namespace is loaded and the
caller may block), enables ACPI mode if needed, writes `SLP_TYP | SLP_EN` to PM1b then PM1a (or the
hardware-reduced sleep register), and if the machine is still running 2 s later, says so and returns
(`NOT_SUPPORTED` to user space).

## Resetting

`power_reboot` tries, in order: the FADT reset register, the 8042 reset line, port 0xCF9, and
finally a triple fault. It never returns.

## Who may do it

- User space: `system_power(power, action)` with the **POWER resource**, which the kernel gives to
  init only.
- kdb: `poweroff`, `reboot`.
- The machine's power button: the kernel signals init's power-button event, and init shuts down
  cleanly before asking ([acpi.md](acpi.md)).

The kernel flushes nothing; storage services must sync before asking.

## Tests

`poweroff` (VMEX resource refused; with POWER, QEMU must actually exit), `poweroff-uefi`, `reboot`,
`powerbutton`, and the `\_S5` scanner fuzzed in `fuzz`.

## Limitations

S3 sleep is not supported. Devices are not quiesced before S5 beyond what `\_PTS` does and the
services' own shutdown.
