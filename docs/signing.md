# Signing: verified boot, measured boot, code signing

**Code:** `user/lib/crypto` (`doscrypt`: SHA-256, SHA-512, Ed25519, `.dsig`);
`boot/common/dcrypto.c` (the loaders' C verifier); `boot/stage3`, `boot/uefi/loader.c`;
`kernel/rust/src/security/` (verification, measurement log, TPM 2.0 driver); `tools/dbuild` (`dbuild img`)
(`pubkey`, `sign`, `verify`).

## Chain of trust

```
firmware ──► loader ──verifies kernel .dsig──► kernel ──verifies .dsig (vmo_verify)──► programs, drivers
                │                                │
                └─ measures PCR 8                └─ measures PCR 10 (each verified or allowed image)
                         TPM 2.0 (when present) + the kernel's own measurement log
```

Nothing of the kernel is used before its signature checks out. A kernel that fails verification
never runs; the loader says why and returns to the firmware (UEFI) or halts (BIOS).

The kernel decides what code may run, before the image is parsed:

| Trust | How a program image gets it |
|---|---|
| Signed | `vmo_verify(vmo, dsig)` with a valid `.dsig` by the D-OS key |
| Kernel image | programs embedded in the kernel (covered by its signature) |
| Unsigned | `vmo_allow_unsigned(vmo, vmex)` by a holder of the VMEX resource |

Both calls seal the VMO first, so nothing can change it afterwards. `vmo_verify` also checks
signed service manifests (kind 5) and `.dapp` application bundles (kind 6, [apps.md](apps.md)):
they are verified as genuine data and never become runnable directly (a `.dapp`'s inner executable
must carry its own `KIND_PROGRAM` `.dsig`).

## Keys

- Ed25519 (RFC 8032). A key is a 32-byte seed; its public half is compiled into both loaders and
  the kernel (generated `build/obj/trust.c`).
- Development builds create `build\keys\dev-signing.seed` on first build; it is **never
  committed**, so every checkout trusts only its own key. `DOS_SIGNING_KEY` selects another key.
- Key id: the first 16 bytes of SHA-512(public key).

## `.dsig` v1 (256 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `DSIG` |
| 4 | 2 | version 1 |
| 6 | 2 | algorithm 1 (Ed25519) |
| 8 | 4 | kind: 1 kernel, 2 program, 3 driver, 4 package, 5 manifest, 6 app (`.dapp` bundle) |
| 12 | 4 | flags (0) |
| 16 | 16 | key id |
| 32 | 8 | content size |
| 40 | 64 | SHA-512 of the content |
| 104 | 88 | name (UTF-8, NUL-padded) |
| 192 | 64 | Ed25519 signature of bytes 0-191 |

`dbuild img sign <seed> <kind> <name> <file> <out.dsig>` makes one; `dbuild img verify` checks one.

## Measured boot

The kernel keeps a measurement log and software PCRs (SHA-256 bank, TPM extend rule).

| PCR | Contents |
|---|---|
| 8 | the kernel's `.dsig` header, then this boot's attestation key |
| 10 | every program the kernel verified (`.dsig` header) or allowed unsigned (content hash); every service manifest the service manager accepted or refused (`svc ...`, [services.md](services.md)) |

On UEFI machines with a TPM, the loader also extends PCR 8 through TCG2. The kernel's TPM 2.0
driver (ACPI `TPM2` table: TIS, or CRB started by register, by the TPM device's ACPI `_DSM` as AMD
firmware TPMs need, or both) replays the log into the TPM and mirrors every later measurement; if
the TPM fails, the kernel's log stays authoritative. The TPM also quotes PCRs 8 and 10 for remote
attestation ([attestation.md](attestation.md)) and seals user identity credentials under the owner
SRK via `TPM_SEAL`/`TPM_UNSEAL` ([identity.md](identity.md)). kdb `measure` prints the
log and PCRs.

## Tests

- `crypto-host`: FIPS 180 and RFC 8032 vectors, non-canonical inputs refused, `.dsig` tampering,
  Rust signer vs. C verifier cross-checks.
- `bios-badsig`, `uefi-badsig`: one flipped kernel byte; the kernel never starts.
- `selftest`: Ed25519 in the kernel, the TPM command layer against a simulated TPM (including broken
  ones).
- `user`: unsigned images are refused unless a VMEX holder allows them.
- `storage`: a signed program loaded from disk runs; tampered, padded and forged copies are refused.

## Limitations

- The loader is not signed for UEFI Secure Boot; BIOS has no hardware root of trust at all.
- TPM: TIS and CRB are only exercised on real hardware (QEMU on Windows has no TPM); the command
  layer and attestation are tested against the kernel's simulated TPM.
- One compiled-in key; no revocation or rotation yet.
- Verification is not constant-time (it handles public data only). Ed25519 signing is (the kernel signs
  attestation reports with its per-boot key).
