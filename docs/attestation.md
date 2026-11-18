# Remote attestation

Lets a party on another machine ask "is this machine running an unmodified, signed D-OS, and what
code has it run?" and get a fresh answer it can check.

**Code:** `kernel/rust/src/security/attest.rs` (kernel side); `user/lib/crypto/src/attest.rs`
(`doscrypt::attest`: report format and verifier); `tools/dosimg` (`attest-verify`);
`user/utest/attest.c`.

## Protocol

```
 verifier                                     D-OS machine
 nonce = 32 random bytes  ───── nonce ─────►  program: dos_attest(nonce, buf, DOS_ATTEST_MAX)
                                              kernel: { nonce, kernel version, trusted key id,
                                                        attestation key, PCR 8, PCR 10, log }
                          ◄──── report ─────          signed by this boot's attestation key
 doscrypt::attest::verify(report, nonce, policy):
   signature, nonce (no replay), log replays to the PCRs, PCR 8 = the reference kernel then the
   attestation key, the trusted D-OS key, policy on unsigned code
```

`dosimg attest-verify <report> <nonce hex> <KERNEL.DSIG> <public key hex> [allow-unsigned]` is a
complete verifier.

## The attestation key

At boot, right after measuring itself, the kernel creates an Ed25519 key pair from the CPU's RNG and
measures the public key into PCR 8. The private key never leaves kernel memory and dies with the
boot. Because the key is in the measured chain, it cannot be swapped without changing PCR 8.
Signing is constant-time (scalar multiplications by secrets double and add on every bit), and the
key material is wiped when the key is dropped.

## Report format (v1)

Little-endian; `doscrypt::attest` documents every offset: magic `DOSATT01`, version, flags (`TPM`,
`TPM_MATCH`, `KERNEL_VERIFIED`), firmware, lost-event count, nonce, kernel version, key id,
attestation public key, PCR 8, PCR 10, the event log (92 bytes per event), signature. Size: 188 +
92 × events + 64 bytes (max 23 804).

## What a report proves

**Today:** within the trust of the signed D-OS kernel, which kernel booted, that its loader verified
it, and every program verified or allowed since boot, fresh for this nonce. Tampering, replay and
reports from a different kernel are all detected.

**Not yet:** there is no hardware root. A kernel modified *and* re-signed with the D-OS key could
forge a report. The verifier says so explicitly (`software evidence: rooted in the verified
kernel`). The hardware step is a TPM2_Quote over PCR 8 with a TPM-resident key.

## Hardware root: what is ready

The verifier side of a TPM quote is in `doscrypt`:

- `p256`: ECDSA P-256 verification (the curve TPM attestation keys sign with); strict key and
  signature checks.
- `tpm::verify_quote(ak_public, quote, signature, nonce, pcrs)`: parses the attestation key's
  public area (`TPMT_PUBLIC`, ECC P-256) and requires a restricted, TPM-bound signing key, so the
  TPM only signs data it produced itself; checks the ECDSA signature over the quote
  (`TPMS_ATTEST`), the `TPM_GENERATED` magic and quote type, the signer's Name, the nonce, the
  exact PCR selection (SHA-256 bank) and the PCR digest against the expected values.

Still to do: TPM2_CreatePrimary and TPM2_Quote in the kernel's TPM driver (some TPMs need AML to
start commands), and proving the attestation key belongs to a real TPM (certification through the
endorsement key and the vendor's EK certificate).

## Tests

- `attest`: a ring-3 program gets a report for a fresh nonce; the host verifies it like a remote
  party would and refuses it for another nonce, with one byte changed, or against another kernel.
- `crypto-host`: every kind of bad report is refused, including well-signed but inconsistent ones.
  P-256: RFC 6979 vectors, bad keys and out-of-range signatures, and signatures made by .NET
  (valid ones accepted, altered ones refused). Quotes: a good one verifies; another nonce, PCR
  values or selection, signer, key type, any changed byte, and every truncated or damaged blob
  are refused.
- `user`: nonce echoed, buffer too small refused and untouched, bad pointers refused.

## Limitations

- Software evidence only, until the TPM quote.
- No rights are needed to call `attest`; a report reveals program names.
- The log holds 256 events; beyond that verifiers refuse reports rather than trust a gap.
