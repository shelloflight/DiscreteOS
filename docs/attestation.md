# Remote attestation

Lets a party on another machine ask "is this machine running an unmodified, signed D-OS, and what
code has it run?" and get a fresh answer it can check. With a TPM, the hardware vouches for the
answer.

**Code:** `kernel/rust/src/security/attest.rs` (kernel side) and `tpm.rs` (TPM commands);
`user/lib/crypto/src/attest.rs` (`doscrypt::attest`: report format, verifier, challenge);
`doscrypt::{tpm, rsa, x509, sym}` (quotes, endorsement keys, certificates); `tools/dbuild` (`dbuild img`)
(`attest-verify`, `attest-challenge`); `user/utest/attest.c`.

## Protocol

```
 verifier                                     D-OS machine
 nonce = 32 random bytes  ───── nonce ─────►  program: dos_attest(nonce, buf, DOS_ATTEST_MAX)
                                              kernel: { nonce, kernel version, trusted key id,
                                                        attestation key, PCR 8, PCR 10, log,
                                                        TPM: quote(nonce, PCR 8 + 10), AK, EK,
                                                             EK certificate }
                          ◄──── report ─────          signed by this boot's attestation key
 doscrypt::attest::verify(report, nonce, policy):
   signature, nonce (no replay), log replays to the PCRs, PCR 8 = the reference kernel then the
   attestation key, the trusted D-OS key, policy on unsigned code; with TPM evidence: the quote
   (TPM attestation key, this nonce, the reported PCRs), the EK certificate against the TPM
   vendors' CAs the verifier trusts
 challenge = doscrypt::attest::challenge(report, credential)
                          ── challenge ────►  program: dos_attest_activate(challenge, out)
                          ◄── credential ───  kernel: TPM2_ActivateCredential (only this TPM can)
 credential equal: the attestation key that quoted is in the TPM the certificate names
```

`dbuild img attest-verify <report> <nonce hex> <KERNEL.DSIG> <public key hex> [allow-unsigned]
[require-tpm] [ek-ca=<cert.der> ...]` is a complete verifier; `dbuild img attest-challenge <report>
<out>` writes the challenge and prints the credential the machine must return.

## The keys

- **Report key** (Ed25519, per boot): at boot, right after measuring itself, the kernel creates it
  from the CPU's RNG and measures the public key into PCR 8. The private key never leaves kernel
  memory and dies with the boot; signing is constant-time and the key is wiped when dropped.
- **TPM attestation key (AK)**: ECC P-256, restricted signing (the TPM only signs data it produced,
  such as quotes), a primary key of the endorsement hierarchy: the same key every boot.
- **Endorsement key (EK)**: the TCG RSA 2048 EK (the persistent one at 0x81010001 when present,
  otherwise created from the same template) and its manufacturer certificate (NV 0x01C00002).

The TPM keys are made on the first report, not at boot (an RSA EK can take seconds to create).

## Report format (v2)

Little-endian; `doscrypt::attest` documents every offset: magic `DOSATT01`, version, flags (`TPM`,
`TPM_MATCH`, `KERNEL_VERIFIED`), firmware, lost-event count, nonce, kernel version, key id,
attestation public key, PCR 8, PCR 10, the event log (92 bytes per event), the TPM evidence
(length, then AK public area, quote, quote signature, EK public area, EK certificate, in TPM wire
format), signature. Size: 188 + 92 × events + 4 + evidence + 64 bytes (at most 26 624). The
kernel adds evidence only when the TPM's PCRs 8 and 10 equal the log's.

## What a report proves

- **Without TPM evidence:** within the trust of the signed D-OS kernel, which kernel booted, that
  its loader verified it, and every program verified or allowed since boot, fresh for this nonce.
  A kernel modified *and* re-signed with the D-OS key could forge it; the verifier says so
  (`software evidence: rooted in the verified kernel`).
- **With a verified quote:** a TPM attestation key saw these PCR values for this nonce. The PCRs
  include the report key, so the report's signer is the key that booted with this kernel.
- **With the certificate and the challenge:** that TPM is a genuine one, as far as its vendor's
  CA is trusted. Validity dates and revocation of the vendor CA are the verifier's PKI to check.

## Tests

- `attest`: a ring-3 program gets a report for a fresh nonce; the host verifies it like a remote
  party would and refuses it for another nonce, with one byte changed, against another kernel, or
  when a TPM is required.
- `attest-tpm`: the same with the kernel's simulated TPM (TEST keys, `doscrypt::testkeys`): the
  report carries a quote and an EK certificate, verified against the TEST CA; a CA that did not
  sign it is refused; the host makes the challenge.
- `selftest`: report, quote and certificate against the simulated TPM; the challenge answered by
  the TPM, damaged and foreign ones refused.
- `crypto-host`: every kind of bad report and quote refused; RSA (PKCS #1 v1.5 with SHA-256/384,
  OAEP), X.509 and EK certificates checked against .NET; AES, HMAC and KDFa against published
  vectors; the credential round trip; truncated, damaged and random certificates and evidence
  refused without a panic. When `build/host/ekcert.der` exists (the build machine's own EK
  certificate, never committed), it must parse.
- `user`: nonce echoed, buffer too small refused and untouched, bad pointers refused; a challenge
  not for this machine refused.

## Limitations

- No rights are needed to call `attest` or `attest_activate`; a report reveals program names, and
  the TPM keys identify the machine across boots (as the EK always does).
- Only RSA 2048 EKs (the kind every PC TPM has); ECC EK certificates are not read.
- The log holds 256 events; beyond that verifiers refuse reports rather than trust a gap.
