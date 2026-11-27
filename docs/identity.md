# User identities and lock screen

D-OS separates people from ambient privilege. There is **no `root` user** and no superuser
escalation (`su`/`sudo`): every identity has an explicit capability bitmask and its own isolated
home namespace, and every running program holds only the handles granted for that identity and its
signed manifest. Credentials are sealed by the hardware **TPM 2.0** storage root key (with an
authenticated software fallback when no TPM 2.0 is present), and signing in or unlocking happens
exclusively inside a **compositor-drawn lock screen** that applications cannot imitate or intercept.

**Code:** `user/lib/identity` (`dosid`: `no_std`, `#![forbid(unsafe_code)]`, PBKDF2-HMAC-SHA256,
identity model, capability masks, software ChaCha20-Poly1305 seal fallback, exponential auth
throttling, TOML store codec, wire codecs), `user/identity/` (`identity.dsvc`),
`user/init/services/identity.dman`, `user/lib/libd/src/identity.rs`,
`user/lib/awmi/src/lock.rs` (compositor lock/login screen),
`kernel/rust/src/security/tpm.rs` (`TPM_SEAL` / `TPM_UNSEAL`), `user/lib/crypto/src/tpm.rs`.
**Tests:** `identity-host`, `identity-tpm`.

## Identity model

| Property | Design |
|---|---|
| Names | Lowercase `a-z`, `0-9`, `-` (1..24 chars, starting with a letter). `"root"` is refused with `"D-OS has no root user"`; `superuser`, `su`, `sudo`, `wheel`, `system`, `kernel`, `init`, `nobody` are also reserved. |
| Roles | Templates that choose initial defaults, never ambient authority: **Standard** (`files:read/write`, `net:client`, `audio:*`, `display:query`, `system:query`) and **Operator** (adds `net:control`, `display:admin`, `system:admin`, `app:admin`, `identity:admin`). |
| Namespaces | On installed systems with a dedicated `home` DFS volume, each identity gets an isolated `/home` mapped directly to `home:/<name>` (falling back to `/data/home/<name>` on live/test media). Enforced by both `appmgr` and `shell` (updating automatically on `identity switch`). An **Operator** identity may also reach `/data`; a **Standard** identity cannot cross into another identity's home directory. |
| Default boot | A single default `user` (Operator) exists with no enrolled passphrase so a fresh boot lands directly on the desktop. On newly installed disks, `appmgr` launches the skippable first-boot setup wizard (`oobe.dapp`, config persisted in `/home/.dos/oobe.toml`) once and bypasses it thereafter. Enrolling a passphrase (or setting `lock = on` in `esp:/DOS/BOOT.CFG`) engages the compositor login/lock screen on boot. |
| Persistence | Metadata and sealed credential blobs are stored in `/home/.dos/identities.toml` on installed systems (falling back to `/data/identities/store.toml`); otherwise the store operates in memory. |

## TPM 2.0 credential sealing (ABI v16)

Credential secrets never sit in plaintext on disk or in another service's memory:

1. **Key derivation:** PBKDF2-HMAC-SHA256 (16,000 iterations, 16-byte random salt from
   `sys::get_random`) derives a 32-byte passphrase auth digest (and an independent 32-byte key for
   software fallback).
2. **TPM 2.0 path (`SEAL_TPM2`):** `identity.dsvc` is the only service holding `grants.tpm-seal = true`
   (`DOS_TAG_TPM_SEAL`, ABI v16). On enrollment, the kernel creates a TPM 2.0 keyed-hash sealed
   data object (`TPM2_Create`) under the owner-hierarchy ECC P-256 Storage Root Key (SRK,
   `0x81000001`, created on demand if absent) bound to the passphrase auth value (`TPM_SEAL`,
   syscall 75). On authentication, `TPM_UNSEAL` (syscall 76) loads the blob under the SRK and
   unseals it inside the TPM; the kernel validates that the returned secret matches the stored
   commitment in constant time.
3. **Software fallback (`SEAL_SOFTWARE`):** When no TPM 2.0 is present (`ERR_NOT_SUPPORTED`),
   `identity.dsvc` seals the 32-byte secret with ChaCha20-Poly1305 keyed from the passphrase-derived
   seal key and bound with AAD containing the identity name and role.
4. **Brute-force protection & memory hygiene:** Consecutive authentication failures trigger
   exponential backoff (1 s, 2 s, 4 s, ... capped at 60 s) tracked per identity. Passphrase and
   intermediate key buffers are wiped (`wipe_bytes`) immediately after verification.

## Unforgeable compositor lock & login screen

Only `awmi.dsvc` holds `identity.session` (`OP_AUTHENTICATE`). Applications cannot authenticate
directly, cannot suppress window decorations (`FLAG_DECORATED` is enforced by the compositor on
`OP_CREATE`), and cannot overlay or capture input while locked:

- **Input isolation & chrome:** When locked, the compositor draws a minimal top bar (`D-OS`,
  colour-coded `TPM 2.0` state badge — green when hardware-sealed, amber when TPM is present but
  unsealed, red when absent — and UTC clock), discards every application key and pointer event,
  suppresses window rendering beneath an opaque backdrop, disables `Super+Esc` / `Ctrl+Alt+Esc`
  escape to the text console, and handles all typing inside its own `LockScreen` state machine.
- **Triggers:**
  - **Manual lock:** `Super+L`, launcher *"Lock screen"*, shell `gui lock`, or `OP_LOCK` (`awmi.admin`).
  - **Idle timeout:** Configurable per-system policy (`idle_timeout_secs`, default 15 min, `0` = off)
    pushed via `OP_SET_LOCK_POLICY` and tracked in `awmi.dsvc`.
  - **Sleep lock:** Before ACPI S3 suspend (`power sleep`), `init` sends `svc::SUSPEND` to `awmi`
    first; when `lock_on_sleep` is enabled (default `true`), the compositor locks the session and
    renders the lock frame before `devmgr` quiesces drivers.
  - **Boot login:** Engaged automatically when an enrolled credential exists or `lock = on` is set
    in `esp:/DOS/BOOT.CFG`.
- **Identity switching:** The lock/login screen lets the user cycle identities (`Tab`) and sign in
  directly; on unlock, `awmi` updates the active identity and `appmgr` applies the newly active
  identity's namespace and permissions to launched apps.

## Capability model (`grants.identity`)

```toml
[grants]
identity = ["query"]    # active identity, identity list, lock policy (Settings, shell, appmgr)
identity = ["admin"]    # create non-root identities, enroll passphrases, switch, lock policy (Settings, shell)
identity = ["session"]  # OP_AUTHENTICATE (awmi.dsvc ONLY)
```

| Op | Endpoint | Meaning |
|---|---|---|
| `OP_ACTIVE` (1100) | query, admin, session | active identity record |
| `OP_LIST` (1101) | query, admin, session | all configured identities |
| `OP_POLICY` (1102) | query, admin, session | idle timeout, `lock_on_sleep`, `lock_at_boot`, TPM presence |
| `OP_AUTHENTICATE` (1103) | session | verify passphrase (TPM unseal or software AEAD), enforce backoff, wipe buffer |
| `OP_ENROLL` (1104) | admin | enroll or rotate passphrase (TPM SRK seal or software fallback) |
| `OP_CREATE` (1105) | admin | create a new Standard or Operator identity (refuses `root` and reserved names) |
| `OP_SET_POLICY` (1106) | admin | update idle timeout and sleep-lock policy |
| `OP_SWITCH` (1107) | admin | switch active identity (refused if target has an enrolled passphrase unless authenticated) |
| `OP_TEST_STATUS` (1108) | query, admin | test-mode counters (auth successes, failures, lock/unlock events) |

## Trade-offs

- **Single active graphical session:** One identity owns the desktop at a time; fast multi-seat
  concurrent graphical sessions are not implemented.
- **No external recovery escrow:** A forgotten TPM-sealed passphrase cannot be recovered offline;
  enrolling a second Operator identity provides local recovery without introducing a `root` account.
- **PBKDF2 iteration count (16,000):** Chosen so QEMU and software-emulated boots remain responsive
  while still imposing meaningful cost on offline guessing; hardware TPM sealing adds rate-limited
  chip-bound verification on top.

## Tests

- `identity-host`: `dosid` unit tests (no-`root` / reserved-name enforcement, PBKDF2-HMAC-SHA256
  RFC 6070 vectors, software AEAD seal/unseal + tamper rejection, exponential backoff schedule,
  fail-closed TOML store round-trip and malformed input rejection, wire codecs).
- `identity-tpm` (QEMU with simulated TPM 2.0): proves ungranted processes cannot call `TPM_SEAL` /
  `TPM_UNSEAL`; refuses `root` creation; enrolls a passphrase sealed under the TPM 2.0 SRK; proves
  non-session clients are denied `OP_AUTHENTICATE`; proves a locked compositor blocks key/pointer
  delivery to apps and rejects wrong passphrases with exponential throttling; unlocks with the valid
  passphrase; verifies idle-timeout lock (`OP_TEST_IDLE_EXPIRE`) and S3 sleep lock (`svc::SUSPEND`);
  verifies per-identity home namespace isolation between two non-root identities.
