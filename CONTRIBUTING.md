# Contributing to D-OS

Thanks for considering a contribution. D-OS is a security-focused operating system, so every change
is held to two standards: it must **matter**, and it must be **proven** to work with the current
code base.

## What makes a good contribution

**Welcome:**
- new hardware support (drivers: USB 3 hubs, mice and storage, network cards, ...);
- features that move the system forward (see the limitations at the end of each doc page);
- bug fixes, with a test that reproduces the bug;
- measurable performance work, with before/after numbers from the same machine;
- security hardening, with a test that proves the protection fires;
- documentation that makes a subsystem easier to understand.

**Not accepted:**
- cosmetic churn: reformatting, renames, or comment edits across files with no functional purpose;
- untested code, or code that only "should work";
- new external dependencies without prior discussion (see [Dependencies](#dependencies));
- changes that weaken a protection or a test to make something pass;
- code you cannot explain line by line, whatever tool helped write it.

**For anything large** (a new subsystem, an ABI change, a design change), open an issue first and
describe the plan. It saves you from building something that cannot be merged.

## Before you start

1. Read [docs/architecture.md](docs/architecture.md), then the doc page for the area you are
   changing.
2. Set up the toolchain and run `.\dbuild.ps1 test` (Windows) or `./dbuild.sh test` (Linux) once on a clean checkout, so you know your
   environment passes before you change anything ([docs/building.md](docs/building.md)).

## Requirements for every pull request

1. **Focused.** One change per pull request. Split unrelated work.
2. **Tested.** New behaviour has a test that fails without your change and passes with it. A
   protection test proves the protection *fires*. Parsers of untrusted input get a fuzzer.
3. **Proof of passing.** Run the **full** suite on your final commit:
   ```sh
   ./dbuild.sh test      # Linux
   .\dbuild.ps1 test     # Windows
   ```
   Paste `build/test-report.md` into the pull request. It must say `TEST PASSED`, `full suite`,
   and a tree of `<commit> (clean)` matching the head of your branch. A partial run (`--case`) is
   fine while working but not as proof.
4. **Clean.** No new compiler warnings; the `static` case (clang analyzer, clippy) passes; the
   build stays reproducible.
5. **Documented.** Update the doc page for the area you touched. Changes to the ABI follow
   [docs/abi.md](docs/abi.md#versioning) (new numbers only, version bump).
6. **Trade-offs stated.** D-OS weighs every change against being *Fast, Secure, Practical*. If
   your change costs one for another, say so in the pull request.
7. **Signed off.** Commit with `git commit -s` (or use `.\dbuild.ps1 commit` / `./dbuild.sh commit`, which prompts for DCO sign-off), certifying the
   [Developer Certificate of Origin](https://developercertificate.org/): you wrote the code or have
   the right to submit it under the project's license.

The pull request template walks through all of this.

## Code style

Match the code around you.

- **C**: freestanding, `-Wall -Wextra -Werror`, explicit-width types, kernel style as in
  `kernel/`. No allocation in interrupt handlers or hot paths. Out of memory is an error, never a
  panic.
- **Rust**: `no_std`; every `unsafe` block carries a `// SAFETY:` comment; clippy clean.
- **NASM**: only where C or Rust cannot do it.
- **Comments** explain *why*, and the rules a reader must not break. Keep them current.
- **Errors** say what happened and what to do next.

## Dependencies

No external crates or libraries: all code is in-tree, `no_std`, with `Cargo.lock` committed. A
dependency must be discussed in an issue first, be compatible with `GPL-3.0-or-later`, be small and auditable, and
must not break reproducible builds.

## Review and merging

The maintainer reviews every pull request, may ask for changes, and may decline changes that do not
fit the project's direction. Once merged, the change is announced in the `#changelog` channel of
the [D-OS Discord](https://discord.gg/discrete).

## Reporting bugs and security issues

- Bugs: open an issue with the steps, the expected and actual result, and the serial log or a photo
  of the screen.
- Security vulnerabilities: **do not open a public issue**. See [SECURITY.md](.github/SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the
[GNU General Public License, version 3 or any later version](LICENSE) (`GPL-3.0-or-later`), the
license of the project.
