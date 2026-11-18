# Security policy

Security is a core goal of D-OS, and reports are taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub's
[private vulnerability reporting](https://github.com/shelloflight/DiscreteOS/security/advisories/new)
(the *Security* tab → *Report a vulnerability*).

Include:
- the affected component and version (`D-KRNL x.y.z` from the boot log, or the commit);
- what an attacker can do, and from where (ring 3 program, disk contents, device, network, ...);
- steps or a test program that reproduce it.

You will get an answer as soon as the maintainer can review it. Please allow time for a fix before
disclosing publicly.

## Scope

In scope: the loaders, the kernel, user-space drivers and services, D-CMPL, the build's signing and
reproducibility, and the host tools that parse untrusted data.

D-OS is in early development and is not yet meant for production use. Known limitations are
listed at the end of each page in `docs/` and are not vulnerabilities on their own.
