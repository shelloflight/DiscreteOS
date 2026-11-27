# Networking

D-OS provides an in-tree, zero-dependency, capability-gated networking stack with IOMMU-confined
user-space NIC drivers and strict TLS 1.3. All NIC drivers run as isolated unprivileged user-space
processes (`.ddrv`) inside per-device IOMMU domains; Ethernet frames and socket payloads flow
through zero-copy shared-memory `IoRing` VMOs (`app` ↔ `net.dsvc` ↔ NIC drivers).

**Code:** `user/lib/net` (`dosnet`: `no_std`, `#![forbid(unsafe_code)]` wire parsers, ARP, IPv4,
ICMP, UDP, DHCPv4, DNS, RFC 9293 TCP, strict TLS 1.3 client, SSH-2 client, root CA bundle loader),
`user/lib/crypto` (`doscrypt`: compiler-barriered constant-time X25519, ChaCha20-Poly1305,
zero-table algebraic AES-128-GCM and AES-256-GCM, HKDF-SHA256/SHA384, RSA-PSS SHA-256/384/512,
ECDSA P-256 & P-384, Ed25519, FIPS 202 SHA-3/SHAKE, FIPS 203 ML-KEM-768, full X.509 v3
chain/SAN/expiry/NameConstraints/revocation verification), `kernel/rust/src/security/csprng.rs`
(Fast-Key-Erasure ChaCha20 kernel CSPRNG, `SYS_GET_RANDOM`), `user/init/certs/roots.pem` (curated
public Root CAs compiled to `sys:/certs/roots.der`), `user/net` (`net.dsvc`),
`user/devmgr/src/{net_drv,virtio_net,e1000e,r8169}.rs`, `user/lib/libd/src/net.rs`,
`user/init/services/net.dman`.
**Tests:** `crypto-host`, `net-host` (including live OpenSSL 3.5+ wire interop), `net-virtio`,
`net-e1000e`, `net-shell`.

## Architecture

| Component | Role |
|---|---|
| `virtio-net.ddrv` | VirtIO 1.0+ network adapter (PCI `1AF4:1041`): modern PCI transport, RX/TX virtqueues with 12-byte `virtio_net_hdr`, link status detection, MSI-X interrupts, IOMMU-confined DMA buffers. |
| `e1000e.ddrv` | Intel Gigabit & 2.5GbE Ethernet (PCI `8086:*` class `02.00`): supports classic `e1000e`/`e1000` (82574L, I217/I218/I219) plus `igb` (I210/I211/I350) and `igc` (I225-V/I226-V 2.5GbE) extended queue registers (`0xC000`/`0xE000`, `SRRCTL`, `RXDCTL`/`TXDCTL` queue enable, `EIMS`/`IVAR`), dynamic link polling, and IOMMU-confined 24-entry TX/RX rings. |
| `r8169.ddrv` | Realtek Gigabit / 2.5GbE / 5GbE Ethernet (PCI `10EC:*` class `02.00`): supports RTL8111/8168/8169 and RTL8125/8125B/8125D/8126/8127 (auto-detected via PCI device ID / `TxConfig` XID), with 8125-specific TX doorbell (`0x90`), 32-bit IMR/ISR (`0x38`/`0x3C`), `RX_FETCH_DFLT_8125`, `MISC.RXDV_GATED_EN` clearing, explicit single-queue reset (`RSS_CTRL_8125` / `Q_NUM_CTRL_8125` cleared so warm reboots from multi-queue OSes steer all unicast frames to RX Queue 0), dynamic link polling, and IOMMU-confined 24-entry TX/RX rings. The MAC address is read as Linux reads it (the factory backup register `0x19E0` on RTL8125 and later, ERI `0xE0` on RTL8168E-VL and later, else `IDR0-5`; a random locally administered one if none is valid) and written back into the receive filter. |
| `net.dsvc` | Owns the `dosnet::NetStack` state machine, runs automatic DHCPv4 configuration when a NIC attaches, manages client TCP/UDP/DNS/ICMP requests over shared `IoRing` channels, and enforces capability boundaries across endpoints. |
| `dosnet` | Pure-Rust `no_std` network stack (`#![forbid(unsafe_code)]`): strict bounds-checked Ethernet II, ARP, IPv4, ICMPv4, UDP, DHCPv4, DNS (with compression-pointer loop and depth protection), RFC 9293 TCP, and strict TLS 1.3. |

## Capability model

Services declare network permissions in their signed `.dman` manifest under `[grants]`:

```toml
[grants]
net = ["client"]                    # DNS lookup, outbound TCP and UDP sockets
net = ["client", "icmp"]            # plus ICMP echo (`ping`)
net = ["client", "icmp", "control"] # plus interface status and configuration
net = ["status"]                    # interface status only (read-only; the desktop's indicator)
```

- **No ambient authority:** a process without `grants.net` receives no network endpoint handles
  from `init` and cannot access the network.
- **Role separation:** `net.dsvc` exposes separate `net.client`, `net.icmp`, `net.control` and
  read-only `net.status` endpoints. Calling `OP_PING` over a `net.client` handle or calling `OP_SET_DNS` over a
  non-control handle is refused with `ERR_ACCESS_DENIED`.

## Client API (`libd::net`)

- `status(ctrl)` — query active link state, DHCP/static mode, MAC address, IPv4 address, netmask,
  gateway, primary/secondary DNS servers, public fallback flag, and packet counters.
- `set_dns(ctrl, ip)` — override the primary DNS resolver address (requires `net.control`).
- `set_config(ctrl, &NetConfig)` — switch between automatic DHCPv4 (with optional custom DNS
  overrides) and manual static IPv4 (`ip`, `netmask`, `gateway`, `dns1`, `dns2`, `dns_fallback`;
  requires `net.control`). Also exposed in the **Settings → Network** panel and the shell `net`
  command.
- `resolve(client, name)` — resolve a hostname via UDP DNS (`A` record). A lookup retries every
  750 ms (and fails over immediately on `SERVFAIL`/`REFUSED`/`NOTIMP`) across the configured
  primary and secondary resolvers and, when public fallback is enabled, 1.1.1.1, 9.9.9.9, and
  8.8.8.8 (trade-off: fallback lookups are visible to the public resolver; toggleable in Settings).
- `ping(icmp, ip, timeout_ms)` — send an ICMP Echo Request and return round-trip time (requires
  `net.icmp`).
- `TcpStream::connect(client, ip, port)` — open a zero-copy `IoRing`-backed TCP connection
  (`read`, `write`, `close`).
- `UdpSocket::bind(client, local_port)` — bind an `IoRing`-backed UDP socket (`send_to`,
  `recv_from`).
- `random_bytes(out)` / `random_bytes_strict(out)` — backed by the kernel Fast-Key-Erasure ChaCha20
  CSPRNG (`SYS_GET_RANDOM`, ABI v14, seeded from `RDSEED`/`RDRAND` + `TPM2_GetRandom`).

## TLS 1.3 and cryptography

`dosnet::tls::TlsClient` implements **strict TLS 1.3 only** (RFC 8446) on top of `doscrypt`:

- **Post-quantum hybrid & classical key exchange:** offers **`X25519MLKEM768`** (`0x11EC`, FIPS
  203 ML-KEM-768 + constant-time X25519) alongside classical **`X25519`** (`0x001D`) in 1 RTT,
  with full RFC 8446 `HelloRetryRequest` (cookie echo + synthetic `message_hash`) support.
- **AEAD cipher suites:** supports all three modern TLS 1.3 suites — **`TLS_AES_256_GCM_SHA384`**
  (`0x1302`), **`TLS_CHACHA20_POLY1305_SHA256`** (`0x1303`), and **`TLS_AES_128_GCM_SHA256`**
  (`0x1301`). AES-GCM uses a zero-table algebraic GF(2^8) S-box and table-free constant-time GHASH
  (immune to cache-timing attacks); all secret masks use compiler optimization barriers (`ct.rs`)
  and buffers are wiped with `write_volatile` on auth failure and `Drop`.
- **Server authentication & root CA store:** verifies `CertificateVerify` (`ecdsa_secp256r1_sha256`,
  `ecdsa_secp384r1_sha384`, `rsa_pss_rsae_sha256`/`sha384`/`sha512`, `ed25519`) and full X.509 v3
  chains (unlimited trust anchors, out-of-order intermediates, RSA ≥ 2048-bit enforcement, validity
  windows against UTC clock, `basicConstraints`/`pathLen`, `keyUsage`, `extendedKeyUsage`, RFC 5280
  `nameConstraints`, optional SHA-256 revocation denylist, unknown critical extension refusal, and
  RFC 6125 SAN matching). A curated bundle of SHA-256+ public Root CAs (`user/init/certs/roots.pem`)
  is compiled into `sys:/certs/roots.der` on the immutable Ed25519-verified `sys` volume.
- **No downgrade:** TLS 1.2 and older handshakes, RFC 8446 §4.1.3 downgrade sentinels, unencrypted
  alerts in encrypted phases, invalid record versions, weak RSA keys (< 2048 bits), and tampered
  transcripts are rejected immediately.

## Shell commands

The shell holds `net = ["client", "icmp", "control"]` and provides:

- `net` (`ip` alias) — display link state, DHCP/static mode, MAC, IPv4 address, gateway, DNS, and
  TX/RX counters. `net check` tests each step to the internet (address, router, ICMP, TCP 443,
  DNS) and reports what does not work. `net dhcp` renews DHCPv4, `net dns <ip|auto> [dns2]`
  sets or resets DNS resolvers, and `net static <ip> <mask> <gw> [dns1] [dns2]` configures a
  manual static IPv4 address.
- `ping <host> [count]` — resolve a hostname or IPv4 address and send ICMP Echo Requests (default
  4 pings), reporting per-reply RTT and packet loss summary. When no reply comes, it tries TCP
  ports 443 and 80 on the host and says whether the host is reachable that way (many networks
  drop ping but carry everything else). An unanswered ping is logged by
  `net.dsvc` with where it failed (`log net`): no ARP reply from the first hop (the gateway, for
  hosts off the subnet), or the echo sent with no reply, with the frame counters. Drivers log
  frames dropped because the network service had no receive buffer posted.
- `tls <host> [port]` — resolve a host, load `/sys/certs/roots.der`, perform a strict TLS 1.3
  handshake using the kernel CSPRNG and UTC clock, and report the negotiated cipher suite and key
  exchange group (e.g. `TLS_AES_256_GCM_SHA384 / X25519MLKEM768`).
- `ssh [user@]host [-p port] [-i key] [-y] [command...]` — connect to an SSH-2 server using
  `dosnet::ssh` (`curve25519-sha256` with strict KEX, `aes256-gcm@openssh.com` /
  `aes128-gcm@openssh.com`, `ssh-ed25519` / `ecdsa-sha2-nistp256` / `rsa-sha2-256` / `rsa-sha2-512`
  host key verification with TOFU `/home/.ssh/known_hosts`, Ed25519 public-key and masked
  password/keyboard-interactive authentication, remote `exec`, and interactive PTY shell with `~.`
  disconnect). `ssh probe <host> [port]` verifies KEX and prints the server banner, cipher, and
  SHA-256 fingerprint; `ssh keygen [path]` generates an Ed25519 keypair in `/home/.ssh/id_ed25519`.

## Tests

- `crypto-host`: RFC 7748 X25519, RFC 8439 ChaCha20-Poly1305, NIST SP 800-38D AES-128/256-GCM,
  RFC 5869 / RFC 8448 HKDF-SHA256 & SHA384, RSA-PSS, NIST P-384 ECDSA, FIPS 202 SHA-3/SHAKE,
  FIPS 203 ML-KEM-768 (exhaustive `Compress_d`, implicit rejection, bad `ek` rejection), X.509 v3
  chain/SAN/expiry/revocation tests, and a 5,000-round X.509 fuzzer.
- `net-host`: Ethernet/ARP/IPv4/ICMP/UDP/TCP/DHCP/DNS unit tests, loopback stack test, TLS 1.3
  PQ hybrid + all-cipher-suite + HRR + negative security tests, curated public Root CA bundle
  verification, live loopback wire interoperability against host OpenSSL 3.5+, 10,000-round packet
  fuzzer, and 5,000-round TLS record fuzzer.
- `net-virtio`, `net-e1000e`: offline QEMU user-net tests under Intel VT-d verifying IOMMU NIC
  bring-up, DHCP lease acquisition, ungranted-process refusal, role separation, DNS lookup, ICMP
  ping, TCP HTTP round-trip, post-quantum `X25519MLKEM768` + `TLS_AES_256_GCM_SHA384` handshake
  backed by the kernel CSPRNG, and bad-SAN TLS 1.3 rejection.
- `net-shell`: QEMU shell test verifying DHCP, `net` status output, `ping 10.0.2.2 2` and
  `net check`.
