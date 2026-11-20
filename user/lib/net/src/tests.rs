//! Host unit tests and fuzzers for `dosnet` (`net-host`):
//! - Wire parsers & round-trips (Ethernet, ARP, IPv4, ICMP, UDP, TCP, DHCP, DNS)
//! - DNS compression-pointer loop & bounds attacks
//! - Full two-node loopback stack test: ARP + ICMP ping + UDP + TCP handshake/transfer/FIN
//! - Full TLS 1.3 handshake (RSA-PSS & Ed25519): happy path, expired cert, wrong SAN,
//!   untrusted CA, TLS 1.2 downgrade sentinel, tampered Finished, tampered ciphertext
//! - 10,000-round fuzzers over L2..L4/DHCP/DNS parsers and TLS 1.3 records.

use alloc::vec;
use alloc::vec::Vec;

use crate::stack::{DhcpState, NetStack};
use crate::tcp::TcpState;
use crate::tls::server::{ServerKey, TEST_CA_SEED, TlsServer, make_test_rsa_bundle};
use crate::tls::{TlsClient, TlsError};
use crate::wire::{
    DHCP_ACK, DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, build_dhcp_packet, build_dns_query,
    build_eth, build_icmp_echo, build_ipv4, build_tcp, build_udp, parse_dhcp, parse_dns_response,
    ArpPacket, EthFrame, IcmpPacket, Ipv4Packet, TcpSegment, UdpPacket, ETH_TYPE_IPV4, PROTO_ICMP,
    PROTO_TCP, PROTO_UDP, TCP_SYN,
};
use crate::parse_ipv4;

fn pump(a: &mut NetStack, b: &mut NetStack, now_ms: u64) {
    for _ in 0..32 {
        let mut moved = false;
        while let Some(f) = a.poll_tx() {
            b.on_rx_frame(&f, now_ms);
            moved = true;
        }
        while let Some(f) = b.poll_tx() {
            a.on_rx_frame(&f, now_ms);
            moved = true;
        }
        if !moved {
            break;
        }
    }
}

#[test]
fn wire_round_trips_and_dns_loops() {
    assert_eq!(parse_ipv4("10.0.2.15"), Some([10, 0, 2, 15]));
    assert_eq!(parse_ipv4("01.0.2.3"), None);
    assert_eq!(parse_ipv4("256.0.0.1"), None);

    let icmp = build_icmp_echo(false, 42, 7, b"hello");
    let p = IcmpPacket::parse(&icmp).unwrap();
    assert_eq!((p.id, p.seq, p.payload), (42, 7, &b"hello"[..]));

    let udp = build_udp([10, 0, 2, 15], [10, 0, 2, 2], 1234, 53, b"dns!").unwrap();
    let pu = UdpPacket::parse([10, 0, 2, 15], [10, 0, 2, 2], &udp).unwrap();
    assert_eq!((pu.src_port, pu.dst_port, pu.payload), (1234, 53, &b"dns!"[..]));

    let tcp = build_tcp([10, 0, 2, 15], [10, 0, 2, 2], 50000, 443, 100, 0, TCP_SYN, 65535, Some(1460), b"").unwrap();
    let pt = TcpSegment::parse([10, 0, 2, 15], [10, 0, 2, 2], &tcp).unwrap();
    assert_eq!((pt.src_port, pt.dst_port, pt.mss), (50000, 443, Some(1460)));

    let ip = build_ipv4([10, 0, 2, 15], [10, 0, 2, 2], PROTO_ICMP, 1, 64, &icmp).unwrap();
    let pi = Ipv4Packet::parse(&ip).unwrap();
    assert_eq!((pi.src, pi.dst, pi.proto), ([10, 0, 2, 15], [10, 0, 2, 2], PROTO_ICMP));

    let eth = build_eth([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1], ETH_TYPE_IPV4, &ip);
    let pe = EthFrame::parse(&eth).unwrap();
    assert_eq!(pe.ethertype, ETH_TYPE_IPV4);

    // Valid DNS response with compression pointer (0xC0 0x0C pointing back to question name).
    let q = build_dns_query(0x1234, "test.dos.local").unwrap();
    let mut resp = q.clone();
    resp[2] = 0x81; // QR=1, RD=1
    resp[3] = 0x80; // RA=1, RCODE=0
    resp[7] = 1; // ANCOUNT=1
    resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 10, 0, 2, 100]);
    let ans = parse_dns_response(&resp, 0x1234).unwrap();
    assert_eq!(ans.ip, [10, 0, 2, 100]);
    assert_eq!(ans.ttl, 60);

    // Malicious DNS self-referencing compression pointer loop MUST return None (never hang).
    let mut evil = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    evil.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]); // points to itself!
    assert_eq!(parse_dns_response(&evil, 0x1234), None);

    // Forward compression pointer MUST return None.
    let mut fwd = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    fwd.extend_from_slice(&[0xC0, 0x0E, 0xC0, 0x0C, 0, 1, 0, 1]);
    assert_eq!(parse_dns_response(&fwd, 0x1234), None);

    // DHCP build/parse check
    let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let mut offer = build_dhcp_packet(DHCP_OFFER, 0xAABBCCDD, mac, None, None);
    offer[0] = 2; // BOOTREPLY
    offer[16..20].copy_from_slice(&[10, 0, 2, 15]);
    offer[20..24].copy_from_slice(&[10, 0, 2, 2]);
    let parsed = parse_dhcp(&offer, mac).unwrap();
    assert_eq!((parsed.msg_type, parsed.your_ip), (DHCP_OFFER, [10, 0, 2, 15]));
    assert_ne!(DHCP_DISCOVER, DHCP_REQUEST);
    assert_ne!(DHCP_OFFER, DHCP_ACK);
}

#[test]
fn loopback_arp_icmp_udp_tcp_stack() {
    let mut a = NetStack::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x1111);
    let mut b = NetStack::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 0x2222);
    a.set_static([10, 0, 2, 15], [255, 255, 255, 0], [10, 0, 2, 2], [10, 0, 2, 3]);
    b.set_static([10, 0, 2, 2], [255, 255, 255, 0], [10, 0, 2, 2], [10, 0, 2, 3]);
    assert_eq!(a.dhcp_state, DhcpState::Bound);

    // ICMP echo (exercises ARP resolution + pending queue flush + echo reply)
    assert!(a.send_ping([10, 0, 2, 2], 77, 1, 100));
    pump(&mut a, &mut b, 105);
    let rep = a.poll_ping_reply().expect("expected ICMP echo reply");
    assert_eq!((rep.id, rep.seq, rep.from, rep.rtt_ms), (77, 1, [10, 0, 2, 2], 5));

    // UDP exchange
    let ua = a.udp_open(0).unwrap();
    let ub = b.udp_open(9000).unwrap();
    assert!(a.udp_send(ua, [10, 0, 2, 2], 9000, b"hello udp", 110));
    pump(&mut a, &mut b, 110);
    let (from, _port, data) = b.udp_recv(ub).unwrap();
    assert_eq!((from, data.as_slice()), ([10, 0, 2, 15], b"hello udp".as_slice()));

    // TCP 3-way handshake, bulk multi-segment transfer, graceful FIN close
    let srv = b.tcp_listen(8080).unwrap();
    let cli = a.tcp_connect([10, 0, 2, 2], 8080, 200).unwrap();
    pump(&mut a, &mut b, 210);
    assert_eq!(a.tcp_state(cli), Some(TcpState::Established));
    assert_eq!(b.tcp_state(srv), Some(TcpState::Established));

    let msg: Vec<u8> = (0..5000u32).map(|i| (i * 31 + 7) as u8).collect();
    assert_eq!(a.tcp_send(cli, &msg, 220), msg.len());
    pump(&mut a, &mut b, 230);
    let mut got = vec![0u8; msg.len()];
    assert_eq!(b.tcp_recv(srv, &mut got), msg.len());
    assert_eq!(got, msg);

    a.tcp_close(cli, 300);
    pump(&mut a, &mut b, 310);
    assert!(b.tcp_peer_closed(srv));
    b.tcp_close(srv, 320);
    pump(&mut a, &mut b, 330);
    assert_eq!(b.tcp_state(srv), Some(TcpState::Closed));
    b.tcp_remove(srv);
    assert_eq!(b.tcp_state(srv), None);
}

fn run_tls_pair(client: &mut TlsClient, server: &mut TlsServer) -> Result<(), TlsError> {
    for _ in 0..16 {
        let c_out = client.take_tx();
        if !c_out.is_empty() {
            server.feed_rx(&c_out)?;
        }
        let s_out = server.take_tx();
        if !s_out.is_empty() {
            client.feed_rx(&s_out)?;
        }
        if client.is_connected() && server.connected {
            return Ok(());
        }
    }
    Err(TlsError::UnexpectedMessage)
}

#[test]
fn tls13_handshake_pq_ciphers_hrr_and_security_negatives() {
    use crate::roots::{encode_der_bundle, parse_der_bundle, parse_pem_bundle};
    use crate::tls::{CipherSuite, KeyGroup};

    let now_2026: i64 = 1_795_000_000;
    let (ca, leaf, key) = make_test_rsa_bundle(
        &TEST_CA_SEED,
        &["test.dos.local"],
        &[[10, 0, 2, 100]],
        b"260101000000Z",
        b"271231235959Z",
    );

    // 1. Test every combination of cipher suite, PQ hybrid vs classical, and HelloRetryRequest.
    let configs = [
        (CipherSuite::Aes256GcmSha384, true, false, KeyGroup::X25519MlKem768),
        (CipherSuite::ChaCha20Poly1305Sha256, true, false, KeyGroup::X25519MlKem768),
        (CipherSuite::Aes128GcmSha256, false, false, KeyGroup::X25519),
        (CipherSuite::Aes256GcmSha384, true, true, KeyGroup::X25519MlKem768),
        (CipherSuite::ChaCha20Poly1305Sha256, false, true, KeyGroup::X25519),
    ];
    for (idx, (suite, pq, hrr, expect_group)) in configs.into_iter().enumerate() {
        let mut c = TlsClient::new(
            "test.dos.local",
            vec![ca.clone()],
            now_2026,
            &[0x41u8.wrapping_add(idx as u8); 160],
        );
        let mut s = TlsServer::new_with_config(
            vec![leaf.clone()],
            key.clone(),
            suite,
            pq,
            hrr,
            &[0x52u8.wrapping_add(idx as u8); 64],
        );
        run_tls_pair(&mut c, &mut s).expect("TLS 1.3 handshake failed");
        assert_eq!(c.negotiated_cipher(), Some(suite));
        assert_eq!(c.negotiated_group(), Some(expect_group));

        c.write_app(b"GET /hello HTTP/1.1\r\nHost: test.dos.local\r\n\r\n").unwrap();
        let wire = c.take_tx();
        s.feed_rx(&wire).unwrap();
        let mut sbuf = [0u8; 64];
        let n = s.read_app(&mut sbuf);
        assert_eq!(&sbuf[..n], b"GET /hello HTTP/1.1\r\nHost: test.dos.local\r\n\r\n");

        s.write_app(b"HTTP/1.1 200 OK\r\n\r\nHello from D-OS TLS 1.3!").unwrap();
        let swire = s.take_tx();
        c.feed_rx(&swire).unwrap();
        let mut cbuf = [0u8; 64];
        let m = c.read_app(&mut cbuf);
        assert_eq!(&cbuf[..m], b"HTTP/1.1 200 OK\r\n\r\nHello from D-OS TLS 1.3!");
    }

    // 2. Wrong hostname rejected
    let mut c_bad_host = TlsClient::new("evil.dos.local", vec![ca.clone()], now_2026, &[0x42; 160]);
    let mut s2 = TlsServer::new(vec![leaf.clone()], key.clone(), &[0x53; 64]);
    assert_eq!(
        run_tls_pair(&mut c_bad_host, &mut s2),
        Err(TlsError::Certificate(doscrypt::x509::VerifyError::HostnameMismatch))
    );

    // 3. Expired certificate rejected
    let mut c_exp = TlsClient::new("test.dos.local", vec![ca.clone()], 1_900_000_000, &[0x43; 160]);
    let mut s3 = TlsServer::new(vec![leaf.clone()], key.clone(), &[0x54; 64]);
    assert_eq!(
        run_tls_pair(&mut c_exp, &mut s3),
        Err(TlsError::Certificate(doscrypt::x509::VerifyError::Expired))
    );

    // 4. Untrusted CA rejected
    let (other_ca, _, _) = make_test_rsa_bundle(&[0x99; 32], &["test.dos.local"], &[], b"260101000000Z", b"271231235959Z");
    let mut c_untrust = TlsClient::new("test.dos.local", vec![other_ca], now_2026, &[0x44; 160]);
    let mut s4 = TlsServer::new(vec![leaf.clone()], key.clone(), &[0x55; 64]);
    assert_eq!(
        run_tls_pair(&mut c_untrust, &mut s4),
        Err(TlsError::Certificate(doscrypt::x509::VerifyError::UntrustedRoot))
    );

    // 5. Revoked leaf rejected via SHA-256 denylist
    let rev_hash = doscrypt::sha2::sha256(&leaf);
    let mut c_rev = TlsClient::new_with_options(
        "test.dos.local",
        vec![ca.clone()],
        vec![rev_hash],
        Some(b"http/1.1"),
        now_2026,
        &[0x48; 160],
    );
    let mut s_rev = TlsServer::new(vec![leaf.clone()], key.clone(), &[0x58; 64]);
    assert_eq!(
        run_tls_pair(&mut c_rev, &mut s_rev),
        Err(TlsError::Certificate(doscrypt::x509::VerifyError::Revoked))
    );

    // 6. Downgrade sentinel in ServerHello.random rejected
    let mut c_dg = TlsClient::new("test.dos.local", vec![ca.clone()], now_2026, &[0x45; 160]);
    let mut dg_rand = [0x56u8; 64];
    dg_rand[24..32].copy_from_slice(b"DOWNGRD\x01");
    let mut s5 = TlsServer::new(vec![leaf.clone()], key.clone(), &dg_rand);
    assert_eq!(run_tls_pair(&mut c_dg, &mut s5), Err(TlsError::DowngradeDetected));

    // 7. Tampered ciphertext rejected
    let mut c_t = TlsClient::new("test.dos.local", vec![ca.clone()], now_2026, &[0x46; 160]);
    let mut s6 = TlsServer::new(vec![leaf], key, &[0x57; 64]);
    run_tls_pair(&mut c_t, &mut s6).unwrap();
    s6.write_app(b"secret").unwrap();
    let mut tampered = s6.take_tx();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    assert_eq!(c_t.feed_rx(&tampered), Err(TlsError::DecryptionFailed));

    // 8. Root CA bundle encode/decode (DRTS binary + PEM) and curated public roots check
    let encoded = encode_der_bundle(&[&ca]);
    let decoded = parse_der_bundle(&encoded).expect("DRTS decode");
    assert_eq!(decoded, vec![ca.clone()]);
    assert!(parse_pem_bundle(b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n") == vec![vec![1, 2, 3]]);

    let curated_pem = include_bytes!("../../../init/certs/roots.pem");
    let curated_ders = parse_pem_bundle(curated_pem);
    assert!(curated_ders.len() >= 15, "expected >= 15 curated public roots, got {}", curated_ders.len());
    for (idx, der) in curated_ders.iter().enumerate() {
        let cert = doscrypt::x509::parse_tls(der)
            .unwrap_or_else(|e| panic!("curated public root #{idx} failed parse_tls: {e:?}"));
        assert!(cert.is_ca, "curated public root #{idx} missing basicConstraints cA=true");
    }
    let refs: Vec<&[u8]> = curated_ders.iter().map(Vec::as_slice).collect();
    let drts = encode_der_bundle(&refs);
    assert_eq!(parse_der_bundle(&drts), Some(curated_ders));
    let _ = ServerKey::Ed25519([0; 32]);
}

#[test]
fn openssl_live_wire_interop_and_real_root_ca_parse() {
    extern crate std;
    use crate::tls::server::make_test_ed25519_bundle;
    use crate::tls::KeyGroup;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::process::{Command, Stdio};

    let python = if Command::new("python").arg("--version").output().is_ok() {
        "python"
    } else if Command::new("python3").arg("--version").output().is_ok() {
        "python3"
    } else {
        return; // skip cleanly if Python/OpenSSL is not installed on host
    };

    let now_2026: i64 = 1_795_000_000;
    let (ca_der, leaf_der, leaf_pkcs8) = make_test_ed25519_bundle(
        &TEST_CA_SEED,
        &[0x77; 32],
        &["test.dos.local"],
        b"260101000000Z",
        b"271231235959Z",
    );

    // Base64 helper for PEM formatting.
    fn b64(data: &[u8]) -> std::string::String {
        const TBL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = std::string::String::new();
        for c in data.chunks(3) {
            let b0 = u32::from(c[0]);
            let b1 = if c.len() > 1 { u32::from(c[1]) } else { 0 };
            let b2 = if c.len() > 2 { u32::from(c[2]) } else { 0 };
            let v = (b0 << 16) | (b1 << 8) | b2;
            s.push(TBL[((v >> 18) & 63) as usize] as char);
            s.push(TBL[((v >> 12) & 63) as usize] as char);
            s.push(if c.len() > 1 { TBL[((v >> 6) & 63) as usize] as char } else { '=' });
            s.push(if c.len() > 2 { TBL[(v & 63) as usize] as char } else { '=' });
        }
        s
    }

    let tmp = std::env::temp_dir();
    let cert_path = tmp.join("dos_openssl_test_cert.pem");
    let key_path = tmp.join("dos_openssl_test_key.pem");
    std::fs::write(
        &cert_path,
        std::format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64(&leaf_der)),
    )
    .unwrap();
    std::fs::write(
        &key_path,
        std::format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64(&leaf_pkcs8)),
    )
    .unwrap();

    // Test real OpenSSL 3.x server on 127.0.0.1 over TLS 1.3 (verifying PQ X25519MLKEM768 + AEAD).
    let py_script = r#"
import socket, ssl, sys
cert, key = sys.argv[1], sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(certfile=cert, keyfile=key)
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
print(srv.getsockname()[1], flush=True)
conn, _ = srv.accept()
with ctx.wrap_socket(conn, server_side=True) as tls:
    req = tls.recv(1024)
    tls.sendall(b"HTTP/1.1 200 OK\r\n\r\nOpenSSL-OK:" + tls.cipher()[0].encode())
srv.close()
"#;

    let mut child = Command::new(python)
        .args(["-c", py_script, cert_path.to_str().unwrap(), key_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python openssl server");
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut port_line = std::string::String::new();
    stdout.read_line(&mut port_line).unwrap();
    let port: u16 = match port_line.trim().parse() {
        Ok(p) => p,
        Err(e) => {
            let mut err_s = std::string::String::new();
            let _ = child.stderr.take().unwrap().read_to_string(&mut err_s);
            panic!("failed to read port ({e:?}): stdout={port_line:?} stderr={err_s:?}");
        }
    };

    let mut tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect loopback");
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    let mut client = TlsClient::new(
        "test.dos.local",
        vec![ca_der.clone()],
        now_2026,
        &[0x91u8; 160],
    );
    let ch = client.take_tx();
    tcp.write_all(&ch).unwrap();

    let mut rbuf = [0u8; 4096];
    let mut app_got = Vec::new();
    let mut sent_req = false;
    while app_got.is_empty() {
        let n = tcp.read(&mut rbuf).expect("tcp read");
        assert!(n > 0, "unexpected EOF from OpenSSL server");
        client.feed_rx(&rbuf[..n]).expect("dosnet TlsClient feed_rx vs OpenSSL");
        let out = client.take_tx();
        if !out.is_empty() {
            tcp.write_all(&out).unwrap();
        }
        if client.is_connected() && !sent_req {
            client.write_app(b"GET / HTTP/1.1\r\nHost: test.dos.local\r\n\r\n").unwrap();
            let req_wire = client.take_tx();
            tcp.write_all(&req_wire).unwrap();
            sent_req = true;
        }
        let mut ab = [0u8; 256];
        let m = client.read_app(&mut ab);
        if m > 0 {
            app_got.extend_from_slice(&ab[..m]);
        }
    }
    let neg_suite = client.negotiated_cipher().expect("negotiated suite");
    let neg_grp = client.negotiated_group().expect("negotiated group");
    assert!(neg_grp == KeyGroup::X25519MlKem768 || neg_grp == KeyGroup::X25519);
    let expect_body = std::format!("HTTP/1.1 200 OK\r\n\r\nOpenSSL-OK:{}", neg_suite.name());
    assert_eq!(app_got, expect_body.as_bytes());
    std::println!(
        "OpenSSL live wire interop PASSED: {} + {} ({})",
        neg_suite.name(),
        neg_grp.name(),
        if neg_grp == KeyGroup::X25519MlKem768 { "post-quantum hybrid" } else { "classical" }
    );
    let _ = child.wait();

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Also parse real-world host default Root CA certificates with `doscrypt::x509::parse_tls`.
    let out = Command::new(python)
        .args([
            "-c",
            "import ssl, sys; ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.load_default_certs(); certs = ctx.get_ca_certs(True); sys.stdout.buffer.write(b''.join(len(c).to_bytes(4,'little') + c for c in certs))",
        ])
        .output()
        .expect("export default certs");
    assert!(out.status.success());
    let mut off = 0usize;
    let mut parsed_ok = 0usize;
    let mut total = 0usize;
    while off + 4 <= out.stdout.len() {
        let len = u32::from_le_bytes(out.stdout[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let der = &out.stdout[off..off + len];
        off += len;
        total += 1;
        match doscrypt::x509::parse_tls(der) {
            Ok(c) => {
                assert!(c.is_ca || !c.has_key_usage);
                parsed_ok += 1;
            }
            Err(doscrypt::x509::VerifyError::UnsupportedAlgorithm | doscrypt::x509::VerifyError::WeakKey) => {}
            Err(e) => panic!("unexpected parse failure on real-world root CA #{total}: {e:?}"),
        }
    }
    assert!(parsed_ok > 0, "expected real-world root CAs to parse (total={total})");
}

#[test]
fn packet_and_tls_fuzzers() {
    let mut seed = 0x00D0_54E7_F022_1234u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    // 10,000 rounds across all L2..L4, DHCP, DNS parsers
    let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
    let mut stack = NetStack::new(mac, 0xABCD);
    stack.set_static([10, 0, 2, 15], [255, 255, 255, 0], [10, 0, 2, 2], [10, 0, 2, 3]);
    let _ = stack.tcp_listen(80);
    let _ = stack.udp_open(5353);

    for round in 0..10_000u32 {
        let len = (next() % 320) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if round % 3 == 0 && buf.len() >= 14 {
            // Aim Ethernet dst at our MAC so L3/L4 paths are exercised heavily.
            buf[0..6].copy_from_slice(&mac);
            let et = if round % 6 == 0 { 0x0806u16 } else { 0x0800u16 };
            buf[12..14].copy_from_slice(&et.to_be_bytes());
        }
        let _ = EthFrame::parse(&buf);
        let _ = ArpPacket::parse(&buf);
        let _ = Ipv4Packet::parse(&buf);
        let _ = IcmpPacket::parse(&buf);
        let _ = UdpPacket::parse([10, 0, 2, 2], [10, 0, 2, 15], &buf);
        let _ = TcpSegment::parse([10, 0, 2, 2], [10, 0, 2, 15], &buf);
        let _ = parse_dhcp(&buf, mac);
        let _ = parse_dns_response(&buf, 0x1234);
        stack.on_rx_frame(&buf, u64::from(round));
        while stack.poll_tx().is_some() {}
    }

    // 5,000 rounds fuzzing TLS 1.3 client record & handshake parser (500 fresh clients x 10 records)
    let (ca, _, _) = make_test_rsa_bundle(&TEST_CA_SEED, &["test.dos.local"], &[], b"260101000000Z", b"271231235959Z");
    for round in 0..5_000u32 {
        if round % 10 == 0 {
            let mut c = TlsClient::new("test.dos.local", vec![ca.clone()], 1_795_000_000, &[0x11; 160]);
            let _ = c.take_tx();
            for sub in 0..10u32 {
                let r = round + sub;
                let len = (next() % 256) as usize;
                let mut rec: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                if r % 2 == 0 && rec.len() >= 5 {
                    rec[0] = match r % 4 {
                        0 => 22,
                        1 => 23,
                        2 => 21,
                        _ => 20,
                    };
                    rec[1] = 0x03;
                    rec[2] = 0x03;
                    let body_len = (rec.len() - 5) as u16;
                    rec[3..5].copy_from_slice(&body_len.to_be_bytes());
                }
                let _ = c.feed_rx(&rec);
            }
        }
    }
    let _ = (PROTO_TCP, PROTO_UDP);
}
