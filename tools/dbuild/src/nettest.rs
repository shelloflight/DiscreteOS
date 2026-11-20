//! Offline local host test servers for QEMU `-netdev user` tests:
//! - UDP DNS server answering `test.dos.local` -> `10.0.2.100`
//! - TCP HTTP server on `10.0.2.100:80`
//! - Valid TLS 1.3 server on `10.0.2.100:443` (RSA-PSS, SAN `test.dos.local`)
//! - Bad-cert TLS 1.3 server on `10.0.2.100:444` (SAN `wrong.dos.local`)

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dosnet::tls::server::{ServerKey, TEST_CA_SEED, TlsServer, make_test_rsa_bundle};

pub struct NetTestServer {
    pub dns_port: u16,
    pub tcp_port: u16,
    pub tls_port: u16,
    pub bad_tls_port: u16,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl NetTestServer {
    pub fn start() -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        // 1. UDP DNS responder
        let dns_sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind dns: {e}"))?;
        let dns_port = dns_sock.local_addr().map_err(|e| e.to_string())?.port();
        let _ = dns_sock.set_read_timeout(Some(Duration::from_millis(100)));
        let stop_dns = Arc::clone(&stop);
        threads.push(thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !stop_dns.load(Ordering::Relaxed) {
                let Ok((n, peer)) = dns_sock.recv_from(&mut buf) else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                // Build standard A response pointing to 10.0.2.100.
                let mut resp = buf[..n].to_vec();
                resp[2] = 0x81; // QR=1, RD=1
                resp[3] = 0x80; // RA=1, NOERROR
                resp[6] = 0;
                resp[7] = 1; // ANCOUNT=1
                resp[8..12].fill(0);
                // Pointer to question name at offset 12 (0xC00C), TYPE=A, CLASS=IN, TTL=60, RDATA=10.0.2.100
                resp.extend_from_slice(&[
                    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 10, 0,
                    2, 100,
                ]);
                let _ = dns_sock.send_to(&resp, peer);
            }
        }));

        // 2. Plain TCP HTTP responder
        let tcp_l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind tcp: {e}"))?;
        let tcp_port = tcp_l.local_addr().map_err(|e| e.to_string())?.port();
        let _ = tcp_l.set_nonblocking(true);
        let stop_tcp = Arc::clone(&stop);
        threads.push(thread::spawn(move || {
            while !stop_tcp.load(Ordering::Relaxed) {
                let Ok((mut s, _)) = tcp_l.accept() else {
                    thread::sleep(Duration::from_millis(20));
                    continue;
                };
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                let mut req = [0u8; 512];
                let _ = s.read(&mut req);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\nHello from D-OS TCP test!");
                let _ = s.flush();
            }
        }));

        // 3. Valid TLS 1.3 server (SAN: test.dos.local)
        let (_ca, good_leaf, good_key) = make_test_rsa_bundle(
            &TEST_CA_SEED,
            &["test.dos.local"],
            &[[10, 0, 2, 100]],
            b"250101000000Z",
            b"350101000000Z",
        );
        let (tls_port, th_good) = spawn_tls_server(good_leaf, good_key, Arc::clone(&stop))?;
        threads.push(th_good);

        // 4. Bad-SAN TLS 1.3 server (SAN: wrong.dos.local)
        let (_ca2, bad_leaf, bad_key) = make_test_rsa_bundle(
            &TEST_CA_SEED,
            &["wrong.dos.local"],
            &[],
            b"250101000000Z",
            b"350101000000Z",
        );
        let (bad_tls_port, th_bad) = spawn_tls_server(bad_leaf, bad_key, Arc::clone(&stop))?;
        threads.push(th_bad);

        Ok(Self {
            dns_port,
            tcp_port,
            tls_port,
            bad_tls_port,
            stop,
            threads,
        })
    }

    pub fn netdev_arg(&self) -> String {
        format!(
            "user,id=net0,bootfile=dns:{},guestfwd=tcp:10.0.2.100:80-tcp:127.0.0.1:{},guestfwd=tcp:10.0.2.100:443-tcp:127.0.0.1:{},guestfwd=tcp:10.0.2.100:444-tcp:127.0.0.1:{}",
            self.dns_port, self.tcp_port, self.tls_port, self.bad_tls_port
        )
    }
}

impl Drop for NetTestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.threads.drain(..) {
            let _ = h.join();
        }
    }
}

fn spawn_tls_server(
    leaf_der: Vec<u8>,
    key: ServerKey,
    stop: Arc<AtomicBool>,
) -> Result<(u16, JoinHandle<()>), String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind tls: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let _ = l.set_nonblocking(true);
    let handle = thread::spawn(move || {
        let mut ctr = 1u8;
        while !stop.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = l.accept() else {
                thread::sleep(Duration::from_millis(20));
                continue;
            };
            let _ = s.set_nonblocking(false);
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let rand64 = [ctr.wrapping_mul(37).wrapping_add(11); 64];
            ctr = ctr.wrapping_add(1);
            let mut srv = TlsServer::new(vec![leaf_der.clone()], key.clone(), &rand64);
            let mut buf = [0u8; 4096];
            let mut replied = false;
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if srv.feed_rx(&buf[..n]).is_err() {
                    break;
                }
                let out = srv.take_tx();
                if !out.is_empty() && s.write_all(&out).is_err() {
                    break;
                }
                if srv.connected && !replied {
                    let mut app = [0u8; 512];
                    let m = srv.read_app(&mut app);
                    if m > 0 {
                        let _ = srv.write_app(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\nHello from D-OS TLS 1.3!",
                        );
                        let resp = srv.take_tx();
                        let _ = s.write_all(&resp);
                        let _ = s.flush();
                        replied = true;
                    }
                }
                if srv.closed {
                    break;
                }
            }
        }
    });
    Ok((port, handle))
}
