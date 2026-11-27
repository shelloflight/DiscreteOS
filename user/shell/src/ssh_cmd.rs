//! Built-in `ssh` shell command backed by `dosnet::ssh` (RFC 4251..4254, RFC 5647, RFC 8731).
//!
//! Usage:
//! - `ssh [user@]host [-p port] [-i key] [-y] [command...]`
//! - `ssh probe <host> [port]` — verify SSH-2 handshake, host key signature & fingerprint
//! - `ssh keygen [path]` — generate an Ed25519 client keypair (default `/home/.ssh/id_ed25519`)

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dosnet::ssh::{
    self, AuthMethod, Event as SshEvent, HostKeyInfo, SshClient, SshError, State as SshState,
};
use libd::fs::{self as fp};
use libd::proto::key;
use libd::rec::{Record, Value};
use libd::sys;
use libd::term;

use crate::{Shell, normalize, show};

const KEY_HEADER: &str = "DOS-SSH-ED25519-V1:";
const KNOWN_HOSTS_PATH: &str = "/home/.ssh/known_hosts";
const DEFAULT_KEY_PATH: &str = "/home/.ssh/id_ed25519";

type Res = Result<Vec<Record>, String>;

fn text(s: &str) -> Value {
    Value::Text(String::from(s))
}

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

pub fn ssh_cmd(sh: &mut Shell, args: &[String]) -> Res {
    if args.is_empty() {
        return Err(String::from(
            "ssh: usage: ssh [user@]host [-p port] [-i key] [-y] [command...] | ssh probe <host> [port] | ssh keygen [path]",
        ));
    }
    match args[0].as_str() {
        "keygen" => ssh_keygen(sh, args.get(1).map(String::as_str)),
        "probe" => ssh_probe(sh, &args[1..]),
        _ => ssh_connect(sh, args),
    }
}

fn ssh_keygen(sh: &mut Shell, path_arg: Option<&str>) -> Res {
    let mut seed = [0u8; 32];
    libd::net::random_bytes(&mut seed)
        .map_err(|e| format!("ssh keygen: kernel CSPRNG refused: {}", sys::status(e)))?;
    let pub_key = ssh::ed25519_public_from_seed(&seed);
    let auth_line = ssh::format_ed25519_authorized_key(&pub_key, "discreteos");
    let fp_str = ssh::host_key_fingerprint(&ssh::encode_ed25519_pubkey_blob(&pub_key));

    let key_path = path_arg.map(|p| normalize(&sh.place, p)).unwrap_or_else(|| String::from(DEFAULT_KEY_PATH));
    let pub_path = format!("{}.pub", key_path);

    let mut content = String::from(KEY_HEADER);
    for b in &seed {
        content.push_str(&format!("{:02x}", b));
    }
    content.push('\n');
    seed.fill(0);

    ensure_parent_dir(sh, &key_path)?;
    write_file_bytes(sh, "ssh keygen", &key_path, content.as_bytes())?;
    let pub_content = format!("{}\n", auth_line);
    let _ = write_file_bytes(sh, "ssh keygen", &pub_path, pub_content.as_bytes());

    sh.write(&show::ok_line(&format!("generated Ed25519 SSH key at {} ({})", key_path, fp_str)));
    sh.write(&format!("  public key ({}):\n  {}\n", pub_path, auth_line));
    Ok(alloc::vec![
        Record::new()
            .with("key", Value::Text(key_path))
            .with("algorithm", text("ssh-ed25519"))
            .with("fingerprint", Value::Text(fp_str)),
    ])
}

fn ssh_probe(sh: &mut Shell, args: &[String]) -> Res {
    let Some(host) = args.first().map(String::as_str) else {
        return Err(String::from("ssh probe: usage: ssh probe <host> [port]"));
    };
    let port = match args.get(1) {
        Some(s) => s
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| String::from("ssh probe: port must be 1..65535"))?,
        None => 22,
    };
    let (ip, mut stream, mut client, info) = handshake(sh, host, port)?;
    client.disconnect();
    let fin = client.take_tx();
    if !fin.is_empty() {
        let _ = stream.write_all(&fin);
    }
    stream.close();
    let ip_s = fmt_ip(ip);
    sh.write(&show::ok_line(&format!(
        "SSH-2 verified {} ({}:{}): {} / {} / {}",
        host,
        ip_s,
        port,
        info.host_key_alg.name(),
        info.cipher_c2s.name(),
        info.fingerprint
    )));
    libd::println!(
        "ssh: probe ok {}:{} banner={} alg={} cipher={} fp={}",
        ip_s,
        port,
        info.server_banner,
        info.host_key_alg.name(),
        info.cipher_c2s.name(),
        info.fingerprint
    );
    Ok(alloc::vec![
        Record::new()
            .with("host", Value::Text(String::from(host)))
            .with("ip", Value::Text(ip_s))
            .with("port", Value::Int(i64::from(port)))
            .with("banner", Value::Text(info.server_banner))
            .with("host_key", text(info.host_key_alg.name()))
            .with("cipher", text(info.cipher_c2s.name()))
            .with("fingerprint", Value::Text(info.fingerprint)),
    ])
}

fn ssh_connect(sh: &mut Shell, args: &[String]) -> Res {
    let mut port: u16 = 22;
    let mut key_path: Option<String> = None;
    let mut auto_trust = false;
    let mut target: Option<String> = None;
    let mut cmd_parts: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if target.is_none() {
            match a {
                "-p" => {
                    i += 1;
                    let ps = args.get(i).ok_or_else(|| String::from("ssh: -p requires a port number"))?;
                    port = ps
                        .parse::<u16>()
                        .ok()
                        .filter(|&p| p > 0)
                        .ok_or_else(|| format!("ssh: invalid port '{}'", ps))?;
                }
                "-i" => {
                    i += 1;
                    let kp = args.get(i).ok_or_else(|| String::from("ssh: -i requires a key path"))?;
                    key_path = Some(normalize(&sh.place, kp));
                }
                "-y" | "--accept-host-key" => auto_trust = true,
                _ if a.starts_with('-') => {
                    return Err(format!("ssh: unknown option '{}'", a));
                }
                _ => target = Some(String::from(a)),
            }
        } else {
            cmd_parts.push(String::from(a));
        }
        i += 1;
    }

    let Some(target_s) = target else {
        return Err(String::from("ssh: missing [user@]host"));
    };
    let default_user = active_username(sh);
    let (user, host) = match target_s.split_once('@') {
        Some((u, h)) if !u.is_empty() && !h.is_empty() => (String::from(u), String::from(h)),
        None => (default_user, target_s),
        _ => return Err(format!("ssh: invalid target '{}'", target_s)),
    };

    let (_ip, mut stream, mut client, info) = handshake(sh, &host, port)?;

    // Verify / TOFU host key BEFORE sending any credentials.
    verify_known_host(sh, &host, port, &info, auto_trust)?;

    client.accept_host_key().map_err(|e| format!("ssh: {:?}", e))?;
    pump_until(&mut stream, &mut client, |s| s == SshState::AuthReady, 10_000)
        .map_err(|e| format!("ssh: service auth failed: {:?}", e))?;

    // Authentication sequence:
    // 1. Explicit -i key or default /home/.ssh/id_ed25519 (if present)
    // 2. Try `none` (works on passwordless / test servers, otherwise reveals allowed methods cleanly)
    // 3. Prompt masked password (supports both `password` and `keyboard-interactive`)
    let mut authed = false;
    let try_key = key_path.or_else(|| {
        read_file_bytes(sh, DEFAULT_KEY_PATH).ok().map(|_| String::from(DEFAULT_KEY_PATH))
    });
    if let Some(kp) = try_key
        && let Ok(seed) = load_ed25519_key(sh, &kp)
    {
        client.authenticate(&user, AuthMethod::PublicKeyEd25519(seed)).map_err(|e| format!("ssh: {:?}", e))?;
        match pump_until(&mut stream, &mut client, |s| s == SshState::Authenticated, 10_000) {
            Ok(()) => authed = true,
            Err(SshError::AuthFailed(_)) => {}
            Err(e) => {
                stream.close();
                return Err(format!("ssh: authentication error: {:?}", e));
            }
        }
    }

    if !authed {
        client.authenticate(&user, AuthMethod::None).map_err(|e| format!("ssh: {:?}", e))?;
        match pump_until(&mut stream, &mut client, |s| s == SshState::Authenticated, 10_000) {
            Ok(()) => authed = true,
            Err(SshError::AuthFailed(_)) => {}
            Err(e) => {
                stream.close();
                return Err(format!("ssh: authentication error: {:?}", e));
            }
        }
    }

    if !authed {
        for attempt in 0..3 {
            let prompt = format!("{}@{}'s password: ", user, host);
            let Some(mut pw) = sh.read_line_sync(&prompt, true) else {
                client.disconnect();
                let fin = client.take_tx();
                let _ = stream.write_all(&fin);
                stream.close();
                return Err(String::from("ssh: cancelled"));
            };
            let pw_bytes = pw.as_bytes().to_vec();
            // SAFETY: zeroize local String bytes after copying into AuthMethod.
            pw.clear();
            client.authenticate(&user, AuthMethod::Password(pw_bytes)).map_err(|e| format!("ssh: {:?}", e))?;
            match pump_until(&mut stream, &mut client, |s| s == SshState::Authenticated, 15_000) {
                Ok(()) => {
                    authed = true;
                    break;
                }
                Err(SshError::AuthFailed(_)) => {
                    sh.error(&format!("Permission denied (attempt {}/3)", attempt + 1));
                }
                Err(e) => {
                    stream.close();
                    return Err(format!("ssh: authentication error: {:?}", e));
                }
            }
        }
    }
    if !authed {
        client.disconnect();
        let fin = client.take_tx();
        let _ = stream.write_all(&fin);
        stream.close();
        return Err(String::from("ssh: authentication failed"));
    }

    // Drain any auth banners.
    while let Some(ev) = client.pop_event() {
        if let SshEvent::Banner(b) = ev {
            sh.write(&b);
        }
    }

    // Open session channel.
    client.open_session().map_err(|e| format!("ssh: {:?}", e))?;
    pump_until(&mut stream, &mut client, |s| s == SshState::ChannelReady, 10_000)
        .map_err(|e| format!("ssh: open session failed: {:?}", e))?;

    let mut vt = VtFilter::new();
    let mut exit_status: Option<u32> = None;

    if !cmd_parts.is_empty() {
        // Non-interactive remote exec.
        let remote_cmd = cmd_parts.join(" ");
        client.request_exec(&remote_cmd).map_err(|e| format!("ssh: {:?}", e))?;
        pump_until(
            &mut stream,
            &mut client,
            |s| s == SshState::Active || s == SshState::Closed,
            10_000,
        )
        .map_err(|e| format!("ssh: exec failed: {:?}", e))?;

        let mut rx_buf = [0u8; 4096];
        let dl = sys::clock_ns() + 30_000_000_000;
        loop {
            flush_tx(&mut stream, &mut client)?;
            let mut got_eof = false;
            while let Some(ev) = client.pop_event() {
                match ev {
                    SshEvent::Stdout(b) => {
                        let s = vt.push(&b);
                        if !s.is_empty() {
                            sh.write(&s);
                        }
                    }
                    SshEvent::Stderr(b) => {
                        let s = vt.push(&b);
                        if !s.is_empty() {
                            sh.write(&show::coloured(term::LIGHT_RED, &s));
                        }
                    }
                    SshEvent::ExitStatus(c) => exit_status = Some(c),
                    SshEvent::Eof | SshEvent::Closed => got_eof = true,
                    SshEvent::Banner(b) => sh.write(&b),
                }
            }
            if client.state() == SshState::Closed || got_eof {
                break;
            }
            if sys::clock_ns() >= dl {
                break;
            }
            match stream.read(&mut rx_buf, 200) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = client.feed_rx(&rx_buf[..n]) {
                        stream.close();
                        return Err(format!("ssh: {:?}", e));
                    }
                }
                Err(sys::ERR_TIMED_OUT) => continue,
                Err(_) => break,
            }
        }
        client.disconnect();
        let fin = client.take_tx();
        if !fin.is_empty() {
            let _ = stream.write_all(&fin);
        }
        stream.close();
        if let Some(code) = exit_status {
            libd::println!("ssh: exec on {} exited with status {}", host, code);
            if code != 0 {
                return Err(format!("ssh: remote command exited with status {}", code));
            }
        }
        Ok(Vec::new())
    } else {
        // Interactive PTY shell session (full VT100/ANSI emulation in terminal RAW_MODE).
        let mut cur_cols = sh.cols.clamp(20, 400) as u32;
        let mut cur_rows = sh.rows.clamp(5, 200) as u32;
        client.request_shell(cur_cols, cur_rows).map_err(|e| format!("ssh: {:?}", e))?;
        pump_until(
            &mut stream,
            &mut client,
            |s| s == SshState::Active || s == SshState::Closed,
            10_000,
        )
        .map_err(|e| format!("ssh: shell request failed: {:?}", e))?;

        sh.set_raw_mode(true);
        sh.write_raw(
            format!(
                "\x1b[90mConnected to {}@{}:{} (type '~.' after Enter to disconnect)\x1b[0m\r\n",
                user, host, port
            )
            .as_bytes(),
        );

        let mut rx_buf = [0u8; 4096];
        let mut after_newline = true;
        let mut saw_tilde = false;
        let mut disconnected_by_user = false;

        'interactive: loop {
            flush_tx(&mut stream, &mut client)?;
            while let Some(ev) = client.pop_event() {
                match ev {
                    SshEvent::Stdout(b) | SshEvent::Stderr(b) => {
                        sh.write_raw(&b);
                    }
                    SshEvent::ExitStatus(c) => exit_status = Some(c),
                    SshEvent::Eof | SshEvent::Closed => break 'interactive,
                    SshEvent::Banner(b) => sh.write_raw(b.as_bytes()),
                }
            }
            if client.state() == SshState::Closed {
                break;
            }

            // Drain any pending raw keys (and detect terminal grid resizes -> SIGWINCH).
            while let Some(k) = sh.poll_raw_key() {
                let base = k & key::MASK;
                if saw_tilde {
                    saw_tilde = false;
                    if base == u32::from(b'.') {
                        disconnected_by_user = true;
                        break 'interactive;
                    }
                    if base == u32::from(b'~') {
                        let _ = client.send_data(b"~");
                        after_newline = false;
                        continue;
                    }
                    let _ = client.send_data(b"~");
                }
                if after_newline && base == u32::from(b'~') && (k & (key::CTRL | key::ALT)) == 0 {
                    saw_tilde = true;
                    continue;
                }
                let bytes = encode_terminal_key(k);
                if !bytes.is_empty() {
                    after_newline = bytes == b"\r" || bytes == b"\n";
                    let _ = client.send_data(&bytes);
                    flush_tx(&mut stream, &mut client)?;
                }
            }

            let nc = sh.cols.clamp(20, 400) as u32;
            let nr = sh.rows.clamp(5, 200) as u32;
            if nc != cur_cols || nr != cur_rows {
                cur_cols = nc;
                cur_rows = nr;
                client.send_window_change(cur_cols, cur_rows);
                flush_tx(&mut stream, &mut client)?;
            }

            // Poll TCP socket briefly (10 ms keeps typing responsive while yielding CPU).
            match stream.read(&mut rx_buf, 10) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = client.feed_rx(&rx_buf[..n]) {
                        sh.set_raw_mode(false);
                        stream.close();
                        return Err(format!("ssh: {:?}", e));
                    }
                }
                Err(sys::ERR_TIMED_OUT) => {}
                Err(_) => break,
            }
        }

        sh.set_raw_mode(false);
        client.disconnect();
        let fin = client.take_tx();
        if !fin.is_empty() {
            let _ = stream.write_all(&fin);
        }
        stream.close();
        if disconnected_by_user {
            sh.write(&format!("\n{}", show::ok_line(&format!("Connection to {} closed.", host))));
        } else {
            let suffix = exit_status.map_or(String::new(), |c| format!(" (exit {})", c));
            sh.write(&format!("\n{}", show::ok_line(&format!("SSH session to {} ended{}", host, suffix))));
        }
        Ok(Vec::new())
    }
}

fn handshake(
    sh: &Shell,
    host: &str,
    port: u16,
) -> Result<([u8; 4], libd::net::TcpStream, SshClient, HostKeyInfo), String> {
    if sh.net_client == 0 {
        return Err(String::from("ssh: no network client capability granted to this session"));
    }
    let ip = libd::net::resolve(sh.net_client, host)
        .map_err(|e| format!("ssh: cannot resolve '{}': {}", host, sys::status(e)))?;
    let ip_s = fmt_ip(ip);
    let mut stream = libd::net::TcpStream::connect(sh.net_client, ip, port, 10_000)
        .map_err(|e| format!("ssh: connect {}:{} failed: {}", ip_s, port, sys::status(e)))?;

    let mut rand64 = [0u8; 64];
    libd::net::random_bytes(&mut rand64)
        .map_err(|e| format!("ssh: kernel CSPRNG refused: {}", sys::status(e)))?;

    let mut client = SshClient::new(&rand64);
    rand64.fill(0);

    if let Err(e) = pump_until(&mut stream, &mut client, |s| s == SshState::VerifyHostKey, 15_000) {
        stream.close();
        return Err(format!("ssh: handshake failed: {:?}", e));
    }
    let info = client
        .host_key_info()
        .cloned()
        .ok_or_else(|| String::from("ssh: missing host key info"))?;
    Ok((ip, stream, client, info))
}

fn flush_tx(stream: &mut libd::net::TcpStream, client: &mut SshClient) -> Result<(), String> {
    let out = client.take_tx();
    if !out.is_empty() {
        stream
            .write_all(&out)
            .map_err(|e| format!("ssh: write failed: {}", sys::status(e)))?;
    }
    Ok(())
}

fn pump_until<F>(
    stream: &mut libd::net::TcpStream,
    client: &mut SshClient,
    done: F,
    timeout_ms: u64,
) -> Result<(), SshError>
where
    F: Fn(SshState) -> bool,
{
    let dl = sys::clock_ns() + timeout_ms * 1_000_000;
    let mut buf = [0u8; 4096];
    loop {
        let out = client.take_tx();
        if !out.is_empty()
            && stream.write_all(&out).is_err()
        {
            return Err(SshError::Disconnected(0, String::from("write failed")));
        }
        if done(client.state()) {
            return Ok(());
        }
        if client.state() == SshState::Closed {
            return Err(SshError::Disconnected(0, String::from("connection closed")));
        }
        if sys::clock_ns() >= dl {
            return Err(SshError::Disconnected(0, format!("timed out in {:?}", client.state())));
        }
        match stream.read(&mut buf, 2_000) {
            Ok(0) => return Err(SshError::Disconnected(0, String::from("peer closed connection"))),
            Ok(n) => client.feed_rx(&buf[..n])?,
            Err(sys::ERR_TIMED_OUT) => continue,
            Err(_) => return Err(SshError::Disconnected(0, String::from("read failed"))),
        }
    }
}

fn active_username(sh: &Shell) -> String {
    let ep = if sh.identity_query != 0 { sh.identity_query } else { sh.identity_admin };
    if ep != 0
        && let Ok(a) = libd::identity::active(ep)
    {
        return String::from(a.name_str());
    }
    String::from("user")
}

fn verify_known_host(
    sh: &mut Shell,
    host: &str,
    port: u16,
    info: &HostKeyInfo,
    auto_trust: bool,
) -> Result<(), String> {
    let host_key_id = format!("{}:{}", host, port);
    let existing = read_file_bytes(sh, KNOWN_HOSTS_PATH).unwrap_or_default();
    let existing_str = String::from_utf8_lossy(&existing);

    for line in existing_str.lines() {
        let mut parts = line.split_whitespace();
        let (Some(h), Some(_alg), Some(fp)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if h == host_key_id {
            if fp == info.fingerprint {
                return Ok(());
            }
            return Err(format!(
                "ssh: REMOTE HOST IDENTIFICATION HAS CHANGED for {}! Expected {}, got {} — connection refused",
                host_key_id, fp, info.fingerprint
            ));
        }
    }

    if !auto_trust {
        sh.write(&format!(
            "The authenticity of host '{}' cannot be established.\n  {} key fingerprint is {}.\n",
            host_key_id,
            info.host_key_alg.name(),
            info.fingerprint
        ));
        let Some(ans) = sh.read_line_sync("Trust this host key and continue? [yes/no]: ", false) else {
            return Err(String::from("ssh: host key verification cancelled"));
        };
        if !matches!(ans.trim(), "yes" | "y" | "YES" | "Y") {
            return Err(String::from("ssh: host key verification failed"));
        }
    }

    // Best-effort persist to /home/.ssh/known_hosts (works whenever /home is writable).
    if ensure_parent_dir(sh, KNOWN_HOSTS_PATH).is_ok() {
        let mut updated = existing_str.into_owned();
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(&format!(
            "{} {} {}\n",
            host_key_id,
            info.host_key_alg.name(),
            info.fingerprint
        ));
        let _ = write_file_bytes(sh, "ssh", KNOWN_HOSTS_PATH, updated.as_bytes());
    }
    Ok(())
}

fn ensure_parent_dir(sh: &Shell, abs_path: &str) -> Result<(), String> {
    let Some((parent, _)) = abs_path.rsplit_once('/') else {
        return Ok(());
    };
    if parent.is_empty() || parent == "/" || parent == "/home" {
        return Ok(());
    }
    let _ = sh.open("ssh", parent, fp::O_DIRECTORY | fp::O_CREATE, fp::R_READ | fp::R_WRITE)?;
    Ok(())
}

fn read_file_bytes(sh: &Shell, abs_path: &str) -> Result<Vec<u8>, String> {
    let (node, kind) = sh.open("ssh", abs_path, 0, fp::R_READ)?;
    if kind != fp::KIND_FILE {
        return Err(format!("ssh: {} is not a file", abs_path));
    }
    let size = node.stat().map_err(|e| format!("ssh: stat {}: {}", abs_path, fp::message(e)))?.size as usize;
    if size > 64 * 1024 {
        return Err(format!("ssh: {} is too large", abs_path));
    }
    let mut buf = alloc::vec![0u8; size];
    let n = node.read(0, &mut buf).map_err(|e| format!("ssh: read {}: {}", abs_path, fp::message(e)))?;
    buf.truncate(n);
    Ok(buf)
}

fn write_file_bytes(sh: &Shell, what: &str, abs_path: &str, data: &[u8]) -> Result<(), String> {
    let (node, _) = sh.open(what, abs_path, fp::O_CREATE | fp::O_TRUNCATE, fp::R_READ | fp::R_WRITE)?;
    node.write(0, data).map_err(|e| format!("{}: write {}: {}", what, abs_path, fp::message(e)))?;
    let _ = node.sync();
    Ok(())
}

fn load_ed25519_key(sh: &Shell, path: &str) -> Result<[u8; 32], String> {
    let raw = read_file_bytes(sh, path)?;
    let s = core::str::from_utf8(&raw).map_err(|_| String::from("ssh: invalid key encoding"))?;
    let hex = s
        .trim()
        .strip_prefix(KEY_HEADER)
        .ok_or_else(|| String::from("ssh: unsupported key format (generate with 'ssh keygen')"))?;
    if hex.len() != 64 {
        return Err(String::from("ssh: malformed Ed25519 key length"));
    }
    let mut seed = [0u8; 32];
    for (i, slot) in seed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| String::from("ssh: invalid hex in Ed25519 key"))?;
    }
    Ok(seed)
}

fn encode_terminal_key(k: u32) -> Vec<u8> {
    let base = k & key::MASK;
    let ctrl = (k & key::CTRL) != 0;
    let alt = (k & key::ALT) != 0;
    let shift = (k & key::SHIFT) != 0;
    let mut seq = match base {
        key::UP => if ctrl { b"\x1b[1;5A".to_vec() } else { b"\x1b[A".to_vec() },
        key::DOWN => if ctrl { b"\x1b[1;5B".to_vec() } else { b"\x1b[B".to_vec() },
        key::RIGHT => if ctrl { b"\x1b[1;5C".to_vec() } else { b"\x1b[C".to_vec() },
        key::LEFT => if ctrl { b"\x1b[1;5D".to_vec() } else { b"\x1b[D".to_vec() },
        key::HOME => b"\x1b[H".to_vec(),
        key::END => b"\x1b[F".to_vec(),
        key::INSERT => b"\x1b[2~".to_vec(),
        key::DELETE => b"\x1b[3~".to_vec(),
        key::PAGE_UP => b"\x1b[5~".to_vec(),
        key::PAGE_DOWN => b"\x1b[6~".to_vec(),
        key::F1 => b"\x1bOP".to_vec(),
        key::F2 => b"\x1bOQ".to_vec(),
        key::F3 => b"\x1bOR".to_vec(),
        key::F4 => b"\x1bOS".to_vec(),
        key::F5 => b"\x1b[15~".to_vec(),
        key::F6 => b"\x1b[17~".to_vec(),
        key::F7 => b"\x1b[18~".to_vec(),
        key::F8 => b"\x1b[19~".to_vec(),
        key::F9 => b"\x1b[20~".to_vec(),
        key::F10 => b"\x1b[21~".to_vec(),
        key::F11 => b"\x1b[23~".to_vec(),
        key::F12 => b"\x1b[24~".to_vec(),
        0x09 if shift => b"\x1b[Z".to_vec(),
        0x08 => alloc::vec![0x7F],
        0x0A | 0x0D => alloc::vec![b'\r'],
        0x01..=0x1F => alloc::vec![base as u8],
        0x20..=0x7E => alloc::vec![base as u8],
        0xA0..=0xFF => {
            if let Some(ch) = char::from_u32(base) {
                let mut tmp = [0u8; 4];
                ch.encode_utf8(&mut tmp).as_bytes().to_vec()
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    };
    if alt && seq.len() == 1 {
        seq.insert(0, 0x1B);
    }
    seq
}

/// Lightweight VT100/ANSI stream filter (with proper streaming UTF-8 decoding) for non-interactive
/// `ssh host <cmd>` (`exec`) output: translates SGR colors into D-OS terminal style bytes and
/// strips control sequences cleanly.
struct VtFilter {
    state: u8, // 0=normal, 1=ESC, 2=CSI, 3=OSC
    csi: Vec<u8>,
    utf8_buf: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
}

impl VtFilter {
    fn new() -> Self {
        Self { state: 0, csi: Vec::new(), utf8_buf: [0; 4], utf8_len: 0, utf8_need: 0 }
    }

    fn push(&mut self, bytes: &[u8]) -> String {
        let mut out = String::new();
        for &b in bytes {
            match self.state {
                0 => match b {
                    0x1B => {
                        self.utf8_len = 0;
                        self.utf8_need = 0;
                        self.state = 1;
                    }
                    b'\r' => {} // D-OS terminal uses \n
                    b'\n' | b'\t' => out.push(b as char),
                    0x20..=0x7E => {
                        self.utf8_len = 0;
                        self.utf8_need = 0;
                        out.push(b as char);
                    }
                    0x80..=0xFF => {
                        if (b & 0xC0) == 0x80 {
                            if self.utf8_need > 0 && self.utf8_len < self.utf8_need {
                                self.utf8_buf[self.utf8_len] = b;
                                self.utf8_len += 1;
                                if self.utf8_len == self.utf8_need {
                                    if let Ok(s) = core::str::from_utf8(&self.utf8_buf[..self.utf8_len]) {
                                        out.push_str(s);
                                    }
                                    self.utf8_len = 0;
                                    self.utf8_need = 0;
                                }
                            } else {
                                self.utf8_len = 0;
                                self.utf8_need = 0;
                            }
                        } else {
                            let need = if (b & 0xE0) == 0xC0 {
                                2
                            } else if (b & 0xF0) == 0xE0 {
                                3
                            } else if (b & 0xF8) == 0xF0 {
                                4
                            } else {
                                0
                            };
                            if need > 0 {
                                self.utf8_buf[0] = b;
                                self.utf8_len = 1;
                                self.utf8_need = need;
                            }
                        }
                    }
                    _ => {}
                },
                1 => match b {
                    b'[' => {
                        self.csi.clear();
                        self.state = 2;
                    }
                    b']' => self.state = 3,
                    _ => self.state = 0,
                },
                2 => {
                    if (0x40..=0x7E).contains(&b) {
                        if b == b'm' {
                            self.apply_sgr(&mut out);
                        }
                        self.csi.clear();
                        self.state = 0;
                    } else if self.csi.len() < 64 {
                        self.csi.push(b);
                    }
                }
                3 => {
                    if b == 0x07 || b == 0x1B {
                        self.state = 0;
                    }
                }
                _ => self.state = 0,
            }
        }
        out
    }

    fn apply_sgr(&self, out: &mut String) {
        let s = core::str::from_utf8(&self.csi).unwrap_or("");
        if s.is_empty() || s == "0" {
            out.push_str(&show::plain());
            return;
        }
        for part in s.split(';') {
            let fg = match part {
                "0" => {
                    out.push_str(&show::plain());
                    continue;
                }
                "30" => Some(term::DARK_GREY),
                "31" => Some(term::RED),
                "32" => Some(term::GREEN),
                "33" => Some(term::YELLOW),
                "34" => Some(term::BLUE),
                "35" => Some(term::MAGENTA),
                "36" => Some(term::CYAN),
                "37" => Some(term::GREY),
                "90" => Some(term::DARK_GREY),
                "91" => Some(term::LIGHT_RED),
                "92" => Some(term::LIGHT_GREEN),
                "93" => Some(term::YELLOW),
                "94" => Some(term::LIGHT_BLUE),
                "95" => Some(term::LIGHT_MAGENTA),
                "96" => Some(term::LIGHT_CYAN),
                "97" => Some(term::WHITE),
                _ => None,
            };
            if let Some(c) = fg {
                out.push_str(&show::style(c));
            }
        }
    }
}
