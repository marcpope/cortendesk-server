// Modified by the CortenDesk Server project on 2026-11-03: client address from
// trusted proxies (`client_ip`). See
// CHANGES.md. This file is part of a modified version of rustdesk-server,
// distributed under the AGPL-3.0 like the original.

use clap::App;
use hbb_common::{
    anyhow::{Context, Result}, log, ResultType
};
use ini::Ini;
use sodiumoxide::crypto::sign;
use std::{
    io::prelude::*,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Instant, SystemTime},
};

pub fn parse_bind_address(value: &str) -> Result<Option<IpAddr>> {
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        value
            .parse()
            .with_context(|| format!("Invalid bind address: {value}"))
            .map(Some)
    }
}

pub async fn listen_tcp(
    bind_addr: Option<IpAddr>,
    port: u16,
) -> ResultType<hbb_common::tokio::net::TcpListener> {
    if let Some(bind_addr) = bind_addr {
        hbb_common::tcp::new_listener(SocketAddr::new(bind_addr, port), true).await
    } else {
        hbb_common::tcp::listen_any(port).await
    }
}

pub fn console_addr(bind_addr: Option<IpAddr>, port: u16) -> Option<SocketAddr> {
    let bind_addr = bind_addr?;
    if bind_addr.is_unspecified() || bind_addr == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
}

// The runtime console (check_cmd) is reached via 127.0.0.1, so when the bind
// address does not already accept connections to 127.0.0.1 (it is neither the
// any-address nor 127.0.0.1 itself), the console gets a dedicated listener
// there; it is never bound to the external bind address.
pub async fn listen_console(
    bind_addr: Option<IpAddr>,
    port: u16,
) -> ResultType<Option<hbb_common::tokio::net::TcpListener>> {
    match console_addr(bind_addr, port) {
        Some(addr) => {
            let listener = hbb_common::tcp::new_listener(addr, true).await?;
            log::info!("Listening on tcp {} for the console", addr);
            Ok(Some(listener))
        }
        None => Ok(None),
    }
}

pub async fn accept_or_pending(
    listener: Option<&hbb_common::tokio::net::TcpListener>,
) -> std::io::Result<(hbb_common::tokio::net::TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

#[allow(dead_code)]
pub(crate) fn get_expired_time() -> Instant {
    let now = Instant::now();
    now.checked_sub(std::time::Duration::from_secs(3600))
        .unwrap_or(now)
}

#[allow(dead_code)]
pub(crate) fn test_if_valid_server(host: &str, name: &str) -> ResultType<SocketAddr> {
    use std::net::ToSocketAddrs;
    let res = if host.contains(':') {
        host.to_socket_addrs()?.next().context("")
    } else {
        format!("{}:{}", host, 0)
            .to_socket_addrs()?
            .next()
            .context("")
    };
    if res.is_err() {
        log::error!("Invalid {} {}: {:?}", name, host, res);
    }
    res
}

#[allow(dead_code)]
pub(crate) fn get_servers(s: &str, tag: &str) -> Vec<String> {
    let servers: Vec<String> = s
        .split(',')
        .filter(|x| !x.is_empty() && test_if_valid_server(x, tag).is_ok())
        .map(|x| x.to_owned())
        .collect();
    log::info!("{}={:?}", tag, servers);
    servers
}

#[allow(dead_code)]
#[inline]
fn arg_name(name: &str) -> String {
    name.to_uppercase().replace('_', "-")
}

#[allow(dead_code)]
#[inline]
pub fn set_arg(name: &str, value: &str) {
    std::env::set_var(arg_name(name), value);
}

#[allow(dead_code)]
pub fn init_args(args: &str, name: &str, about: &str) {
    let matches = App::new(name)
        .version(crate::version::VERSION)
        .author("CortenDesk — a fork of rustdesk-server <https://github.com/marcpope/cortendesk-server>")
        .about(about)
        .args_from_usage(args)
        .get_matches();
    if let Ok(v) = Ini::load_from_file(".env") {
        if let Some(section) = v.section(None::<String>) {
            section
                .iter()
                .for_each(|(k, v)| set_arg(k, v));
        }
    }
    if let Some(config) = matches.value_of("config") {
        if let Ok(v) = Ini::load_from_file(config) {
            if let Some(section) = v.section(None::<String>) {
                section
                    .iter()
                    .for_each(|(k, v)| set_arg(k, v));
            }
        }
    }
    for (k, v) in matches.args {
        if let Some(v) = v.vals.first() {
            set_arg(k, &v.to_string_lossy());
        }
    }
}

#[allow(dead_code)]
pub fn get_arg_opt(name: &str) -> Option<String> {
    let dashed = arg_name(name);
    let underscored = dashed.replace('-', "_");
    let lower_dashed = dashed.to_lowercase();
    let lower_underscored = underscored.to_lowercase();
    for alias in [&dashed, &underscored, &lower_dashed, &lower_underscored] {
        if let Ok(value) = std::env::var(alias) {
            return Some(value);
        }
    }
    let mut aliases = std::env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            if arg_name(&key) == dashed {
                Some((key, value.into_string().ok()?))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    aliases.sort_by(|a, b| a.0.cmp(&b.0));
    aliases.into_iter().next().map(|(_, value)| value)
}

#[allow(dead_code)]
#[inline]
pub fn get_arg(name: &str) -> String {
    get_arg_or(name, "".to_owned())
}

#[allow(dead_code)]
#[inline]
pub fn get_arg_or(name: &str, default: String) -> String {
    get_arg_opt(name).unwrap_or(default)
}

#[allow(dead_code)]
#[inline]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or_default()
}

pub fn gen_sk(wait: u64) -> (String, Option<sign::SecretKey>) {
    let sk_file = "id_ed25519";
    if wait > 0 && !std::path::Path::new(sk_file).exists() {
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
    if let Ok(mut file) = std::fs::File::open(sk_file) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            let contents = contents.trim();
            let sk = base64::decode(contents).unwrap_or_default();
            if sk.len() == sign::SECRETKEYBYTES {
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                let pk = base64::encode(&tmp[sign::SECRETKEYBYTES / 2..]);
                log::info!("Private key comes from {}", sk_file);
                return (pk, Some(sign::SecretKey(tmp)));
            } else {
                // don't use log here, since it is async
                println!("Fatal error: malformed private key in {sk_file}.");
                std::process::exit(1);
            }
        }
    } else {
        let gen_func = || {
            let (tmp, sk) = sign::gen_keypair();
            (base64::encode(tmp), sk)
        };
        let (mut pk, mut sk) = gen_func();
        for _ in 0..300 {
            if !pk.contains('/') && !pk.contains(':') {
                break;
            }
            (pk, sk) = gen_func();
        }
        let pub_file = format!("{sk_file}.pub");
        if let Ok(mut f) = std::fs::File::create(&pub_file) {
            f.write_all(pk.as_bytes()).ok();
            if let Ok(mut f) = std::fs::File::create(sk_file) {
                let s = base64::encode(&sk);
                if f.write_all(s.as_bytes()).is_ok() {
                    log::info!("Private/public key written to {}/{}", sk_file, pub_file);
                    log::debug!("Public key: {}", pk);
                    return (pk, Some(sk));
                }
            }
        }
    }
    ("".to_owned(), None)
}

#[cfg(unix)]
pub async fn listen_signal() -> Result<()> {
    use hbb_common::tokio;
    use hbb_common::tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async {
        let mut s = signal(SignalKind::terminate())?;
        let terminate = s.recv();
        let mut s = signal(SignalKind::interrupt())?;
        let interrupt = s.recv();
        let mut s = signal(SignalKind::quit())?;
        let quit = s.recv();

        tokio::select! {
            _ = terminate => {
                log::info!("signal terminate");
            }
            _ = interrupt => {
                log::info!("signal interrupt");
            }
            _ = quit => {
                log::info!("signal quit");
            }
        }
        Ok(())
    })
    .await?
}

#[cfg(not(unix))]
pub async fn listen_signal() -> Result<()> {
    let () = std::future::pending().await;
    unreachable!();
}


// Upstream polled RustDesk's release feed here once a day and logged when a
// newer rustdesk-server existed. Removed with the fork: it compared their
// version numbers against ours, so a current build reported itself as out of
// date, and it made a daily request to a third party that a self-hosted
// server has no reason to make.

/// Reverse proxies allowed to name the client in `X-Forwarded-For`, from
/// `TRUSTED_PROXIES` / `--trusted-proxies`: comma-separated CIDRs. Empty, the
/// default, trusts none, and the header is ignored.
static TRUSTED_PROXIES: once_cell::sync::OnceCell<Vec<ipnetwork::IpNetwork>> =
    once_cell::sync::OnceCell::new();

pub fn parse_trusted_proxies(value: &str) -> ResultType<Vec<ipnetwork::IpNetwork>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|item| {
            item.parse::<ipnetwork::IpNetwork>()
                .map_err(|err| hbb_common::anyhow::anyhow!("invalid trusted proxy {}: {}", item, err))
        })
        .collect()
}

/// Read `TRUSTED_PROXIES` once at startup. An invalid entry stops the server.
pub fn init_trusted_proxies() -> ResultType<()> {
    let proxies = parse_trusted_proxies(&get_arg("TRUSTED-PROXIES"))?;
    if proxies.is_empty() {
        log::info!("No trusted proxies: X-Forwarded-For is ignored");
    } else {
        log::info!("Trusted proxies: {:?}", proxies);
    }
    TRUSTED_PROXIES.set(proxies).ok();
    Ok(())
}

/// The IPv4 address inside an IPv4-mapped IPv6 address, else `ip` itself.
pub fn norm_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        ip => ip,
    }
}

fn parse_hop(hop: &str) -> Option<IpAddr> {
    hop.parse::<IpAddr>()
        .ok()
        .or_else(|| hop.parse::<SocketAddr>().ok().map(|a| a.ip()))
        .or_else(|| hop.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
        .map(norm_ip)
}

/// The client address of a WebSocket connection from `peer`. Only a trusted
/// proxy may name it: `X-Forwarded-For` is read from the right, skipping
/// trusted proxies, and the first other address is the client. Entries left of
/// it were written by the client and are never used. An unreadable entry stops
/// the walk at the last proxy.
pub fn client_ip(peer: IpAddr, headers: &tungstenite::http::HeaderMap) -> IpAddr {
    client_ip_with(peer, headers, TRUSTED_PROXIES.get().map_or(&[], |v| v.as_slice()))
}

fn client_ip_with(
    peer: IpAddr,
    headers: &tungstenite::http::HeaderMap,
    trusted: &[ipnetwork::IpNetwork],
) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    let mut client = norm_ip(peer);
    if !is_trusted(client) {
        return client;
    }
    let mut hops = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else { return client };
        hops.extend(value.split(',').map(str::trim));
    }
    for hop in hops.into_iter().rev() {
        let Some(ip) = parse_hop(hop) else { break };
        client = ip;
        if !is_trusted(ip) {
            break;
        }
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn argument_names_ignore_case_and_separator() {
        let aliases = [
            "RUSTDESK-CONFIG-ALIAS-TEST",
            "RUSTDESK_CONFIG_ALIAS_TEST",
            "rustdesk-config-alias-test",
            "rustdesk_config_alias_test",
            "RustDesk_Config-Alias_Test",
        ];
        for alias in aliases {
            std::env::remove_var(alias);
        }
        for alias in aliases {
            std::env::set_var(alias, alias);
            assert_eq!(get_arg("RUSTDESK_CONFIG_ALIAS_TEST"), alias);
            std::env::remove_var(alias);
        }
        set_arg("rustdesk_config_alias_test", "normalized");
        assert_eq!(
            std::env::var("RUSTDESK-CONFIG-ALIAS-TEST").unwrap(),
            "normalized"
        );
        std::env::set_var("RUSTDESK_CONFIG_ALIAS_TEST", "inherited");
        set_arg("rustdesk-config-alias-test", "higher-priority");
        assert_eq!(get_arg("rustdesk_config_alias_test"), "higher-priority");
        std::env::remove_var("RUSTDESK-CONFIG-ALIAS-TEST");
        std::env::remove_var("RUSTDESK_CONFIG_ALIAS_TEST");
    }

    fn xff(values: &[&str]) -> tungstenite::http::HeaderMap {
        let mut headers = tungstenite::http::HeaderMap::new();
        for v in values {
            headers.append("X-Forwarded-For", v.parse().unwrap());
        }
        headers.insert("X-Real-IP", "192.0.2.66".parse().unwrap());
        headers
    }

    #[test]
    fn client_ip_trusts_only_configured_proxies() {
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let none = parse_trusted_proxies("").unwrap();
        let lo = parse_trusted_proxies("127.0.0.1/32, 10.0.0.0/8").unwrap();
        // No trusted proxies: the header is ignored. X-Real-IP is never read.
        assert_eq!(client_ip_with(proxy, &xff(&["198.51.100.7"]), &none), proxy);
        // Untrusted peer: ignored.
        let direct: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(client_ip_with(direct, &xff(&["198.51.100.7"]), &lo), direct);
        // A forged entry on the left is skipped; the proxy's own is on the right.
        assert_eq!(
            client_ip_with(proxy, &xff(&["6.6.6.6, 198.51.100.7"]), &lo).to_string(),
            "198.51.100.7"
        );
        // Chained proxies, across header lines, v4-mapped and with ports.
        assert_eq!(
            client_ip_with(
                "::ffff:127.0.0.1".parse().unwrap(),
                &xff(&["6.6.6.6", "[2001:db8::7]:4000, 10.1.2.3:80"]),
                &lo
            )
            .to_string(),
            "2001:db8::7"
        );
        assert_eq!(
            client_ip_with(proxy, &xff(&["::ffff:198.51.100.9"]), &lo).to_string(),
            "198.51.100.9"
        );
        // Unreadable entry: stop at the last proxy.
        assert_eq!(client_ip_with(proxy, &xff(&["198.51.100.7, junk"]), &lo), proxy);
        // No header from a trusted proxy: the proxy itself.
        assert_eq!(client_ip_with(proxy, &xff(&[]), &lo), proxy);
        assert!(parse_trusted_proxies("10.0.0.0/8,nonsense").is_err());
    }

    #[test]
    fn parses_bind_address() {
        assert_eq!(parse_bind_address("").unwrap(), None);
        assert_eq!(
            parse_bind_address("127.0.0.1").unwrap(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_bind_address("::1").unwrap(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(parse_bind_address("not-an-ip").is_err());
    }

    #[hbb_common::tokio::test]
    async fn tcp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = listen_tcp(Some(bind_addr), 0).await.unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), bind_addr);
    }

    #[test]
    fn console_addr_only_when_bind_does_not_cover_ipv4_localhost() {
        for bind_addr in [
            None,
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ] {
            assert_eq!(console_addr(bind_addr, 21117), None);
        }
        for bind_addr in [
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some("2001:db8::1".parse().unwrap()),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            assert_eq!(
                console_addr(bind_addr, 21117),
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21117))
            );
        }
    }

    #[hbb_common::tokio::test]
    async fn console_listener_binds_ipv4_localhost() {
        let listener = listen_console(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            listener.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert!(listen_console(None, 0).await.unwrap().is_none());
        assert!(listen_console(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
            .await
            .unwrap()
            .is_none());
    }
}
