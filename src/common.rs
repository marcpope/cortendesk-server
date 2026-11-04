// Modified by the CortenDesk Server project on 2026-11-03: client address from
// trusted proxies (`client_ip`). Modified on 2026-11-04: key file handling
// (`gen_sk`), ported from upstream rustdesk-server commit 873230e. See
// CHANGES.md. This file is part of a modified version of rustdesk-server,
// distributed under the AGPL-3.0 like the original.

use clap::App;
use hbb_common::{
    anyhow::{Context, Result}, log, ResultType
};
use ini::Ini;
use sodiumoxide::crypto::sign;
use std::{
    fs,
    io::prelude::*,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
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

#[cfg(unix)]
const PRIVATE_KEY_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PUBLIC_KEY_FILE_MODE: u32 = 0o644;
const MAX_KEY_SYMLINKS: usize = 40;

fn resolve_key_path(path: &Path) -> ResultType<PathBuf> {
    let mut path = path.to_path_buf();
    // Bound traversal even if symlinks change while they are being resolved.
    for _ in 0..MAX_KEY_SYMLINKS {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {}
            Ok(_) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(path),
            Err(err) => return Err(err.into()),
        }
        let target = fs::read_link(&path)?;
        path.pop();
        path.push(target);
    }
    hbb_common::anyhow::bail!(
        "Too many key symlinks (limit: {MAX_KEY_SYMLINKS}): {}",
        path.display()
    );
}

/// On Unix, restricts access from creation so another user cannot retain a readable descriptor.
/// Follows dangling symlinks for configured key paths, but never overwrites an existing key.
/// Writes after verifying Unix permissions; failures close and try to remove the new file.
fn create_private_key_file(path: &str, contents: &[u8]) -> ResultType<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let path = resolve_key_path(Path::new(path))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(PRIVATE_KEY_FILE_MODE);
    let mut file = options.open(&path)?;
    let result = (|| {
        #[cfg(unix)]
        set_private_key_permissions(&file, true)?;
        file.write_all(contents)
            .context("Failed to write private key")
    })();
    if let Err(err) = result {
        drop(file);
        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove {} after {err:#}", path.display()))?;
        return Err(err);
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_key_permissions(file: &fs::File, newly_created: bool) -> ResultType<()> {
    use std::os::unix::fs::PermissionsExt;

    const PERMISSION_BITS: u32 = 0o7777;
    let mode = file.metadata()?.permissions().mode() & PERMISSION_BITS;
    if !newly_created && mode & !PRIVATE_KEY_FILE_MODE == 0 {
        return Ok(());
    }
    hbb_common::anyhow::ensure!(
        !newly_created || mode & !PRIVATE_KEY_FILE_MODE == 0,
        "Unsafe initial private key permissions: {mode:04o}"
    );
    if mode != PRIVATE_KEY_FILE_MODE {
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_KEY_FILE_MODE))
            .context("Failed to set private key permissions to 0600")?;
        let mode = file.metadata()?.permissions().mode() & PERMISSION_BITS;
        hbb_common::anyhow::ensure!(
            mode == PRIVATE_KEY_FILE_MODE,
            "Private key permissions are {mode:04o}, expected 0600"
        );
    }
    Ok(())
}

/// Where the public key belongs, or `None` when that file already holds `pk`.
/// A file holding another key is stale: hbbs signs with the private key either
/// way, so the file is rewritten with a warning rather than refused.
fn public_key_target(path: &Path, pk: &str) -> ResultType<Option<PathBuf>> {
    let path = resolve_key_path(path).context("Failed to resolve public key path")?;
    match fs::read_to_string(&path) {
        Ok(contents) if contents.trim() == pk => Ok(None),
        Ok(_) => {
            log::warn!(
                "{} does not match the private key in id_ed25519; rewriting it with the key derived from id_ed25519",
                path.display()
            );
            Ok(Some(path))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Some(path)),
        Err(err) => Err(err).context("Failed to read public key file"),
    }
}

/// Writes `pk` to the public key file when it is missing or stale, through a
/// temporary file renamed into place, so a partial key is never seen. Mode
/// 0644. With `required = false`, failing to create the temporary file only
/// warns, for keys provisioned in a read-only directory.
fn write_public_key(path: &str, pk: &str, required: bool) -> ResultType<()> {
    let Some(path) = public_key_target(Path::new(path), pk)? else {
        return Ok(());
    };
    let temporary = path.with_file_name(format!(".id_ed25519.pub.{}", uuid::Uuid::new_v4()));
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(file) => file,
        // Existing private keys may be provisioned in a read-only directory.
        Err(err) if !required => {
            log::warn!(
                "Failed to create {}: {err}; using the existing private key",
                path.display()
            );
            return Ok(());
        }
        Err(err) => return Err(err).context("Failed to create public key file"),
    };
    let temporary = match tempfile::TempPath::try_from_path(&temporary) {
        Ok(path) => path,
        Err(err) => {
            fs::remove_file(&temporary).ok();
            return Err(err).context("Failed to create public key file");
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(PUBLIC_KEY_FILE_MODE))
            .context("Failed to set public key permissions")?;
    }
    file.write_all(pk.as_bytes())
        .context("Failed to write public key")?;
    file.sync_all().context("Failed to sync public key")?;
    drop(file);
    temporary
        .persist(&path)
        .map_err(|err| err.error)
        .context("Failed to publish public key file")?;
    Ok(())
}

pub fn gen_sk(wait: u64) -> ResultType<(String, Option<sign::SecretKey>)> {
    let sk_file = "id_ed25519";
    let pub_file = format!("{sk_file}.pub");
    if wait > 0 && !std::path::Path::new(sk_file).exists() {
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
    match fs::File::open(sk_file) {
        Ok(mut file) => {
            #[cfg(unix)]
            set_private_key_permissions(&file, false)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .context("Failed to read private key")?;
            let sk = base64::decode(contents.trim()).context("Malformed private key")?;
            let sk = sign::SecretKey::from_slice(&sk).context("Malformed private key")?;
            let pk = base64::encode(sk.public_key());
            write_public_key(&pub_file, &pk, false)?;
            log::info!("Private key comes from {}", sk_file);
            return Ok((pk, Some(sk)));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("Failed to open private key"),
    }
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
    // Fail on an unreadable public key path before creating anything.
    public_key_target(Path::new(&pub_file), &pk)?;
    create_private_key_file(sk_file, base64::encode(&sk).as_bytes())
        .context("Failed to create private key file")?;
    write_public_key(&pub_file, &pk, true)?;
    log::info!("Private/public key written to {}/{}", sk_file, pub_file);
    log::debug!("Public key: {}", pk);
    Ok((pk, Some(sk)))
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

    #[cfg(unix)]
    #[test]
    fn key_path_symlinks_are_bounded() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let mut path = target.clone();
        for index in 1..MAX_KEY_SYMLINKS {
            let link = directory.path().join(format!("link-{index}"));
            symlink(&path, &link).unwrap();
            path = link;
        }
        assert_eq!(resolve_key_path(&path).unwrap(), target);
        let extra = directory.path().join("extra");
        symlink(&path, &extra).unwrap();
        let cycle = directory.path().join("cycle");
        symlink(&cycle, &cycle).unwrap();
        for path in [&extra, &cycle] {
            let error = resolve_key_path(path).unwrap_err();
            assert!(error.to_string().starts_with("Too many key symlinks"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_permissions() {
        use std::process::Command;

        const CHILD_ENV: &str = "CORTENDESK_PRIVATE_KEY_TEST_CHILD";
        const CHILD_COMPLETED: &str = "private_key_test_child_completed";
        const TEST_NAME: &str = "common::tests::private_key_file_permissions";
        if std::env::var_os(CHILD_ENV).is_some() {
            const TEST_UMASK: libc::mode_t = 0o022;
            // The child process isolates the umask from other tests.
            unsafe { libc::umask(TEST_UMASK) };
            assert_private_key_file_permissions();
            println!("{CHILD_COMPLETED}");
            return;
        }

        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains(CHILD_COMPLETED),
            "key-file test failed ({}):\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    fn with_file_size_limit<T>(limit: libc::rlim_t, run: impl FnOnce() -> T) -> T {
        unsafe {
            let mut limits = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut limits), 0);
            let handler = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            assert_ne!(handler, libc::SIG_ERR);
            let restricted = libc::rlimit {
                rlim_cur: limit,
                ..limits
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &restricted), 0);
            let result = run();
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limits), 0);
            assert_ne!(libc::signal(libc::SIGXFSZ, handler), libc::SIG_ERR);
            result
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_public_key_write_failure(public_key: &str) {
        const WRITE_LIMIT: libc::rlim_t = 16;
        let pub_file = "id_ed25519.pub";
        fs::remove_file(pub_file).unwrap();
        assert!(with_file_size_limit(WRITE_LIMIT, || gen_sk(0)).is_err());
        assert!(!Path::new(pub_file).exists());
        assert_eq!(gen_sk(0).unwrap().0, public_key);
        assert_eq!(fs::read_to_string(pub_file).unwrap(), public_key);
    }

    #[cfg(unix)]
    fn assert_public_key_recovery() -> String {
        use std::os::unix::fs::PermissionsExt;

        let sk_file = "id_ed25519";
        let pub_file = "id_ed25519.pub";
        let pub_mode = || fs::metadata(pub_file).unwrap().permissions().mode() & 0o777;
        let mismatched_key = base64::encode(sign::gen_keypair().0);
        // A stale .pub without a private key: a new pair is made and the
        // .pub rewritten to match it.
        fs::write(pub_file, &mismatched_key).unwrap();
        let public_key = gen_sk(0).unwrap().0;
        assert_ne!(public_key, mismatched_key);
        assert_eq!(fs::read_to_string(pub_file).unwrap(), public_key);
        assert_eq!(pub_mode(), PUBLIC_KEY_FILE_MODE);
        let private_key = fs::read(sk_file).unwrap();
        // An unreadable .pub path is an error, and nothing is changed.
        fs::remove_file(pub_file).unwrap();
        fs::create_dir(pub_file).unwrap();
        assert!(gen_sk(0).is_err());
        fs::remove_dir(pub_file).unwrap();
        // A missing one is written from the private key.
        assert_eq!(gen_sk(0).unwrap().0, public_key);
        assert_eq!(fs::read_to_string(pub_file).unwrap(), public_key);
        #[cfg(target_os = "linux")]
        assert_public_key_write_failure(&public_key);
        // A stale one beside an existing private key (issue #6): the private
        // key is kept and the .pub rewritten from it, 0644.
        fs::write(pub_file, &mismatched_key).unwrap();
        fs::set_permissions(pub_file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(gen_sk(0).unwrap().0, public_key);
        assert_eq!(fs::read(sk_file).unwrap(), private_key);
        assert_eq!(fs::read_to_string(pub_file).unwrap(), public_key);
        assert_eq!(pub_mode(), PUBLIC_KEY_FILE_MODE);
        // No temporary files are left behind.
        assert!(fs::read_dir(".")
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().starts_with(".id_ed25519.pub.")));
        public_key
    }

    #[cfg(unix)]
    fn assert_private_key_file_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        const PERMISSION_BITS: u32 = 0o777;
        const NEW_FILE_MODE: u32 = 0o600;
        const EXISTING_MODE: u32 = 0o644;
        const READ_ONLY_MODE: u32 = 0o400;
        const RESTRICTIVE_UMASK: libc::mode_t = 0o777;
        let directory = tempfile::tempdir().unwrap();
        std::env::set_current_dir(directory.path()).unwrap();
        let path = Path::new("id_ed25519");
        // A private key that exists but cannot be read, or is not a key, stops
        // the server and leaves both files as they are (issue #6). Before, an
        // unreadable one made it write a new, unmatched id_ed25519.pub.
        for contents in [&[0xff, 0xfe, 0x00][..], b"not a key"] {
            fs::write(path, contents).unwrap();
            assert!(gen_sk(0).is_err());
            assert_eq!(fs::read(path).unwrap(), contents);
            assert!(!Path::new("id_ed25519.pub").exists());
        }
        fs::remove_file(path).unwrap();
        // One that cannot even be opened: a symlink loop fails with ELOOP, as
        // a file the server may not read fails with EACCES, which root never gets.
        symlink("id_ed25519", path).unwrap();
        assert!(gen_sk(0).is_err());
        assert!(path.is_symlink());
        assert!(!Path::new("id_ed25519.pub").exists());
        fs::remove_file(path).unwrap();
        let mode = || fs::metadata(path).unwrap().permissions().mode() & PERMISSION_BITS;
        symlink("key-alias", path).unwrap();
        symlink("key-target", "key-alias").unwrap();
        #[cfg(target_os = "linux")]
        {
            const PARTIAL_WRITE_LIMIT: libc::rlim_t = 16;
            for limit in [0, PARTIAL_WRITE_LIMIT] {
                assert!(with_file_size_limit(limit, || gen_sk(0)).is_err());
                assert!(path.is_symlink() && Path::new("key-alias").is_symlink());
                assert!(!Path::new("key-target").exists());
                assert!(!Path::new("id_ed25519.pub").exists());
            }
        }
        let public_key = assert_public_key_recovery();
        assert_eq!(mode(), NEW_FILE_MODE);
        let contents = fs::read(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(EXISTING_MODE)).unwrap();
        let file = fs::File::open(path).unwrap();
        assert!(set_private_key_permissions(&file, true).is_err());
        assert_eq!(mode(), EXISTING_MODE);
        gen_sk(0).unwrap();
        assert_eq!(mode(), NEW_FILE_MODE);
        assert_eq!(fs::read(path).unwrap(), contents);
        assert!(create_private_key_file("id_ed25519", b"do not overwrite").is_err());
        assert_eq!(fs::read(path).unwrap(), contents);
        fs::set_permissions(path, fs::Permissions::from_mode(READ_ONLY_MODE)).unwrap();
        fs::set_permissions("id_ed25519.pub", fs::Permissions::from_mode(READ_ONLY_MODE)).unwrap();
        assert_eq!(gen_sk(0).unwrap().0, public_key);
        assert_eq!(mode(), READ_ONLY_MODE);

        fs::remove_file(path).unwrap();
        fs::remove_file("id_ed25519.pub").unwrap();
        unsafe { libc::umask(RESTRICTIVE_UMASK) };
        gen_sk(0).unwrap();
        assert_eq!(mode(), NEW_FILE_MODE);
        let contents = fs::read(path).unwrap();
        gen_sk(0).unwrap();
        assert_eq!(fs::read(path).unwrap(), contents);
        std::env::set_current_dir(directory.path().parent().unwrap()).unwrap();
    }
}
