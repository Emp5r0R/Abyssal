//! Runtime configuration and process-level health probing.
//!
//! Environment parsing stays centralized here so the relay's startup path can
//! focus on constructing state, starting background tasks, and serving HTTP.

use super::*;

pub(super) fn configured_bind_addr() -> SocketAddr {
    env::var("ABYSSAL_BIND_ADDR")
        .or_else(|_| env::var("MIRAGE_BIND_ADDR"))
        .unwrap_or_else(|_| "0.0.0.0:4020".to_string())
        .parse()
        .expect("ABYSSAL_BIND_ADDR must be a valid socket address")
}

pub(super) fn healthcheck_response_is_healthy(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200 ")
        && response
            .windows(b"\"ok\":true".len())
            .any(|window| window == b"\"ok\":true")
}

pub(super) async fn healthcheck(bind_addr: SocketAddr) -> bool {
    let health_addr = env::var("ABYSSAL_HEALTHCHECK_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_addr.port()));
    let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(health_addr)).await
    else {
        return false;
    };
    let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if tokio::time::timeout(Duration::from_secs(2), stream.write_all(request))
        .await
        .is_err()
    {
        return false;
    }
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let mut response = Vec::with_capacity(512);
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<bool, io::Error>(healthcheck_response_is_healthy(&response));
            }
            response.extend_from_slice(&buffer[..read]);
            if healthcheck_response_is_healthy(&response) {
                return Ok::<bool, io::Error>(true);
            }
            if response.len() >= 4096 {
                return Ok::<bool, io::Error>(false);
            }
        }
    })
    .await;
    matches!(result, Ok(Ok(true)))
}

pub(super) fn read_usize_env(key: &str, fallback: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(fallback)
}

pub(super) fn attachment_record_limits_from_values(
    global: Option<&str>,
    account: Option<&str>,
) -> (usize, usize) {
    let global = global
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ATTACHMENT_RECORD_LIMIT)
        .clamp(MIN_ATTACHMENT_RECORD_LIMIT, MAX_ATTACHMENT_RECORD_LIMIT);
    let account = account
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ATTACHMENT_ACCOUNT_RECORD_LIMIT)
        .clamp(MIN_ATTACHMENT_RECORD_LIMIT, global);
    (global, account)
}

pub(super) fn pending_message_ttl_ms_from_env() -> u64 {
    let configured = env::var("ABYSSAL_PENDING_MESSAGE_TTL_HOURS").ok();
    pending_message_ttl_ms_from_value(configured.as_deref())
}

pub(super) fn pending_message_ttl_ms_from_value(value: Option<&str>) -> u64 {
    let hours = value
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PENDING_MESSAGE_TTL_HOURS)
        .clamp(MIN_PENDING_MESSAGE_TTL_HOURS, MAX_PENDING_MESSAGE_TTL_HOURS);
    (hours as u64).saturating_mul(HOURS_TO_MILLISECONDS)
}

pub(super) fn parse_origins_from_env(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| normalize_web_origin(value).ok())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn normalize_web_origin(value: &str) -> Result<String, String> {
    let trimmed = value.trim().trim_end_matches('/');
    let uri = trimmed
        .parse::<Uri>()
        .map_err(|_| "web origin rejected".to_string())?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "web origin rejected".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "web origin rejected".to_string())?;
    if !matches!(scheme, "http" | "https")
        || !matches!(uri.path(), "" | "/")
        || uri.query().is_some()
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || (scheme == "http"
            && !matches!(
                authority.host().to_ascii_lowercase().as_str(),
                "localhost" | "127.0.0.1" | "[::1]" | "::1"
            ))
    {
        return Err("web origin rejected".to_string());
    }
    Ok(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.as_str().to_ascii_lowercase()
    ))
}

pub(super) fn normalized_origin_authority(value: &str) -> Option<String> {
    let uri = value.trim().trim_end_matches('/').parse::<Uri>().ok()?;
    let authority = uri.authority()?;
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return None;
    }
    Some(authority.as_str().to_ascii_lowercase())
}

pub(super) fn resolve_web_root() -> Option<PathBuf> {
    if let Ok(configured) = env::var("ABYSSAL_WEB_ROOT") {
        let path = PathBuf::from(configured);
        if path.join("index.html").is_file() {
            return Some(path);
        }
        warn!("ABYSSAL_WEB_ROOT has no index.html; web client disabled");
        return None;
    }

    ["apps/web/dist", "../apps/web/dist", "/opt/abyssal/web"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.join("index.html").is_file())
}
