use crate::{codec, InviteError};
use std::{collections::HashSet, net::IpAddr};
use url::{Host, Url};

pub const MAX_LOCATORS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LoopbackHost {
    Localhost,
    Ipv4,
    Ipv6,
    AndroidEmulator,
}

impl LoopbackHost {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Localhost => "localhost",
            Self::Ipv4 => "127.0.0.1",
            Self::Ipv6 => "::1",
            Self::AndroidEmulator => "10.0.2.2",
        }
    }

    fn tag(self) -> u64 {
        match self {
            Self::Localhost => 1,
            Self::Ipv4 => 2,
            Self::Ipv6 => 3,
            Self::AndroidEmulator => 4,
        }
    }

    fn from_tag(tag: u64) -> Result<Self, InviteError> {
        match tag {
            1 => Ok(Self::Localhost),
            2 => Ok(Self::Ipv4),
            3 => Ok(Self::Ipv6),
            4 => Ok(Self::AndroidEmulator),
            _ => Err(InviteError::UnsupportedTransport),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum NodeLocator {
    Https { host: String, port: u16 },
    LoopbackDevelopment { host: LoopbackHost, port: u16 },
}

impl NodeLocator {
    pub fn api_base_url(&self) -> String {
        match self {
            Self::Https { host, port } => authority_url("https", host, *port, 443),
            Self::LoopbackDevelopment { host, port } => {
                authority_url("http", host.as_str(), *port, 80)
            }
        }
    }

    pub fn websocket_base_url(&self) -> String {
        match self {
            Self::Https { host, port } => authority_url("wss", host, *port, 443),
            Self::LoopbackDevelopment { host, port } => {
                authority_url("ws", host.as_str(), *port, 80)
            }
        }
    }

    pub fn display_host(&self) -> String {
        match self {
            Self::Https { host, port } => authority(host, *port, 443),
            Self::LoopbackDevelopment { host, port } => authority(host.as_str(), *port, 80),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), InviteError> {
        match self {
            Self::Https { host, port } => {
                if *port == 0 || !valid_remote_host(host) {
                    return Err(InviteError::UnsafeLocator);
                }
            }
            Self::LoopbackDevelopment { port, .. } if *port == 0 => {
                return Err(InviteError::UnsafeLocator);
            }
            Self::LoopbackDevelopment { .. } => {}
        }
        Ok(())
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) {
        codec::encode_array(output, 3);
        match self {
            Self::Https { host, port } => {
                codec::encode_uint(output, 1);
                codec::encode_text(output, host);
                codec::encode_uint(output, u64::from(*port));
            }
            Self::LoopbackDevelopment { host, port } => {
                codec::encode_uint(output, 2);
                codec::encode_uint(output, host.tag());
                codec::encode_uint(output, u64::from(*port));
            }
        }
    }

    pub(crate) fn decode(decoder: &mut codec::Decoder<'_>) -> Result<Self, InviteError> {
        decoder.array(3)?;
        let kind = decoder.uint()?;
        let locator = match kind {
            1 => Self::Https {
                host: decoder.text(codec::MAX_HOST_BYTES)?,
                port: decode_port(decoder.uint()?)?,
            },
            2 => Self::LoopbackDevelopment {
                host: LoopbackHost::from_tag(decoder.uint()?)?,
                port: decode_port(decoder.uint()?)?,
            },
            _ => return Err(InviteError::UnsupportedTransport),
        };
        locator.validate()?;
        Ok(locator)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportedTransports {
    pub https: bool,
    pub loopback_development: bool,
}

impl SupportedTransports {
    pub const PRODUCTION: Self = Self {
        https: true,
        loopback_development: false,
    };
    pub const DEVELOPMENT: Self = Self {
        https: true,
        loopback_development: true,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLocatorPolicy {
    Production,
    ExplicitDevelopment,
}

pub fn select_locator(
    locators: &[NodeLocator],
    supported: SupportedTransports,
    policy: RuntimeLocatorPolicy,
) -> Result<NodeLocator, InviteError> {
    if supported.https {
        if let Some(locator) = locators
            .iter()
            .find(|locator| matches!(locator, NodeLocator::Https { .. }))
        {
            return Ok(locator.clone());
        }
    }
    if supported.loopback_development && policy == RuntimeLocatorPolicy::ExplicitDevelopment {
        if let Some(locator) = locators
            .iter()
            .find(|locator| matches!(locator, NodeLocator::LoopbackDevelopment { .. }))
        {
            return Ok(locator.clone());
        }
    }
    Err(InviteError::UnsupportedTransport)
}

pub fn locator_from_public_url(value: &str) -> Result<NodeLocator, InviteError> {
    if value.is_empty()
        || value.len() > 512
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(InviteError::UnsafeLocator);
    }
    let url = Url::parse(value).map_err(|_| InviteError::UnsafeLocator)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(InviteError::UnsafeLocator);
    }
    let host = url.host().ok_or(InviteError::UnsafeLocator)?;
    let port = url
        .port_or_known_default()
        .ok_or(InviteError::UnsafeLocator)?;
    match url.scheme() {
        "https" => {
            let host = canonical_remote_url_host(host)?;
            let locator = NodeLocator::Https { host, port };
            locator.validate()?;
            Ok(locator)
        }
        "http" => {
            let host = match host {
                Host::Domain("localhost") => LoopbackHost::Localhost,
                Host::Ipv4(value) if value.is_loopback() => LoopbackHost::Ipv4,
                Host::Ipv4(value) if value.octets() == [10, 0, 2, 2] => {
                    LoopbackHost::AndroidEmulator
                }
                Host::Ipv6(value) if value.is_loopback() => LoopbackHost::Ipv6,
                _ => return Err(InviteError::UnsafeLocator),
            };
            Ok(NodeLocator::LoopbackDevelopment { host, port })
        }
        _ => Err(InviteError::UnsupportedTransport),
    }
}

pub(crate) fn validate_locator_set(locators: &[NodeLocator]) -> Result<(), InviteError> {
    if locators.is_empty() || locators.len() > MAX_LOCATORS {
        return Err(InviteError::Invalid);
    }
    let mut unique = HashSet::with_capacity(locators.len());
    for locator in locators {
        locator.validate()?;
        if !unique.insert(locator) {
            return Err(InviteError::Invalid);
        }
    }
    Ok(())
}

fn canonical_remote_url_host(host: Host<&str>) -> Result<String, InviteError> {
    match host {
        Host::Domain(value) if valid_remote_host(value) => Ok(value.to_owned()),
        // Literal remote IPs are intentionally excluded from V1. DNS names
        // remain subject to client-side public-address resolution policy.
        Host::Ipv4(_) | Host::Ipv6(_) | Host::Domain(_) => Err(InviteError::UnsafeLocator),
    }
}

fn valid_remote_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > codec::MAX_HOST_BYTES
        || host != host.to_ascii_lowercase()
        || !host.is_ascii()
        || !host.contains('.')
        || host.ends_with('.')
        || host.starts_with('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".onion")
        || host.ends_with(".home.arpa")
        || host.ends_with(".invalid")
        || host.ends_with(".test")
        || host.ends_with(".example")
        || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn decode_port(value: u64) -> Result<u16, InviteError> {
    let port = u16::try_from(value).map_err(|_| InviteError::UnsafeLocator)?;
    (port > 0).then_some(port).ok_or(InviteError::UnsafeLocator)
}

fn authority_url(scheme: &str, host: &str, port: u16, default_port: u16) -> String {
    format!("{scheme}://{}", authority(host, port, default_port))
}

fn authority(host: &str, port: u16, default_port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_url_policy_rejects_ssrf_shapes() {
        for value in [
            "file:///etc/passwd",
            "http://169.254.169.254",
            "http://192.168.1.1",
            "https://example.com@evil.test",
            "https://example.com#evil",
            "data:text/plain,x",
            "javascript:alert(1)",
            "gopher://example.com",
            "ftp://example.com",
            "https://127.0.0.1",
            "https://node.onion",
            "https://router.home.arpa",
            "https://node.test",
            "https://ex\u{00e4}mple.com",
            "https://example.com/path",
            "https://example.com?x=1",
        ] {
            assert!(locator_from_public_url(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn public_url_policy_accepts_https_and_exact_development_loopbacks() {
        assert_eq!(
            locator_from_public_url("https://chat.example.com:8443").unwrap(),
            NodeLocator::Https {
                host: "chat.example.com".to_owned(),
                port: 8443,
            }
        );
        assert_eq!(
            locator_from_public_url("https://EXAMPLE.com").unwrap(),
            NodeLocator::Https {
                host: "example.com".to_owned(),
                port: 443,
            }
        );
        for value in [
            "http://localhost:4020",
            "http://127.0.0.1:4020",
            "http://[::1]:4020",
            "http://10.0.2.2:4020",
        ] {
            assert!(matches!(
                locator_from_public_url(value),
                Ok(NodeLocator::LoopbackDevelopment { port: 4020, .. })
            ));
        }
    }

    #[test]
    fn selection_prefers_https_and_requires_explicit_development_policy() {
        let local = NodeLocator::LoopbackDevelopment {
            host: LoopbackHost::Ipv4,
            port: 4020,
        };
        assert_eq!(
            select_locator(
                std::slice::from_ref(&local),
                SupportedTransports::DEVELOPMENT,
                RuntimeLocatorPolicy::ExplicitDevelopment
            ),
            Ok(local.clone())
        );
        assert_eq!(
            select_locator(
                &[local],
                SupportedTransports::DEVELOPMENT,
                RuntimeLocatorPolicy::Production
            ),
            Err(InviteError::UnsupportedTransport)
        );
    }
}
