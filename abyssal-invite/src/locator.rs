//! Locator selection policy. The locator type, its encoding, and its
//! validation are the shared `invite-capsule` implementation.

use crate::InviteError;

pub use invite_capsule::{Locator as NodeLocator, LoopbackHost, MAX_LOCATORS};

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

/// Derives a locator from a node's public URL (HTTPS, development loopback,
/// onion, or I2P).
pub fn locator_from_public_url(value: &str) -> Result<NodeLocator, InviteError> {
    Ok(NodeLocator::from_public_url(value)?)
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
