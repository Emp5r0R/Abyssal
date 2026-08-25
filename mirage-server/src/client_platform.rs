use std::env;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ClientPlatform {
    Android,
    Web,
}

impl ClientPlatform {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "android" => Some(Self::Android),
            "web" => Some(Self::Web),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InteropPolicy {
    allow_android_to_web: bool,
    allow_web_to_android: bool,
}

impl InteropPolicy {
    pub(crate) const fn new(allow_android_to_web: bool, allow_web_to_android: bool) -> Self {
        Self {
            allow_android_to_web,
            allow_web_to_android,
        }
    }

    pub(crate) fn from_env() -> Self {
        Self::new(
            strict_bool_env("ABYSSAL_ALLOW_ANDROID_TO_WEB", false),
            strict_bool_env("ABYSSAL_ALLOW_WEB_TO_ANDROID", true),
        )
    }

    pub(crate) const fn allows(self, sender: ClientPlatform, recipient: ClientPlatform) -> bool {
        match (sender, recipient) {
            (ClientPlatform::Android, ClientPlatform::Web) => self.allow_android_to_web,
            (ClientPlatform::Web, ClientPlatform::Android) => self.allow_web_to_android,
            _ => true,
        }
    }

    pub(crate) const fn allow_android_to_web(self) -> bool {
        self.allow_android_to_web
    }

    pub(crate) const fn allow_web_to_android(self) -> bool {
        self.allow_web_to_android
    }
}

fn strict_bool_env(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => parse_bool_env_value(name, &value),
        Err(env::VarError::NotPresent) => default,
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}

fn parse_bool_env_value(name: &str, value: &str) -> bool {
    match value {
        "true" => true,
        "false" => false,
        _ => panic!("{name} must be exactly true or false"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_directional_and_same_platform_is_always_allowed() {
        let policy = InteropPolicy::new(false, true);
        assert!(!policy.allows(ClientPlatform::Android, ClientPlatform::Web));
        assert!(policy.allows(ClientPlatform::Web, ClientPlatform::Android));
        assert!(policy.allows(ClientPlatform::Android, ClientPlatform::Android));
        assert!(policy.allows(ClientPlatform::Web, ClientPlatform::Web));
    }

    #[test]
    fn platform_parser_is_an_exact_allowlist() {
        assert_eq!(
            ClientPlatform::parse("android"),
            Some(ClientPlatform::Android)
        );
        assert_eq!(ClientPlatform::parse("web"), Some(ClientPlatform::Web));
        assert_eq!(ClientPlatform::parse("Android"), None);
        assert_eq!(ClientPlatform::parse("web "), None);
        assert_eq!(ClientPlatform::parse("desktop"), None);
    }

    #[test]
    fn boolean_policy_values_are_exact_and_invalid_values_fail_closed() {
        assert!(parse_bool_env_value("TEST_POLICY", "true"));
        assert!(!parse_bool_env_value("TEST_POLICY", "false"));
        for value in ["TRUE", "False", "1", "yes", " true", "false ", ""] {
            assert!(
                std::panic::catch_unwind(|| parse_bool_env_value("TEST_POLICY", value)).is_err()
            );
        }
    }
}
