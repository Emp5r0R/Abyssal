//! Operator configuration only; bind addresses never become invitations.
use abyssal_invite::{locator_from_public_url, NodeLocator, MAX_LOCATORS};
use std::collections::HashSet;

pub(super) fn from_env() -> Result<Vec<NodeLocator>, String> {
    let read = |key| match std::env::var(key) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(String::new()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("advertised locator configuration must be UTF-8".to_owned())
        }
    };
    let single = read("ABYSSAL_PUBLIC_URL")?;
    let multiple = read("ABYSSAL_PUBLIC_LOCATORS")?;
    parse(&single, &multiple).map_err(str::to_owned)
}

fn parse(single: &str, multiple: &str) -> Result<Vec<NodeLocator>, &'static str> {
    let urls: Vec<String> = match (single.is_empty(), multiple.is_empty()) {
        (false, true) if single.len() <= 512 => vec![single.to_owned()],
        (true, false) if multiple.len() <= 2048 => serde_json::from_str(multiple)
            .map_err(|_| "ABYSSAL_PUBLIC_LOCATORS must be a JSON array of public URLs")?,
        _ => return Err("set only one of ABYSSAL_PUBLIC_URL or ABYSSAL_PUBLIC_LOCATORS"),
    };
    if urls.is_empty() || urls.len() > MAX_LOCATORS {
        return Err("advertise between one and four unique locators");
    }
    let mut unique = HashSet::new();
    urls.iter()
        .map(|url| {
            let locator = locator_from_public_url(url).map_err(|_| "invalid advertised locator")?;
            if !unique.insert(locator.clone()) {
                return Err("duplicate advertised locator");
            }
            Ok(locator)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_multiple_authenticated_transports_and_single_url_migration() {
        assert_eq!(parse("https://node.example.com", "").unwrap().len(), 1);
        let locators = parse("", r#"["https://node.example.com","http://pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion","http://ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"]"#).unwrap();
        assert!(matches!(locators[0], NodeLocator::Https { .. }));
        assert!(matches!(locators[1], NodeLocator::OnionV3 { .. }));
        assert!(matches!(locators[2], NodeLocator::I2pB32 { .. }));
    }

    #[test]
    fn rejects_conflicts_duplicates_oversize_and_non_locator_data() {
        for (single, multiple) in [
            ("", ""),
            ("https://node.example.com", "[]"),
            ("", "[]"),
            (
                "",
                r#"["https://node.example.com","https://NODE.example.com:443/"]"#,
            ),
            ("", r#"{"url":"https://node.example.com"}"#),
            ("", r#"["file:///etc/passwd"]"#),
            ("", r#"["http://169.254.169.254"]"#),
            ("", r#"["http://alias.i2p"]"#),
            ("", r#"["http://invalid.onion"]"#),
        ] {
            assert!(parse(single, multiple).is_err());
        }
        assert!(parse("", &" ".repeat(2049)).is_err());
        let too_many = serde_json::to_string(&vec!["https://node.example.com"; 5]).unwrap();
        assert!(parse("", &too_many).is_err());
    }
}
