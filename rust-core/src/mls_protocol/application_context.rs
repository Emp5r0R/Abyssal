use super::canonical_username;

const DOMAIN: &[u8] = b"ABYSSAL-MLS-V10-APPLICATION";

/// Matches the clients' four length-prefixed fields without accepting suffixes.
pub(super) fn sender(data: &[u8], room: &str, message: &str) -> Result<String, String> {
    let mut remaining = data;
    for expected in [DOMAIN, room.as_bytes(), message.as_bytes()] {
        let (length, rest) = remaining.split_at_checked(4).ok_or("Payload unavailable")?;
        let length =
            u32::from_be_bytes(length.try_into().map_err(|_| "Payload unavailable")?) as usize;
        if length != expected.len() || !rest.starts_with(expected) {
            return Err("Payload unavailable".into());
        }
        remaining = &rest[length..];
    }
    let (length, name) = remaining.split_at_checked(4).ok_or("Payload unavailable")?;
    let length = u32::from_be_bytes(length.try_into().map_err(|_| "Payload unavailable")?) as usize;
    if length != name.len() {
        return Err("Payload unavailable".into());
    }
    canonical_username(std::str::from_utf8(name).map_err(|_| "Payload unavailable")?)
}

#[cfg(test)]
pub(super) fn encode(room: &str, message: &str, sender: &str) -> Vec<u8> {
    [
        DOMAIN,
        room.as_bytes(),
        message.as_bytes(),
        sender.as_bytes(),
    ]
    .into_iter()
    .flat_map(|field| {
        (field.len() as u32)
            .to_be_bytes()
            .into_iter()
            .chain(field.iter().copied())
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contexts_are_exact_bounded_and_sender_canonical() {
        let valid = encode("room", "message", "Alice");
        assert_eq!(sender(&valid, "room", "message").unwrap(), "alice");
        assert!(sender(&valid, "other", "message").is_err());
        assert!(sender(&valid, "room", "other").is_err());
        for end in 0..valid.len() {
            assert!(sender(&valid[..end], "room", "message").is_err());
        }
        let mut suffix = valid.clone();
        suffix.push(0);
        assert!(sender(&suffix, "room", "message").is_err());
        let mut huge = valid;
        huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(sender(&huge, "room", "message").is_err());
        for name in ["", "a/b", "a\0b", &"x".repeat(81)] {
            assert!(sender(&encode("room", "message", name), "room", "message").is_err());
        }
    }
}
