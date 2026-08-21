use rand::{rngs::OsRng, RngCore};

pub(crate) const MESSAGE_TRANSPORT_BUCKETS: [usize; 5] = [4096, 16_384, 65_536, 262_144, 1_048_576];
pub(crate) const MESSAGE_TRANSPORT_MAX_BUCKET: usize = 1_048_576;

const FILLER_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn valid_message_transport_padding(value: &str) -> bool {
    value.len() <= MESSAGE_TRANSPORT_MAX_BUCKET
        && value.bytes().all(|byte| FILLER_ALPHABET.contains(&byte))
}

pub(crate) fn random_message_transport_padding(length: usize) -> Result<String, String> {
    if length > MESSAGE_TRANSPORT_MAX_BUCKET {
        return Err("message transport padding length rejected".to_string());
    }
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    for byte in &mut bytes {
        *byte = FILLER_ALPHABET[usize::from(*byte & 63)];
    }
    String::from_utf8(bytes).map_err(|_| "message transport padding generation failed".to_string())
}

pub(crate) fn json_string_len(value: &str) -> Option<usize> {
    let mut length = 2usize;
    for byte in value.bytes() {
        let escaped_len = match byte {
            0x08 | 0x09 | 0x0a | 0x0c | 0x0d | b'"' | b'\\' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        };
        length = length.checked_add(escaped_len)?;
    }
    Some(length)
}

pub(crate) fn json_field_len(key: &str, value_len: usize) -> Option<usize> {
    json_string_len(key)?.checked_add(1)?.checked_add(value_len)
}

pub(crate) fn json_string_field_len(key: &str, value: &str) -> Option<usize> {
    json_field_len(key, json_string_len(value)?)
}

pub(crate) fn json_object_len(fields: &[usize]) -> Option<usize> {
    fields
        .iter()
        .enumerate()
        .try_fold(2usize, |length, (index, field)| {
            length
                .checked_add(usize::from(index != 0))?
                .checked_add(*field)
        })
}

pub(crate) fn json_array_len<I>(values: I) -> Option<usize>
where
    I: IntoIterator<Item = Option<usize>>,
{
    values
        .into_iter()
        .enumerate()
        .try_fold(2usize, |length, (index, value)| {
            length
                .checked_add(usize::from(index != 0))?
                .checked_add(value?)
        })
}

pub(crate) fn json_number_len<T: ToString>(value: T) -> Option<usize> {
    Some(value.to_string().len())
}

pub(crate) const fn json_bool_len(value: bool) -> usize {
    if value {
        4
    } else {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filler_is_bounded_random_and_url_safe() {
        let first = random_message_transport_padding(4096).expect("first filler");
        let second = random_message_transport_padding(4096).expect("second filler");
        assert_eq!(first.len(), 4096);
        assert!(valid_message_transport_padding(&first));
        assert_ne!(first, second);
        assert!(random_message_transport_padding(MESSAGE_TRANSPORT_MAX_BUCKET + 1).is_err());
    }

    #[test]
    fn json_length_helpers_match_serde_json() {
        for value in ["plain", "quote\"slash\\", "line\nfeed", "Abyssal"] {
            assert_eq!(
                json_string_len(value),
                Some(serde_json::to_string(value).expect("JSON string").len())
            );
        }
        assert_eq!(json_bool_len(true), 4);
        assert_eq!(json_bool_len(false), 5);
    }
}
