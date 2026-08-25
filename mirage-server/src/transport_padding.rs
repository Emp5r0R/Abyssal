use rand::{rngs::OsRng, RngCore};

pub(crate) const MESSAGE_TRANSPORT_BUCKETS: [usize; 5] = [4096, 16_384, 65_536, 262_144, 1_048_576];
pub(crate) const MESSAGE_TRANSPORT_MAX_BUCKET: usize = 1_048_576;
pub(crate) const CONTROL_TRANSPORT_BUCKETS: [usize; 8] = [
    4096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304, 16_777_216, 17_825_792,
];
pub(crate) const CONTROL_TRANSPORT_MAX_BUCKET: usize = 17_825_792;

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

pub(crate) fn control_transport_wire_limit(domain_limit: usize) -> usize {
    if domain_limit <= MESSAGE_TRANSPORT_MAX_BUCKET {
        MESSAGE_TRANSPORT_MAX_BUCKET
    } else {
        CONTROL_TRANSPORT_MAX_BUCKET
    }
}

pub(crate) fn control_transport_frame_len(inner: &str, domain_limit: usize) -> Option<usize> {
    if inner.len() > domain_limit || !inner.starts_with('{') || !inner.ends_with('}') {
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(inner).ok()?;
    let object = value.as_object()?;
    if object.contains_key("padding_bucket") || object.contains_key("padding") {
        return None;
    }
    let prefix_len = inner.len().checked_sub(1)?;
    let wire_limit = control_transport_wire_limit(domain_limit);
    CONTROL_TRANSPORT_BUCKETS.iter().copied().find(|bucket| {
        *bucket <= wire_limit
            && prefix_len
                .checked_add(control_transport_suffix(*bucket, "").len())
                .is_some_and(|empty_len| empty_len <= *bucket)
    })
}

pub(crate) fn pad_control_transport_frame(
    inner: &str,
    domain_limit: usize,
) -> Result<String, String> {
    let bucket = control_transport_frame_len(inner, domain_limit)
        .ok_or_else(|| "control transport padding unavailable".to_string())?;
    let prefix = inner
        .strip_suffix('}')
        .ok_or_else(|| "control transport frame rejected".to_string())?;
    let empty_suffix = control_transport_suffix(bucket, "");
    let empty_len = prefix
        .len()
        .checked_add(empty_suffix.len())
        .ok_or_else(|| "control transport padding length rejected".to_string())?;
    let filler_len = bucket
        .checked_sub(empty_len)
        .ok_or_else(|| "control transport padding length rejected".to_string())?;
    let filler = random_transport_padding(filler_len, control_transport_wire_limit(domain_limit))?;
    let padded = format!("{prefix}{}", control_transport_suffix(bucket, &filler));
    if padded.len() != bucket {
        return Err("control transport padding length rejected".to_string());
    }
    Ok(padded)
}

pub(crate) fn strip_control_transport_frame(
    text: &str,
    domain_limit: usize,
) -> Result<String, String> {
    let wire_limit = control_transport_wire_limit(domain_limit);
    if text.len() > wire_limit {
        return Err("control transport frame too large".to_string());
    }
    let value = serde_json::from_str::<serde_json::Value>(text)
        .map_err(|_| "control transport frame rejected".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "control transport frame rejected".to_string())?;
    let bucket = object
        .get("padding_bucket")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "control transport padding bucket rejected".to_string())?;
    let padding = object
        .get("padding")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "control transport padding rejected".to_string())?;
    if bucket > wire_limit
        || !CONTROL_TRANSPORT_BUCKETS.contains(&bucket)
        || !valid_transport_padding(padding, wire_limit)
    {
        return Err("control transport padding rejected".to_string());
    }
    let suffix = control_transport_suffix(bucket, padding);
    let prefix = text
        .strip_suffix(&suffix)
        .ok_or_else(|| "control transport padding suffix rejected".to_string())?;
    let inner = format!("{prefix}}}");
    if inner.len() > domain_limit {
        return Err("control transport frame too large".to_string());
    }
    let canonical_bucket = control_transport_frame_len(&inner, domain_limit)
        .ok_or_else(|| "control transport padding unavailable".to_string())?;
    let empty_len = prefix
        .len()
        .checked_add(control_transport_suffix(canonical_bucket, "").len())
        .ok_or_else(|| "control transport padding length rejected".to_string())?;
    if bucket != canonical_bucket
        || padding.len() != canonical_bucket.saturating_sub(empty_len)
        || text.len() != canonical_bucket
    {
        return Err("control transport padding length rejected".to_string());
    }
    Ok(inner)
}

fn control_transport_suffix(bucket: usize, padding: &str) -> String {
    format!(r#","padding_bucket":{bucket},"padding":"{padding}"}}"#)
}

fn valid_transport_padding(value: &str, max: usize) -> bool {
    value.len() <= max && value.bytes().all(|byte| FILLER_ALPHABET.contains(&byte))
}

fn random_transport_padding(length: usize, max: usize) -> Result<String, String> {
    if length > max {
        return Err("control transport padding length rejected".to_string());
    }
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    for byte in &mut bytes {
        *byte = FILLER_ALPHABET[usize::from(*byte & 63)];
    }
    String::from_utf8(bytes).map_err(|_| "control transport padding generation failed".to_string())
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
    fn control_frames_use_the_smallest_exact_bucket_and_strip_losslessly() {
        let inner = r#"{"type":"activity"}"#;
        let first = pad_control_transport_frame(inner, MESSAGE_TRANSPORT_MAX_BUCKET)
            .expect("first padded frame");
        let second = pad_control_transport_frame(inner, MESSAGE_TRANSPORT_MAX_BUCKET)
            .expect("second padded frame");
        assert_eq!(first.len(), 4096);
        assert_eq!(second.len(), 4096);
        assert_ne!(first, second);
        assert_eq!(
            strip_control_transport_frame(&first, MESSAGE_TRANSPORT_MAX_BUCKET),
            Ok(inner.to_string())
        );
    }

    #[test]
    fn control_padding_rejects_tampering_noncanonical_buckets_and_embedded_fields() {
        let inner = r#"{"type":"activity"}"#;
        let padded =
            pad_control_transport_frame(inner, MESSAGE_TRANSPORT_MAX_BUCKET).expect("padded frame");
        assert!(strip_control_transport_frame(
            &padded.replacen("\"padding_bucket\":4096", "\"padding_bucket\":16384", 1),
            MESSAGE_TRANSPORT_MAX_BUCKET
        )
        .is_err());
        assert!(strip_control_transport_frame(
            &padded[..padded.len() - 1],
            MESSAGE_TRANSPORT_MAX_BUCKET
        )
        .is_err());
        assert!(pad_control_transport_frame(
            r#"{"type":"activity","padding":"hidden"}"#,
            MESSAGE_TRANSPORT_MAX_BUCKET
        )
        .is_err());
    }

    #[test]
    fn large_control_frames_are_bounded_to_the_mls_wire_ceiling() {
        let inner = format!(
            r#"{{"type":"mls_application","ciphertext_b64":"{}"}}"#,
            "A".repeat(1_100_000)
        );
        assert!(pad_control_transport_frame(&inner, MESSAGE_TRANSPORT_MAX_BUCKET).is_err());
        let padded = pad_control_transport_frame(&inner, 16_777_216).expect("MLS padding");
        assert_eq!(padded.len(), 4_194_304);
        assert_eq!(
            strip_control_transport_frame(&padded, 16_777_216),
            Ok(inner)
        );
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
