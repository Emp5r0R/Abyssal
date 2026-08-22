//! Strict JSON representation helpers for protocol-v10 MLS counters.
//!
//! JSON numbers are deliberately excluded: JavaScript clients cannot represent
//! every `u64` exactly.  The protocol therefore uses canonical decimal strings
//! for all MLS epochs, revisions, and policy durations.

use serde::{de::Error, Deserialize, Deserializer, Serializer};

pub(crate) mod decimal_u64 {
    use super::*;

    pub(crate) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 1 && value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(D::Error::custom("invalid canonical decimal u64"));
        }
        value
            .parse::<u64>()
            .map_err(|_| D::Error::custom("decimal u64 out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::decimal_u64;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Counter {
        #[serde(with = "decimal_u64")]
        value: u64,
    }

    #[test]
    fn canonical_decimal_u64_round_trips_as_a_string() {
        let counter = Counter { value: u64::MAX };
        let encoded = serde_json::to_string(&counter).expect("counter JSON");
        assert_eq!(encoded, r#"{"value":"18446744073709551615"}"#);
        assert_eq!(serde_json::from_str::<Counter>(&encoded).unwrap(), counter);
    }

    #[test]
    fn canonical_decimal_u64_rejects_noncanonical_values_and_numbers() {
        for value in [
            r#"{"value":""}"#,
            r#"{"value":"+1"}"#,
            r#"{"value":"-1"}"#,
            r#"{"value":" 1"}"#,
            r#"{"value":"1 "}"#,
            r#"{"value":"01"}"#,
            r#"{"value":"1.0"}"#,
            r#"{"value":"abc"}"#,
            r#"{"value":"18446744073709551616"}"#,
            r#"{"value":1}"#,
            r#"{"value":18446744073709551615}"#,
        ] {
            assert!(serde_json::from_str::<Counter>(value).is_err(), "{value}");
        }
    }
}
