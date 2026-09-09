use uuid::Uuid;

/// Public routing identifier, independent of client display profiles and credentials.
fn new_account_id() -> String {
    format!("acct_{}", Uuid::new_v4().simple())
}

pub(super) fn unique_account_id(mut is_taken: impl FnMut(&str) -> bool) -> Option<String> {
    (0..128)
        .map(|_| new_account_id())
        .find(|candidate| !is_taken(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn collision_retries_are_bounded_and_never_return_an_occupied_id() {
        let mut attempts = 0;
        assert!(unique_account_id(|_| {
            attempts += 1;
            true
        })
        .is_none());
        assert_eq!(attempts, 128);
        attempts = 0;
        assert!(unique_account_id(|_| {
            attempts += 1;
            attempts < 3
        })
        .is_some());
        assert_eq!(attempts, 3);
    }

    #[test]
    fn account_ids_are_canonical_random_and_protocol_compatible() {
        let mut seen = HashSet::new();
        for _ in 0..1024 {
            let id = new_account_id();
            assert_eq!(id.len(), 37);
            assert!(crate::valid_username(&id));
            let uuid = Uuid::parse_str(id.strip_prefix("acct_").unwrap()).unwrap();
            assert_eq!(uuid.get_version_num(), 4);
            assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
            assert_eq!(format!("acct_{}", uuid.simple()), id);
            assert!(seen.insert(id));
        }
    }
}
