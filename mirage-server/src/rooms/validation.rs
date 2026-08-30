//! Canonical identifiers, rosters, and protocol-boundary validation.

use super::*;

pub(super) fn changed_usernames(
    current: &BTreeMap<String, Member>,
    next: &BTreeMap<String, Member>,
) -> HashSet<String> {
    current
        .keys()
        .chain(next.keys())
        .filter(|username| {
            current
                .get(*username)
                .map(|member| (&member.code_id, &member.stable_identity))
                != next
                    .get(*username)
                    .map(|member| (&member.code_id, &member.stable_identity))
        })
        .cloned()
        .collect()
}

pub(super) fn canonical_username(value: &str) -> Result<String, String> {
    validate_username(value)?;
    Ok(value.to_ascii_lowercase())
}

pub(super) fn roster_size(roster: &[RosterMember]) -> Result<usize, String> {
    roster.iter().try_fold(0_usize, |total, member| {
        total
            .checked_add(member.username.len())
            .and_then(|bytes| bytes.checked_add(member.stable_identity.len()))
            .ok_or_else(|| "state snapshot accounting rejected".to_string())
    })
}

pub(super) fn snapshot_size(snapshot: &StateSnapshot) -> Result<usize, String> {
    snapshot
        .state_envelope
        .len()
        .checked_add(roster_size(&snapshot.roster)?)
        .ok_or_else(|| "state snapshot accounting rejected".to_string())
}

pub(super) fn canonical_room_roster(room: &RelayRoom) -> Result<Vec<RosterMember>, String> {
    room.members
        .values()
        .map(|member| {
            Ok(RosterMember {
                username: canonical_username(&member.username)?,
                stable_identity: member.stable_identity.clone(),
            })
        })
        .collect()
}

pub(super) fn rosters_match_room(
    roster: &[RosterMember],
    room: &RelayRoom,
) -> Result<bool, String> {
    let candidate = roster_map(roster)?;
    if candidate.len() != room.members.len() {
        return Ok(false);
    }
    Ok(candidate.iter().all(|(username, member)| {
        room.members.get(username).is_some_and(|current| {
            current.code_id != [0_u8; 32] && current.stable_identity == member.stable_identity
        })
    }))
}

pub(super) fn roster_map(roster: &[RosterMember]) -> Result<BTreeMap<String, Member>, String> {
    if roster.is_empty() || roster.len() > MAX_MEMBERS {
        return Err("membership roster rejected".to_string());
    }
    let mut members = BTreeMap::new();
    let mut identities = HashSet::new();
    for member in roster {
        validate_username(&member.username)?;
        validate_stable_identity(&member.stable_identity)?;
        let canonical = canonical_username(&member.username)?;
        if !identities.insert(member.stable_identity.clone()) || members.contains_key(&canonical) {
            return Err("membership roster rejected".to_string());
        }
        // New-member code IDs are bound from their JoinRequest in
        // `begin_membership`; existing members use a sentinel until then.
        members.insert(
            canonical,
            Member {
                username: member.username.clone(),
                code_id: [0_u8; 32],
                stable_identity: member.stable_identity.clone(),
                active: false,
            },
        );
    }
    Ok(members)
}

pub(super) fn resolve_next_roster(
    room: &RelayRoom,
    transition: &MembershipTransition,
) -> Result<BTreeMap<String, Member>, String> {
    let requested_next = roster_map(&transition.roster)?;
    let mut next = BTreeMap::new();
    for (username, member) in requested_next {
        if let Some(current) = room.members.get(&username) {
            if current.stable_identity != member.stable_identity {
                return Err("membership roster identity changed".to_string());
            }
            next.insert(username, current.clone());
        } else {
            let request = transition
                .request_id
                .as_ref()
                .and_then(|id| room.joins.get(id))
                .ok_or_else(|| "join request required".to_string())?;
            if canonical_username(&request.request.username)? != username
                || request.request.stable_identity != member.stable_identity
            {
                return Err("join request binding rejected".to_string());
            }
            next.insert(
                username,
                Member {
                    username: request.request.username.clone(),
                    code_id: request.request.code_id,
                    stable_identity: member.stable_identity.clone(),
                    active: false,
                },
            );
        }
    }
    Ok(next)
}

pub(super) fn validate_transition(transition: &MembershipTransition) -> Result<(), String> {
    validate_room_id(&transition.room_id)?;
    validate_request_id(&transition.message_id)?;
    if let Some(request_id) = &transition.request_id {
        validate_request_id(request_id)?;
    }
    validate_group_id(&transition.group_id)?;
    validate_digest(&transition.membership_digest)?;
    if transition.control.is_empty() || transition.control.len() > MAX_CONTROL_BYTES {
        return Err("membership control rejected".to_string());
    }
    if transition.welcome.len() > MAX_CONTROL_BYTES {
        return Err("membership welcome rejected".to_string());
    }
    if transition.authenticated_data.is_empty()
        || transition.authenticated_data.len() > MAX_AUTHENTICATED_DATA_BYTES
    {
        return Err("membership authenticated data rejected".to_string());
    }
    if transition.state_envelope.is_empty() || transition.state_envelope.len() > MAX_STATE_BYTES {
        return Err("membership state rejected".to_string());
    }
    Ok(())
}

pub(super) fn validate_current_metadata(
    room: &RelayRoom,
    group_id: &[u8],
    epoch: u64,
    membership_digest: &[u8],
) -> Result<(), String> {
    if room.group_id != group_id
        || room.epoch != epoch
        || room.membership_digest != membership_digest
    {
        return Err("room checkpoint rejected".to_string());
    }
    Ok(())
}

pub(super) fn validate_room_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_ROOM_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("room id rejected".to_string());
    }
    Ok(())
}

pub(super) fn validate_request_id(value: &str) -> Result<(), String> {
    validate_room_id(value).map_err(|_| "message id rejected".to_string())
}

pub(super) fn validate_username(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_USERNAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("username rejected".to_string());
    }
    Ok(())
}

pub(super) fn validate_group_id(value: &[u8]) -> Result<(), String> {
    if value.len() != GROUP_ID_BYTES || value.iter().all(|byte| *byte == 0) {
        return Err("group id rejected".to_string());
    }
    Ok(())
}

pub(super) fn validate_digest(value: &[u8]) -> Result<(), String> {
    if value.len() != MEMBERSHIP_DIGEST_BYTES {
        return Err("membership digest rejected".to_string());
    }
    Ok(())
}

pub(super) fn validate_stable_identity(value: &[u8]) -> Result<(), String> {
    if value.len() != STABLE_IDENTITY_BYTES || value.iter().all(|byte| *byte == 0) {
        return Err("stable identity rejected".to_string());
    }
    Ok(())
}

pub(super) fn validate_state_envelope(value: &[u8]) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_STATE_BYTES {
        return Err("state snapshot rejected".to_string());
    }
    Ok(())
}
