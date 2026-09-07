//! Bounded HTTP upload framing. Metadata stays out of request URLs and headers.
use super::*;

const PREFIX_BYTES: usize = 1024;
const MAGIC: &[u8; 8] = b"ABYUP001";
const PREFIX_TIMEOUT: Duration = Duration::from_secs(10);

fn decode_prefix(prefix: &[u8]) -> Result<AttachmentQuery, StatusCode> {
    if prefix.len() != PREFIX_BYTES || &prefix[..8] != MAGIC {
        return Err(StatusCode::BAD_REQUEST);
    }
    let length = u16::from_be_bytes([prefix[8], prefix[9]]) as usize;
    if length == 0 || length > PREFIX_BYTES - 10 || prefix[10 + length..].iter().any(|b| *b != 0) {
        return Err(StatusCode::BAD_REQUEST);
    }
    serde_json::from_slice(&prefix[10..10 + length]).map_err(|_| StatusCode::BAD_REQUEST)
}

async fn read_prefix(body: Body, timeout: Duration) -> Result<(AttachmentQuery, Body), StatusCode> {
    tokio::time::timeout(timeout, async move {
        let mut stream = body.into_data_stream();
        let mut prefix = Zeroizing::new([0u8; PREFIX_BYTES]);
        let mut offset = 0;
        while offset < PREFIX_BYTES {
            let mut bytes = stream
                .next()
                .await
                .ok_or(StatusCode::BAD_REQUEST)?
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            let count = (PREFIX_BYTES - offset).min(bytes.len());
            prefix[offset..offset + count].copy_from_slice(&bytes[..count]);
            bytes = bytes.slice(count..);
            offset += count;
            if offset == PREFIX_BYTES {
                let metadata = decode_prefix(prefix.as_ref())?;
                let remaining =
                    futures_util::stream::once(async move { Ok::<_, axum::Error>(bytes) })
                        .chain(stream);
                return Ok((metadata, Body::from_stream(remaining)));
            }
            tokio::task::yield_now().await;
        }
        Err(StatusCode::BAD_REQUEST)
    })
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
}

pub(super) async fn upload_attachment_v2(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let upload_epoch = state.attachment_epoch.load(Ordering::Acquire);
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some()
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .is_none_or(|value| value != "application/octet-stream")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let auth = match auth_from_headers(&state, &parts.headers).await {
        Ok(auth) => auth,
        Err(status) => return status.into_response(),
    };
    let length = match declared_attachment_length(
        &parts.headers,
        encrypted_attachment_limit_bytes("FILE") + PREFIX_BYTES,
    ) {
        Ok(length) if length > PREFIX_BYTES => length - PREFIX_BYTES,
        Ok(_) => return StatusCode::BAD_REQUEST.into_response(),
        Err(status) => return status.into_response(),
    };
    // Slow prefix readers consume the same bounded global admission slots as uploads.
    let account_permit = match acquire_account_attachment_upload_permit(&state, &auth.code_id).await
    {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };
    let permit = match acquire_attachment_upload_permit(&state.attachment_uploads) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };
    let (metadata, body) = match read_prefix(body, PREFIX_TIMEOUT).await {
        Ok(decoded) => decoded,
        Err(status) => return status.into_response(),
    };
    drop(permit);
    drop(account_permit);
    if state.attachment_epoch.load(Ordering::Acquire) != upload_epoch {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let mut headers = parts.headers;
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    upload_attachment(State(state), Query(metadata), headers, body)
        .await
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(json: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; PREFIX_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&(json.len() as u16).to_be_bytes());
        bytes[10..10 + json.len()].copy_from_slice(json);
        bytes
    }

    #[test]
    fn strict_bounded_metadata() {
        let valid = prefix(br#"{"chat_id":"dm_Alice_Bob","message_id":"message"}"#);
        assert_eq!(decode_prefix(&valid).unwrap().chat_id, "dm_Alice_Bob");
        for json in [
            br#"{"chat_id":"a","chat_id":"b","message_id":"m"}"#.as_slice(),
            br#"{"chat_id":"a","message_id":"m","name":"secret"}"#,
            br#"{"chat_id":"a","message_id":"m","ttl_sec":-1}"#,
            br#"{"chat_id":"a"}"#,
            b"{} trailing",
            b"\xff",
            b"",
        ] {
            assert!(decode_prefix(&prefix(json)).is_err());
        }
        for index in [0, 7, 8, 9, PREFIX_BYTES - 1] {
            let mut invalid = valid.clone();
            invalid[index] ^= 0xff;
            assert!(decode_prefix(&invalid).is_err());
        }
        assert!(decode_prefix(&valid[..PREFIX_BYTES - 1]).is_err());
        assert!(decode_prefix(&[0; PREFIX_BYTES + 1]).is_err());
    }

    #[tokio::test]
    async fn fragmented_prefix_preserves_all_ciphertext() {
        let mut bytes = prefix(br#"{"chat_id":"dm_Alice_Bob","message_id":"m"}"#);
        bytes.extend_from_slice(&[3, 9, 8, 7]);
        for split in [1, 9, 1000, 1024, 1025, 1028] {
            let body = Body::from_stream(futures_util::stream::iter(vec![
                Ok::<_, Infallible>(Bytes::copy_from_slice(&bytes[..split])),
                Ok(Bytes::copy_from_slice(&bytes[split..])),
            ]));
            let (_, rest) = read_prefix(body, Duration::from_secs(1)).await.unwrap();
            assert_eq!(
                axum::body::to_bytes(rest, 4).await.unwrap().as_ref(),
                &[3, 9, 8, 7]
            );
        }
    }

    #[tokio::test]
    async fn truncated_and_stalled_prefixes_fail() {
        assert!(
            read_prefix(Body::from(vec![0; 100]), Duration::from_secs(1))
                .await
                .is_err()
        );
        let stalled =
            Body::from_stream(futures_util::stream::pending::<Result<Bytes, Infallible>>());
        assert!(matches!(
            read_prefix(stalled, Duration::from_millis(5)).await,
            Err(StatusCode::REQUEST_TIMEOUT)
        ));
        let empty_frames = Body::from_stream(futures_util::stream::repeat_with(|| {
            Ok::<_, Infallible>(Bytes::new())
        }));
        assert!(matches!(
            read_prefix(empty_frames, Duration::from_millis(5)).await,
            Err(StatusCode::REQUEST_TIMEOUT)
        ));
    }
}
