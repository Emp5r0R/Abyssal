//! Incremental transport-v11 attachment stream I/O.

use super::*;
use abyssal_transport::{
    AttachmentFrame, AttachmentStreamOpener, AttachmentStreamSealer, ATTACHMENT_STREAM_FRAME_BYTES,
    ATTACHMENT_STREAM_PAYLOAD_BYTES,
};

pub(super) struct ReceivedAttachmentStream {
    pub(super) ciphertext: Zeroizing<Vec<u8>>,
    pub(super) ciphertext_digest: [u8; 32],
}

pub(super) async fn receive_upload_stream(
    body: Body,
    mut opener: AttachmentStreamOpener,
    ciphertext_len: usize,
    epoch: Arc<AtomicU64>,
    captured_epoch: u64,
) -> Result<ReceivedAttachmentStream, ()> {
    let data_frames =
        abyssal_transport::attachment_data_frame_count(ciphertext_len as u64).map_err(|_| ())?;
    let bucket_frames =
        abyssal_transport::attachment_bucket_frame_count(data_frames).map_err(|_| ())?;
    let expected_stream_bytes = bucket_frames
        .checked_add(1)
        .and_then(|frames| usize::from(frames).checked_mul(ATTACHMENT_STREAM_FRAME_BYTES))
        .ok_or(())?;
    let deadline = tokio::time::Instant::now() + ATTACHMENT_UPLOAD_TOTAL_TIMEOUT;
    let mut stream = body.into_data_stream();
    let mut frame = Zeroizing::new(Vec::with_capacity(ATTACHMENT_STREAM_FRAME_BYTES));
    let mut ciphertext = Zeroizing::new(Vec::with_capacity(ciphertext_len));
    let mut ciphertext_hasher = Sha256::new();
    let mut stream_bytes = 0usize;
    let mut ended = false;

    loop {
        let idle_deadline =
            (tokio::time::Instant::now() + ATTACHMENT_UPLOAD_IDLE_TIMEOUT).min(deadline);
        let next = tokio::time::timeout_at(idle_deadline, stream.next())
            .await
            .map_err(|_| ())?;
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(|_| ())?;
        if chunk.is_empty() {
            continue;
        }
        stream_bytes = stream_bytes.checked_add(chunk.len()).ok_or(())?;
        if stream_bytes > expected_stream_bytes {
            return Err(());
        }
        if ended {
            return Err(());
        }
        let mut offset = 0;
        while offset < chunk.len() {
            let take = (ATTACHMENT_STREAM_FRAME_BYTES - frame.len()).min(chunk.len() - offset);
            frame.extend_from_slice(&chunk[offset..offset + take]);
            offset += take;
            if frame.len() != ATTACHMENT_STREAM_FRAME_BYTES {
                continue;
            }
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return Err(());
            }
            match opener.open(&frame).map_err(|_| ())? {
                AttachmentFrame::Data(payload) => {
                    let next_len = ciphertext.len().checked_add(payload.len()).ok_or(())?;
                    if next_len > ciphertext_len {
                        return Err(());
                    }
                    ciphertext_hasher.update(payload.as_slice());
                    ciphertext.extend_from_slice(payload.as_slice());
                }
                AttachmentFrame::Padding => {}
                AttachmentFrame::End => ended = true,
            }
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return Err(());
            }
            frame.clear();
            if ended && offset != chunk.len() {
                return Err(());
            }
        }
    }
    if !ended
        || !opener.is_complete()
        || !frame.is_empty()
        || ciphertext.len() != ciphertext_len
        || stream_bytes != expected_stream_bytes
        || epoch.load(Ordering::Acquire) != captured_epoch
    {
        return Err(());
    }
    let ciphertext_digest: [u8; 32] = ciphertext_hasher.finalize().into();
    Ok(ReceivedAttachmentStream {
        ciphertext,
        ciphertext_digest,
    })
}

pub(super) async fn digest_empty_stream(body: Body) -> Result<(), ()> {
    digest_empty_stream_with_timeout(body, ATTACHMENT_UPLOAD_TOTAL_TIMEOUT).await
}

pub(super) async fn digest_empty_stream_with_timeout(
    body: Body,
    timeout: Duration,
) -> Result<(), ()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut stream = body.into_data_stream();
    loop {
        let idle_deadline =
            (tokio::time::Instant::now() + ATTACHMENT_UPLOAD_IDLE_TIMEOUT).min(deadline);
        let next = tokio::time::timeout_at(idle_deadline, stream.next())
            .await
            .map_err(|_| ())?;
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(|_| ())?;
        if !chunk.is_empty() {
            return Err(());
        }
    }
    Ok(())
}

/// Consume a retry body without opening stream records. A client may resend a
/// complete upload when the encrypted action response was lost; decrypting
/// those records again would reuse their operation-bound AEAD nonces. The
/// cached action result is authoritative, so only bounded draining is needed.
pub(super) async fn consume_retry_stream(
    body: Body,
    timeout: Duration,
    maximum_bytes: usize,
) -> Result<(), ()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut stream = body.into_data_stream();
    let mut total_bytes = 0usize;
    loop {
        let idle_deadline =
            (tokio::time::Instant::now() + ATTACHMENT_UPLOAD_IDLE_TIMEOUT).min(deadline);
        let next = tokio::time::timeout_at(idle_deadline, stream.next())
            .await
            .map_err(|_| ())?;
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(|_| ())?;
        total_bytes = total_bytes.checked_add(chunk.len()).ok_or(())?;
        if total_bytes > maximum_bytes {
            return Err(());
        }
    }
    Ok(())
}

pub(super) fn download_response(
    result_record: Vec<u8>,
    blob: Arc<AttachmentBlob>,
    mut sealer: AttachmentStreamSealer,
    permit: OwnedSemaphorePermit,
    epoch: Arc<AtomicU64>,
    captured_epoch: u64,
) -> Response {
    let (sender, receiver) = mpsc::channel(1);
    tokio::spawn(async move {
        let _permit = permit;
        let deadline = tokio::time::Instant::now() + ATTACHMENT_DOWNLOAD_TOTAL_TIMEOUT;
        if send_frame(
            &sender,
            Bytes::from(result_record),
            &epoch,
            captured_epoch,
            deadline,
        )
        .await
        .is_err()
        {
            return;
        }
        for chunk in blob.bytes.chunks(ATTACHMENT_STREAM_PAYLOAD_BYTES) {
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return;
            }
            let Ok(record) = sealer.seal_data(chunk) else {
                return;
            };
            if send_frame(
                &sender,
                Bytes::copy_from_slice(record.as_slice()),
                &epoch,
                captured_epoch,
                deadline,
            )
            .await
            .is_err()
            {
                return;
            }
        }
        let padding_frames = sealer
            .bucket_frame_count()
            .saturating_sub(sealer.data_frame_count());
        for _ in 0..padding_frames {
            if epoch.load(Ordering::Acquire) != captured_epoch {
                return;
            }
            let Ok(record) = sealer.seal_padding() else {
                return;
            };
            if send_frame(
                &sender,
                Bytes::copy_from_slice(record.as_slice()),
                &epoch,
                captured_epoch,
                deadline,
            )
            .await
            .is_err()
            {
                return;
            }
        }
        if epoch.load(Ordering::Acquire) != captured_epoch {
            return;
        }
        let Ok(record) = sealer.seal_end() else {
            return;
        };
        let _ = send_frame(
            &sender,
            Bytes::copy_from_slice(record.as_slice()),
            &epoch,
            captured_epoch,
            deadline,
        )
        .await;
    });
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|chunk| (Ok::<Bytes, Infallible>(chunk), receiver))
    });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub(super) fn record_only_response(record: Vec<u8>) -> Response {
    let stream =
        futures_util::stream::once(async move { Ok::<Bytes, Infallible>(Bytes::from(record)) });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn send_frame(
    sender: &mpsc::Sender<Bytes>,
    frame: Bytes,
    epoch: &Arc<AtomicU64>,
    captured_epoch: u64,
    deadline: tokio::time::Instant,
) -> Result<(), ()> {
    if epoch.load(Ordering::Acquire) != captured_epoch {
        return Err(());
    }
    let send_deadline =
        (tokio::time::Instant::now() + ATTACHMENT_DOWNLOAD_STALL_TIMEOUT).min(deadline);
    tokio::time::timeout_at(send_deadline, sender.send(frame))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    if epoch.load(Ordering::Acquire) != captured_epoch {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_transport::{AttachmentStreamBinding, Direction};

    const NODE: [u8; 32] = [3; 32];
    const SESSION: [u8; 32] = [4; 32];
    const ROOT: [u8; 32] = [5; 32];
    const HANDLE: [u8; 16] = [6; 16];

    fn framed_upload() -> Vec<u8> {
        let mut sealer = AttachmentStreamBinding::new(NODE, SESSION, HANDLE)
            .unwrap()
            .into_sealer(&ROOT, Direction::ClientToServer, 1)
            .unwrap();
        let data = sealer.seal_data(&[0xA5]).unwrap();
        let end = sealer.seal_end().unwrap();
        let mut body = Vec::with_capacity(data.len() + end.len());
        body.extend_from_slice(&data);
        body.extend_from_slice(&end);
        body
    }

    #[tokio::test]
    async fn fragmented_records_are_reassembled_and_hashed() {
        let body = framed_upload();
        let chunks = body
            .chunks(ATTACHMENT_STREAM_FRAME_BYTES / 2)
            .map(|chunk| Ok::<Bytes, axum::Error>(Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>();
        let opener = AttachmentStreamBinding::new(NODE, SESSION, HANDLE)
            .unwrap()
            .into_opener(&ROOT, Direction::ClientToServer, 1, 1, 1)
            .unwrap();
        let result = receive_upload_stream(
            Body::from_stream(futures_util::stream::iter(chunks)),
            opener,
            1,
            Arc::new(AtomicU64::new(0)),
            0,
        )
        .await
        .unwrap();
        assert_eq!(result.ciphertext.as_slice(), &[0xA5]);
        let expected_digest: [u8; 32] = Sha256::digest([0xA5]).into();
        assert_eq!(result.ciphertext_digest, expected_digest);
    }

    #[tokio::test]
    async fn trailing_record_bytes_and_epoch_change_fail_closed() {
        let mut body = framed_upload();
        body.push(0xFF);
        let opener = AttachmentStreamBinding::new(NODE, SESSION, HANDLE)
            .unwrap()
            .into_opener(&ROOT, Direction::ClientToServer, 1, 1, 1)
            .unwrap();
        assert!(
            receive_upload_stream(Body::from(body), opener, 1, Arc::new(AtomicU64::new(0)), 0,)
                .await
                .is_err()
        );

        let epoch = Arc::new(AtomicU64::new(1));
        let opener = AttachmentStreamBinding::new(NODE, SESSION, HANDLE)
            .unwrap()
            .into_opener(&ROOT, Direction::ClientToServer, 1, 1, 1)
            .unwrap();
        assert!(
            receive_upload_stream(Body::from(framed_upload()), opener, 1, epoch, 0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cached_retry_body_is_drained_without_opening_or_overflowing() {
        assert!(
            consume_retry_stream(Body::from(vec![1, 2, 3]), Duration::from_secs(1), 3)
                .await
                .is_ok()
        );
        assert!(
            consume_retry_stream(Body::from(vec![1, 2, 3, 4]), Duration::from_secs(1), 3)
                .await
                .is_err()
        );
    }
}
