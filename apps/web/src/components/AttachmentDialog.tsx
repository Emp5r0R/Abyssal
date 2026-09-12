import { FileArchive, Image, Upload, Video, X } from "lucide-react";
import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { classifyMedia, MEDIA_LIMIT_BYTES, mediaAllowed } from "../domain/messagePolicy";
import { formatBytes } from "../domain/format";
import type { AttachmentOptions, RoomRecord } from "../domain/types";
import { PrivacyBlur } from "./PrivacyBlur";
import { Dialog, IconButton, Toggle } from "./Ui";

export function AttachmentDialog({
  room,
  retentionSec,
  onCancel,
  onPickerState,
  onSend,
}: {
  room: RoomRecord;
  retentionSec: number;
  onCancel: () => void;
  onPickerState: (active: boolean) => void;
  onSend: (file: File, options: AttachmentOptions) => Promise<boolean>;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const pickerStateRef = useRef(onPickerState);
  const [file, setFile] = useState<File | null>(null);
  const [oneTime, setOneTime] = useState(false);
  const [deleteAfterDownload, setDeleteAfterDownload] = useState(false);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  useEffect(() => {
    pickerStateRef.current = onPickerState;
  }, [onPickerState]);

  useEffect(() => {
    const input = inputRef.current;
    if (!input) return undefined;
    const resetPickerState = () => pickerStateRef.current(false);
    input.addEventListener("cancel", resetPickerState);
    return () => input.removeEventListener("cancel", resetPickerState);
  }, []);

  useEffect(() => () => pickerStateRef.current(false), []);

  const choose = () => {
    onPickerState(true);
    inputRef.current?.click();
  };
  const selected = (event: ChangeEvent<HTMLInputElement>) => {
    onPickerState(false);
    const next = event.target.files?.[0] ?? null;
    event.currentTarget.value = "";
    if (!next) return;
    const type = classifyMedia(next);
    if (next.size <= 0) {
      setFile(null);
      setFeedback("Choose a non-empty file.");
      return;
    }
    if (next.size > MEDIA_LIMIT_BYTES[type]) {
      setFile(null);
      setFeedback(`File exceeds the ${type.toLowerCase()} limit of ${formatBytes(MEDIA_LIMIT_BYTES[type])}.`);
      return;
    }
    if (!mediaAllowed(room, type)) {
      setFile(null);
      setFeedback(`This room does not allow ${type.toLowerCase()} attachments.`);
      return;
    }
    setFile(next);
    setFeedback(null);
    if (type === "FILE") setOneTime(false);
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file || busy) return;
    setBusy(true);
    try {
      const accepted = await onSend(file, { oneTime, deleteAfterDownload, ttlSec: 0 });
      if (accepted) onCancel();
      else setFeedback("Attachment could not be sent. Try again.");
    } catch {
      setFeedback("Attachment could not be sent. Try again.");
    } finally {
      setBusy(false);
    }
  };
  const mediaType = file ? classifyMedia(file) : null;

  return (
    <Dialog
      title="Encrypted attachment"
      description={`Plaintext stays in current browser process. ${retentionSec === 0 ? "No read expiry." : `Expires ${retentionSec}s after read.`}`}
      onClose={onCancel}
      actions={
        <>
          <button className="secondary-button" type="button" onClick={onCancel}>CANCEL</button>
          <button className="primary-button" type="submit" form="attachment-form" disabled={!file || busy}>
            <Upload size={17} /> {busy ? "UPLOADING" : "SEND"}
          </button>
        </>
      }
    >
      <form id="attachment-form" className="attachment-form" onSubmit={submit}>
        <input
          ref={inputRef}
          className="sr-only"
          type="file"
          onChange={selected}
          tabIndex={-1}
        />
        {file ? (
          <div className="selected-file">
            <div className={`file-type-mark type-${mediaType?.toLowerCase()}`}>{mediaIcon(mediaType)}</div>
            <div>
              <PrivacyBlur><strong>{file.name}</strong></PrivacyBlur>
              <PrivacyBlur><span>{formatBytes(file.size)} · {mediaType}</span></PrivacyBlur>
            </div>
            <IconButton label="Remove attachment" onClick={() => { setFile(null); setFeedback(null); }}><X size={18} /></IconButton>
          </div>
        ) : (
          <button className="file-drop" type="button" onClick={choose}>
            <Upload size={24} />
            <strong>CHOOSE FILE</strong>
            <span>Images 20 MB · Videos 100 MB · Files 200 MB</span>
          </button>
        )}
        {feedback ? <p className="form-feedback" role="status" aria-live="polite">{feedback}</p> : null}
        <div className="attachment-options">
          <Toggle
            checked={oneTime}
            onChange={setOneTime}
            disabled={mediaType === "FILE" || !file}
            label="One-time view"
          />
          <Toggle
            checked={deleteAfterDownload || oneTime}
            onChange={setDeleteAfterDownload}
            disabled={oneTime || !file}
            label="Delete after recipient download"
          />
        </div>
      </form>
    </Dialog>
  );
}

function mediaIcon(type: ReturnType<typeof classifyMedia> | null) {
  if (type === "IMAGE") return <Image size={22} />;
  if (type === "VIDEO") return <Video size={22} />;
  return <FileArchive size={22} />;
}
