import { FileArchive, Image, Upload, Video, X } from "lucide-react";
import { useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { classifyMedia, MEDIA_LIMIT_BYTES, mediaAllowed } from "../domain/messagePolicy";
import { formatBytes } from "../domain/format";
import type { AttachmentOptions, RoomRecord } from "../domain/types";
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
  const [file, setFile] = useState<File | null>(null);
  const [oneTime, setOneTime] = useState(false);
  const [deleteAfterDownload, setDeleteAfterDownload] = useState(false);
  const [busy, setBusy] = useState(false);

  const choose = () => {
    onPickerState(true);
    inputRef.current?.click();
  };
  const selected = (event: ChangeEvent<HTMLInputElement>) => {
    onPickerState(false);
    const next = event.target.files?.[0] ?? null;
    if (!next) return;
    const type = classifyMedia(next);
    if (next.size <= 0 || next.size > MEDIA_LIMIT_BYTES[type] || !mediaAllowed(room, type)) return;
    setFile(next);
    if (type === "FILE") setOneTime(false);
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file || busy) return;
    setBusy(true);
    const accepted = await onSend(file, { oneTime, deleteAfterDownload, ttlSec: 0 });
    setBusy(false);
    if (accepted) onCancel();
  };
  const mediaType = file ? classifyMedia(file) : null;

  return (
    <Dialog
      title="Encrypted attachment"
      description={`Plaintext stays in current browser process. ${retentionSec === 0 ? "No read expiry." : `Expires ${retentionSec}s after read.`}`}
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
              <strong>{file.name}</strong>
              <span>{formatBytes(file.size)} · {mediaType}</span>
            </div>
            <IconButton label="Remove attachment" onClick={() => setFile(null)}><X size={18} /></IconButton>
          </div>
        ) : (
          <button className="file-drop" type="button" onClick={choose}>
            <Upload size={24} />
            <strong>CHOOSE FILE</strong>
            <span>Images 20 MB · Videos 100 MB · Files 200 MB</span>
          </button>
        )}
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
