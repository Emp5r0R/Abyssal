import { useState, type FormEvent } from "react";
import { clampRoom } from "../domain/messagePolicy";
import type { RoomRecord } from "../domain/types";
import { Dialog, Field, Toggle } from "./Ui";

function newRoom(): RoomRecord {
  return {
    id: "forum_pending",
    name: "",
    self_destruct_timer_sec: 10,
    overall_expiry_sec: 300,
    allow_images: true,
    allow_videos: true,
    allow_files: true,
    enforce_text_absolute_expiry: false,
    image_read_timer_sec: 10,
    image_overall_expiry_sec: 300,
    enforce_image_absolute_expiry: false,
    video_read_timer_sec: 15,
    video_overall_expiry_sec: 600,
    enforce_video_absolute_expiry: false,
    file_read_timer_sec: 30,
    file_overall_expiry_sec: 900,
    enforce_file_absolute_expiry: false,
  };
}

export function CreateRoomDialog({ onCancel, onCreate }: { onCancel: () => void; onCreate: (room: RoomRecord) => boolean }) {
  const [room, setRoom] = useState(newRoom);
  const number = (key: keyof RoomRecord, value: string) => setRoom((current) => ({ ...current, [key]: Number(value) || 0 }));
  const boolean = (key: keyof RoomRecord, value: boolean) => setRoom((current) => ({ ...current, [key]: value }));
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const next = clampRoom(room);
    next.id = `forum_${crypto.randomUUID().replaceAll("-", "")}`;
    if (next.name && onCreate(next)) onCancel();
  };

  return (
    <Dialog
      className="room-dialog"
      title="Create room"
      description="Room policy applies to every participant."
      actions={
        <>
          <button className="secondary-button" type="button" onClick={onCancel}>CANCEL</button>
          <button className="primary-button" type="submit" form="create-room-form" disabled={!room.name.trim()}>CREATE</button>
        </>
      }
    >
      <form id="create-room-form" className="room-form" onSubmit={submit}>
        <Field label="Room name" autoFocus maxLength={36} value={room.name} onChange={(event) => setRoom((current) => ({ ...current, name: event.target.value }))} />

        <PolicySection title="Text" enabled>
          <NumberPair
            read={room.self_destruct_timer_sec}
            absolute={room.overall_expiry_sec}
            enforce={room.enforce_text_absolute_expiry}
            onRead={(value) => number("self_destruct_timer_sec", value)}
            onAbsolute={(value) => number("overall_expiry_sec", value)}
            onEnforce={(value) => boolean("enforce_text_absolute_expiry", value)}
          />
        </PolicySection>

        <PolicySection title="Images" enabled={room.allow_images} onEnabled={(value) => boolean("allow_images", value)}>
          <NumberPair
            read={room.image_read_timer_sec}
            absolute={room.image_overall_expiry_sec}
            enforce={room.enforce_image_absolute_expiry}
            onRead={(value) => number("image_read_timer_sec", value)}
            onAbsolute={(value) => number("image_overall_expiry_sec", value)}
            onEnforce={(value) => boolean("enforce_image_absolute_expiry", value)}
          />
        </PolicySection>

        <PolicySection title="Videos" enabled={room.allow_videos} onEnabled={(value) => boolean("allow_videos", value)}>
          <NumberPair
            read={room.video_read_timer_sec}
            absolute={room.video_overall_expiry_sec}
            enforce={room.enforce_video_absolute_expiry}
            onRead={(value) => number("video_read_timer_sec", value)}
            onAbsolute={(value) => number("video_overall_expiry_sec", value)}
            onEnforce={(value) => boolean("enforce_video_absolute_expiry", value)}
          />
        </PolicySection>

        <PolicySection title="Files" enabled={room.allow_files} onEnabled={(value) => boolean("allow_files", value)}>
          <NumberPair
            read={room.file_read_timer_sec}
            absolute={room.file_overall_expiry_sec}
            enforce={room.enforce_file_absolute_expiry}
            onRead={(value) => number("file_read_timer_sec", value)}
            onAbsolute={(value) => number("file_overall_expiry_sec", value)}
            onEnforce={(value) => boolean("enforce_file_absolute_expiry", value)}
          />
        </PolicySection>
      </form>
    </Dialog>
  );
}

function PolicySection({
  title,
  enabled,
  onEnabled,
  children,
}: {
  title: string;
  enabled: boolean;
  onEnabled?: (value: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <fieldset className={`policy-section ${enabled ? "" : "is-disabled"}`}>
      <legend>{title}</legend>
      {onEnabled ? <Toggle checked={enabled} onChange={onEnabled} label={`Allow ${title.toLowerCase()}`} /> : null}
      <div className="policy-fields">{children}</div>
    </fieldset>
  );
}

function NumberPair({
  read,
  absolute,
  enforce,
  onRead,
  onAbsolute,
  onEnforce,
}: {
  read: number;
  absolute: number;
  enforce: boolean;
  onRead: (value: string) => void;
  onAbsolute: (value: string) => void;
  onEnforce: (value: boolean) => void;
}) {
  return (
    <>
      <Field label="After read (seconds, 0 = never)" type="number" inputMode="numeric" min={0} max={86400} value={read} onChange={(event) => onRead(event.target.value)} />
      <Field label="Absolute lifetime (seconds)" type="number" inputMode="numeric" min={0} max={86400} value={absolute} disabled={!enforce} onChange={(event) => onAbsolute(event.target.value)} />
      <Toggle checked={enforce} onChange={onEnforce} label="Enforce absolute lifetime" />
    </>
  );
}
