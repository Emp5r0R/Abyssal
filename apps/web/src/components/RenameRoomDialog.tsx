import { useState, type FormEvent } from "react";
import { MAX_ROOM_NAME, validRoomName } from "../domain/roomProfile";
import { Dialog, Field } from "./Ui";

/** The owner renames a room. Members on current apps see the new name; older apps keep the old one. */
export function RenameRoomDialog({
  currentName,
  connected,
  onRename,
  onClose,
}: {
  currentName: string;
  connected: boolean;
  onRename: (name: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const [name, setName] = useState(currentName);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const valid = validRoomName(name) && name.trim() !== currentName;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    setFailed(false);
    const renamed = await onRename(name.trim());
    setBusy(false);
    if (renamed) onClose();
    else setFailed(true);
  };

  return (
    <Dialog
      title="Rename room"
      description="The new name is sent end-to-end encrypted to everyone in the room."
      onClose={onClose}
      actions={(
        <>
          <button className="secondary-button" type="button" onClick={onClose}>Cancel</button>
          <button className="primary-button" type="submit" form="rename-room-form" disabled={!valid || busy || !connected}>
            {busy ? "Saving…" : "Save"}
          </button>
        </>
      )}
    >
      <form id="rename-room-form" onSubmit={submit}>
        <Field
          label="Room name"
          value={name}
          maxLength={MAX_ROOM_NAME}
          autoFocus
          hint={`Up to ${MAX_ROOM_NAME} characters.`}
          onChange={(event) => { setFailed(false); setName(event.target.value); }}
        />
        {failed ? <p className="field-error" role="alert">Could not rename the room. Try again when the relay is connected.</p> : null}
      </form>
    </Dialog>
  );
}
