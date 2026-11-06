import { UserMinus } from "lucide-react";
import { useState } from "react";
import { accountInitials, shortAccountId } from "../domain/displayLabels";
import { PrivacyBlur } from "./PrivacyBlur";
import { Dialog } from "./Ui";

/**
 * Who is in a room. The owner can remove anyone else; the removed member's
 * app drops the room and later messages are encrypted without them.
 */
export function RoomMembersDialog({
  members,
  ownerUsername,
  username,
  displayNames,
  connected,
  onRemove,
  onClose,
}: {
  members: string[];
  ownerUsername?: string;
  username: string;
  displayNames: ReadonlyMap<string, string>;
  connected: boolean;
  onRemove?: (member: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const [confirming, setConfirming] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const isOwner = !!ownerUsername && ownerUsername.toLowerCase() === username.toLowerCase();
  const sorted = [...members].sort((left, right) => rank(left) - rank(right) || label(left).localeCompare(label(right)));

  function rank(member: string): number {
    if (ownerUsername && member.toLowerCase() === ownerUsername.toLowerCase()) return 0;
    return member.toLowerCase() === username.toLowerCase() ? 1 : 2;
  }

  function label(member: string): string {
    return displayNames.get(member.toLowerCase()) ?? shortAccountId(member);
  }

  async function remove(member: string) {
    if (!onRemove) return;
    setBusy(true);
    setFailed(false);
    const removed = await onRemove(member);
    setBusy(false);
    if (removed) setConfirming(null);
    else setFailed(true);
  }

  if (confirming) {
    return (
      <Dialog
        title="Remove from room?"
        description={`${label(confirming)} stops receiving messages in this room. They can ask to join again.`}
        onClose={() => setConfirming(null)}
        actions={(
          <>
            <button className="secondary-button" type="button" disabled={busy} onClick={() => setConfirming(null)}>Cancel</button>
            <button className="danger-button" type="button" disabled={busy || !connected} onClick={() => void remove(confirming)}>
              {busy ? "Removing…" : "Remove"}
            </button>
          </>
        )}
      >
        {failed ? <p className="field-error" role="alert">Could not remove this member. Try again when the relay is connected.</p> : null}
      </Dialog>
    );
  }

  return (
    <Dialog title={`Members (${members.length})`} onClose={onClose}>
      <ul className="member-list">
        {sorted.map((member) => {
          const isRoomOwner = rank(member) === 0;
          const isYou = member.toLowerCase() === username.toLowerCase();
          return (
            <li key={member}>
              <span className="avatar" aria-hidden="true">{accountInitials(label(member))}</span>
              <span className="member-name">
                <PrivacyBlur><strong>{label(member)}</strong></PrivacyBlur>
                <small>{shortAccountId(member)}{isRoomOwner ? " · Owner" : ""}{isYou ? " · You" : ""}</small>
              </span>
              {isOwner && !isYou && !isRoomOwner && onRemove ? (
                <button
                  type="button"
                  className="secondary-button is-compact"
                  disabled={!connected}
                  aria-label={`Remove ${label(member)}`}
                  onClick={() => { setFailed(false); setConfirming(member); }}
                >
                  <UserMinus size={15} aria-hidden="true" />Remove
                </button>
              ) : null}
            </li>
          );
        })}
      </ul>
    </Dialog>
  );
}
