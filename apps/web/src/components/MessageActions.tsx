import { MessageSquareReply, Pencil, SmilePlus, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { REACTION_EMOJI, reactionSummary, type ReactionEmoji } from "../domain/messageActions";
import type { ChatMessage } from "../domain/types";
import { Dialog, IconButton } from "./Ui";

/** Reaction counts under a message. Tapping one toggles your own reaction. */
export function MessageReactions({
  message,
  username,
  disabled,
  onToggle,
}: {
  message: ChatMessage;
  username: string;
  disabled: boolean;
  onToggle: (emoji: ReactionEmoji, active: boolean) => void;
}) {
  const summary = reactionSummary(message, username);
  if (summary.length === 0) return null;
  return (
    <div className="message-reactions" role="group" aria-label="Reactions">
      {summary.map(({ emoji, count, mine }) => (
        <button
          key={emoji}
          type="button"
          className={mine ? "is-mine" : ""}
          aria-pressed={mine}
          aria-label={`${emoji} ${count}${mine ? ", including you" : ""}`}
          disabled={disabled}
          onClick={() => onToggle(emoji, !mine)}
        >
          <span aria-hidden="true">{emoji}</span>
          <span>{count}</span>
        </button>
      ))}
    </div>
  );
}

/** Reply, react and, for your own messages, edit and delete. Shown on hover, focus or touch. */
export function MessageActionBar({
  message,
  username,
  disabled,
  onReply,
  onReact,
  onEdit,
  onDelete,
}: {
  message: ChatMessage;
  username: string;
  disabled: boolean;
  onReply: () => void;
  onReact: (emoji: ReactionEmoji, active: boolean) => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const [picking, setPicking] = useState(false);
  const pickerRef = useRef<HTMLDivElement>(null);
  const mineReactions = new Set(reactionSummary(message, username).filter((item) => item.mine).map((item) => item.emoji));

  useEffect(() => {
    if (!picking) return;
    const close = (event: PointerEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent ? event.key === "Escape" : !pickerRef.current?.contains(event.target as Node)) {
        setPicking(false);
      }
    };
    window.addEventListener("pointerdown", close);
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("pointerdown", close);
      window.removeEventListener("keydown", close);
    };
  }, [picking]);

  return (
    <div className="message-actions" ref={pickerRef}>
      <IconButton label="Reply" onClick={onReply}><MessageSquareReply size={16} /></IconButton>
      <IconButton label="React" disabled={disabled} onClick={() => setPicking((value) => !value)}><SmilePlus size={16} /></IconButton>
      {message.mine && message.kind === "text" ? (
        <IconButton label="Edit message" disabled={disabled} onClick={onEdit}><Pencil size={15} /></IconButton>
      ) : null}
      {message.mine ? (
        <IconButton label="Delete for everyone" disabled={disabled} onClick={onDelete}><Trash2 size={15} /></IconButton>
      ) : null}
      {picking ? (
        <div className="reaction-picker" role="menu" aria-label="Choose a reaction">
          {REACTION_EMOJI.map((emoji) => (
            <button
              key={emoji}
              type="button"
              role="menuitemcheckbox"
              aria-checked={mineReactions.has(emoji)}
              className={mineReactions.has(emoji) ? "is-mine" : ""}
              onClick={() => {
                setPicking(false);
                onReact(emoji, !mineReactions.has(emoji));
              }}
            >
              {emoji}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function DeleteMessageDialog({ onConfirm, onClose }: { onConfirm: () => void; onClose: () => void }) {
  return (
    <Dialog
      title="Delete for everyone?"
      description="The message is removed from this conversation in every Abyssal app that still has it. Anyone who already read it may have kept a copy."
      onClose={onClose}
      actions={(
        <>
          <button type="button" className="secondary-button" onClick={onClose}>Cancel</button>
          <button type="button" className="danger-button" onClick={onConfirm}>Delete</button>
        </>
      )}
    >
      {null}
    </Dialog>
  );
}
