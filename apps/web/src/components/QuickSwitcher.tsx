import { Hash, MessageCircle, Search } from "lucide-react";
import { useId, useMemo, useState, type KeyboardEvent } from "react";
import { filterConversations, type ConversationEntry } from "../domain/displayLabels";
import { PrivacyBlur } from "./PrivacyBlur";
import { Dialog } from "./Ui";

/** Ctrl/⌘+K: type to filter conversations, arrows to move, Enter to open. */
export function QuickSwitcher({ conversations, onOpen, onClose }: {
  conversations: readonly ConversationEntry[];
  onOpen: (id: string) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const listId = useId();
  const matches = useMemo(() => filterConversations(conversations, query), [conversations, query]);
  const active = Math.min(selected, Math.max(0, matches.length - 1));

  const open = (entry: ConversationEntry | undefined) => {
    if (!entry) return;
    onOpen(entry.id);
    onClose();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (matches.length === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      setSelected((active + step + matches.length) % matches.length);
    } else if (event.key === "Enter") {
      event.preventDefault();
      open(matches[active]);
    }
  };

  return (
    <Dialog title="Jump to a conversation" className="quick-switcher" onClose={onClose}>
      <label className="quick-switcher-search">
        <Search size={16} aria-hidden="true" />
        <input
          autoFocus
          aria-label="Search conversations"
          aria-controls={listId}
          aria-activedescendant={matches[active] ? `${listId}-${active}` : undefined}
          placeholder="Room or person"
          value={query}
          onChange={(event) => { setQuery(event.target.value); setSelected(0); }}
          onKeyDown={onKeyDown}
        />
      </label>
      {matches.length === 0 ? (
        <p className="quick-switcher-empty">{conversations.length === 0 ? "No conversations yet." : "No conversations match."}</p>
      ) : (
        <ul id={listId} className="quick-switcher-list" role="listbox" aria-label="Conversations">
          {matches.map((entry, index) => (
            <li
              key={entry.id}
              id={`${listId}-${index}`}
              role="option"
              aria-selected={index === active}
              className={index === active ? "is-active" : undefined}
              onMouseEnter={() => setSelected(index)}
              onClick={() => open(entry)}
            >
              {entry.kind === "room" ? <Hash size={15} aria-hidden="true" /> : <MessageCircle size={15} aria-hidden="true" />}
              <PrivacyBlur>{entry.label}</PrivacyBlur>
              <span className="quick-switcher-kind">{entry.kind === "room" ? "Room" : "Direct"}</span>
            </li>
          ))}
        </ul>
      )}
    </Dialog>
  );
}
