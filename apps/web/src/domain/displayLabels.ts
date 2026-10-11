import type { ChatMessage, DirectRecord, RoomRecord } from "./types";

const ACCOUNT_ID = /^acct_([0-9a-f]{8,})$/iu;

/** Shortens a generated account ID for display; the full ID stays available as a tooltip. */
export function shortAccountId(username: string): string {
  const match = ACCOUNT_ID.exec(username);
  if (!match) return username;
  const hex = match[1];
  return `${hex.slice(0, 4)}…${hex.slice(-4)}`;
}

/** Shortens an opaque room ID such as `forum_<hex>` for display. */
export function shortRoomId(roomId: string): string {
  const body = roomId.replace(/^forum_/u, "");
  return body.length > 12 ? `${body.slice(0, 4)}…${body.slice(-4)}` : body;
}

/**
 * A room's display name. Members who never received the owner's room name see
 * the opaque ID as the name; show that shortened rather than as 32 hex digits.
 */
export function roomLabel(room: { id: string; name: string }): string {
  const body = room.id.replace(/^forum_/u, "");
  return room.name && room.name !== body.slice(0, 36) ? room.name : `Room ${shortRoomId(room.id)}`;
}

/** Two-character avatar text for an account or display name. */
export function accountInitials(label: string): string {
  const match = ACCOUNT_ID.exec(label);
  const source = match ? match[1] : label.replace(/[^A-Za-z0-9]/gu, "");
  return (source.slice(0, 2) || "?").toUpperCase();
}

/**
 * The most recent self-chosen display name seen from each sender. Names are
 * unverified labels, so callers must keep showing the account ID beside them.
 */
export function displayNamesBySender(messages: Readonly<Record<string, readonly ChatMessage[]>>): Map<string, string> {
  const names = new Map<string, { name: string; at: number }>();
  for (const list of Object.values(messages)) {
    for (const message of list) {
      if (message.mine || !message.senderDisplayName) continue;
      const key = message.sender.toLowerCase();
      const known = names.get(key);
      if (!known || known.at <= message.createdAtMs) names.set(key, { name: message.senderDisplayName, at: message.createdAtMs });
    }
  }
  return new Map([...names].map(([key, value]) => [key, value.name]));
}

export interface ConversationEntry {
  id: string;
  kind: "room" | "direct";
  label: string;
  /** Extra text a search may match, such as the full account or room ID. */
  searchText: string;
}

/** Every open conversation in sidebar order: rooms first, then direct messages. */
export function conversationEntries(
  rooms: readonly RoomRecord[],
  directs: readonly DirectRecord[],
  displayNames: ReadonlyMap<string, string>,
): ConversationEntry[] {
  return [
    ...rooms.map((room) => ({ id: room.id, kind: "room" as const, label: roomLabel(room), searchText: room.id })),
    ...directs.map((direct) => ({
      id: direct.id,
      kind: "direct" as const,
      label: displayNames.get(direct.peer_username.toLowerCase()) ?? shortAccountId(direct.peer_username),
      searchText: direct.peer_username,
    })),
  ];
}

/** Case-insensitive match on the label or the underlying ID. */
export function filterConversations(entries: readonly ConversationEntry[], query: string): ConversationEntry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [...entries];
  return entries.filter((entry) => entry.label.toLowerCase().includes(needle) || entry.searchText.toLowerCase().includes(needle));
}
