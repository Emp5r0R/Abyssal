import { mentionsUsername } from "./messageAttention";
import type { ChatMessage } from "./types";

/**
 * Reactions, edits and delete-for-everyone travel as their own encrypted
 * messages, like read receipts. Clients that do not know these kinds drop them
 * without touching any other state, so they need no wire-version change.
 */

/** Emoji a message can be reacted with. A fixed set keeps payloads small and predictable. */
export const REACTION_EMOJI = ["👍", "❤️", "😂", "😮", "😢", "🙏"] as const;
export type ReactionEmoji = (typeof REACTION_EMOJI)[number];

export type MessageAction =
  | { kind: "reaction"; targetId: string; emoji: ReactionEmoji; active: boolean }
  | { kind: "delete"; targetId: string }
  | { kind: "edit"; targetId: string; content: string };

export const MESSAGE_ACTION_KINDS: ReadonlySet<string> = new Set(["reaction", "delete", "edit"]);
export const MAX_EDIT_CHARS = 8_000;
/** Matches the relay's room member limit, so every member can react once per emoji. */
export const MAX_REACTORS_PER_EMOJI = 117;

const CONTROL_ID = /^[A-Za-z0-9_-]{1,128}$/u;

export function isMessageActionKind(kind: unknown): boolean {
  return typeof kind === "string" && MESSAGE_ACTION_KINDS.has(kind);
}

export function isReactionEmoji(value: unknown): value is ReactionEmoji {
  return typeof value === "string" && (REACTION_EMOJI as readonly string[]).includes(value);
}

/** The JSON body for [action]; directory-stamp and sender fields are added by the caller. */
export function messageActionPayload(id: string, action: MessageAction): Record<string, unknown> {
  switch (action.kind) {
    case "reaction":
      return { kind: "reaction", id, target_id: action.targetId, emoji: action.emoji, active: action.active };
    case "delete":
      return { kind: "delete", id, target_id: action.targetId };
    case "edit":
      return { kind: "edit", id, target_id: action.targetId, content: action.content };
  }
}

/**
 * Reads an action from a decrypted payload. The payload id must equal the
 * relay's authoritative message id, as for every other payload kind.
 */
export function parseMessageAction(payload: Record<string, unknown>, authoritativeId: string): MessageAction | null {
  if (!isMessageActionKind(payload.kind) || payload.id !== authoritativeId || !CONTROL_ID.test(authoritativeId)) return null;
  const targetId = payload.target_id;
  if (typeof targetId !== "string" || !CONTROL_ID.test(targetId) || targetId === authoritativeId) return null;
  if (payload.kind === "reaction") {
    if (!isReactionEmoji(payload.emoji) || typeof payload.active !== "boolean") return null;
    return { kind: "reaction", targetId, emoji: payload.emoji, active: payload.active };
  }
  if (payload.kind === "delete") return { kind: "delete", targetId };
  const content = typeof payload.content === "string" ? payload.content.trim() : "";
  if (!content || content.length > MAX_EDIT_CHARS) return null;
  return { kind: "edit", targetId, content };
}

/** Whether [actor] may apply [action] to [target]. Only a message's sender can edit or delete it. */
export function actionAllowed(target: ChatMessage, action: MessageAction, actor: string): boolean {
  if (action.kind === "reaction") return true;
  if (target.sender.toLowerCase() !== actor.toLowerCase()) return false;
  return action.kind === "delete" || target.kind === "text";
}

export interface AppliedAction {
  /** The new list, or the same array when nothing changed. */
  messages: ChatMessage[];
  /** A message removed by delete-for-everyone; the caller wipes it. */
  removed?: ChatMessage;
}

/**
 * Applies [action] from [actor] to one conversation. Actions on messages that
 * are no longer in memory, or that the actor may not change, are ignored.
 */
export function applyMessageAction(
  list: ChatMessage[],
  action: MessageAction,
  actor: string,
  currentUsername: string,
  nowMs: number,
): AppliedAction {
  const index = list.findIndex((message) => message.id === action.targetId);
  const target = index >= 0 ? list[index] : undefined;
  if (!target || !actionAllowed(target, action, actor)) return { messages: list };
  const next = [...list];
  if (action.kind === "delete") {
    next.splice(index, 1);
    return { messages: next, removed: target };
  }
  if (action.kind === "edit") {
    if (target.content === action.content) return { messages: list };
    next[index] = {
      ...target,
      content: action.content,
      editedAtMs: nowMs,
      mentionsCurrentUser: !target.mine && mentionsUsername(action.content, currentUsername),
    };
    return { messages: next };
  }
  const reactions = withReaction(target.reactions, action.emoji, actor, action.active);
  if (reactions === target.reactions) return { messages: list };
  next[index] = { ...target, reactions };
  return { messages: next };
}

function withReaction(
  current: ChatMessage["reactions"],
  emoji: ReactionEmoji,
  actor: string,
  active: boolean,
): ChatMessage["reactions"] {
  const key = actor.toLowerCase();
  const people = current?.[emoji] ?? [];
  const has = people.includes(key);
  if (has === active) return current;
  if (active && people.length >= MAX_REACTORS_PER_EMOJI) return current;
  const updated = active ? [...people, key] : people.filter((person) => person !== key);
  const next: NonNullable<ChatMessage["reactions"]> = { ...current };
  if (updated.length > 0) next[emoji] = updated;
  else delete next[emoji];
  return Object.keys(next).length > 0 ? next : undefined;
}

/** Reactions in display order with counts and whether the current user is among them. */
export function reactionSummary(
  message: ChatMessage,
  currentUsername: string,
): { emoji: ReactionEmoji; count: number; mine: boolean }[] {
  const me = currentUsername.toLowerCase();
  return REACTION_EMOJI.flatMap((emoji) => {
    const people = message.reactions?.[emoji];
    return people && people.length > 0 ? [{ emoji, count: people.length, mine: people.includes(me) }] : [];
  });
}

/**
 * Messages in a conversation that match [query], case-insensitively, by text,
 * attachment name or sender display name. A blank query matches everything.
 */
export function searchMessages(messages: readonly ChatMessage[], query: string): ChatMessage[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [...messages];
  return messages.filter((message) =>
    message.content.toLowerCase().includes(needle) ||
    (message.attachment?.name.toLowerCase().includes(needle) ?? false) ||
    (message.senderDisplayName?.toLowerCase().includes(needle) ?? false));
}
