import type { ChatMessage } from "./types";

/**
 * How much a message notification reveals. Notifications appear outside the page,
 * on the lock screen and in the OS notification history, so each level shows less.
 */
export type NotificationLevel = "off" | "private" | "sender" | "preview";

export const NOTIFICATION_LEVELS: readonly NotificationLevel[] = Object.freeze(["off", "private", "sender", "preview"]);

export interface NotificationContent {
  title: string;
  body: string;
  /** One notification per conversation; a newer message replaces the older one. */
  tag: string;
}

export interface NotificationContext {
  level: NotificationLevel;
  /** The page is hidden or another window has focus. */
  away: boolean;
  /** The workspace is behind the calculator cover. */
  locked: boolean;
  activeChatId: string | null;
}

const PREVIEW_LENGTH = 120;

/** Whether a newly arrived message should raise a notification at all. */
export function shouldNotify(message: ChatMessage, context: NotificationContext): boolean {
  if (context.level === "off" || message.mine || context.locked) return false;
  // A conversation open in a focused window is already being read.
  return context.away || message.chatId !== context.activeChatId;
}

/**
 * What the notification says. `conversation` names a room, or is null for a direct
 * chat; `sender` is the sender's display label.
 */
export function notificationContent(
  message: ChatMessage,
  level: Exclude<NotificationLevel, "off">,
  labels: { sender: string; conversation: string | null },
): NotificationContent {
  const tag = `abyssal-${message.chatId}`;
  if (level === "private") return { title: "Abyssal", body: "New message", tag };
  const title = labels.conversation ? `${labels.sender} in ${labels.conversation}` : labels.sender;
  if (level === "sender") return { title, body: "New message", tag };
  return { title, body: previewText(message), tag };
}

function previewText(message: ChatMessage): string {
  if (message.kind === "attachment") {
    if (message.attachment?.reactionShortcode) return `Reacted ${message.attachment.reactionShortcode}`;
    switch (message.attachment?.mediaType) {
      case "IMAGE": return "Sent a photo";
      case "VIDEO": return "Sent a video";
      default: return "Sent a file";
    }
  }
  const text = message.content.replace(/\s+/gu, " ").trim();
  if (!text) return "New message";
  return text.length > PREVIEW_LENGTH ? `${text.slice(0, PREVIEW_LENGTH - 1)}…` : text;
}
