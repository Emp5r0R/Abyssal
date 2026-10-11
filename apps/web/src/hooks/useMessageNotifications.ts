import { useEffect, useRef } from "react";
import { notificationContent, shouldNotify, type NotificationLevel } from "../domain/notificationPolicy";
import type { ChatMessage } from "../domain/types";
import type { Notifier } from "../platform/notifier";

export interface MessageNotificationOptions {
  notifier: Notifier;
  /** False while signed out; resets what has been seen. */
  enabled: boolean;
  level: NotificationLevel;
  locked: boolean;
  activeChatId: string | null;
  messages: Readonly<Record<string, readonly ChatMessage[]>>;
  labelsFor: (message: ChatMessage) => { sender: string; conversation: string | null };
  onOpen: (chatId: string) => void;
}

/**
 * Raises a notification for each message that arrives after sign-in, according
 * to the chosen privacy level. Messages already present when notifications start
 * are treated as seen, so enabling them never replays a backlog.
 */
export function useMessageNotifications(options: MessageNotificationOptions): void {
  const { notifier, enabled, level, locked, messages } = options;
  const seen = useRef<Set<string> | null>(null);
  const latest = useRef(options);
  useEffect(() => { latest.current = options; });

  useEffect(() => {
    if (!enabled) {
      seen.current = null;
      notifier.closeAll();
      return;
    }
    const current = new Set<string>();
    const arrived: ChatMessage[] = [];
    for (const list of Object.values(messages)) {
      for (const message of list) {
        current.add(message.id);
        if (seen.current && !seen.current.has(message.id)) arrived.push(message);
      }
    }
    seen.current = current;
    if (level === "off") return;
    const { activeChatId, labelsFor, onOpen } = latest.current;
    const away = document.visibilityState === "hidden" || !document.hasFocus();
    for (const message of arrived) {
      if (!shouldNotify(message, { level, away, locked, activeChatId })) continue;
      notifier.show(notificationContent(message, level, labelsFor(message)), () => onOpen(message.chatId));
    }
  }, [enabled, level, locked, messages, notifier]);

  // Locking or turning notifications off removes anything already on screen.
  useEffect(() => {
    if (locked || level === "off") notifier.closeAll();
  }, [level, locked, notifier]);
}
