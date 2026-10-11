import { useEffect, useRef } from "react";
import { matchShortcut, type ShortcutAction } from "../domain/keyboardShortcuts";

export type ShortcutHandlers = Partial<Record<ShortcutAction, () => void>>;

/**
 * Routes workspace key presses to handlers. Only actions with a handler are
 * consumed, so a disabled action (for example lock without a PIN) leaves the
 * browser's own behaviour alone. Keys pressed inside an open dialog are ignored.
 */
export function useKeyboardShortcuts(handlers: ShortcutHandlers, enabled: boolean): void {
  const latest = useRef(handlers);
  useEffect(() => { latest.current = handlers; });

  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.isComposing || event.repeat) return;
      if (event.target instanceof Element && event.target.closest("[role='dialog']")) return;
      const action = matchShortcut(event, isTyping(event.target));
      const handler = action ? latest.current[action] : undefined;
      if (!handler) return;
      event.preventDefault();
      handler();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [enabled]);
}

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement ||
    (target instanceof HTMLInputElement && !["button", "checkbox", "radio", "range", "submit"].includes(target.type));
}
