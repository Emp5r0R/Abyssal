export type ShortcutAction =
  | "quick-switcher"
  | "previous-conversation"
  | "next-conversation"
  | "go-home"
  | "focus-composer"
  | "create-room"
  | "open-settings"
  | "lock"
  | "toggle-blur"
  | "show-shortcuts";

/** The parts of a keyboard event a shortcut depends on. */
export interface KeyStroke {
  key: string;
  code: string;
  altKey: boolean;
  ctrlKey: boolean;
  metaKey: boolean;
  shiftKey: boolean;
}

interface ShortcutDefinition {
  action: ShortcutAction;
  description: string;
  /** Allowed while typing in a field. Single-key shortcuts never are. */
  whileTyping: boolean;
  matches: (stroke: KeyStroke) => boolean;
  keys: (mac: boolean) => string[];
}

const noModifiers = (stroke: KeyStroke) => !stroke.altKey && !stroke.ctrlKey && !stroke.metaKey;
const primary = (stroke: KeyStroke) => stroke.ctrlKey !== stroke.metaKey && !stroke.altKey;
// App actions use Alt+Shift with the physical key: browsers leave these free, and
// matching `code` keeps them working where Option+Shift types a symbol on macOS.
const altShift = (code: string) => (stroke: KeyStroke) =>
  stroke.altKey && stroke.shiftKey && !stroke.ctrlKey && !stroke.metaKey && stroke.code === code;
const alt = (mac: boolean) => (mac ? "⌥" : "Alt");
const altShiftKeys = (letter: string) => (mac: boolean) => [alt(mac), "Shift", letter];

export const SHORTCUTS: readonly ShortcutDefinition[] = Object.freeze([
  {
    action: "quick-switcher",
    description: "Jump to a conversation",
    whileTyping: true,
    matches: (stroke) => primary(stroke) && !stroke.shiftKey && stroke.key.toLowerCase() === "k",
    keys: (mac) => [mac ? "⌘" : "Ctrl", "K"],
  },
  {
    action: "previous-conversation",
    description: "Previous conversation",
    whileTyping: true,
    matches: (stroke) => stroke.altKey && !stroke.ctrlKey && !stroke.metaKey && !stroke.shiftKey && stroke.key === "ArrowUp",
    keys: (mac) => [alt(mac), "↑"],
  },
  {
    action: "next-conversation",
    description: "Next conversation",
    whileTyping: true,
    matches: (stroke) => stroke.altKey && !stroke.ctrlKey && !stroke.metaKey && !stroke.shiftKey && stroke.key === "ArrowDown",
    keys: (mac) => [alt(mac), "↓"],
  },
  { action: "go-home", description: "Go to Home", whileTyping: true, matches: altShift("KeyH"), keys: altShiftKeys("H") },
  {
    action: "focus-composer",
    description: "Write a message",
    whileTyping: false,
    matches: (stroke) => noModifiers(stroke) && stroke.key === "/",
    keys: () => ["/"],
  },
  { action: "create-room", description: "Create a room", whileTyping: true, matches: altShift("KeyN"), keys: altShiftKeys("N") },
  { action: "open-settings", description: "Open settings", whileTyping: true, matches: altShift("KeyS"), keys: altShiftKeys("S") },
  { action: "lock", description: "Lock behind the calculator", whileTyping: true, matches: altShift("KeyL"), keys: altShiftKeys("L") },
  { action: "toggle-blur", description: "Blur or unblur names and messages", whileTyping: true, matches: altShift("KeyB"), keys: altShiftKeys("B") },
  {
    action: "show-shortcuts",
    description: "Show keyboard shortcuts",
    whileTyping: false,
    matches: (stroke) => !stroke.altKey && !stroke.ctrlKey && !stroke.metaKey && stroke.key === "?",
    keys: () => ["?"],
  },
] satisfies ShortcutDefinition[]);

/** The action a key press triggers, or null. `typing` is true inside text fields. */
export function matchShortcut(stroke: KeyStroke, typing: boolean): ShortcutAction | null {
  const match = SHORTCUTS.find((shortcut) => shortcut.matches(stroke));
  if (!match || (typing && !match.whileTyping)) return null;
  return match.action;
}

/** The conversation `step` places away from `current`, wrapping at either end. */
export function adjacentConversation(ids: readonly string[], current: string | null, step: 1 | -1): string | null {
  if (ids.length === 0) return null;
  const index = current === null ? -1 : ids.indexOf(current);
  if (index === -1) return step === 1 ? ids[0] : ids[ids.length - 1];
  return ids[(index + step + ids.length) % ids.length];
}
