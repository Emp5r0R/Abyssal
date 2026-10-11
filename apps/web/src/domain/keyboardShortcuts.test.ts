import { describe, expect, it } from "vitest";
import { adjacentConversation, matchShortcut, SHORTCUTS, type KeyStroke } from "./keyboardShortcuts";

const stroke = (overrides: Partial<KeyStroke>): KeyStroke => ({
  key: "", code: "", altKey: false, ctrlKey: false, metaKey: false, shiftKey: false, ...overrides,
});

describe("keyboard shortcuts", () => {
  it("maps each documented stroke to its action", () => {
    expect(matchShortcut(stroke({ key: "k", ctrlKey: true }), false)).toBe("quick-switcher");
    expect(matchShortcut(stroke({ key: "K", metaKey: true }), true)).toBe("quick-switcher");
    expect(matchShortcut(stroke({ key: "ArrowUp", altKey: true }), true)).toBe("previous-conversation");
    expect(matchShortcut(stroke({ key: "ArrowDown", altKey: true }), true)).toBe("next-conversation");
    expect(matchShortcut(stroke({ key: "/" }), false)).toBe("focus-composer");
    expect(matchShortcut(stroke({ key: "?", shiftKey: true }), false)).toBe("show-shortcuts");
    for (const [code, action] of [["KeyH", "go-home"], ["KeyN", "create-room"], ["KeyS", "open-settings"], ["KeyL", "lock"], ["KeyB", "toggle-blur"]] as const) {
      // macOS reports a symbol as `key` for Option+Shift+letter; the physical code still matches.
      expect(matchShortcut(stroke({ key: "ı", code, altKey: true, shiftKey: true }), true)).toBe(action);
    }
  });

  it("never fires single-key shortcuts while typing, or near-miss modifier combinations", () => {
    expect(matchShortcut(stroke({ key: "/" }), true)).toBeNull();
    expect(matchShortcut(stroke({ key: "?", shiftKey: true }), true)).toBeNull();
    expect(matchShortcut(stroke({ key: "k", ctrlKey: true, metaKey: true }), false)).toBeNull();
    expect(matchShortcut(stroke({ key: "k", ctrlKey: true, shiftKey: true }), false)).toBeNull();
    expect(matchShortcut(stroke({ code: "KeyL", altKey: true }), false)).toBeNull();
    expect(matchShortcut(stroke({ code: "KeyL", altKey: true, shiftKey: true, ctrlKey: true }), false)).toBeNull();
    expect(matchShortcut(stroke({ key: "ArrowUp", altKey: true, shiftKey: true }), false)).toBeNull();
    expect(matchShortcut(stroke({ key: "a" }), false)).toBeNull();
  });

  it("documents a distinct, platform-aware key list for every action", () => {
    expect(new Set(SHORTCUTS.map((shortcut) => shortcut.action)).size).toBe(SHORTCUTS.length);
    const lock = SHORTCUTS.find((shortcut) => shortcut.action === "lock")!;
    expect(lock.keys(true)).toEqual(["⌥", "Shift", "L"]);
    expect(lock.keys(false)).toEqual(["Alt", "Shift", "L"]);
  });

  it("steps through conversations and wraps around", () => {
    const ids = ["a", "b", "c"];
    expect(adjacentConversation(ids, "b", 1)).toBe("c");
    expect(adjacentConversation(ids, "c", 1)).toBe("a");
    expect(adjacentConversation(ids, "a", -1)).toBe("c");
    expect(adjacentConversation(ids, null, 1)).toBe("a");
    expect(adjacentConversation(ids, null, -1)).toBe("c");
    expect(adjacentConversation(ids, "gone", 1)).toBe("a");
    expect(adjacentConversation([], null, 1)).toBeNull();
  });
});
