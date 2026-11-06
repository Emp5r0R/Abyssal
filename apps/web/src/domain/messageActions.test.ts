import { describe, expect, it } from "vitest";
import {
  MAX_EDIT_CHARS,
  MAX_REACTORS_PER_EMOJI,
  applyMessageAction,
  isMessageActionKind,
  messageActionPayload,
  parseMessageAction,
  reactionSummary,
  searchMessages,
} from "./messageActions";
import type { ChatMessage } from "./types";

function message(id: string, sender: string, extra: Partial<ChatMessage> = {}): ChatMessage {
  return {
    id,
    chatId: "dm_a",
    sender,
    content: `hello from ${sender}`,
    kind: "text",
    createdAtMs: 1,
    receivedAtMs: 1,
    selfDestructSec: 0,
    absoluteExpirySec: 0,
    mine: sender === "me",
    ...extra,
  };
}

describe("message action payloads", () => {
  it("round-trips every action kind bound to the authoritative id", () => {
    const actions = [
      { kind: "reaction", targetId: "m1", emoji: "👍", active: true },
      { kind: "delete", targetId: "m1" },
      { kind: "edit", targetId: "m1", content: "fixed" },
    ] as const;
    for (const action of actions) {
      const payload = messageActionPayload("a1", action);
      expect(isMessageActionKind(payload.kind)).toBe(true);
      expect(parseMessageAction(payload, "a1")).toEqual(action);
      expect(parseMessageAction(payload, "other")).toBeNull();
    }
  });

  it("rejects unknown emoji, bad ids, self-targets and oversized edits", () => {
    expect(parseMessageAction({ kind: "reaction", id: "a1", target_id: "m1", emoji: "🔥", active: true }, "a1")).toBeNull();
    expect(parseMessageAction({ kind: "reaction", id: "a1", target_id: "m1", emoji: "👍", active: "yes" }, "a1")).toBeNull();
    expect(parseMessageAction({ kind: "delete", id: "a1", target_id: "../x" }, "a1")).toBeNull();
    expect(parseMessageAction({ kind: "delete", id: "a1", target_id: "a1" }, "a1")).toBeNull();
    expect(parseMessageAction({ kind: "edit", id: "a1", target_id: "m1", content: "  " }, "a1")).toBeNull();
    expect(parseMessageAction({ kind: "edit", id: "a1", target_id: "m1", content: "x".repeat(MAX_EDIT_CHARS + 1) }, "a1")).toBeNull();
    expect(parseMessageAction({ kind: "text", id: "a1", target_id: "m1" }, "a1")).toBeNull();
  });
});

describe("applying message actions", () => {
  it("toggles one reaction per person and emoji, case-insensitively", () => {
    const list = [message("m1", "alice")];
    const once = applyMessageAction(list, { kind: "reaction", targetId: "m1", emoji: "👍", active: true }, "Bob", "me", 5);
    const twice = applyMessageAction(once.messages, { kind: "reaction", targetId: "m1", emoji: "👍", active: true }, "bob", "me", 6);
    expect(twice.messages).toBe(once.messages);
    expect(reactionSummary(once.messages[0], "BOB")).toEqual([{ emoji: "👍", count: 1, mine: true }]);
    const removed = applyMessageAction(once.messages, { kind: "reaction", targetId: "m1", emoji: "👍", active: false }, "bob", "me", 7);
    expect(removed.messages[0].reactions).toBeUndefined();
  });

  it("caps reactors per emoji", () => {
    let list = [message("m1", "alice")];
    for (let index = 0; index < MAX_REACTORS_PER_EMOJI + 3; index += 1) {
      list = applyMessageAction(list, { kind: "reaction", targetId: "m1", emoji: "❤️", active: true }, `user${index}`, "me", 1).messages;
    }
    expect(list[0].reactions?.["❤️"]).toHaveLength(MAX_REACTORS_PER_EMOJI);
  });

  it("lets only the sender edit their text or delete their message", () => {
    const list = [message("m1", "alice"), message("m2", "bob", { kind: "attachment" })];
    const edit = { kind: "edit", targetId: "m1", content: "hi @me" } as const;
    expect(applyMessageAction(list, edit, "mallory", "me", 9).messages).toBe(list);
    const edited = applyMessageAction(list, edit, "ALICE", "me", 9).messages[0];
    expect(edited).toMatchObject({ content: "hi @me", editedAtMs: 9, mentionsCurrentUser: true });
    expect(applyMessageAction(list, { kind: "edit", targetId: "m2", content: "x" }, "bob", "me", 9).messages).toBe(list);

    expect(applyMessageAction(list, { kind: "delete", targetId: "m2" }, "alice", "me", 9).messages).toBe(list);
    const deleted = applyMessageAction(list, { kind: "delete", targetId: "m2" }, "bob", "me", 9);
    expect(deleted.messages.map((item) => item.id)).toEqual(["m1"]);
    expect(deleted.removed?.id).toBe("m2");
  });

  it("ignores actions for messages no longer in memory", () => {
    const list = [message("m1", "alice")];
    expect(applyMessageAction(list, { kind: "delete", targetId: "gone" }, "alice", "me", 1).messages).toBe(list);
  });
});

describe("searching a conversation", () => {
  it("matches text, attachment names and sender names case-insensitively", () => {
    const list = [
      message("m1", "alice", { content: "Meet at NOON", senderDisplayName: "Alice" }),
      message("m2", "bob", { kind: "attachment", content: "plan.pdf", attachment: { id: "a", encryptionVersion: 2, encryptionKey: new Uint8Array(32), name: "plan.pdf", mediaType: "FILE", mimeType: "application/pdf", sizeBytes: 1, oneTime: false, deleteAfterDownload: false } }),
      message("m3", "carol", { content: "ok", senderDisplayName: "Carol Noonan" }),
    ];
    expect(searchMessages(list, " noon ").map((item) => item.id)).toEqual(["m1", "m3"]);
    expect(searchMessages(list, "PLAN").map((item) => item.id)).toEqual(["m2"]);
    expect(searchMessages(list, "")).toHaveLength(3);
    expect(searchMessages(list, "zzz")).toEqual([]);
  });
});
