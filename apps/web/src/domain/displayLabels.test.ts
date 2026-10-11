import { describe, expect, it } from "vitest";
import { accountInitials, conversationEntries, displayNamesBySender, filterConversations, roomLabel, shortAccountId, shortRoomId } from "./displayLabels";
import type { ChatMessage } from "./types";

const message = (sender: string, createdAtMs: number, senderDisplayName?: string, mine = false): ChatMessage => ({
  id: `${sender}-${createdAtMs}`, chatId: "dm", sender, content: "", kind: "text", createdAtMs, receivedAtMs: createdAtMs,
  selfDestructSec: 0, absoluteExpirySec: 0, mine, senderDisplayName,
});

describe("account labels", () => {
  it("shortens generated account IDs and leaves other names alone", () => {
    expect(shortAccountId("acct_10bae1a3659440688930a460dd27ce30")).toBe("10ba…ce30");
    expect(shortAccountId("Alice")).toBe("Alice");
    expect(shortAccountId("acct_xyz")).toBe("acct_xyz");
  });

  it("shortens opaque room IDs", () => {
    expect(shortRoomId("forum_9f2c1a7b0000000000000000deadbeef")).toBe("9f2c…beef");
    expect(shortRoomId("forum_ops")).toBe("ops");
  });

  it("labels rooms by name, falling back to a short ID for unnamed joined rooms", () => {
    expect(roomLabel({ id: "forum_9f2c1a7b0000000000000000deadbeef", name: "Operations" })).toBe("Operations");
    expect(roomLabel({ id: "forum_9f2c1a7b0000000000000000deadbeef", name: "9f2c1a7b0000000000000000deadbeef" })).toBe("Room 9f2c…beef");
    expect(roomLabel({ id: "forum_9f2c1a7b0000000000000000deadbeef", name: "" })).toBe("Room 9f2c…beef");
  });

  it("derives avatar initials", () => {
    expect(accountInitials("acct_10bae1a3659440688930a460dd27ce30")).toBe("10");
    expect(accountInitials("QuietAurora")).toBe("QU");
    expect(accountInitials("--")).toBe("?");
  });

  it("keeps the latest display name per sender and ignores own messages", () => {
    const names = displayNamesBySender({
      a: [message("Bob", 1, "OldName"), message("Bob", 3, "NewName"), message("Me", 4, "Mine", true)],
      b: [message("bob", 2, "Middle"), message("Carol", 5)],
    });
    expect(names.get("bob")).toBe("NewName");
    expect(names.has("me")).toBe(false);
    expect(names.has("carol")).toBe(false);
  });

  it("lists conversations in sidebar order and filters by label or ID", () => {
    const rooms = [{ id: "forum_ops", name: "Operations" }] as never[];
    const directs = [{ id: "dm_1", peer_username: "acct_10bae1a3659440688930a460dd27ce30" }, { id: "dm_2", peer_username: "acct_334a5379dff34f23bbfe27a7b09e9f94" }];
    const entries = conversationEntries(rooms, directs, new Map([["acct_10bae1a3659440688930a460dd27ce30", "SilverComet"]]));
    expect(entries.map((entry) => [entry.id, entry.kind, entry.label])).toEqual([
      ["forum_ops", "room", "Operations"],
      ["dm_1", "direct", "SilverComet"],
      ["dm_2", "direct", "334a…9f94"],
    ]);
    expect(filterConversations(entries, " silver ").map((entry) => entry.id)).toEqual(["dm_1"]);
    expect(filterConversations(entries, "334a5379").map((entry) => entry.id)).toEqual(["dm_2"]);
    expect(filterConversations(entries, "")).toHaveLength(3);
  });
});
