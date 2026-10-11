import { describe, expect, it } from "vitest";
import { notificationContent, shouldNotify, type NotificationContext } from "./notificationPolicy";
import type { ChatMessage } from "./types";

const message = (overrides: Partial<ChatMessage> = {}): ChatMessage => ({
  id: "m1", chatId: "dm_1", sender: "acct_peer", content: "Meet at   the\\nusual place", kind: "text",
  createdAtMs: 1, receivedAtMs: 1, selfDestructSec: 0, absoluteExpirySec: 0, mine: false, ...overrides,
});

const context = (overrides: Partial<NotificationContext> = {}): NotificationContext => ({
  level: "sender", away: true, locked: false, activeChatId: "dm_1", ...overrides,
});

describe("notification policy", () => {
  it("notifies about others' messages while away or in another conversation", () => {
    expect(shouldNotify(message(), context())).toBe(true);
    expect(shouldNotify(message(), context({ away: false, activeChatId: "forum_ops" }))).toBe(true);
    expect(shouldNotify(message(), context({ away: false }))).toBe(false);
  });

  it("stays silent when off, for your own messages, and behind the calculator", () => {
    expect(shouldNotify(message(), context({ level: "off" }))).toBe(false);
    expect(shouldNotify(message({ mine: true }), context())).toBe(false);
    expect(shouldNotify(message(), context({ locked: true }))).toBe(false);
  });

  it("reveals less at each lower level", () => {
    const labels = { sender: "SilverComet", conversation: "Operations" };
    expect(notificationContent(message(), "private", labels)).toEqual({ title: "Abyssal", body: "New message", tag: "abyssal-dm_1" });
    expect(notificationContent(message(), "sender", labels)).toEqual({ title: "SilverComet in Operations", body: "New message", tag: "abyssal-dm_1" });
    expect(notificationContent(message(), "preview", { sender: "SilverComet", conversation: null }).body).toBe("Meet at the\\nusual place");
  });

  it("summarises attachments and shortens long previews", () => {
    const labels = { sender: "S", conversation: null };
    const attachment = (mediaType: "IMAGE" | "VIDEO" | "FILE", reactionShortcode?: string) => message({
      kind: "attachment",
      attachment: { id: "a", encryptionVersion: 2, encryptionKey: new Uint8Array(), name: "x", mediaType, mimeType: "", sizeBytes: 1, oneTime: false, deleteAfterDownload: false, reactionShortcode },
    });
    expect(notificationContent(attachment("IMAGE"), "preview", labels).body).toBe("Sent a photo");
    expect(notificationContent(attachment("VIDEO"), "preview", labels).body).toBe("Sent a video");
    expect(notificationContent(attachment("FILE"), "preview", labels).body).toBe("Sent a file");
    expect(notificationContent(attachment("IMAGE", ":fire:"), "preview", labels).body).toBe("Reacted :fire:");
    const long = notificationContent(message({ content: "x".repeat(500) }), "preview", labels).body;
    expect(long).toHaveLength(120);
    expect(long.endsWith("…")).toBe(true);
    expect(notificationContent(message({ content: "   " }), "preview", labels).body).toBe("New message");
  });
});
