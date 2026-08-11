import { describe, expect, it } from "vitest";
import type { ChatMessage } from "./types";
import {
  appendBoundedMessage,
  DEFAULT_MESSAGE_MEMORY_LIMITS,
  estimateMessageMemoryBytes,
  type MessageMemoryLimits,
} from "./messageMemoryPolicy";

const LARGE_BYTE_LIMIT = 64 * 1024 * 1024;

function limits(overrides: Partial<MessageMemoryLimits> = {}): MessageMemoryLimits {
  return {
    maxMessagesPerChat: 500,
    maxBytesPerChat: LARGE_BYTE_LIMIT,
    maxMessagesGlobal: 5_000,
    maxBytesGlobal: LARGE_BYTE_LIMIT,
    ...overrides,
  };
}

function message(
  id: string,
  chatId: string,
  receivedAtMs: number,
  options: { content?: string; keyFill?: number } = {},
): ChatMessage {
  const attachment = options.keyFill === undefined ? undefined : {
    id: `attachment_${id}`,
    encryptionVersion: 1,
    encryptionKey: new Uint8Array(32).fill(options.keyFill),
    name: `${id}.bin`,
    mediaType: "FILE" as const,
    mimeType: "application/octet-stream",
    sizeBytes: 1,
    oneTime: false,
    deleteAfterDownload: false,
  };
  return {
    id,
    chatId,
    sender: "Alice",
    content: options.content ?? (attachment?.name || "secret"),
    kind: attachment ? "attachment" : "text",
    createdAtMs: receivedAtMs,
    receivedAtMs,
    selfDestructSec: 0,
    absoluteExpirySec: 0,
    mine: false,
    senderPublicKeyB64: "A".repeat(171),
    attachment,
  };
}

function countMessages(messages: Record<string, ChatMessage[]>): number {
  return Object.values(messages).reduce((count, list) => count + list.length, 0);
}

describe("message memory policy", () => {
  it("uses the production count and memory ceilings", () => {
    expect(DEFAULT_MESSAGE_MEMORY_LIMITS).toEqual({
      maxMessagesPerChat: 500,
      maxBytesPerChat: 8 * 1024 * 1024,
      maxMessagesGlobal: 5_000,
      maxBytesGlobal: 32 * 1024 * 1024,
    });
  });

  it("bounds a no-expiry multi-room flood by the global count", () => {
    let messages: Record<string, ChatMessage[]> = { empty_chat: [] };
    const policy = limits({ maxMessagesPerChat: 3, maxMessagesGlobal: 5 });
    for (let index = 0; index < 6; index += 1) {
      messages = appendBoundedMessage(
        messages,
        message(`message_${index}`, `chat_${index % 3}`, index),
        policy,
      );
    }

    expect(countMessages(messages)).toBe(5);
    expect(Object.values(messages).every((list) => list.length > 0)).toBe(true);
    expect(Object.values(messages).flat().some((candidate) => candidate.id === "message_0")).toBe(false);
    expect(Object.values(messages).flat().every((candidate) =>
      candidate.selfDestructSec === 0 && candidate.absoluteExpirySec === 0)).toBe(true);

    let singleChat: Record<string, ChatMessage[]> = {};
    for (let index = 0; index < 4; index += 1) {
      singleChat = appendBoundedMessage(
        singleChat,
        message(`single_${index}`, "chat_only", index),
        limits({ maxMessagesPerChat: 3, maxMessagesGlobal: 10 }),
      );
    }
    expect(singleChat.chat_only.map((candidate) => candidate.id)).toEqual([
      "single_1",
      "single_2",
      "single_3",
    ]);
  });

  it("enforces both per-chat and global byte budgets", () => {
    const first = message("first", "chat_a", 1, { content: "x".repeat(200) });
    const second = message("second", "chat_a", 2, { content: "x".repeat(200) });
    const oneMessageBytes = estimateMessageMemoryBytes(first);
    let messages = appendBoundedMessage({}, first, limits({
      maxBytesPerChat: oneMessageBytes * 2 - 1,
    }));
    messages = appendBoundedMessage(messages, second, limits({
      maxBytesPerChat: oneMessageBytes * 2 - 1,
    }));
    expect(messages.chat_a.map((candidate) => candidate.id)).toEqual(["second"]);

    const third = message("third", "chat_b", 3, { content: "x".repeat(200) });
    messages = appendBoundedMessage(messages, third, limits({
      maxBytesGlobal: oneMessageBytes * 2 - 1,
    }));
    expect(countMessages(messages)).toBe(1);
    expect(messages.chat_b?.[0]?.id).toBe("third");
  });

  it("evicts deterministic oldest messages and wipes attachment keys", () => {
    const fromB = message("same", "chat_b", 10, { keyFill: 1 });
    const fromA = message("same", "chat_a", 10, { keyFill: 2 });
    const newest = message("same", "chat_c", 10, { keyFill: 3 });
    let messages = appendBoundedMessage({}, fromB, limits({ maxMessagesGlobal: 2 }));
    messages = appendBoundedMessage(messages, fromA, limits({ maxMessagesGlobal: 2 }));
    messages = appendBoundedMessage(messages, newest, limits({ maxMessagesGlobal: 2 }));

    expect(Object.keys(messages).sort()).toEqual(["chat_b", "chat_c"]);
    expect(fromA.attachment?.encryptionKey.every((byte) => byte === 0)).toBe(true);
    expect(fromA.content).toBe("");
    expect(fromB.attachment?.encryptionKey.every((byte) => byte === 1)).toBe(true);
    expect(newest.attachment?.encryptionKey.every((byte) => byte === 3)).toBe(true);
  });

  it("rejects a single over-budget message and preserves a stored same-object duplicate", () => {
    const oversized = message("oversized", "chat_a", 1, {
      content: "x".repeat(1_000),
      keyFill: 7,
    });
    const oversizedBytes = estimateMessageMemoryBytes(oversized);
    expect(appendBoundedMessage({}, oversized, limits({
      maxBytesPerChat: oversizedBytes - 1,
    }))).toEqual({});
    expect(oversized.attachment?.encryptionKey.every((byte) => byte === 0)).toBe(true);

    const stored = message("duplicate", "chat_b", 2, { keyFill: 9 });
    const current = appendBoundedMessage({}, stored, limits());
    expect(appendBoundedMessage(current, stored, limits())).toBe(current);
    expect(stored.attachment?.encryptionKey.every((byte) => byte === 9)).toBe(true);

    const duplicateCopy = message("duplicate", "chat_b", 3, { keyFill: 8 });
    expect(appendBoundedMessage(current, duplicateCopy, limits())).toBe(current);
    expect(duplicateCopy.attachment?.encryptionKey.every((byte) => byte === 0)).toBe(true);
  });
});
