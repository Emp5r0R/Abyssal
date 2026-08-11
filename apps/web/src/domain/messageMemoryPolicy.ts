import type { ChatMessage } from "./types";

export interface MessageMemoryLimits {
  maxMessagesPerChat: number;
  maxBytesPerChat: number;
  maxMessagesGlobal: number;
  maxBytesGlobal: number;
}

export const DEFAULT_MESSAGE_MEMORY_LIMITS: Readonly<MessageMemoryLimits> = Object.freeze({
  maxMessagesPerChat: 500,
  maxBytesPerChat: 8 * 1024 * 1024,
  maxMessagesGlobal: 5_000,
  maxBytesGlobal: 32 * 1024 * 1024,
});

const MESSAGE_OBJECT_OVERHEAD_BYTES = 256;
const ATTACHMENT_OBJECT_OVERHEAD_BYTES = 256;
const TYPED_ARRAY_OVERHEAD_BYTES = 64;
const STRING_OVERHEAD_BYTES = 16;
const NUMBER_AND_BOOLEAN_FIELDS_BYTES = 96;

export function estimateMessageMemoryBytes(message: ChatMessage): number {
  let bytes = MESSAGE_OBJECT_OVERHEAD_BYTES + NUMBER_AND_BOOLEAN_FIELDS_BYTES;
  bytes += estimateString(message.id);
  bytes += estimateString(message.chatId);
  bytes += estimateString(message.sender);
  bytes += estimateString(message.content);
  bytes += estimateString(message.replyToId);
  bytes += estimateString(message.senderPublicKeyB64);

  const attachment = message.attachment;
  if (attachment) {
    bytes += ATTACHMENT_OBJECT_OVERHEAD_BYTES;
    bytes += TYPED_ARRAY_OVERHEAD_BYTES + attachment.encryptionKey.byteLength;
    bytes += estimateString(attachment.id);
    bytes += estimateString(attachment.name);
    bytes += estimateString(attachment.mediaType);
    bytes += estimateString(attachment.mimeType);
    bytes += estimateString(attachment.reactionShortcode);
  }
  return Math.min(Number.MAX_SAFE_INTEGER, bytes);
}

export function appendBoundedMessage(
  current: Record<string, ChatMessage[]>,
  message: ChatMessage,
  limits: Readonly<MessageMemoryLimits> = DEFAULT_MESSAGE_MEMORY_LIMITS,
): Record<string, ChatMessage[]> {
  const list = current[message.chatId] ?? [];
  const duplicate = list.find((candidate) => candidate.id === message.id);
  if (duplicate) {
    if (duplicate !== message) wipeEvictedMessage(message);
    return current;
  }

  const messageBytes = estimateMessageMemoryBytes(message);
  if (messageBytes > limits.maxBytesPerChat || messageBytes > limits.maxBytesGlobal) {
    wipeEvictedMessage(message);
    return current;
  }

  const next: Record<string, ChatMessage[]> = { ...current };
  for (const [chatId, messages] of Object.entries(next)) {
    if (messages.length === 0) delete next[chatId];
  }
  next[message.chatId] = [...list, message];

  let totalCount = 0;
  let totalBytes = 0;
  for (const messages of Object.values(next)) {
    totalCount += messages.length;
    totalBytes += messages.reduce(
      (sum, candidate) => sum + estimateMessageMemoryBytes(candidate),
      0,
    );
  }

  let chatBytes = next[message.chatId].reduce(
    (sum, candidate) => sum + estimateMessageMemoryBytes(candidate),
    0,
  );
  while (
    (next[message.chatId]?.length ?? 0) > limits.maxMessagesPerChat ||
    chatBytes > limits.maxBytesPerChat
  ) {
    const messages = next[message.chatId];
    if (!messages?.length) break;
    const removed = removeAt(next, current, message.chatId, oldestIndex(message.chatId, messages));
    if (!removed) break;
    const removedBytes = estimateMessageMemoryBytes(removed);
    chatBytes -= removedBytes;
    totalBytes -= removedBytes;
    totalCount -= 1;
    wipeEvictedMessage(removed);
  }

  while (totalCount > limits.maxMessagesGlobal || totalBytes > limits.maxBytesGlobal) {
    const oldest = oldestGlobal(next);
    if (!oldest) break;
    const removed = removeAt(next, current, oldest.chatId, oldest.index);
    if (!removed) break;
    totalBytes -= estimateMessageMemoryBytes(removed);
    totalCount -= 1;
    wipeEvictedMessage(removed);
  }

  return next;
}

export function wipeMessageAttachmentKey(message: ChatMessage): void {
  message.attachment?.encryptionKey.fill(0);
}

export function wipeEvictedMessage(message: ChatMessage): void {
  wipeMessageAttachmentKey(message);
  message.content = "";
  message.replyToId = undefined;
  if (message.attachment) {
    message.attachment.name = "";
    message.attachment.reactionShortcode = undefined;
  }
}

function estimateString(value: string | undefined): number {
  return value === undefined ? 0 : STRING_OVERHEAD_BYTES + value.length * 2;
}

function removeAt(
  next: Record<string, ChatMessage[]>,
  current: Record<string, ChatMessage[]>,
  chatId: string,
  index: number,
): ChatMessage | undefined {
  const existing = next[chatId];
  if (!existing || index < 0 || index >= existing.length) return undefined;
  const mutable = existing === current[chatId] ? [...existing] : existing;
  const [removed] = mutable.splice(index, 1);
  if (mutable.length === 0) delete next[chatId];
  else next[chatId] = mutable;
  return removed;
}

function oldestIndex(chatId: string, messages: ChatMessage[]): number {
  let index = 0;
  for (let candidate = 1; candidate < messages.length; candidate += 1) {
    if (compareMessages(chatId, messages[candidate], chatId, messages[index]) < 0) index = candidate;
  }
  return index;
}

function oldestGlobal(messages: Record<string, ChatMessage[]>): {
  chatId: string;
  index: number;
  message: ChatMessage;
} | null {
  let oldest: { chatId: string; index: number; message: ChatMessage } | null = null;
  for (const [chatId, list] of Object.entries(messages)) {
    for (let index = 0; index < list.length; index += 1) {
      const message = list[index];
      if (!oldest || compareMessages(chatId, message, oldest.chatId, oldest.message) < 0) {
        oldest = { chatId, index, message };
      }
    }
  }
  return oldest;
}

function compareMessages(
  leftChatId: string,
  left: ChatMessage,
  rightChatId: string,
  right: ChatMessage,
): number {
  return compareNumber(left.receivedAtMs, right.receivedAtMs) ||
    compareNumber(left.createdAtMs, right.createdAtMs) ||
    compareString(leftChatId, rightChatId) ||
    compareString(left.id, right.id);
}

function compareNumber(left: number, right: number): number {
  const normalizedLeft = Number.isFinite(left) ? left : Number.MAX_SAFE_INTEGER;
  const normalizedRight = Number.isFinite(right) ? right : Number.MAX_SAFE_INTEGER;
  return normalizedLeft === normalizedRight ? 0 : normalizedLeft < normalizedRight ? -1 : 1;
}

function compareString(left: string, right: string): number {
  return left === right ? 0 : left < right ? -1 : 1;
}
