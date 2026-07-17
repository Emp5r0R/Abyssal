export function mentionsUsername(content: string, username: string): boolean {
  if (!content || !username) return false;
  const escaped = username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_])@${escaped}(?=$|[^A-Za-z0-9_])`, "i").test(content);
}

export function splitMentionText(content: string): Array<{ text: string; username?: string }> {
  return content
    .split(/(@[A-Za-z0-9_]{2,80})/g)
    .filter(Boolean)
    .map((text) => text.startsWith("@") ? { text, username: text.slice(1) } : { text });
}

export function replyTargetsCurrentUser(
  sender: string,
  currentUsername: string,
  replyToId: string | undefined,
  ownMessageIds: ReadonlySet<string>,
): boolean {
  return sender !== currentUsername && !!replyToId && ownMessageIds.has(replyToId);
}
