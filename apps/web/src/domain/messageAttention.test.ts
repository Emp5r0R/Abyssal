import { describe, expect, it } from "vitest";
import { mentionsUsername, replyTargetsCurrentUser, splitMentionText } from "./messageAttention";

describe("message attention", () => {
  it("matches a full username regardless of case", () => {
    expect(mentionsUsername("hello @SilentFox482, check this", "silentfox482")).toBe(true);
    expect(mentionsUsername("hello @SilentFox4820", "SilentFox482")).toBe(false);
    expect(mentionsUsername("mail@SilentFox482.example", "SilentFox482")).toBe(false);
  });

  it("splits mention tokens without using HTML parsing", () => {
    expect(splitMentionText("Hi @SilentFox482 and @NebulaTiger93")).toEqual([
      { text: "Hi " },
      { text: "@SilentFox482", username: "SilentFox482" },
      { text: " and " },
      { text: "@NebulaTiger93", username: "NebulaTiger93" },
    ]);
  });

  it("highlights replies only for the author of the original message", () => {
    const ownMessageIds = new Set(["message-a"]);
    expect(replyTargetsCurrentUser("UserB", "UserA", "message-a", ownMessageIds)).toBe(true);
    expect(replyTargetsCurrentUser("UserA", "UserA", "message-a", ownMessageIds)).toBe(false);
    expect(replyTargetsCurrentUser("UserB", "UserA", "message-b", ownMessageIds)).toBe(false);
  });
});
