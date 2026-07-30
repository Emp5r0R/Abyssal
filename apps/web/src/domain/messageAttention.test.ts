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

  it("returns false for empty content or username", () => {
    expect(mentionsUsername("", "user")).toBe(false);
    expect(mentionsUsername("hello @user", "")).toBe(false);
  });

  it("handles special regex characters in username", () => {
    expect(mentionsUsername("hi @user.name", "user.name")).toBe(true);
    expect(mentionsUsername("hi @user+name", "user+name")).toBe(true);
    expect(mentionsUsername("hi @user(name)", "user(name)")).toBe(true);
    expect(mentionsUsername("hi @user[name]", "user[name]")).toBe(true);
  });

  it("detects mention at start of string", () => {
    expect(mentionsUsername("@Alice hello", "Alice")).toBe(true);
  });

  it("detects mention at end of string", () => {
    expect(mentionsUsername("hello @Bob", "Bob")).toBe(true);
  });

  it("does not match mention as substring of longer username", () => {
    expect(mentionsUsername("hello @AliceX", "Alice")).toBe(false);
    expect(mentionsUsername("hello @XAlice", "Alice")).toBe(false);
  });

  it("splits text with no mentions", () => {
    expect(splitMentionText("hello world")).toEqual([{ text: "hello world" }]);
  });

  it("splits text with adjacent mentions", () => {
    const result = splitMentionText("@Alice@Bob");
    expect(result).toEqual([
      { text: "@Alice", username: "Alice" },
      { text: "@Bob", username: "Bob" },
    ]);
  });

  it("splits text with @ at start", () => {
    const result = splitMentionText("@User1 hello");
    expect(result).toEqual([
      { text: "@User1", username: "User1" },
      { text: " hello" },
    ]);
  });

  it("splitMentionText ignores single-char mentions", () => {
    expect(splitMentionText("hello @a")).toEqual([{ text: "hello @a" }]);
  });

  it("replyTargetsCurrentUser returns false for undefined replyToId", () => {
    expect(replyTargetsCurrentUser("UserB", "UserA", undefined, new Set(["msg"]))).toBe(false);
  });

  it("replyTargetsCurrentUser returns false for undefined currentUsername", () => {
    expect(replyTargetsCurrentUser("UserB", "UserA", "msg", new Set(["msg"]))).toBe(true);
  });
});
