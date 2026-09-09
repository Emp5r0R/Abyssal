import { describe, expect, it } from "vitest";
import { displayNameFromEntropy, newPrivateDisplayName, readSenderProfile, senderProfile } from "./senderProfile";

describe("private sender profiles", () => {
  it("shares the Android generation vector and emits bounded profiles", () => {
    expect(displayNameFromEntropy(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 255]))).toBe("SilentSignal0203040506FF");
    const names = new Set(Array.from({ length: 128 }, () => newPrivateDisplayName()));
    expect(names.size).toBe(128);
    for (const name of names) expect(readSenderProfile(senderProfile(name))).toBe(name);
    expect(readSenderProfile(undefined)).toBeUndefined();
  });
  it("rejects malformed profiles without treating display names as identifiers", () => {
    for (const name of ["", "a".repeat(37), " A", "A\n", "@Alice", "<script>", "a\u202eb", "\ud800"]) {
      expect(() => senderProfile(name)).toThrow();
    }
    for (const value of [null, [], {}, { version: 2, display_name: "Alice" }, { version: "1", display_name: "Alice" },
      { version: 1, display_name: 9 }, { version: 1, display_name: "Alice", username: "Bob" }]) {
      expect(() => readSenderProfile(value)).toThrow();
    }
    expect(() => displayNameFromEntropy(new Uint8Array(9))).toThrow();
    expect(readSenderProfile({ version: 1, display_name: "Alice" })).toBe("Alice");
  });
});
