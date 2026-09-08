import { describe, expect, it } from "vitest";
import { readRoomProfile, roomProfile } from "./roomProfile";

describe("encrypted room profile", () => {
  it("accepts the shared V1 vector and bounded Unicode names", () => {
    const vector = '{"version":1,"name":"Private incident response"}';
    expect(JSON.stringify(readRoomProfile(JSON.parse(vector)))).toBe(vector);
    for (const name of ["A", "x".repeat(36), "\uD83D\uDD12 room", "caf\u00e9", "a b"]) {
      expect(readRoomProfile(roomProfile(name)).name).toBe(name);
    }
  });
  it("rejects malformed, extended, control-bearing and noncanonical profiles", () => {
    for (const name of ["", "x".repeat(37), " a", "a ", "a\n", "a\u0085b", "\u00a0a", "a\ufeff", "\ud800", "\udfff"]) {
      expect(() => roomProfile(name)).toThrow();
    }
    for (const value of [null, undefined, [], "name", {}, { version: 2, name: "A" }, { version: "1", name: "A" },
      { version: 1, name: 5 }, { version: 1, name: "A", extra: true }, Object.create({ version: 1, name: "A" })]) {
      expect(() => readRoomProfile(value)).toThrow();
    }
  });
});
