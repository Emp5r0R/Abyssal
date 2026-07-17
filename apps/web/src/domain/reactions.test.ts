import { readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { exactReactionShortcut, REACTIONS, reactionByShortcode, searchReactions } from "./reactions";

describe("bundled reactions", () => {
  it("assigns one unique shortcut and path to every bundled reaction", () => {
    const directory = resolve(process.cwd(), "public/abyssal-emojis");
    const bundledFiles = readdirSync(directory).filter((name) => /\.(gif|png)$/i.test(name)).sort();
    expect(REACTIONS.map((reaction) => reaction.filename).sort()).toEqual(bundledFiles);
    expect(new Set(REACTIONS.map((reaction) => reaction.shortcode)).size).toBe(REACTIONS.length);
    expect(new Set(REACTIONS.map((reaction) => reaction.path)).size).toBe(REACTIONS.length);
  });

  it("resolves exact shortcuts case-insensitively", () => {
    expect(exactReactionShortcut(" :FIRE: ")?.filename).toBe("fire.gif");
    expect(exactReactionShortcut("message :fire:")).toBeUndefined();
    expect(reactionByShortcode(":gura_swag:")?.mimeType).toBe("image/png");
  });

  it("searches names and shortcut text", () => {
    expect(searchReactions(":fire:").map((reaction) => reaction.filename)).toContain("fire.gif");
  });
});
