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

  it("searchReactions with empty query returns all reactions", () => {
    expect(searchReactions("").length).toBe(REACTIONS.length);
    expect(searchReactions("   ").length).toBe(REACTIONS.length);
    expect(searchReactions(":").length).toBe(REACTIONS.length);
  });

  it("searchReactions respects limit parameter", () => {
    expect(searchReactions("e", 3).length).toBe(3);
    expect(searchReactions("pepe", 1).length).toBe(1);
    expect(searchReactions("fire", 0).length).toBe(0);
  });

  it("reactionByShortcode returns undefined for undefined input", () => {
    expect(reactionByShortcode(undefined)).toBeUndefined();
  });

  it("reactionByShortcode returns undefined for empty string", () => {
    expect(reactionByShortcode("")).toBeUndefined();
  });

  it("reactionByShortcode returns undefined for unknown shortcode", () => {
    expect(reactionByShortcode(":nonexistent:")).toBeUndefined();
  });

  it("exactReactionShortcut trims whitespace", () => {
    expect(exactReactionShortcut("   :fire:   ")?.filename).toBe("fire.gif");
    expect(exactReactionShortcut("\n:fire:\t")?.filename).toBe("fire.gif");
  });

  it("exactReactionShortcut returns undefined for non-shortcode text", () => {
    expect(exactReactionShortcut("fire")).toBeUndefined();
    expect(exactReactionShortcut("hello world")).toBeUndefined();
  });

  it("PNG reactions have correct mimeType", () => {
    const pngReactions = REACTIONS.filter((r) => r.filename.endsWith(".png"));
    expect(pngReactions.length).toBeGreaterThan(0);
    for (const reaction of pngReactions) {
      expect(reaction.mimeType).toBe("image/png");
    }
  });

  it("all reactions have valid path prefix", () => {
    for (const reaction of REACTIONS) {
      expect(reaction.path).toMatch(/^\/abyssal-emojis\//);
    }
  });

  it("all reactions have non-empty labels", () => {
    for (const reaction of REACTIONS) {
      expect(reaction.label.length).toBeGreaterThan(0);
    }
  });

  it("REACTIONS array is frozen", () => {
    expect(Object.isFrozen(REACTIONS)).toBe(true);
  });

  it("searchReactions is case-insensitive", () => {
    const lower = searchReactions("fire").map((r) => r.filename);
    const upper = searchReactions("FIRE").map((r) => r.filename);
    expect(lower).toEqual(upper);
  });

  it("searchReactions finds by filename substring", () => {
    const results = searchReactions("gura");
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some((r) => r.filename.includes("gura"))).toBe(true);
  });
});
