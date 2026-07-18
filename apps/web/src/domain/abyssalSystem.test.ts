import { describe, expect, it } from "vitest";
import { normalizeNodeUrl } from "../security/nodeUrl";
import { classifyMedia, mediaAllowed, MEDIA_LIMIT_BYTES, clampRoom } from "./messagePolicy";
import { mentionsUsername, splitMentionText } from "./messageAttention";
import { reactionByShortcode, exactReactionShortcut } from "./reactions";

describe("Abyssal System Security & Feature Suite", () => {
  describe("1. Login & Connection Normalization", () => {
    it("normalizes standard hosts and defaults scheme to https", () => {
      const url = normalizeNodeUrl("node.example.com", "https:");
      expect(url.apiBaseUrl).toBe("https://node.example.com");
      expect(url.wsBaseUrl).toBe("wss://node.example.com");
    });

    it("rejects malicious or insecure remote URLs (security policy)", () => {
      expect(() => normalizeNodeUrl("http://remote-node.com", "https:")).toThrow();
      expect(() => normalizeNodeUrl("https://node.com?query=malicious", "https:")).toThrow();
      expect(() => normalizeNodeUrl("https://attacker:password@node.com", "https:")).toThrow();
    });

    it("allows loopback HTTP/WS for local testing", () => {
      const url = normalizeNodeUrl("http://127.0.0.1:4020", "https:");
      expect(url.apiBaseUrl).toBe("http://127.0.0.1:4020");
      expect(url.wsBaseUrl).toBe("ws://127.0.0.1:4020");
    });
  });

  describe("2. Message Send & Receive Logic", () => {
    it("parses user mentions accurately and case-insensitively", () => {
      expect(mentionsUsername("Check out @User123", "user123")).toBe(true);
      expect(mentionsUsername("Check out @User123", "another")).toBe(false);
    });

    it("safely splits content into text nodes without executing scripts", () => {
      const tokens = splitMentionText("Check @User123 <script>alert(1)</script>");
      expect(tokens).toEqual([
        { text: "Check " },
        { text: "@User123", username: "User123" },
        { text: " <script>alert(1)</script>" }
      ]);
    });
  });

  describe("3. Attachments, MIME Types, & Size Bounds", () => {
    it("classifies file MIME types correctly", () => {
      const imageFile = new File([], "test.jpg", { type: "image/jpeg" });
      const videoFile = new File([], "test.mp4", { type: "video/mp4" });
      const docFile = new File([], "test.pdf", { type: "application/pdf" });

      expect(classifyMedia(imageFile)).toBe("IMAGE");
      expect(classifyMedia(videoFile)).toBe("VIDEO");
      expect(classifyMedia(docFile)).toBe("FILE");
    });

    it("enforces static media size limit constraints", () => {
      expect(MEDIA_LIMIT_BYTES.IMAGE).toBe(20 * 1024 * 1024);
      expect(MEDIA_LIMIT_BYTES.VIDEO).toBe(100 * 1024 * 1024);
      expect(MEDIA_LIMIT_BYTES.FILE).toBe(200 * 1024 * 1024);
    });

    it("respects room-level media validation policies", () => {
      const restrictedRoom = {
        id: "forum_restricted",
        name: "Restricted",
        self_destruct_timer_sec: 10,
        overall_expiry_sec: 100,
        allow_images: true,
        allow_videos: false,
        allow_files: false,
        enforce_text_absolute_expiry: true,
        image_read_timer_sec: 10,
        image_overall_expiry_sec: 100,
        enforce_image_absolute_expiry: true,
        video_read_timer_sec: 10,
        video_overall_expiry_sec: 100,
        enforce_video_absolute_expiry: true,
        file_read_timer_sec: 10,
        file_overall_expiry_sec: 100,
        enforce_file_absolute_expiry: true,
      };

      expect(mediaAllowed(restrictedRoom, "IMAGE")).toBe(true);
      expect(mediaAllowed(restrictedRoom, "VIDEO")).toBe(false);
      expect(mediaAllowed(restrictedRoom, "FILE")).toBe(false);
    });
  });

  describe("4. Security Sanitization & Cyber Injection Attacks", () => {
    it("safely sanitizes and clamps room metadata strings", () => {
      const longRoomName = "A".repeat(100);
      const room = {
        id: "forum_test",
        name: longRoomName,
        self_destruct_timer_sec: 10,
        overall_expiry_sec: 100,
        allow_images: true,
        allow_videos: true,
        allow_files: true,
        enforce_text_absolute_expiry: true,
        image_read_timer_sec: 10,
        image_overall_expiry_sec: 100,
        enforce_image_absolute_expiry: true,
        video_read_timer_sec: 10,
        video_overall_expiry_sec: 100,
        enforce_video_absolute_expiry: true,
        file_read_timer_sec: 10,
        file_overall_expiry_sec: 100,
        enforce_file_absolute_expiry: true,
      };

      const clamped = clampRoom(room);
      expect(clamped.name.length).toBe(36);
      expect(clamped.name).toBe("A".repeat(36));
    });

    it("prevents script and HTML payload injections", () => {
      const rawPayload = "Hello <img src=x onerror=alert('xss')> @UserA";
      const tokens = splitMentionText(rawPayload);
      
      expect(tokens[0].text).toBe("Hello <img src=x onerror=alert('xss')> ");
      expect(tokens[1].username).toBe("UserA");
    });
  });

  describe("5. GIF Emoji Reactions & Shortcodes", () => {
    it("resolves exact shortcodes to correct assets and mime-types", () => {
      const gura = reactionByShortcode(":gura_swag:");
      expect(gura).toBeDefined();
      expect(gura?.filename).toBe("gura_swag.png");
      expect(gura?.mimeType).toBe("image/png");

      const fire = exactReactionShortcut(" :FIRE: ");
      expect(fire).toBeDefined();
      expect(fire?.filename).toBe("fire.gif");
      expect(fire?.mimeType).toBe("image/gif");
    });

    it("rejects invalid shortcode shortcuts", () => {
      expect(exactReactionShortcut("not_a_shortcut")).toBeUndefined();
    });
  });
});
