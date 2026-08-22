import { describe, expect, it } from "vitest";
import {
  LOCAL_SENDER_CLIENT,
  isWebSender,
  parseSenderClient,
  senderClientWireField,
  senderOriginNotice,
} from "./senderClient";

describe("sender client origin disclosure", () => {
  it("accepts only the exact canonical wire values", () => {
    expect(parseSenderClient("android")).toBe("android");
    expect(parseSenderClient("web")).toBe("web");
  });

  it("fails closed on missing, mistyped, or unknown values", () => {
    expect(parseSenderClient(undefined)).toBeNull();
    expect(parseSenderClient(null)).toBeNull();
    expect(parseSenderClient("")).toBeNull();
    expect(parseSenderClient("ANDROID")).toBeNull();
    expect(parseSenderClient("Web")).toBeNull();
    expect(parseSenderClient("desktop")).toBeNull();
    expect(parseSenderClient(1)).toBeNull();
    expect(parseSenderClient(true)).toBeNull();
    expect(parseSenderClient(["web"])).toBeNull();
    expect(parseSenderClient({ client: "web" })).toBeNull();
  });

  it("tags this build as the web platform under the stable wire field", () => {
    expect(LOCAL_SENDER_CLIENT).toBe("web");
    expect(senderClientWireField()).toBe("sender_client");
  });

  it("classifies web-origin senders for warning rendering", () => {
    expect(isWebSender("web")).toBe(true);
    expect(isWebSender("android")).toBe(false);
    expect(isWebSender(undefined)).toBe(false);
    expect(isWebSender(null)).toBe(false);
  });

  it("explains each origin without leaking either notice into the other", () => {
    const web = senderOriginNotice("web");
    const android = senderOriginNotice("android");
    expect(web).toMatch(/web client/i);
    expect(web).toMatch(/screenshot/i);
    expect(android).toMatch(/Android app/i);
    expect(web).not.toBe(android);
  });
});
