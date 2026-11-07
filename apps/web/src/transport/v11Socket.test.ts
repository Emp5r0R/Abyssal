import { beforeEach, describe, expect, it, vi } from "vitest";

const wasm = vi.hoisted(() => {
  class FakeConnection {
    static last: FakeConnection | null = null;
    readonly ticketSeen: number[];
    helloOpened = false;
    destroyed = false;
    freed = false;
    lastPlaintext: Uint8Array | null = null;
    lastOpened: Uint8Array | null = null;
    rejectFrames = false;
    constructor(_node: Uint8Array, _session: Uint8Array, _root: Uint8Array, ticket: Uint8Array) {
      this.ticketSeen = Array.from(ticket);
      FakeConnection.last = this;
    }
    clientHelloBytes(): Uint8Array {
      return new Uint8Array([0xc1]);
    }
    openServerHello(record: Uint8Array): void {
      if (record[0] !== 0x5e) throw new Error("bad hello");
      this.helloOpened = true;
    }
    ready(): boolean {
      return this.helloOpened;
    }
    sealFrame(plaintext: Uint8Array): Uint8Array {
      this.lastPlaintext = plaintext;
      return Uint8Array.from([0xaa, ...plaintext]);
    }
    openFrame(record: Uint8Array): Uint8Array {
      if (this.rejectFrames || record[0] !== 0xaa) throw new Error("aead");
      this.lastOpened = record.slice(1);
      return this.lastOpened;
    }
    destroy(): void {
      this.destroyed = true;
    }
    free(): void {
      this.freed = true;
    }
  }
  return { FakeConnection };
});

vi.mock("../generated/abyssal_core/abyssal_core", () => ({ WasmWsClientConnection: wasm.FakeConnection }));

import { V11SocketChannel, WS_PROTOCOL_V11 } from "./v11Socket";

const keys = {
  nodePublicKey: new Uint8Array(32).fill(1),
  sessionId: new Uint8Array(32).fill(2),
  transportRoot: new Uint8Array(32).fill(3),
};
const buffer = (bytes: number[]) => Uint8Array.from(bytes).buffer;

beforeEach(() => {
  wasm.FakeConnection.last = null;
});

describe("protocol-v11 WebSocket channel", () => {
  it("sends the ticket only inside the ClientHello and opens text after the ServerHello", () => {
    const channel = new V11SocketChannel(keys, "ticket");
    const connection = wasm.FakeConnection.last!;
    expect(WS_PROTOCOL_V11).toBe("abyssal-v11");
    expect(String.fromCharCode(...connection.ticketSeen)).toBe("ticket");
    expect(Array.from(channel.clientHello())).toEqual([0xc1]);
    expect(channel.ready).toBe(false);
    // Nothing may be sealed before the relay proves it holds the session keys.
    expect(() => channel.seal("early")).toThrow("Transport unavailable");

    expect(channel.receive(buffer([0x5e]))).toBeNull();
    expect(channel.ready).toBe(true);

    const sealed = channel.seal("hi");
    expect(Array.from(sealed)).toEqual([0xaa, 0x68, 0x69]);
    expect(connection.lastPlaintext!.every((byte) => byte === 0)).toBe(true);
    expect(channel.receive(buffer([0xaa, 0x6f, 0x6b]))).toBe("ok");
    expect(connection.lastOpened!.every((byte) => byte === 0)).toBe(true);
  });

  it("fails closed on text frames, a bad ServerHello, forged records and invalid UTF-8", () => {
    const textFirst = new V11SocketChannel(keys, "ticket");
    expect(() => textFirst.receive("{\"type\":\"hello\"}")).toThrow("Transport unavailable");

    const badHello = new V11SocketChannel(keys, "ticket");
    expect(() => badHello.receive(buffer([0x00]))).toThrow();
    expect(badHello.ready).toBe(false);

    const channel = new V11SocketChannel(keys, "ticket");
    channel.receive(buffer([0x5e]));
    expect(() => channel.receive("plaintext")).toThrow("Transport unavailable");
    wasm.FakeConnection.last!.rejectFrames = true;
    expect(() => channel.receive(buffer([0xaa, 0x41]))).toThrow("aead");
    wasm.FakeConnection.last!.rejectFrames = false;
    expect(() => channel.receive(buffer([0xaa, 0xff]))).toThrow();
  });

  it("destroys and frees the connection once and refuses use afterwards", () => {
    const channel = new V11SocketChannel(keys, "ticket");
    channel.receive(buffer([0x5e]));
    const connection = wasm.FakeConnection.last!;
    channel.destroy();
    channel.destroy();
    expect(connection.destroyed && connection.freed).toBe(true);
    expect(channel.ready).toBe(false);
    expect(() => channel.seal("late")).toThrow("Transport unavailable");
    expect(() => channel.clientHello()).toThrow("Transport unavailable");
    expect(() => channel.receive(buffer([0xaa]))).toThrow("Transport unavailable");
  });
});
