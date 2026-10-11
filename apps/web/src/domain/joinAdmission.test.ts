import { describe, expect, it } from "vitest";
import { JoinAdmissionQueue } from "./joinAdmission";

describe("JoinAdmissionQueue", () => {
  it("admits one request at a time in candidate order", () => {
    const queue = new JoinAdmissionQueue();
    expect(queue.next(["a", "b"])).toBe("a");
    expect(queue.next(["a", "b"])).toBeNull();
    expect(queue.settle("a", true)).toBe(false);
    expect(queue.next(["b"])).toBe("b");
  });

  it("retries a failed request a bounded number of times, then leaves it to the owner", () => {
    const queue = new JoinAdmissionQueue(2);
    expect(queue.next(["a"])).toBe("a");
    expect(queue.settle("a", false)).toBe(true);
    expect(queue.next(["a"])).toBe("a");
    expect(queue.settle("a", false)).toBe(false);
    expect(queue.next(["a"])).toBeNull();
    expect(queue.next(["a", "b"])).toBe("b");
  });

  it("ignores settlement for a request it did not claim", () => {
    const queue = new JoinAdmissionQueue();
    expect(queue.next(["a"])).toBe("a");
    expect(queue.settle("other", true)).toBe(false);
    expect(queue.next(["b"])).toBeNull();
  });

  it("rejects a non-positive attempt limit", () => {
    expect(() => new JoinAdmissionQueue(0)).toThrow();
  });
});
