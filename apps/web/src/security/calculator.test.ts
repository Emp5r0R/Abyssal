import { describe, expect, it } from "vitest";
import { evaluateExpression } from "./calculator";

describe("evaluateExpression", () => {
  it("respects precedence and parentheses", () => {
    expect(evaluateExpression("2+3*4")).toBe("14");
    expect(evaluateExpression("(2+3)*4")).toBe("20");
  });

  it("rejects malformed and unsafe input", () => {
    expect(() => evaluateExpression("2/0")).toThrow();
    expect(() => evaluateExpression("globalThis.alert(1)")).toThrow();
    expect(() => evaluateExpression("1.2.3")).toThrow();
  });
});

