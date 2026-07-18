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

  it("evaluates exponents and powers", () => {
    expect(evaluateExpression("2^3")).toBe("8");
    expect(evaluateExpression("2^3^2")).toBe("64");
    expect(evaluateExpression("3*2^4")).toBe("48");
    expect(evaluateExpression("4^0.5")).toBe("2");
  });

  it("evaluates trigonometric functions", () => {
    expect(evaluateExpression("sin(0)")).toBe("0");
    expect(evaluateExpression("sin(pi/2)")).toBe("1");
    expect(evaluateExpression("cos(0)")).toBe("1");
    expect(evaluateExpression("cos(pi)")).toBe("-1");
    expect(evaluateExpression("tan(0)")).toBe("0");
  });

  it("evaluates logarithms", () => {
    expect(evaluateExpression("log(100)")).toBe("2");
    expect(evaluateExpression("log(1)")).toBe("0");
    expect(evaluateExpression("ln(e)")).toBe("1");
    expect(evaluateExpression("ln(1)")).toBe("0");
  });

  it("evaluates square root", () => {
    expect(evaluateExpression("sqrt(9)")).toBe("3");
    expect(evaluateExpression("sqrt(0)")).toBe("0");
    expect(() => evaluateExpression("sqrt(-4)")).toThrow();
  });

  it("resolves mathematical constants", () => {
    expect(Number(evaluateExpression("pi"))).toBeCloseTo(Math.PI, 8);
    expect(Number(evaluateExpression("π"))).toBeCloseTo(Math.PI, 8);
    expect(Number(evaluateExpression("e"))).toBeCloseTo(Math.E, 8);
  });

  it("respects complex precedence combinations", () => {
    expect(evaluateExpression("sin(pi/2) + 2^3 * 3 - sqrt(25)")).toBe("20");
    expect(evaluateExpression("ln(e^2)")).toBe("2");
  });

  it("rejects malformed scientific input", () => {
    expect(() => evaluateExpression("sin(")).toThrow();
    expect(() => evaluateExpression("sqrt")).toThrow();
    expect(() => evaluateExpression("sin(1,2)")).toThrow();
    expect(() => evaluateExpression("cos(pi")).toThrow();
    expect(() => evaluateExpression("unknown(5)")).toThrow();
  });
});
