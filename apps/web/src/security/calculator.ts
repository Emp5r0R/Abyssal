export function evaluateExpression(input: string): string {
  const parser = new CalculatorParser(input.replace(/\s+/g, ""));
  const result = parser.parse();
  if (!Number.isFinite(result)) throw new Error("Invalid expression");
  return Number.isInteger(result) ? String(result) : String(Number(result.toFixed(8)));
}

class CalculatorParser {
  private index = 0;

  constructor(private readonly input: string) {}

  parse(): number {
    if (!this.input) return 0;
    const value = this.expression();
    if (this.index !== this.input.length) throw new Error("Unexpected input");
    return value;
  }

  private expression(): number {
    let value = this.term();
    while (this.peek("+") || this.peek("-")) {
      const operator = this.input[this.index++];
      const next = this.term();
      value = operator === "+" ? value + next : value - next;
    }
    return value;
  }

  private term(): number {
    let value = this.factor();
    while (this.peek("*") || this.peek("/")) {
      const operator = this.input[this.index++];
      const next = this.factor();
      if (operator === "/" && next === 0) throw new Error("Division by zero");
      value = operator === "*" ? value * next : value / next;
    }
    return value;
  }

  private factor(): number {
    if (this.peek("-")) {
      this.index += 1;
      return -this.factor();
    }
    if (this.peek("(")) {
      this.index += 1;
      const value = this.expression();
      if (!this.peek(")")) throw new Error("Missing parenthesis");
      this.index += 1;
      return value;
    }
    return this.number();
  }

  private number(): number {
    const start = this.index;
    while (this.index < this.input.length && /[\d.]/.test(this.input[this.index])) this.index += 1;
    if (start === this.index) throw new Error("Number expected");
    const raw = this.input.slice(start, this.index);
    if ((raw.match(/\./g) ?? []).length > 1) throw new Error("Invalid number");
    return Number(raw);
  }

  private peek(value: string): boolean {
    return this.input[this.index] === value;
  }
}

