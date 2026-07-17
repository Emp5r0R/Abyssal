import { Delete, Divide, Equal, Minus, Plus, X } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { evaluateExpression } from "../security/calculator";
import { Dialog, Field } from "./Ui";

export function PinSetup({
  onComplete,
}: {
  onComplete: (pin: string, duressPin: string) => void;
}) {
  const [pin, setPin] = useState("");
  const [confirm, setConfirm] = useState("");
  const [duress, setDuress] = useState("");
  const valid = /^\d{4,12}$/.test(pin) && pin === confirm && (!duress || (/^\d{4,12}$/.test(duress) && duress !== pin));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) onComplete(pin, duress);
  };

  return (
    <Dialog
      title="Set privacy cover PIN"
      description="PIN exists only in this browser tab. Remember it. Reloading clears session."
      actions={
        <button className="primary-button" form="pin-setup-form" disabled={!valid} type="submit">
          ENABLE COVER
        </button>
      }
    >
      <form id="pin-setup-form" className="stack-form" onSubmit={submit}>
        <Field label="Cover PIN" type="password" inputMode="numeric" autoComplete="off" maxLength={12} value={pin} onChange={(event) => setPin(digits(event.target.value))} />
        <Field label="Confirm PIN" type="password" inputMode="numeric" autoComplete="off" maxLength={12} value={confirm} onChange={(event) => setConfirm(digits(event.target.value))} />
        <Field label="Duress PIN (optional)" type="password" inputMode="numeric" autoComplete="off" maxLength={12} value={duress} onChange={(event) => setDuress(digits(event.target.value))} />
      </form>
    </Dialog>
  );
}

const KEYS = ["C", "(", ")", "/", "7", "8", "9", "*", "4", "5", "6", "-", "1", "2", "3", "+", "0", ".", "DEL", "="];

export function CalculatorCover({
  pin,
  duressPin,
  onUnlock,
  onDuress,
}: {
  pin: string;
  duressPin: string;
  onUnlock: () => void;
  onDuress: () => void;
}) {
  const [input, setInput] = useState("");
  const [display, setDisplay] = useState("0");

  useEffect(() => {
    const previous = document.title;
    document.title = "Calculator";
    return () => { document.title = previous; };
  }, []);

  const press = (key: string) => {
    if (key === "C") {
      setInput("");
      setDisplay("0");
      return;
    }
    if (key === "DEL") {
      const next = input.slice(0, -1);
      setInput(next);
      setDisplay(next || "0");
      return;
    }
    if (key === "=") {
      if (input === pin) {
        setInput("");
        setDisplay("0");
        onUnlock();
        return;
      }
      if (duressPin && input === duressPin) {
        setInput("");
        setDisplay("0");
        onDuress();
        return;
      }
      try {
        const result = evaluateExpression(input);
        setInput(result);
        setDisplay(result);
      } catch {
        setInput("");
        setDisplay("Error");
      }
      return;
    }
    if (input.length >= 40) return;
    const next = input + key;
    setInput(next);
    setDisplay(next);
  };

  return (
    <main className="calculator-page">
      <section className="calculator" aria-label="Calculator">
        <header><span>Calculator</span></header>
        <output aria-live="polite">{display}</output>
        <div className="calculator-grid">
          {KEYS.map((key) => (
            <button
              type="button"
              key={key}
              className={key === "=" ? "equals" : isOperator(key) ? "operator" : ""}
              aria-label={calculatorLabel(key)}
              onClick={() => press(key)}
            >
              {calculatorIcon(key) ?? key}
            </button>
          ))}
        </div>
      </section>
    </main>
  );
}

function digits(value: string): string {
  return value.replace(/\D/g, "").slice(0, 12);
}

function isOperator(key: string): boolean {
  return ["/", "*", "-", "+", "C", "DEL"].includes(key);
}

function calculatorIcon(key: string) {
  const props = { size: 21, strokeWidth: 2 };
  if (key === "/") return <Divide {...props} />;
  if (key === "*") return <X {...props} />;
  if (key === "-") return <Minus {...props} />;
  if (key === "+") return <Plus {...props} />;
  if (key === "=") return <Equal {...props} />;
  if (key === "DEL") return <Delete {...props} />;
  return null;
}

function calculatorLabel(key: string): string {
  return ({ "/": "Divide", "*": "Multiply", "-": "Subtract", "+": "Add", "=": "Equals", "DEL": "Delete", C: "Clear" } as Record<string, string>)[key] ?? key;
}

