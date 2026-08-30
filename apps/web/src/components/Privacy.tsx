import { Delete, Divide, Equal, Minus, Plus, X } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { evaluateExpression } from "../security/calculator";
import type { PrivacyPinGate } from "../security/privacyPin";
import { Dialog, Field } from "./Ui";

export function PinSetup({
  onComplete,
}: {
  onComplete: (pin: string, duressPin: string) => Promise<void>;
}) {
  const [pin, setPin] = useState("");
  const [confirm, setConfirm] = useState("");
  const [duress, setDuress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const validCover = /^\d{6,12}$/u.test(pin);
  const validConfirm = validCover && pin === confirm;
  const validDuress = !duress || (/^\d{6,12}$/u.test(duress) && duress !== pin);
  const valid = validCover && validConfirm && validDuress;

  const guidance = !validCover
    ? "Use 6-12 digits for the cover PIN."
    : !confirm
    ? "Re-enter the cover PIN to continue."
    : !validConfirm
    ? "PINs do not match."
    : !validDuress && duress === pin
    ? "Duress PIN must differ from the cover PIN."
    : !validDuress
    ? "Duress PIN must be 6-12 digits or left blank."
    : "Ready to enable privacy cover.";

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!valid || busy) return;
    const coverPin = pin;
    const duressPin = duress;
    setPin("");
    setConfirm("");
    setDuress("");
    setBusy(true);
    setError(false);
    try {
      await onComplete(coverPin, duressPin);
    } catch {
      // Keep the same non-specific failure surface as account entry.
      setError(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      title="Set privacy cover PIN"
      description="PIN exists only in this browser tab. Remember it. Reloading clears session."
      actions={
        <button className="primary-button" form="pin-setup-form" disabled={!valid || busy} type="submit">
          {busy ? "SECURING" : "ENABLE COVER"}
        </button>
      }
    >
      <form id="pin-setup-form" className="stack-form" onSubmit={submit}>
        <Field
          label="Cover PIN"
          name="privacy-cover-pin"
          type="password"
          inputMode="numeric"
          autoComplete="new-password"
          autoCorrect="off"
          spellCheck={false}
          pattern="[0-9]*"
          minLength={6}
          maxLength={12}
          value={pin}
          aria-invalid={pin.length > 0 && !validCover}
          aria-describedby="pin-setup-guidance"
          onChange={(event) => { setError(false); setPin(digits(event.target.value)); }}
        />
        <Field
          label="Confirm PIN"
          name="privacy-cover-pin-confirm"
          type="password"
          inputMode="numeric"
          autoComplete="new-password"
          autoCorrect="off"
          spellCheck={false}
          pattern="[0-9]*"
          minLength={6}
          maxLength={12}
          value={confirm}
          aria-invalid={confirm.length > 0 && !validConfirm}
          aria-describedby="pin-setup-guidance"
          onChange={(event) => { setError(false); setConfirm(digits(event.target.value)); }}
        />
        <Field
          label="Duress PIN (optional)"
          name="privacy-duress-pin"
          type="password"
          inputMode="numeric"
          autoComplete="new-password"
          autoCorrect="off"
          spellCheck={false}
          pattern="[0-9]*"
          minLength={6}
          maxLength={12}
          value={duress}
          aria-invalid={duress.length > 0 && !validDuress}
          aria-describedby="pin-setup-guidance"
          onChange={(event) => { setError(false); setDuress(digits(event.target.value)); }}
        />
        <p id="pin-setup-guidance" className="field-hint pin-setup-guidance" role="status" aria-live="polite">
          {error ? "Could not enable privacy cover." : guidance}
        </p>
      </form>
    </Dialog>
  );
}

const KEYS = [
  "sin", "cos", "tan", "(", ")",
  "ln", "log", "^", "√", "C",
  "π", "7", "8", "9", "/",
  "e", "4", "5", "6", "*",
  "x²", "1", "2", "3", "-",
  "DEL", "0", ".", "=", "+"
];

export function CalculatorCover({
  pinGate,
  onUnlock,
  onDuress,
}: {
  pinGate: PrivacyPinGate;
  onUnlock: () => void;
  onDuress: () => void;
}) {
  const [display, setDisplay] = useState("0");
  const inputRef = useRef("");
  const mountedRef = useRef(true);

  useEffect(() => {
    const previous = document.title;
    document.title = "Calculator";
    return () => {
      mountedRef.current = false;
      inputRef.current = "";
      document.title = previous;
    };
  }, []);

  const replaceInput = (value: string) => {
    inputRef.current = value;
  };

  const press = async (key: string) => {
    if (key === "C") {
      replaceInput("");
      setDisplay("0");
      return;
    }
    if (key === "DEL") {
      const next = inputRef.current.slice(0, -1);
      replaceInput(next);
      setDisplay(next || "0");
      return;
    }
    if (key === "=") {
      const submitted = inputRef.current;
      replaceInput("");
      if (/^\d{6,12}$/u.test(submitted)) {
        setDisplay("0");
        const result = await pinGate.verify(submitted);
        if (!mountedRef.current) return;
        if (result === "unlock" || result === "duress") {
          setDisplay("0");
          if (result === "duress") onDuress();
          else onUnlock();
          return;
        }
      }
      try {
        const result = evaluateExpression(submitted);
        replaceInput(result);
        setDisplay(result);
      } catch {
        replaceInput("");
        setDisplay("Error");
      }
      return;
    }
    if (inputRef.current.length >= 40) return;

    let append = key;
    if (key === "sin") append = "sin(";
    else if (key === "cos") append = "cos(";
    else if (key === "tan") append = "tan(";
    else if (key === "ln") append = "ln(";
    else if (key === "log") append = "log(";
    else if (key === "√") append = "sqrt(";
    else if (key === "x²") append = "^2";

    const next = inputRef.current + append;
    replaceInput(next);
    setDisplay(next);
  };

  return (
    <main className="calculator-page">
      <section className="calculator" aria-label="Calculator">
        <header>
          <div className="calc-branding">
            <img src="/abyssal-mark.svg" alt="" width={16} height={16} />
            <strong>ABYSSAL</strong>
            <span>LABS</span>
          </div>
          <span className="calc-model">MODEL 108S</span>
        </header>
        <output aria-live="polite">{display}</output>
        <div className="calculator-grid">
          {KEYS.map((key) => (
            <button
              type="button"
              key={key}
              className={
                key === "="
                  ? "equals"
                  : isArithmetic(key)
                  ? "arithmetic"
                  : isScientific(key)
                  ? "scientific"
                  : isControl(key)
                  ? "control"
                  : "number"
              }
              aria-label={calculatorLabel(key)}
              onClick={() => void press(key)}
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

function isArithmetic(key: string): boolean {
  return ["/", "*", "-", "+"].includes(key);
}

function isScientific(key: string): boolean {
  return ["sin", "cos", "tan", "ln", "log", "√", "x²", "^", "π", "e"].includes(key);
}

function isControl(key: string): boolean {
  return ["C", "DEL", "(", ")"].includes(key);
}

function calculatorIcon(key: string) {
  const props = { size: 18, strokeWidth: 2 };
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
