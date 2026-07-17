import { Eye, EyeOff, KeyRound, LoaderCircle, RadioTower } from "lucide-react";
import { useState, type FormEvent } from "react";
import type { AccountSession } from "../domain/types";
import { Brand, Field, IconButton, Toggle } from "./Ui";

export function Entrance({
  onLogin,
}: {
  onLogin: (input: { nodeUrl: string; code: string; password: string; retainWhenHidden: boolean }) => Promise<AccountSession>;
}) {
  const [nodeUrl, setNodeUrl] = useState(() => (window.location.port === "4020" ? window.location.origin : ""));
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [retainWhenHidden, setRetainWhenHidden] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(false);
    try {
      await onLogin({ nodeUrl, code, password, retainWhenHidden });
      setCode("");
      setPassword("");
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="entrance-page">
      <section className="entrance-brand-band" aria-label="Abyssal">
        <Brand />
        <div className="entrance-signal" aria-hidden="true">
          <span /><span /><span /><span />
        </div>
        <div className="entrance-node-line">
          <RadioTower size={16} />
          <span>NODE-DEFINED SESSION</span>
        </div>
      </section>

      <section className="entrance-panel">
        <form className="entrance-form" onSubmit={submit} noValidate>
          <div className="form-heading">
            <span className="eyebrow"><KeyRound size={14} /> ACCOUNT ENTRY</span>
            <h1>Enter Abyssal</h1>
            <p>New code creates account. Existing code enters account.</p>
          </div>

          <Field
            label="Node URL"
            name="node-url"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://node.example.com"
            value={nodeUrl}
            onChange={(event) => setNodeUrl(event.target.value)}
            required
          />
          <Field
            label="Invite code"
            name="invite-code"
            autoComplete="off"
            spellCheck={false}
            placeholder="XXXX-XXXXXXXX"
            value={code}
            onChange={(event) => setCode(event.target.value.toUpperCase())}
            required
          />
          <div className="password-field-wrap">
            <Field
              label="Password"
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete="off"
              placeholder="8 characters minimum"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              minLength={8}
            />
            <IconButton label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((value) => !value)}>
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </IconButton>
          </div>

          <Toggle
            checked={retainWhenHidden}
            onChange={setRetainWhenHidden}
            label="Keep session behind privacy cover"
          />

          <div className={`form-error ${error ? "is-visible" : ""}`} role="status" aria-live="polite">
            {error ? "Wrong information." : "\u00a0"}
          </div>

          <button className="primary-button entrance-submit" type="submit" disabled={busy || !nodeUrl || !code || password.length < 8}>
            {busy ? <LoaderCircle className="spin" size={18} /> : <KeyRound size={18} />}
            {busy ? "ENTERING" : "ENTER"}
          </button>
        </form>
      </section>
    </main>
  );
}

