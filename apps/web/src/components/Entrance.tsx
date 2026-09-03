import { ClipboardPaste, Eye, EyeOff, KeyRound, RadioTower } from "lucide-react";
import { useState, type FormEvent } from "react";
import type { AccountSession } from "../domain/types";
import { AbyssalMarkLoader, Brand, Field, IconButton, Toggle } from "./Ui";

export function Entrance({
  onLogin,
  onPreflight,
}: {
  onLogin: (input: { invite: string; password: Uint8Array; retainWhenHidden: boolean }) => Promise<AccountSession>;
  onPreflight: () => Promise<boolean | void>;
}) {
  const [invite, setInvite] = useState("");
  const [password, setPassword] = useState("");
  const [retainWhenHidden, setRetainWhenHidden] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    const submittedPassword = password;
    setPassword("");
    setShowPassword(false);
    let passwordBytes: Uint8Array | undefined;
    try {
      if ((await onPreflight()) === false) {
        throw new Error("Release verification rejected");
      }
      passwordBytes = new TextEncoder().encode(submittedPassword);
      await onLogin({ invite, password: passwordBytes, retainWhenHidden });
      setInvite("");
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Wrong information.";
      setError(INVITE_ERRORS.has(message) ? message : "Wrong information.");
    } finally {
      passwordBytes?.fill(0);
      setBusy(false);
    }
  };

  return (
    <main className="entrance-page">
      <section className="entrance-brand-band" aria-label="Abyssal">
        <Brand />
        <AbyssalMarkLoader className="entrance-signal" size="large" />
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
            <p>One signed invite selects and verifies your Abyssal node.</p>
          </div>

          <label className="field invite-field">
            <span className="field-label">Abyssal invite</span>
            <textarea
              name="invite"
              autoComplete="off"
              spellCheck={false}
              placeholder="ABY1-... or abyssal:invite:..."
              value={invite}
              maxLength={2048}
              onChange={(event) => setInvite(event.target.value)}
              required
            />
            <button
              className="secondary-button invite-paste"
              type="button"
              onClick={() => {
                void navigator.clipboard.readText()
                  .then((value) => setInvite(value.slice(0, 2048)))
                  .catch(() => setError("Unable to read invite."));
              }}
            >
              <ClipboardPaste size={16} /> PASTE INVITE
            </button>
          </label>
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
              maxLength={128}
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
            {error || "\u00a0"}
          </div>

          <button className="primary-button entrance-submit" type="submit" disabled={busy || !invite || password.length < 8 || password.length > 128}>
            {busy ? <AbyssalMarkLoader size="compact" /> : <KeyRound size={18} />}
            {busy ? "ENTERING" : "ENTER"}
          </button>
        </form>
      </section>
    </main>
  );
}

const INVITE_ERRORS = new Set([
  "Invalid invite",
  "Unsupported invite version",
  "Invite belongs to another application",
  "Invite signature invalid",
  "Invite expired",
  "Unsupported invite protocol",
  "Unsupported invite transport",
  "Invite checksum invalid",
  "Unable to reach node",
  "Unable to verify node",
  "Node identity mismatch",
  "Unable to read invite.",
]);
