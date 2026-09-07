import { Camera, ClipboardPaste, Eye, EyeOff, KeyRound, RadioTower } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import type { AccountSession } from "../domain/types";
import { AbyssalMarkLoader, Brand, Field, IconButton, Toggle } from "./Ui";
import { QrScanner } from "./QrScanner";
import { parseInvite, wipeParsedInvite } from "../security/invite";
import { QrImageInput } from "./QrImageInput";

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
  const [scanning, setScanning] = useState(false);
  const [readingImage, setReadingImage] = useState(false);
  const scanGeneration = useRef(0);
  const inviteInput = useRef<HTMLInputElement>(null);
  useEffect(() => () => { scanGeneration.current++; }, []);
  useEffect(() => {
    if (!scanning && invite) inviteInput.current?.focus();
  }, [invite, scanning]);
  const stopScanning = useCallback(() => {
    scanGeneration.current++;
    setScanning(false);
  }, []);
  const acceptScannedInvite = useCallback(async (value: string, signal: AbortSignal) => {
    const generation = scanGeneration.current;
    let parsed;
    try {
      parsed = await parseInvite(value);
      if (signal.aborted || scanGeneration.current !== generation) return false;
      setInvite(value);
      setError("");
      stopScanning();
      return true;
    } catch { return false; }
    finally { wipeParsedInvite(parsed); }
  }, [stopScanning]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy || scanning || readingImage || !invite || password.length < 8 || password.length > 128) return;
    scanGeneration.current++;
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

          {scanning ? <QrScanner onScanned={acceptScannedInvite} onClose={stopScanning} /> : (
            <button className="secondary-button" type="button" disabled={busy || readingImage} onClick={() => {
              scanGeneration.current++;
              setScanning(true);
            }}><Camera size={16} /> SCAN INVITE</button>
          )}
          <QrImageInput disabled={busy || scanning} onScanned={acceptScannedInvite} onBusyChange={setReadingImage} resetKey={invite} />
          <div className="field invite-field">
            <label className="field-label" htmlFor="abyssal-invite">Abyssal invite</label>
            <input
              id="abyssal-invite"
              ref={inviteInput}
              name="invite"
              type="password"
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="ABY1-... or abyssal:invite:..."
              value={invite}
              maxLength={2048}
              onChange={(event) => { scanGeneration.current++; setInvite(event.target.value); }}
              disabled={busy || scanning || readingImage}
              required
            />
            <button
              className="secondary-button invite-paste"
              type="button"
              disabled={busy || scanning || readingImage}
              onClick={() => {
                const generation = ++scanGeneration.current;
                void navigator.clipboard.readText()
                  .then((value) => {
                    if (scanGeneration.current === generation) setInvite(value.slice(0, 2048));
                  })
                  .catch(() => {
                    if (scanGeneration.current === generation) setError("Unable to read invite.");
                  });
              }}
            >
              <ClipboardPaste size={16} /> PASTE INVITE
            </button>
          </div>
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

          <button className="primary-button entrance-submit" type="submit" disabled={busy || scanning || readingImage || !invite || password.length < 8 || password.length > 128}>
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
