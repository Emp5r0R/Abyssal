import { Camera, ClipboardPaste, Eye, EyeOff, LogIn, ShieldCheck, Timer, UserRoundX } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import type { AccountSession } from "../domain/types";
import { AbyssalMarkLoader, Brand, Field, IconButton, Toggle } from "./Ui";
import { QrScanner } from "./QrScanner";
import { parseInvite, wipeParsedInvite } from "../security/invite";
import { QrImageInput } from "./QrImageInput";

export const SIGN_IN_FAILED = "Sign-in failed. Check the invite and password.";

export function Entrance({
  onLogin,
  onPreflight,
  notice = null,
  coverEnabled = true,
  onCoverEnabledChange,
}: {
  onLogin: (input: { invite: string; password: Uint8Array }) => Promise<AccountSession>;
  onPreflight: () => Promise<boolean | void>;
  notice?: string | null;
  coverEnabled?: boolean;
  onCoverEnabledChange?: (enabled: boolean) => void;
}) {
  const [invite, setInvite] = useState("");
  const [password, setPassword] = useState("");
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
      await onLogin({ invite, password: passwordBytes });
      setInvite("");
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : SIGN_IN_FAILED;
      setError(INVITE_ERRORS.has(message) ? message : SIGN_IN_FAILED);
    } finally {
      passwordBytes?.fill(0);
      setBusy(false);
    }
  };

  const inputsLocked = busy || scanning || readingImage;
  const canSubmit = !inputsLocked && !!invite && password.length >= 8 && password.length <= 128;

  return (
    <main className="entrance-page">
      <section className="entrance-intro" aria-label="About Abyssal">
        <Brand />
        <h2>Private conversations that leave no trace.</h2>
        <ul className="entrance-points">
          <li><ShieldCheck size={18} aria-hidden="true" /><span>Messages and files are end-to-end encrypted on your device.</span></li>
          <li><Timer size={18} aria-hidden="true" /><span>Messages disappear on a timer, and the relay keeps nothing on disk.</span></li>
          <li><UserRoundX size={18} aria-hidden="true" /><span>No phone number or email. An invite is all you need.</span></li>
        </ul>
      </section>

      <section className="entrance-panel">
        <form className="entrance-form" onSubmit={submit} noValidate>
          <div className="form-heading">
            <h1>Sign in</h1>
            <p>Use the invite from your node operator. A new invite creates your account; a used one signs you back in.</p>
          </div>
          {notice ? <p className="entrance-notice" role="status">{notice}</p> : null}

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
              placeholder="ABY1-… or abyssal:invite:…"
              value={invite}
              maxLength={2048}
              onChange={(event) => { scanGeneration.current++; setInvite(event.target.value); }}
              disabled={inputsLocked}
              required
            />
            <div className="invite-sources">
              <button
                className="secondary-button is-compact"
                type="button"
                disabled={inputsLocked}
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
                <ClipboardPaste size={15} aria-hidden="true" />Paste invite
              </button>
              {scanning ? null : (
                <button className="secondary-button is-compact" type="button" disabled={busy || readingImage} onClick={() => {
                  scanGeneration.current++;
                  setScanning(true);
                }}><Camera size={15} aria-hidden="true" />Scan invite</button>
              )}
              <QrImageInput compact disabled={busy || scanning} onScanned={acceptScannedInvite} onBusyChange={setReadingImage} resetKey={invite} />
            </div>
          </div>
          {scanning ? <QrScanner onScanned={acceptScannedInvite} onClose={stopScanning} /> : null}

          <div className="password-field-wrap">
            <Field
              label="Password"
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete="off"
              placeholder="At least 8 characters"
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
            checked={coverEnabled}
            onChange={(enabled) => onCoverEnabledChange?.(enabled)}
            disabled={!onCoverEnabledChange}
            label="Calculator privacy cover"
            description="Hide Abyssal behind a calculator when you switch tabs. You can change this later in Settings."
          />

          <div className={`form-error ${error ? "is-visible" : ""}`} role="status" aria-live="polite">
            {error || "\u00a0"}
          </div>

          <button className="primary-button entrance-submit" type="submit" disabled={!canSubmit}>
            {busy ? <AbyssalMarkLoader size="compact" /> : <LogIn size={18} aria-hidden="true" />}
            {busy ? "Signing in…" : "Sign in"}
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
