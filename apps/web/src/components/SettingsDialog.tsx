import { ShieldAlert } from "lucide-react";
import { useState } from "react";
import {
  withBlurEnabled,
  withCoverEnabled,
  withHiddenTabAction,
  type HiddenTabAction,
  type WorkspacePreferences,
} from "../domain/workspacePreferences";
import { CopyableValue } from "./CopyableValue";
import { Dialog, Toggle } from "./Ui";

const HIDDEN_TAB_OPTIONS: ReadonlyArray<{ value: HiddenTabAction; label: string; detail: string }> = [
  { value: "cover", label: "Lock behind the calculator", detail: "Your session stays open. Enter your PIN on the calculator to return." },
  { value: "sign-out", label: "Sign out", detail: "End the session. You sign in again with your invite and password." },
  { value: "stay", label: "Stay signed in", detail: "Nothing happens. The idle timer still signs you out." },
];

export interface SettingsDialogProps {
  preferences: WorkspacePreferences;
  username: string;
  nodeId: string;
  directoryCheckpoint?: string;
  onChange: (preferences: WorkspacePreferences) => void;
  onWipe: () => void;
  onClose: () => void;
}

/** Privacy and display preferences for this tab, session details, and the relay wipe. */
export function SettingsDialog({ preferences, username, nodeId, directoryCheckpoint, onChange, onWipe, onClose }: SettingsDialogProps) {
  const [confirmWipe, setConfirmWipe] = useState(false);
  return (
    <Dialog
      className="settings-dialog"
      title="Settings"
      description="Preferences apply to this browser tab and reset when it reloads."
      onClose={onClose}
      actions={<button className="primary-button" type="button" onClick={onClose}>Done</button>}
    >
      <section className="settings-section" aria-labelledby="settings-privacy">
        <h3 id="settings-privacy">Privacy</h3>
        <Toggle
          label="Calculator privacy cover"
          description="Disguise Abyssal as a calculator. You set a PIN when you turn this on."
          checked={preferences.coverEnabled}
          onChange={(enabled) => onChange(withCoverEnabled(preferences, enabled))}
        />
        <fieldset className="choice-group">
          <legend>When you switch away from this tab</legend>
          {HIDDEN_TAB_OPTIONS.map((option) => {
            const unavailable = option.value === "cover" && !preferences.coverEnabled;
            return (
              <label className={`choice ${preferences.hiddenTabAction === option.value ? "is-selected" : ""} ${unavailable ? "is-disabled" : ""}`} key={option.value}>
                <input
                  type="radio"
                  name="hidden-tab-action"
                  value={option.value}
                  checked={preferences.hiddenTabAction === option.value}
                  disabled={unavailable}
                  onChange={() => onChange(withHiddenTabAction(preferences, option.value))}
                />
                <span>
                  <strong>{option.label}</strong>
                  <small>{unavailable ? "Turn on the calculator cover to use this." : option.detail}</small>
                </span>
              </label>
            );
          })}
        </fieldset>
        <Toggle
          label="Blur names and messages"
          description="Blurred text shows when you hover over it or move focus to it."
          checked={preferences.blurEnabled}
          onChange={(enabled) => onChange(withBlurEnabled(preferences, enabled))}
        />
      </section>

      <section className="settings-section" aria-labelledby="settings-session">
        <h3 id="settings-session">Session</h3>
        <CopyableValue label="Account ID" value={username} />
        <CopyableValue label="Node" value={nodeId} />
        {directoryCheckpoint ? (
          <CopyableValue
            label="Directory checkpoint"
            value={directoryCheckpoint}
            title={`Directory checkpoint ${directoryCheckpoint}`}
            hint="Compare this with your contacts to confirm you see the same directory."
          />
        ) : null}
      </section>

      <section className="settings-section is-danger" aria-labelledby="settings-danger">
        <h3 id="settings-danger">Relay</h3>
        {confirmWipe ? (
          <div className="danger-confirm" role="alert">
            <ShieldAlert size={20} aria-hidden="true" />
            <p>Wipe relay memory? Every account, room, pending message and attachment on this relay disappears now. The relay then needs a restart and new invites.</p>
            <div className="danger-confirm-actions">
              <button className="secondary-button" type="button" onClick={() => setConfirmWipe(false)}>Cancel</button>
              <button className="danger-button" type="button" onClick={() => { setConfirmWipe(false); onWipe(); }}>Wipe now</button>
            </div>
          </div>
        ) : (
          <div className="settings-row">
            <span>
              <strong>Wipe relay memory</strong>
              <small>Erase everything held by this relay for every user.</small>
            </span>
            <button className="danger-button" type="button" onClick={() => setConfirmWipe(true)}>Wipe relay…</button>
          </div>
        )}
      </section>
    </Dialog>
  );
}
