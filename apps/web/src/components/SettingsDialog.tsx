import { Keyboard, ShieldAlert } from "lucide-react";
import { useState } from "react";
import {
  withBlurEnabled,
  withCoverEnabled,
  withHiddenTabAction,
  type HiddenTabAction,
  type WorkspacePreferences,
} from "../domain/workspacePreferences";
import type { NotificationLevel } from "../domain/notificationPolicy";
import type { NotifierPermission } from "../platform/notifier";
import { CopyableValue } from "./CopyableValue";
import { Dialog, Toggle } from "./Ui";

const HIDDEN_TAB_OPTIONS: ReadonlyArray<{ value: HiddenTabAction; label: string; detail: string }> = [
  { value: "cover", label: "Lock behind the calculator", detail: "Your session stays open. Enter your PIN on the calculator to return." },
  { value: "sign-out", label: "Sign out", detail: "End the session. You sign in again with your invite and password." },
  { value: "stay", label: "Stay signed in", detail: "Nothing happens. The idle timer still signs you out." },
];

const NOTIFICATION_OPTIONS: ReadonlyArray<{ value: NotificationLevel; label: string; detail: string }> = [
  { value: "off", label: "Off", detail: "No notifications." },
  { value: "private", label: "Private", detail: "Only “New message”. No name or text." },
  { value: "sender", label: "Sender", detail: "Who wrote, and in which room. No message text." },
  { value: "preview", label: "Sender and preview", detail: "Who wrote and the start of the message. Visible on your lock screen." },
];

export interface SettingsDialogProps {
  preferences: WorkspacePreferences;
  username: string;
  nodeId: string;
  directoryCheckpoint?: string;
  onChange: (preferences: WorkspacePreferences) => void;
  notificationPermission: NotifierPermission;
  /** Asks for browser permission first when needed; the level changes only once allowed. */
  onNotificationLevelChange: (level: NotificationLevel) => void;
  onShowShortcuts: () => void;
  onWipe: () => void;
  onClose: () => void;
}

/** Privacy and display preferences for this tab, session details, and the relay wipe. */
export function SettingsDialog({
  preferences,
  username,
  nodeId,
  directoryCheckpoint,
  onChange,
  notificationPermission,
  onNotificationLevelChange,
  onShowShortcuts,
  onWipe,
  onClose,
}: SettingsDialogProps) {
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

      <section className="settings-section" aria-labelledby="settings-notifications">
        <h3 id="settings-notifications">Notifications</h3>
        <fieldset className="choice-group">
          <legend>What a message notification shows</legend>
          {NOTIFICATION_OPTIONS.map((option) => {
            const unavailable = option.value !== "off" &&
              (notificationPermission === "unsupported" || notificationPermission === "denied");
            return (
              <label className={`choice ${preferences.notificationLevel === option.value ? "is-selected" : ""} ${unavailable ? "is-disabled" : ""}`} key={option.value}>
                <input
                  type="radio"
                  name="notification-level"
                  value={option.value}
                  checked={preferences.notificationLevel === option.value}
                  disabled={unavailable}
                  onChange={() => onNotificationLevelChange(option.value)}
                />
                <span>
                  <strong>{option.label}</strong>
                  <small>{option.detail}</small>
                </span>
              </label>
            );
          })}
        </fieldset>
        <p className="field-hint">{notificationHint(notificationPermission, preferences)}</p>
      </section>

      <section className="settings-section" aria-labelledby="settings-keyboard">
        <h3 id="settings-keyboard">Keyboard</h3>
        <div className="settings-row">
          <span>
            <strong>Keyboard shortcuts</strong>
            <small>Jump between conversations, lock, blur and more. Press ? anywhere to see them.</small>
          </span>
          <button className="secondary-button" type="button" onClick={onShowShortcuts}>
            <Keyboard size={15} aria-hidden="true" />Show shortcuts
          </button>
        </div>
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

function notificationHint(permission: NotifierPermission, preferences: WorkspacePreferences): string {
  if (permission === "unsupported") return "This browser does not support notifications.";
  if (permission === "denied") return "Notifications are blocked for this site. Allow them in your browser's site settings to choose a level.";
  if (preferences.notificationLevel === "off") return "Choosing a level asks your browser for permission.";
  if (preferences.hiddenTabAction === "sign-out") {
    return "You are signed out when you switch away from this tab, so notifications only arrive while this window is open but not in focus.";
  }
  if (preferences.hiddenTabAction === "cover") {
    return "Nothing is shown while the workspace is locked behind the calculator. Choose “Stay signed in” to be notified from other tabs.";
  }
  return "Notifications appear while this tab is in the background or you are in another conversation.";
}
