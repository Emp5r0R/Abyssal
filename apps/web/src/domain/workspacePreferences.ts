/** What the workspace does when the browser tab is hidden. */
export type HiddenTabAction = "cover" | "sign-out" | "stay";

/** How the app reacts to a hidden tab right now. */
export type HiddenTabResponse = "lock" | "sign-out" | "none";

/**
 * Per-tab display and privacy preferences. They live only in memory, like every
 * other piece of web client state, so a reload returns to the defaults.
 */
export interface WorkspacePreferences {
  /** Disguise the workspace as a calculator behind a PIN. */
  readonly coverEnabled: boolean;
  /** Blur names and message text until hovered or focused. */
  readonly blurEnabled: boolean;
  readonly hiddenTabAction: HiddenTabAction;
}

export const DEFAULT_WORKSPACE_PREFERENCES: WorkspacePreferences = Object.freeze({
  coverEnabled: true,
  blurEnabled: false,
  hiddenTabAction: "cover",
});

/** Turning the cover off never leaves a hidden tab unprotected by default: it signs out instead. */
export function withCoverEnabled(preferences: WorkspacePreferences, coverEnabled: boolean): WorkspacePreferences {
  if (preferences.coverEnabled === coverEnabled) return preferences;
  if (coverEnabled) return { ...preferences, coverEnabled, hiddenTabAction: "cover" };
  return {
    ...preferences,
    coverEnabled,
    hiddenTabAction: preferences.hiddenTabAction === "cover" ? "sign-out" : preferences.hiddenTabAction,
  };
}

export function withBlurEnabled(preferences: WorkspacePreferences, blurEnabled: boolean): WorkspacePreferences {
  return preferences.blurEnabled === blurEnabled ? preferences : { ...preferences, blurEnabled };
}

/** The cover action needs the cover; other actions are always allowed. */
export function withHiddenTabAction(preferences: WorkspacePreferences, hiddenTabAction: HiddenTabAction): WorkspacePreferences {
  if (hiddenTabAction === "cover" && !preferences.coverEnabled) return preferences;
  return preferences.hiddenTabAction === hiddenTabAction ? preferences : { ...preferences, hiddenTabAction };
}

/** A cover whose PIN is not set yet cannot lock, so the session ends instead. */
export function hiddenTabResponse(preferences: WorkspacePreferences, coverReady: boolean): HiddenTabResponse {
  switch (preferences.hiddenTabAction) {
    case "cover": return preferences.coverEnabled && coverReady ? "lock" : "sign-out";
    case "sign-out": return "sign-out";
    case "stay": return "none";
  }
}
