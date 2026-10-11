import { useCallback, useRef, useState } from "react";
import {
  DEFAULT_WORKSPACE_PREFERENCES,
  hiddenTabResponse,
  withCoverEnabled,
  type HiddenTabResponse,
  type WorkspacePreferences,
} from "../domain/workspacePreferences";
import { PrivacyPinGate } from "../security/privacyPin";

/**
 * Owns the tab's privacy preferences and the calculator cover: its in-memory PIN
 * verifier and whether the workspace is currently locked behind it.
 */
export function usePrivacyCover() {
  const [preferences, setPreferences] = useState<WorkspacePreferences>(DEFAULT_WORKSPACE_PREFERENCES);
  const [pinGate, setPinGate] = useState<PrivacyPinGate | null>(null);
  const [locked, setLocked] = useState(false);
  const preferencesRef = useRef(preferences);
  const pinGateRef = useRef<PrivacyPinGate | null>(null);

  const destroyPinGate = useCallback(() => {
    pinGateRef.current?.destroy();
    pinGateRef.current = null;
    setPinGate(null);
    setLocked(false);
  }, []);

  const updatePreferences = useCallback((next: WorkspacePreferences) => {
    if (!next.coverEnabled) destroyPinGate();
    preferencesRef.current = next;
    setPreferences(next);
  }, [destroyPinGate]);

  const installPin = useCallback(async (pin: string, duressPin: string) => {
    const nextGate = await PrivacyPinGate.create(pin, duressPin);
    if (!preferencesRef.current.coverEnabled) {
      nextGate.destroy();
      return;
    }
    pinGateRef.current?.destroy();
    pinGateRef.current = nextGate;
    setPinGate(nextGate);
  }, []);

  const skipPinSetup = useCallback(() => {
    updatePreferences(withCoverEnabled(preferencesRef.current, false));
  }, [updatePreferences]);

  const coverReady = pinGate !== null && !pinGate.destroyed;

  /** Locks only when a PIN exists, so the workspace can never lock without a way back. */
  const lock = useCallback(() => {
    if (pinGateRef.current && !pinGateRef.current.destroyed) setLocked(true);
  }, []);

  const unlock = useCallback(() => setLocked(false), []);

  const respondToHiddenTab = useCallback((): HiddenTabResponse => {
    const gate = pinGateRef.current;
    return hiddenTabResponse(preferencesRef.current, gate !== null && !gate.destroyed);
  }, []);

  return {
    preferences,
    updatePreferences,
    pinGate: coverReady ? pinGate : null,
    coverReady,
    needsPinSetup: preferences.coverEnabled && !coverReady,
    locked: locked && coverReady,
    installPin,
    skipPinSetup,
    lock,
    unlock,
    respondToHiddenTab,
    destroyPinGate,
  };
}
