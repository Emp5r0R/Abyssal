import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_WORKSPACE_PREFERENCES, withCoverEnabled, type WorkspacePreferences } from "../domain/workspacePreferences";
import type { NotifierPermission } from "../platform/notifier";
import { SettingsDialog } from "./SettingsDialog";

afterEach(cleanup);

function renderSettings(
  preferences: WorkspacePreferences = DEFAULT_WORKSPACE_PREFERENCES,
  notificationPermission: NotifierPermission = "default",
) {
  const props = {
    preferences,
    notificationPermission,
    onNotificationLevelChange: vi.fn(),
    onShowShortcuts: vi.fn(),
    username: "acct_1234567890abcdef1234567890abcdef",
    nodeId: "abyssal-node-v1:node",
    directoryCheckpoint: "A".repeat(43),
    onChange: vi.fn(),
    onWipe: vi.fn(),
    onClose: vi.fn(),
  };
  render(<SettingsDialog {...props} />);
  return props;
}

describe("SettingsDialog", () => {
  it("turns the cover off and blur on through pure preference updates", () => {
    const props = renderSettings();
    fireEvent.click(screen.getByRole("switch", { name: /Calculator privacy cover/u }));
    expect(props.onChange).toHaveBeenLastCalledWith({ ...DEFAULT_WORKSPACE_PREFERENCES, coverEnabled: false, hiddenTabAction: "sign-out" });
    fireEvent.click(screen.getByRole("switch", { name: /Blur names and messages/u }));
    expect(props.onChange).toHaveBeenLastCalledWith({ ...DEFAULT_WORKSPACE_PREFERENCES, blurEnabled: true });
  });

  it("disables the lock choice while the cover is off", () => {
    const props = renderSettings(withCoverEnabled(DEFAULT_WORKSPACE_PREFERENCES, false));
    expect(screen.getByRole("radio", { name: /Lock behind the calculator/u })).toBeDisabled();
    expect(screen.getByRole("radio", { name: /Sign out/u })).toBeChecked();
    fireEvent.click(screen.getByRole("radio", { name: /Stay signed in/u }));
    expect(props.onChange).toHaveBeenLastCalledWith({ ...DEFAULT_WORKSPACE_PREFERENCES, coverEnabled: false, hiddenTabAction: "stay" });
  });

  it("exposes session identifiers for out-of-band comparison", () => {
    renderSettings();
    expect(screen.getByTitle(`Directory checkpoint ${"A".repeat(43)}`)).toBeInTheDocument();
    expect(screen.getByText("acct_1234567890abcdef1234567890abcdef")).toBeInTheDocument();
  });

  it("requires a second explicit step before wiping the relay", () => {
    const props = renderSettings();
    fireEvent.click(screen.getByRole("button", { name: "Wipe relay…" }));
    expect(props.onWipe).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("button", { name: "Wipe now" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Wipe relay…" }));
    fireEvent.click(screen.getByRole("button", { name: "Wipe now" }));
    expect(props.onWipe).toHaveBeenCalledOnce();
  });

  it("closes from the Done action", () => {
    const props = renderSettings();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(props.onClose).toHaveBeenCalledOnce();
  });

  it("hands notification levels to the caller, which asks for permission", () => {
    const props = renderSettings();
    expect(screen.getByRole("radio", { name: /^Off/u })).toBeChecked();
    expect(screen.getByText("Choosing a level asks your browser for permission.")).toBeVisible();
    fireEvent.click(screen.getByRole("radio", { name: /Sender and preview/u }));
    expect(props.onNotificationLevelChange).toHaveBeenCalledWith("preview");
    expect(props.onChange).not.toHaveBeenCalled();
  });

  it("explains blocked notifications and keeps levels unavailable", () => {
    renderSettings(DEFAULT_WORKSPACE_PREFERENCES, "denied");
    expect(screen.getByRole("radio", { name: /^Private/u })).toBeDisabled();
    expect(screen.getByRole("radio", { name: /^Off/u })).toBeEnabled();
    expect(screen.getByText(/blocked for this site/u)).toBeVisible();
  });

  it("warns that a locked workspace stays silent", () => {
    renderSettings({ ...DEFAULT_WORKSPACE_PREFERENCES, notificationLevel: "sender" }, "granted");
    expect(screen.getByText(/Nothing is shown while the workspace is locked/u)).toBeVisible();
  });

  it("opens the keyboard shortcut list", () => {
    const props = renderSettings();
    fireEvent.click(screen.getByRole("button", { name: "Show shortcuts" }));
    expect(props.onShowShortcuts).toHaveBeenCalledOnce();
  });
});
