import { describe, expect, it } from "vitest";
import {
  DEFAULT_WORKSPACE_PREFERENCES,
  hiddenTabResponse,
  withBlurEnabled,
  withCoverEnabled,
  withHiddenTabAction,
} from "./workspacePreferences";

describe("workspace preferences", () => {
  it("defaults to the calculator cover with blur off", () => {
    expect(DEFAULT_WORKSPACE_PREFERENCES).toEqual({ coverEnabled: true, blurEnabled: false, hiddenTabAction: "cover" });
    expect(Object.isFrozen(DEFAULT_WORKSPACE_PREFERENCES)).toBe(true);
  });

  it("signs out instead of locking once the cover is turned off, and restores locking when it returns", () => {
    const off = withCoverEnabled(DEFAULT_WORKSPACE_PREFERENCES, false);
    expect(off).toEqual({ coverEnabled: false, blurEnabled: false, hiddenTabAction: "sign-out" });
    expect(withCoverEnabled(off, true).hiddenTabAction).toBe("cover");
  });

  it("keeps an explicit stay-signed-in choice when the cover is turned off", () => {
    const stay = withHiddenTabAction(DEFAULT_WORKSPACE_PREFERENCES, "stay");
    expect(withCoverEnabled(stay, false).hiddenTabAction).toBe("stay");
  });

  it("refuses the cover action while the cover is off", () => {
    const off = withCoverEnabled(DEFAULT_WORKSPACE_PREFERENCES, false);
    expect(withHiddenTabAction(off, "cover")).toBe(off);
    expect(withHiddenTabAction(off, "stay").hiddenTabAction).toBe("stay");
  });

  it("returns the same object when nothing changes", () => {
    expect(withCoverEnabled(DEFAULT_WORKSPACE_PREFERENCES, true)).toBe(DEFAULT_WORKSPACE_PREFERENCES);
    expect(withBlurEnabled(DEFAULT_WORKSPACE_PREFERENCES, false)).toBe(DEFAULT_WORKSPACE_PREFERENCES);
    expect(withBlurEnabled(DEFAULT_WORKSPACE_PREFERENCES, true).blurEnabled).toBe(true);
  });

  it("maps the hidden-tab choice to a response", () => {
    expect(hiddenTabResponse(DEFAULT_WORKSPACE_PREFERENCES, true)).toBe("lock");
    expect(hiddenTabResponse(DEFAULT_WORKSPACE_PREFERENCES, false)).toBe("sign-out");
    expect(hiddenTabResponse(withCoverEnabled(DEFAULT_WORKSPACE_PREFERENCES, false), true)).toBe("sign-out");
    expect(hiddenTabResponse(withHiddenTabAction(DEFAULT_WORKSPACE_PREFERENCES, "stay"), false)).toBe("none");
  });
});
