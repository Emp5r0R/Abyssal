import { createContext, useContext } from "react";

export const PRIVACY_BLUR_CLASS = "privacy-blur";

/** Whether sensitive labels blur until hovered or focused. Off unless a provider turns it on. */
export const PrivacyBlurContext = createContext(false);

export function usePrivacyBlur(): boolean {
  return useContext(PrivacyBlurContext);
}

/** Attributes that blur an element and keep it keyboard-revealable, or just the class names when blur is off. */
export function privacyBlurProps(enabled: boolean, className = ""): {
  className: string;
  tabIndex?: number;
  "data-privacy-blur"?: "true";
} {
  if (!enabled) return { className };
  return { className: `${PRIVACY_BLUR_CLASS} ${className}`.trim(), tabIndex: 0, "data-privacy-blur": "true" };
}
