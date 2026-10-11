import type { ReactNode } from "react";
import { PrivacyBlurContext, privacyBlurProps, usePrivacyBlur } from "./privacyBlurContext";

export function PrivacyBlurProvider({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  return <PrivacyBlurContext.Provider value={enabled}>{children}</PrivacyBlurContext.Provider>;
}

/** Wraps a sensitive label so it blurs when the privacy blur preference is on. */
export function PrivacyBlur({ children, className = "", title }: { children: ReactNode; className?: string; title?: string }) {
  const props = privacyBlurProps(usePrivacyBlur(), className);
  return <span {...props} className={props.className || undefined} title={title}>{children}</span>;
}
