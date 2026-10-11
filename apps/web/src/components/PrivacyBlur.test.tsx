import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { PrivacyBlur, PrivacyBlurProvider } from "./PrivacyBlur";
import { PRIVACY_BLUR_CLASS } from "./privacyBlurContext";

afterEach(cleanup);

describe("PrivacyBlur", () => {
  it("renders plain text while blur is off", () => {
    render(<PrivacyBlur className="custom">Sensitive label</PrivacyBlur>);

    const boundary = screen.getByText("Sensitive label");
    expect(boundary).toHaveClass("custom");
    expect(boundary).not.toHaveClass(PRIVACY_BLUR_CLASS);
    expect(boundary).not.toHaveAttribute("data-privacy-blur");
    expect(boundary).not.toHaveAttribute("tabindex");
  });

  it("marks sensitive content and keeps it keyboard-revealable when blur is on", () => {
    render(<PrivacyBlurProvider enabled><PrivacyBlur className="custom">Sensitive label</PrivacyBlur></PrivacyBlurProvider>);

    const boundary = screen.getByText("Sensitive label");
    expect(boundary).toHaveClass(PRIVACY_BLUR_CLASS, "custom");
    expect(boundary).toHaveAttribute("data-privacy-blur", "true");
    expect(boundary).toHaveAttribute("tabindex", "0");
  });
});
