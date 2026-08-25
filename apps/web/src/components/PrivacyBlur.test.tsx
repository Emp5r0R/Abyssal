import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PRIVACY_BLUR_CLASS, PrivacyBlur } from "./PrivacyBlur";

describe("PrivacyBlur", () => {
  it("marks sensitive content and keeps it keyboard-revealable", () => {
    render(<PrivacyBlur className="custom">Sensitive label</PrivacyBlur>);

    const boundary = screen.getByText("Sensitive label");
    expect(boundary).toHaveClass(PRIVACY_BLUR_CLASS, "custom");
    expect(boundary).toHaveAttribute("data-privacy-blur", "true");
    expect(boundary).toHaveAttribute("tabindex", "0");
  });
});
