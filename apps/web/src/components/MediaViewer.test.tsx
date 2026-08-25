import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MediaViewer } from "./MediaViewer";

describe("MediaViewer privacy boundary", () => {
  it("conceals decrypted media and its filename until pointer or keyboard reveal", () => {
    render(<MediaViewer media={{
      messageId: "message-one",
      name: "private-image.png",
      mediaType: "IMAGE",
      mimeType: "image/png",
      objectUrl: "blob:test",
      oneTime: false,
    }} onClose={vi.fn()} />);

    expect(screen.getByText("private-image.png").closest("[data-privacy-blur='true']")).not.toBeNull();
    const stage = screen.getByRole("img", { name: "Decrypted attachment" }).closest(".media-stage");
    expect(stage).toHaveClass("privacy-blur");
    expect(stage).toHaveAttribute("tabindex", "0");
  });
});
