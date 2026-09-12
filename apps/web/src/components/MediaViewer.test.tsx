import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MediaViewer } from "./MediaViewer";

describe("MediaViewer privacy boundary", () => {
  afterEach(cleanup);

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

  it("associates the title and description, traps focus, and closes on Escape", async () => {
    const onClose = vi.fn();
    render(<MediaViewer media={{
      messageId: "message-one",
      name: "private-image.png",
      mediaType: "IMAGE",
      mimeType: "image/png",
      objectUrl: "blob:test",
      oneTime: false,
    }} onClose={onClose} />);

    const dialog = screen.getByRole("dialog");
    const titleId = dialog.getAttribute("aria-labelledby");
    const descriptionId = dialog.getAttribute("aria-describedby");
    expect(titleId).toBeTruthy();
    expect(descriptionId).toBeTruthy();
    expect(document.getElementById(titleId!)).toHaveTextContent("private-image.png");
    expect(document.getElementById(descriptionId!)).toHaveTextContent(/current browser process/u);

    const close = screen.getByRole("button", { name: "Close viewer" });
    await waitFor(() => expect(close).toHaveFocus());
    const stage = screen.getByRole("img", { name: "Decrypted attachment" }).closest<HTMLElement>(".media-stage")!;
    stage.focus();
    fireEvent.keyDown(stage, { key: "Tab" });
    expect(screen.getByText("private-image.png").closest("[data-privacy-blur='true']")).toHaveFocus();

    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("restores focus to the opener after Escape closes the viewer", async () => {
    function ViewerHarness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>Open viewer</button>
          {open ? <MediaViewer media={{
            messageId: "message-one",
            name: "private-image.png",
            mediaType: "IMAGE",
            mimeType: "image/png",
            objectUrl: "blob:test",
            oneTime: false,
          }} onClose={() => setOpen(false)} /> : null}
        </>
      );
    }

    render(<ViewerHarness />);
    const opener = screen.getByRole("button", { name: "Open viewer" });
    opener.focus();
    fireEvent.click(opener);
    await waitFor(() => expect(screen.getByRole("button", { name: "Close viewer" })).toHaveFocus());
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(opener).toHaveFocus());
  });
});
