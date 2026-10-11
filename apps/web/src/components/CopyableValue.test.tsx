import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CopyableValue } from "./CopyableValue";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function stubClipboard(writeText: (value: string) => Promise<void>) {
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
}

describe("CopyableValue", () => {
  it("prints the value as text and copies it on request", async () => {
    const writeText = vi.fn(async () => undefined);
    stubClipboard(writeText);
    render(<CopyableValue label="Verification code" value="abyssal:verify:v1:code" />);

    expect(screen.getByText("abyssal:verify:v1:code")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy verification code" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Copy verification code" })).toHaveTextContent("Copied"));
    expect(writeText).toHaveBeenCalledWith("abyssal:verify:v1:code");
  });

  it("tells the user to copy manually when the clipboard is unavailable", async () => {
    stubClipboard(vi.fn(async () => { throw new Error("denied"); }));
    render(<CopyableValue label="Node" value="node" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy node" }));
    expect(await screen.findByText(/copy it manually/u)).toBeInTheDocument();
  });
});
