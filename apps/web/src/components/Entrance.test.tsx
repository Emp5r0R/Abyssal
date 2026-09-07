import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Entrance } from "./Entrance";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("account entrance secret lifetime", () => {
  it("does not let a delayed clipboard result overwrite newer input or submit", async () => {
    let resolvePaste: ((value: string) => void) | undefined;
    const readText = vi.fn(() => new Promise<string>(resolve => { resolvePaste = resolve; }));
    vi.stubGlobal("navigator", { clipboard: { readText } });
    const onLogin = vi.fn(async () => ({}) as never);
    render(<Entrance onLogin={onLogin} onPreflight={async () => true} />);
    fireEvent.click(screen.getByRole("button", { name: "PASTE INVITE" }));
    fireEvent.change(screen.getByLabelText("Abyssal invite"), { target: { value: "newer-secret" } });
    await act(async () => { resolvePaste?.("stale-secret"); });
    expect(screen.getByLabelText("Abyssal invite")).toHaveValue("newer-secret");
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("type", "password");
    expect(document.body.textContent).not.toContain("secret");
    expect(onLogin).not.toHaveBeenCalled();
  });

  it("clears the password field before authentication and wipes submitted bytes", async () => {
    let submittedPassword: Uint8Array | undefined;
    let rejectLogin: ((error: Error) => void) | undefined;
    const onLogin = vi.fn((input: { password: Uint8Array }) => {
      submittedPassword = input.password;
      return new Promise<never>((_resolve, reject) => {
        rejectLogin = reject;
      });
    });

    const onPreflight = vi.fn(async () => true);
    render(<Entrance onLogin={onLogin} onPreflight={onPreflight} />);
    const signal = document.querySelector(".entrance-signal");
    expect(signal).toHaveClass("abyssal-mark-loader", "abyssal-mark-loader-large");
    expect(signal?.querySelectorAll(":scope > span")).toHaveLength(4);
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("maxlength", "2048");
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("type", "password");
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("autocomplete", "off");
    expect(screen.getByLabelText("Password")).toHaveAttribute("maxlength", "128");
    fireEvent.change(screen.getByLabelText("Abyssal invite"), {
      target: { value: "fixture-invite" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "ENTER" }));

    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(screen.getByLabelText("Abyssal invite")).toBeDisabled();
    await waitFor(() => expect(onLogin).toHaveBeenCalledOnce());
    expect(onPreflight).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "ENTERING" })).toContainElement(
      document.querySelector(".abyssal-mark-loader-compact"),
    );
    expect(new TextDecoder().decode(submittedPassword)).toBe("correct horse battery staple");

    rejectLogin?.(new Error("rejected"));
    await waitFor(() => expect(screen.getByText("Wrong information.")).toBeVisible());
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("type", "password");
    expect(document.body.textContent).not.toContain("fixture-invite");
    expect(submittedPassword?.every((byte) => byte === 0)).toBe(true);
  });

  it("does not call authentication when the fresh release preflight rejects", async () => {
    const onPreflight = vi.fn(async () => false);
    const onLogin = vi.fn(async () => ({}) as never);

    render(<Entrance onLogin={onLogin} onPreflight={onPreflight} />);
    fireEvent.change(screen.getByLabelText("Abyssal invite"), {
      target: { value: "fixture-invite" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "ENTER" }));

    await waitFor(() => expect(onPreflight).toHaveBeenCalledOnce());
    expect(onLogin).not.toHaveBeenCalled();
    expect(screen.getByText("Wrong information.")).toBeVisible();
  });

  it("runs authentication only after the fresh release preflight passes", async () => {
    const onPreflight = vi.fn(async () => true);
    const onLogin = vi.fn(async () => ({}) as never);

    render(<Entrance onLogin={onLogin} onPreflight={onPreflight} />);
    fireEvent.change(screen.getByLabelText("Abyssal invite"), {
      target: { value: "fixture-invite" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "ENTER" }));

    await waitFor(() => expect(onLogin).toHaveBeenCalledOnce());
    expect(onPreflight).toHaveBeenCalledOnce();
    expect(onPreflight.mock.invocationCallOrder[0]).toBeLessThan(onLogin.mock.invocationCallOrder[0]);
  });
});
