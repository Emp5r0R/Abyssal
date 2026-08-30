import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Entrance } from "./Entrance";

afterEach(cleanup);

describe("account entrance secret lifetime", () => {
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
    fireEvent.change(screen.getByLabelText("Node URL"), {
      target: { value: "https://node.example.test" },
    });
    fireEvent.change(screen.getByLabelText("Invite code"), {
      target: { value: "ABYS-INVITE-1234" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "ENTER" }));

    expect(screen.getByLabelText("Password")).toHaveValue("");
    await waitFor(() => expect(onLogin).toHaveBeenCalledOnce());
    expect(onPreflight).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "ENTERING" })).toContainElement(
      document.querySelector(".abyssal-mark-loader-compact"),
    );
    expect(new TextDecoder().decode(submittedPassword)).toBe("correct horse battery staple");

    rejectLogin?.(new Error("rejected"));
    await waitFor(() => expect(screen.getByText("Wrong information.")).toBeVisible());
    expect(submittedPassword?.every((byte) => byte === 0)).toBe(true);
  });

  it("does not call authentication when the fresh release preflight rejects", async () => {
    const onPreflight = vi.fn(async () => false);
    const onLogin = vi.fn(async () => ({}) as never);

    render(<Entrance onLogin={onLogin} onPreflight={onPreflight} />);
    fireEvent.change(screen.getByLabelText("Node URL"), {
      target: { value: "https://node.example.test" },
    });
    fireEvent.change(screen.getByLabelText("Invite code"), {
      target: { value: "ABYS-INVITE-1234" },
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
    fireEvent.change(screen.getByLabelText("Node URL"), {
      target: { value: "https://node.example.test" },
    });
    fireEvent.change(screen.getByLabelText("Invite code"), {
      target: { value: "ABYS-INVITE-1234" },
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
