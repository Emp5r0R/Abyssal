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

    render(<Entrance onLogin={onLogin} />);
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

    expect(onLogin).toHaveBeenCalledOnce();
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(new TextDecoder().decode(submittedPassword)).toBe("correct horse battery staple");

    rejectLogin?.(new Error("rejected"));
    await waitFor(() => expect(screen.getByText("Wrong information.")).toBeVisible());
    expect(submittedPassword?.every((byte) => byte === 0)).toBe(true);
  });
});
