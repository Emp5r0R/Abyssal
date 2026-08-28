import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SecurityRuntimeGate } from "./SecurityRuntimeGate";

afterEach(cleanup);

describe("security runtime gate", () => {
  it("does not mount account UI before the WASM runtime is ready", async () => {
    let resolve!: () => void;
    const initialize = vi.fn(() => new Promise<void>((done) => { resolve = done; }));
    render(<SecurityRuntimeGate initialize={initialize}><div>Account entry</div></SecurityRuntimeGate>);

    expect(screen.queryByText("Account entry")).not.toBeInTheDocument();
    expect(screen.getByText("Verifying release")).toBeInTheDocument();

    await act(async () => { resolve(); });
    expect(screen.getByText("Account entry")).toBeInTheDocument();
  });

  it("fails closed and retries runtime initialization only after user action", async () => {
    const initialize = vi.fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error("unavailable"))
      .mockResolvedValueOnce();
    render(<SecurityRuntimeGate initialize={initialize}><div>Account entry</div></SecurityRuntimeGate>);

    expect(await screen.findByText("Verification unavailable")).toBeInTheDocument();
    expect(screen.queryByText("Account entry")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "RETRY" }));

    expect(await screen.findByText("Account entry")).toBeInTheDocument();
    expect(initialize).toHaveBeenCalledTimes(2);
  });
});
