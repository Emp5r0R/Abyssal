import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PrivacyPinGate } from "../security/privacyPin";
import { CalculatorCover } from "./Privacy";

afterEach(cleanup);

describe("calculator privacy cover", () => {
  it("clears a submitted cover PIN from the display before verification finishes", async () => {
    const gate = await PrivacyPinGate.create("123456", "", {
      iterations: 1_000,
      backoffMs: 1,
    });
    const onUnlock = vi.fn();

    render(<CalculatorCover pinGate={gate} onUnlock={onUnlock} onDuress={vi.fn()} />);
    for (const digit of "123456") fireEvent.click(screen.getByRole("button", { name: digit }));
    expect(screen.getByRole("status")).toHaveTextContent("123456");

    fireEvent.click(screen.getByRole("button", { name: "Equals" }));
    expect(screen.getByRole("status")).toHaveTextContent("0");
    await waitFor(() => expect(onUnlock).toHaveBeenCalledOnce());
    gate.destroy();
  });

  it("routes the distinct duress verifier without unlocking", async () => {
    const gate = await PrivacyPinGate.create("123456", "654321", {
      iterations: 1_000,
      backoffMs: 1,
    });
    const onUnlock = vi.fn();
    const onDuress = vi.fn();

    render(<CalculatorCover pinGate={gate} onUnlock={onUnlock} onDuress={onDuress} />);
    for (const digit of "654321") fireEvent.click(screen.getByRole("button", { name: digit }));
    fireEvent.click(screen.getByRole("button", { name: "Equals" }));

    await waitFor(() => expect(onDuress).toHaveBeenCalledOnce());
    expect(onUnlock).not.toHaveBeenCalled();
    gate.destroy();
  });
});
