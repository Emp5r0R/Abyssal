import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PrivacyPinGate } from "../security/privacyPin";
import { CalculatorCover, PinSetup } from "./Privacy";

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

describe("privacy cover PIN setup", () => {
  it("enables setup only for matching 6-12 digit PINs and rejects duplicate duress PINs", () => {
    const onComplete = vi.fn(async () => undefined);
    render(<PinSetup onComplete={onComplete} />);
    const cover = screen.getByLabelText("Cover PIN");
    const confirm = screen.getByLabelText("Confirm PIN");
    const duress = screen.getByLabelText("Duress PIN (optional)");
    const submit = screen.getByRole("button", { name: "ENABLE COVER" });

    expect(submit).toBeDisabled();
    fireEvent.change(cover, { target: { value: "12345" } });
    fireEvent.change(confirm, { target: { value: "12345" } });
    expect(submit).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("6-12 digits");

    fireEvent.change(cover, { target: { value: "123456" } });
    fireEvent.change(confirm, { target: { value: "654321" } });
    expect(submit).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("do not match");

    fireEvent.change(confirm, { target: { value: "123456" } });
    fireEvent.change(duress, { target: { value: "123456" } });
    expect(submit).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("must differ");

    fireEvent.change(duress, { target: { value: "654321" } });
    expect(submit).toBeEnabled();
    expect(screen.getByRole("status")).toHaveTextContent("Ready");
  });

  it("uses new-password autofill semantics and keeps setup failures vague", async () => {
    const onComplete = vi.fn(async () => { throw new Error("implementation detail"); });
    render(<PinSetup onComplete={onComplete} />);
    const cover = screen.getByLabelText("Cover PIN");
    const confirm = screen.getByLabelText("Confirm PIN");
    fireEvent.change(cover, { target: { value: "123456" } });
    fireEvent.change(confirm, { target: { value: "123456" } });

    expect(cover).toHaveAttribute("autocomplete", "new-password");
    expect(confirm).toHaveAttribute("autocomplete", "new-password");
    expect(cover).toHaveAttribute("name", "privacy-cover-pin");
    fireEvent.click(screen.getByRole("button", { name: "ENABLE COVER" }));

    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Could not enable privacy cover."));
    expect(onComplete).toHaveBeenCalledWith("123456", "");
  });
});
