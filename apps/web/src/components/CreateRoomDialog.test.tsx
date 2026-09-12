import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RoomRecord } from "../domain/types";
import { CreateRoomDialog } from "./CreateRoomDialog";

describe("CreateRoomDialog routing identifier", () => {
  afterEach(cleanup);

  it("never embeds the room display name in the relay-visible identifier", () => {
    const onCreate = vi.fn((room: RoomRecord): boolean => room.id.length > 0);
    render(<CreateRoomDialog onCancel={vi.fn()} onCreate={onCreate} />);

    fireEvent.change(screen.getByLabelText("Room name"), { target: { value: "Private Operations" } });
    fireEvent.click(screen.getByRole("button", { name: "CREATE" }));

    const room = onCreate.mock.calls[0]?.[0];
    expect(room?.name).toBe("Private Operations");
    expect(room?.id).toMatch(/^forum_[0-9a-f]{32}$/u);
    expect(room?.id).not.toContain("private");
    expect(room?.id).not.toContain("operations");
  });

  it("defaults to private and sends the explicit public visibility choice", () => {
    const onCreate = vi.fn((room: RoomRecord) => room.name.length >= 0);
    render(<CreateRoomDialog onCancel={vi.fn()} onCreate={onCreate} />);

    expect(screen.getByRole("radio", { name: "PRIVATE" })).toBeChecked();
    fireEvent.change(screen.getByLabelText("Room name"), { target: { value: "Discoverable" } });
    fireEvent.click(screen.getByRole("radio", { name: "PUBLIC" }));
    fireEvent.click(screen.getByRole("button", { name: "CREATE" }));

    expect(onCreate.mock.calls[0]?.[0].visibility).toBe("public");
  });

  it("reports a failed create result without closing the dialog", () => {
    const onCreate = vi.fn((room: RoomRecord) => room.name.length < 0);
    render(<CreateRoomDialog onCancel={vi.fn()} onCreate={onCreate} />);

    fireEvent.change(screen.getByLabelText("Room name"), { target: { value: "Private Operations" } });
    fireEvent.click(screen.getByRole("button", { name: "CREATE" }));

    expect(screen.getByRole("status")).toHaveTextContent("Room could not be created. Try again.");
    expect(screen.getByRole("heading", { name: "Create room" })).toBeInTheDocument();
  });

  it("closes on Escape and focuses the room name field first", async () => {
    const onCancel = vi.fn();
    render(<CreateRoomDialog onCancel={onCancel} onCreate={vi.fn(() => true)} />);

    await waitFor(() => expect(screen.getByLabelText("Room name")).toHaveFocus());
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCancel).toHaveBeenCalledOnce();
  });
});
