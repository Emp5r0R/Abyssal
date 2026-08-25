import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { RoomRecord } from "../domain/types";
import { CreateRoomDialog } from "./CreateRoomDialog";

describe("CreateRoomDialog routing identifier", () => {
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
});
