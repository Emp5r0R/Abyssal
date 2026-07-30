import "@testing-library/jest-dom/vitest";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { initSync } from "../generated/abyssal_core/abyssal_core";

Object.defineProperty(globalThis, "crypto", {
  configurable: true,
  value: webcrypto,
});

initSync({
  module: readFileSync(resolve(process.cwd(), "src/generated/abyssal_core/abyssal_core_bg.wasm")),
});
