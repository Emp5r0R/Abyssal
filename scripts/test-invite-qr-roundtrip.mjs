// Optional native renderer qualification: requires qrencode on PATH and Node's
// built-in TypeScript stripping support.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { QR_TEST_INVITE } from "../apps/web/src/test/qrFixture.ts";
import { decodeQrLuminance } from "../apps/web/src/security/qrDecoder.ts";
import { decodeQrImage, initSync, parseInviteCapsule } from "../apps/web/src/generated/abyssal_core/abyssal_core.js";

initSync({ module: readFileSync(new URL("../apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm", import.meta.url)) });
const result = spawnSync("bash", [fileURLToPath(new URL("../deploy/render-invite-qr.sh", import.meta.url)), "png"], {
  input: QR_TEST_INVITE + "\n", timeout: 10_000, maxBuffer: 8 * 1024 * 1024,
});
assert.equal(result.status, 0, "Native QR renderer failed");
assert.deepEqual(result.stdout.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
const raster = decodeQrImage(result.stdout, "image/png");
try {
  const pixels = new Uint8ClampedArray(raster.luminance.buffer, raster.luminance.byteOffset, raster.luminance.byteLength);
  const text = decodeQrLuminance(pixels, raster.width, raster.height);
  assert.equal(text, QR_TEST_INVITE);
  const parsed = parseInviteCapsule(text, 2_000_000_000n, false);
  try { assert.equal(parsed.node_url, "https://node.example.com"); }
  finally {
    parsed.capability.fill(0);
    parsed.account_context.fill(0);
    parsed.node_public_key.fill(0);
  }
} finally {
  result.stdout.fill(0);
  raster.luminance.fill(0);
}
console.log("Native QR PNG -> shared raster decoder -> client QR decoder -> signed invite verification passed");
