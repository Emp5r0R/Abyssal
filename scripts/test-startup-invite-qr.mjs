// Disposable-relay qualification: decode terminal output with the client QR reader.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { decodeQrLuminance } from "../apps/web/src/security/qrDecoder.ts";
import { initSync, parseInviteCapsule } from "../apps/web/src/generated/abyssal_core/abyssal_core.js";

initSync({ module: readFileSync(new URL("../apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm", import.meta.url)) });
assert.equal(process.env.ABYSSAL_INTEGRATION_TEST, "1");
const seed = readFileSync(process.env.ABYSSAL_NODE_SIGNING_KEY_FILE);
const privateDer = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
const expectedPublicKey = createPublicKey(createPrivateKey({ key: privateDer, format: "der", type: "pkcs8" })).export({ type: "spki", format: "der" }).subarray(-32);
seed.fill(0); privateDer.fill(0);
const env = { ...process.env, ABYSSAL_INVITE_COUNT: "2", ABYSSAL_INVITE_PRINT_DELAY_MS: "0", RUST_LOG: "off" };
delete env.ABYSSAL_INVITE_QR_ENABLED; // Prove the real startup default, not an explicit override.
const relay = spawn(fileURLToPath(new URL("../target/debug/mirage-server", import.meta.url)), [], { env, stdio: ["ignore", "pipe", "pipe"] });
let output = "";
let tooLarge = false;
relay.stdout.setEncoding("utf8");
relay.stdout.on("data", (chunk) => {
  if (output.length + chunk.length > 256 * 1024) { tooLarge = true; relay.kill("SIGTERM"); }
  else output += chunk;
});
relay.stderr.resume();
const exited = once(relay, "exit");
const deadline = setTimeout(() => relay.kill("SIGKILL"), 15_000);
try {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (relay.exitCode !== null || relay.signalCode !== null) throw new Error("QR test relay exited before readiness");
    try {
      const health = await fetch(`http://${env.ABYSSAL_BIND_ADDR}/health`, { signal: AbortSignal.timeout(200) });
      if (health.ok) break;
    } catch { /* The relay has not bound its listener yet. */ }
    await delay(50);
  }
  const health = await fetch(`http://${env.ABYSSAL_BIND_ADDR}/health`, { signal: AbortSignal.timeout(1000) });
  assert.equal(health.status, 200);
  await delay(50);
  assert.equal(tooLarge, false);
  assert.equal(output.includes("ABYSSAL_INVITE invite="), false);
  assert.equal(output.includes("abyssal:invite:"), false);
  assert.equal(output.includes("ABY1-"), false);
  const blocks = output.split(/Invite \d+ of 2 \(QR\)\n/).slice(1);
  assert.equal(blocks.length, 2);
  const capabilities = [];
  for (const block of blocks) {
    const rows = [...block.matchAll(/\x1b\[30;47m([ \u2580\u2584\u2588]+)\x1b\[0m\n/g)].map(match => [...match[1]]);
    assert.ok(rows.length > 0);
    const columns = rows[0].length;
    assert.ok(columns <= 185);
    assert.equal(rows.length, Math.ceil(columns / 2));
    assert.ok(rows.every(row => row.length === columns));
    const scale = 4;
    const width = columns * scale;
    const height = rows.length * 2 * scale;
    const pixels = new Uint8ClampedArray(width * height).fill(255);
    try {
      for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
        const moduleY = Math.floor(y / scale);
        const char = rows[Math.floor(moduleY / 2)][Math.floor(x / scale)];
        const dark = char === "\u2588" || char === (moduleY % 2 === 0 ? "\u2580" : "\u2584");
        pixels[y * width + x] = dark ? 0 : 255;
      }
      const text = decodeQrLuminance(pixels, width, height);
      assert.ok(text, "terminal QR must decode with the actual client decoder");
      const invite = parseInviteCapsule(text, BigInt(Math.floor(Date.now() / 1000)), true);
      try {
        assert.deepEqual(Buffer.from(invite.node_public_key), expectedPublicKey);
        assert.equal(invite.node_url, `http://${env.ABYSSAL_BIND_ADDR}`);
        capabilities.push(new Uint8Array(invite.capability));
      } finally {
        invite.capability.fill(0); invite.account_context.fill(0); invite.node_public_key.fill(0);
      }
    } finally { pixels.fill(0); }
  }
  try { assert.notDeepEqual(capabilities[0], capabilities[1]); }
  finally { capabilities.forEach(value => value.fill(0)); }
  console.log("Default startup QR-only output decoded and signature-verified; distinct capabilities; no text disclosure");
} finally {
  if (relay.exitCode === null && relay.signalCode === null) relay.kill("SIGTERM");
  await exited;
  clearTimeout(deadline);
  output = "";
}
