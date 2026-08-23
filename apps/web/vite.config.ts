import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const buildId = process.env.ABYSSAL_BUILD_ID ?? "web@0.0.0";
const buildSignature = process.env.ABYSSAL_BUILD_SIGNATURE_B64 ?? "";
const sourceCommit = process.env.ABYSSAL_SOURCE_COMMIT ?? "0000000000000000000000000000000000000000";

if (!/^web@(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(buildId)) {
  throw new Error("ABYSSAL_BUILD_ID is invalid");
}
if (buildSignature !== "" && !/^[A-Za-z0-9_-]{86}$/.test(buildSignature)) {
  throw new Error("ABYSSAL_BUILD_SIGNATURE_B64 is invalid");
}
if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
  throw new Error("ABYSSAL_SOURCE_COMMIT is invalid");
}

const buildIdentity = JSON.stringify({
  schema: "abyssal-build-identity-v1",
  build_id: buildId,
  source_commit: sourceCommit,
  build_signature_b64: buildSignature,
});

export default defineConfig({
  plugins: [
    react(),
    {
      name: "abyssal-build-identity",
      generateBundle() {
        this.emitFile({ type: "asset", fileName: "build-id.json", source: buildIdentity });
      },
    },
  ],
  define: {
    __ABYSSAL_BUILD_ID__: JSON.stringify(buildId),
    __ABYSSAL_BUILD_SIGNATURE_B64__: JSON.stringify(buildSignature),
    __ABYSSAL_SOURCE_COMMIT__: JSON.stringify(sourceCommit),
  },
  build: {
    target: "es2022",
    sourcemap: false,
    reportCompressedSize: true,
  },
  server: {
    port: 4173,
    strictPort: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    css: true,
  },
});
