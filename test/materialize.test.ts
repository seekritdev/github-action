import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { _internal } from "../src/actions.js";
import { decryptSecret, parseServiceToken, secretAad } from "../src/crypto.js";
import { filterValues, materialize } from "../src/materialize.js";
import type { ResolveResponse } from "../src/resolve.js";

/**
 * Golden vectors emitted by the REAL `@seekrit/crypto` (WebCrypto) — the same
 * fixture the Rust `seekrit-run` binary is verified against. Decrypting these
 * with the vendored crypto proves this action's ECDH/HKDF/AES-GCM path is
 * byte-compatible with the canonical browser/CLI implementation.
 */
interface Vectors {
  token: string;
  resolve: ResolveResponse;
  expectedManagedValues: Record<string, string>;
}

const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/vectors.json", import.meta.url), "utf8"),
) as Vectors;

describe("materialize (golden vectors from @seekrit/crypto)", () => {
  it("decrypts every layer and applies app-over-group precedence", async () => {
    const privateKey = await parseServiceToken(vectors.token);
    const { values, provenance } = await materialize(vectors.resolve, privateKey);

    expect(values).toEqual(vectors.expectedManagedValues);

    // SHARED collides across layers; the app layer must win.
    expect(values.SHARED).toBe("from-app");
    expect(provenance.SHARED).toContain("app:");
    expect(provenance.DATABASE_URL).toContain("group:");

    // UTF-8, control chars, and an empty value round-trip exactly.
    expect(values.UNICODE).toBe("héllo-🌍-\n-tab\tend");
    expect(values.EMPTY).toBe("");
  });

  it("binds ciphertext to (environmentId, name) via AAD — a swapped name fails", async () => {
    const privateKey = await parseServiceToken(vectors.token);
    const { unwrapDek } = await import("../src/crypto.js");
    const appLayer = vectors.resolve.layers.find((l) => l.source === "app");
    if (!appLayer) throw new Error("fixture missing app layer");
    const dek = await unwrapDek(appLayer.wrappedDek, privateKey);
    const apiKey = appLayer.secrets.find((s) => s.name === "API_KEY");
    if (!apiKey) throw new Error("fixture missing API_KEY");

    // Correct AAD decrypts; a mismatched name is rejected.
    await expect(
      decryptSecret(dek, apiKey.ciphertext, secretAad(appLayer.environmentId, "API_KEY")),
    ).resolves.toBe("sk-app-12345");
    await expect(
      decryptSecret(dek, apiKey.ciphertext, secretAad(appLayer.environmentId, "WRONG")),
    ).rejects.toThrow();
  });

  it("rejects a malformed service token", async () => {
    await expect(parseServiceToken("not-a-token")).rejects.toThrow();
  });
});

describe("filterValues", () => {
  const values = { A: "1", B: "2", C: "3" };

  it("returns everything when no filters are set", () => {
    expect(filterValues(values, [], [])).toEqual(values);
  });

  it("treats include as an allowlist", () => {
    expect(filterValues(values, ["A", "C"], [])).toEqual({ A: "1", C: "3" });
  });

  it("removes excluded names, even when included", () => {
    expect(filterValues(values, ["A", "B"], ["B"])).toEqual({ A: "1" });
  });
});

describe("workflow-command escaping", () => {
  it("escapes data (%, CR, LF)", () => {
    expect(_internal.escapeData("a%b\r\nc")).toBe("a%25b%0D%0Ac");
  });

  it("escapes properties (adds : and ,)", () => {
    expect(_internal.escapeProperty("a:b,c")).toBe("a%3Ab%2Cc");
  });
});
