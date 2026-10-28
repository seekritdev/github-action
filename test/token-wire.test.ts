import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseServiceToken, serviceTokenAuth } from "../src/crypto.js";
import { fetchResolve } from "../src/resolve.js";

/**
 * The v2 service-token boundary, pinned to the same golden vectors as the
 * monorepo's clients: the bundle carries an auth credential and a private key,
 * and only the auth credential may ever reach the API. Mirrors
 * `sdks/js/test/token-wire.test.mjs` in the seekrit monorepo.
 */
interface Vectors {
  token: string;
  authToken: string;
  tokenId: string;
  resolve: unknown;
}

const v = JSON.parse(
  readFileSync(new URL("./fixtures/vectors.json", import.meta.url), "utf8"),
) as Vectors;
const privatePart = v.token.split(".")[2] as string;
const legacy = `${v.tokenId}_${privatePart}`;

describe("service token v2", () => {
  it("extracts the auth credential, and only that", () => {
    expect(serviceTokenAuth(v.token)).toBe(v.authToken);
    expect(serviceTokenAuth(v.authToken)).toBe(v.authToken);
  });

  it("sends only the auth credential to the API", async () => {
    const seen: RequestInit[] = [];
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      seen.push(init);
      return Response.json(v.resolve);
    }) as unknown as typeof fetch;

    await fetchResolve({ apiUrl: "https://api.test", token: v.token, fetchImpl });

    expect(seen).toHaveLength(1);
    const init = seen[0] as RequestInit;
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${v.authToken}`);
    expect(JSON.stringify(init)).not.toContain(privatePart);
  });

  it("refuses a legacy token before any request is made", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return Response.json(v.resolve);
    }) as unknown as typeof fetch;

    await expect(
      fetchResolve({ apiUrl: "https://api.test", token: legacy, fetchImpl }),
    ).rejects.toThrow(/v2 service token/);
    expect(calls).toBe(0);
  });

  it("still parses a legacy token's key offline, but never an auth credential", async () => {
    await expect(parseServiceToken(legacy)).resolves.toBeDefined();
    await expect(parseServiceToken(v.authToken)).rejects.toThrow();
  });

  it("rejects malformed and unknown-version tokens", () => {
    for (const invalid of [
      `${v.token}.extra`,
      `${v.token}\n`,
      "skt_bad",
      `${v.tokenId}_v3.${"A".repeat(43)}.key`,
    ]) {
      expect(() => serviceTokenAuth(invalid)).toThrow();
    }
  });
});
