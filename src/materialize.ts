/**
 * Turn a resolve response into the concrete variable set, applying the same
 * layer precedence as `seekrit run` / `seekrit-run`:
 *
 *   app-env secrets  >  group secrets   (later layers win)
 *
 * Each layer's DEK is unwrapped once with the principal's private key and its
 * ciphertexts decrypted locally, then `${NAME}` references are expanded across
 * the merged set. Values never leave the runner. A provenance map (names only)
 * records which layer each value came from, for logging.
 */
import type { webcrypto } from "node:crypto";
import { decryptSecret, secretAad, unwrapDek } from "./crypto.js";
import { interpolateSecrets } from "./interpolate.js";
import type { ResolveResponse } from "./resolve.js";

export interface Materialized {
  /** Resolved variable name → plaintext value, references expanded. */
  values: Record<string, string>;
  /** Variable name → the layer it resolved from (names only; never values). */
  provenance: Record<string, string>;
  /** Referenced names found nowhere in the set, left as literal text. */
  unresolved: string[];
}

export async function materialize(
  resolved: ResolveResponse,
  privateKey: webcrypto.CryptoKey,
): Promise<Materialized> {
  const values: Record<string, string> = {};
  const provenance: Record<string, string> = {};

  // Layers arrive lowest precedence first (groups → app); later writes win.
  for (const layer of resolved.layers) {
    const dek = await unwrapDek(layer.wrappedDek, privateKey);
    const label =
      layer.source === "group"
        ? `group:${layer.groupSlug}@${layer.slug}`
        : `app:${resolved.scope.appSlug}/${layer.slug}`;
    for (const secret of layer.secrets) {
      values[secret.name] = await decryptSecret(
        dek,
        secret.ciphertext,
        secretAad(layer.environmentId, secret.name),
      );
      provenance[secret.name] = label;
    }
  }

  // After the merge, so a reference picks up whichever layer won that name.
  const { values: expanded, unresolved } = interpolateSecrets(values);
  return { values: expanded, provenance, unresolved };
}

/**
 * Apply include/exclude name filters to a materialized value set. `include`,
 * when non-empty, is an allowlist; `exclude` always removes. Exact-match on
 * secret names (case-sensitive).
 */
export function filterValues(
  values: Record<string, string>,
  include: string[],
  exclude: string[],
): Record<string, string> {
  const allow = include.length > 0 ? new Set(include) : null;
  const deny = new Set(exclude);
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(values)) {
    if (allow && !allow.has(name)) continue;
    if (deny.has(name)) continue;
    out[name] = value;
  }
  return out;
}
