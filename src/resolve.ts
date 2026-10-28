/**
 * The single network call this action makes: `GET /v1/resolve`, presenting
 * only the service token's auth credential as `Authorization: Bearer
 * skt_<id>_v2.<auth>` — never the private key. The server returns the ordered
 * ciphertext layers + per-principal wrapped DEKs and never sees plaintext
 * (seekrit's zero-knowledge invariant). Response shape mirrors
 * `@seekrit/core`'s `ResolveResponse`.
 */
import { serviceTokenAuth } from "./crypto.js";

/** One `group:env` override, as accepted by the resolve route's `?with=`. */
export interface GroupOverride {
  group: string;
  env: string;
}

/**
 * One layer of a resolved environment (ciphertext + the DEK wrapped to the
 * calling principal). Layers are returned lowest-precedence first: composed
 * groups (in position order) then the application environment's own secrets.
 */
export interface ResolveLayer {
  source: "group" | "app";
  environmentId: string;
  slug: string;
  /** Present for group layers: the composed group's slug. */
  groupSlug?: string;
  /** The environment DEK wrapped to the calling principal's public key. */
  wrappedDek: string;
  secrets: Array<{ name: string; ciphertext: string }>;
}

export interface ResolveScope {
  orgId: string;
  orgSlug: string;
  appId: string;
  appSlug: string;
  envId: string;
  envSlug: string;
}

export interface ResolveResponse {
  scope: ResolveScope;
  /** Lowest precedence first (groups → app). */
  layers: ResolveLayer[];
}

/** Error carrying the API's structured `{ code, message }` and HTTP status. */
export class ResolveError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ResolveError";
    this.status = status;
    this.code = code;
  }
}

export interface ResolveOptions {
  apiUrl: string;
  token: string;
  overrides?: GroupOverride[];
  userAgent?: string;
  /** Injectable for tests; defaults to the global `fetch` (Node 20+). */
  fetchImpl?: typeof fetch;
}

/** Fetch and parse the resolve response for the given service token. */
export async function fetchResolve(opts: ResolveOptions): Promise<ResolveResponse> {
  // Before anything else: a legacy token carries its private key in the one
  // string, so it must be refused here rather than sent.
  const auth = serviceTokenAuth(opts.token);
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = opts.apiUrl.replace(/\/+$/, "");
  const params = new URLSearchParams();
  for (const o of opts.overrides ?? []) params.append("with", `${o.group}:${o.env}`);
  const qs = params.size > 0 ? `?${params}` : "";

  let res: Response;
  try {
    res = await fetchImpl(`${base}/v1/resolve${qs}`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${auth}`,
        accept: "application/json",
        "user-agent": opts.userAgent ?? "seekrit-github-action",
      },
    });
  } catch (err) {
    throw new ResolveError(0, "network", `could not reach ${base}: ${(err as Error).message}`);
  }

  if (!res.ok) {
    const fallback = { error: { code: "internal", message: `HTTP ${res.status}` } };
    const payload = (await res.json().catch(() => fallback)) as typeof fallback;
    throw new ResolveError(
      res.status,
      payload.error?.code ?? "internal",
      payload.error?.message ?? `HTTP ${res.status}`,
    );
  }
  return (await res.json()) as ResolveResponse;
}
