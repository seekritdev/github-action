/**
 * Zero-knowledge crypto for the seekrit GitHub Action — the decrypt-only path.
 *
 * This is a faithful, self-contained port of the canonical browser/CLI
 * implementation in `@seekrit/crypto` (packages/crypto in the seekrit
 * monorepo). It is vendored here so this repository can stand alone: the
 * monorepo's internal packages export TypeScript source directly and are not
 * published to npm.
 *
 * The wire formats are versioned and frozen — `wd1.` wrapped DEKs and `sc1.`
 * secret ciphertexts never change in place (a new scheme gets a new prefix) —
 * so this vendored copy stays compatible. Its correctness is pinned by
 * `test/materialize.test.ts`, which decrypts golden vectors produced by the
 * real `@seekrit/crypto` and asserts byte-for-byte equality.
 *
 * WebCrypto only (Node's `node:crypto` webcrypto), matching seekrit's
 * cross-runtime crypto invariant. No Node-specific crypto primitives.
 */
import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;
type CryptoKey = webcrypto.CryptoKey;

// ── encoding ────────────────────────────────────────────────────────────────
function fromBase64Url(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "base64url"));
}

function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Split a versioned `prefix.a.b.c` blob into its segments, validating the
 * version prefix and segment count. Mirrors `@seekrit/crypto`'s `splitBlob`.
 */
function splitBlob(blob: string, prefix: string, segments: number): string[] {
  const parts = blob.split(".");
  if (parts[0] !== prefix) {
    throw new Error(`expected a "${prefix}" blob, got "${parts[0] ?? ""}"`);
  }
  if (parts.length !== segments + 1 || parts.some((p) => p.length === 0)) {
    throw new Error(`malformed "${prefix}" blob`);
  }
  return parts.slice(1);
}

// ── service token ─────────────────────────────────────────────────────────
// Bundle: `skt_<id>_v2.<32-byte auth secret>.<private key pkcs8, base64url>`
// Wire:   `skt_<id>_v2.<32-byte auth secret>`
// One local bundle holds independent authentication and decryption material.
// Only serviceTokenAuth(token) may be sent to the API; the private key stays on
// the runner. Legacy `skt_<id>_<pkcs8>` bundles still parse offline but must
// never be transmitted.
const TOKEN_PREFIX = "skt";

export function isServiceToken(value: string): boolean {
  return value.startsWith(`${TOKEN_PREFIX}_`);
}

/** Extract only the independent auth credential. Never fall back to a raw token. */
export function serviceTokenAuth(token: string): string {
  const match = /^(skt_[0-9A-Za-z]+_v2\.[A-Za-z0-9_-]{43})(?:\.[A-Za-z0-9_-]+)?$/.exec(token);
  const auth = match?.[1];
  if (!match || match[0] !== token || !auth) {
    throw new Error(
      "a v2 service token is required for API access; replace legacy tokens in the dashboard",
    );
  }
  return auth;
}

/** Recover the ECDH P-256 private key carried by a service token. */
export async function parseServiceToken(token: string): Promise<CryptoKey> {
  // Only the first two underscores are separators — the base64url key segment
  // may itself contain underscores.
  const match = /^(skt_[0-9A-Za-z]+)_(?:v2\.[A-Za-z0-9_-]{43}\.)?([A-Za-z0-9_-]+)$/.exec(token);
  if (!match || match[0] !== token) {
    throw new Error("not a valid seekrit service token");
  }
  const keyB64 = match[2] as string;
  try {
    return await subtle.importKey(
      "pkcs8",
      fromBase64Url(keyB64),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
  } catch {
    throw new Error("service token private key is corrupted");
  }
}

// ── DEK unwrap (ECIES: ephemeral ECDH → HKDF → AES-GCM) ─────────────────────
// Blob format: `wd1.<ephemeral pub (raw)>.<hkdf salt>.<iv>.<ciphertext>`
const WRAP_PREFIX = "wd1";
const HKDF_INFO = "seekrit/wrap-dek/v1";

async function deriveWrappingKey(
  ownPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const sharedBits = await subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    ownPrivateKey,
    256,
  );
  const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8Encode(HKDF_INFO) },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

/** Unwrap an environment DEK with the principal's private ECDH key. */
export async function unwrapDek(wrapped: string, privateKey: CryptoKey): Promise<Uint8Array> {
  const [ephB64, saltB64, ivB64, ctB64] = splitBlob(wrapped, WRAP_PREFIX, 4) as [
    string,
    string,
    string,
    string,
  ];
  const ephemeralKey = await subtle.importKey(
    "raw",
    fromBase64Url(ephB64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const wrappingKey = await deriveWrappingKey(privateKey, ephemeralKey, fromBase64Url(saltB64));
  try {
    const dek = await subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(ivB64) },
      wrappingKey,
      fromBase64Url(ctB64),
    );
    return new Uint8Array(dek);
  } catch {
    throw new Error("DEK unwrap failed: wrong private key or tampered grant");
  }
}

// ── secret decrypt (AES-256-GCM) ────────────────────────────────────────────
// Blob format: `sc1.<iv>.<ciphertext>`
const SECRET_PREFIX = "sc1";

/** AAD binding a secret ciphertext to its environment + name. */
export function secretAad(environmentId: string, secretName: string): string {
  return `${environmentId}/${secretName}`;
}

export async function decryptSecret(dek: Uint8Array, blob: string, aad: string): Promise<string> {
  const [ivB64, ctB64] = splitBlob(blob, SECRET_PREFIX, 2) as [string, string];
  const key = await subtle.importKey("raw", dek, { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    const plaintext = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(ivB64),
        additionalData: utf8Encode(aad),
      },
      key,
      fromBase64Url(ctB64),
    );
    return utf8Decode(new Uint8Array(plaintext));
  } catch {
    throw new Error("secret decryption failed: wrong key, tampered data, or mismatched context");
  }
}
