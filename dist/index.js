// src/actions.ts
import { randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import { EOL } from "node:os";
function escapeData(s) {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeProperty(s) {
  return escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
}
function issueCommand(command, properties, message) {
  let cmd = `::${command}`;
  const entries = Object.entries(properties);
  if (entries.length > 0) {
    cmd += " ";
    cmd += entries.map(([k, v]) => `${k}=${escapeProperty(v)}`).join(",");
  }
  cmd += `::${escapeData(message)}`;
  process.stdout.write(cmd + EOL);
}
function appendFileCommand(envVar, key, value) {
  const filePath = process.env[envVar];
  if (!filePath) {
    throw new Error(`unable to write to ${envVar}: the environment variable is not set`);
  }
  const delimiter = `ghadelimiter_${randomUUID()}`;
  if (key.includes(delimiter)) {
    throw new Error(`unexpected input: name should not contain the delimiter "${delimiter}"`);
  }
  if (value.includes(delimiter)) {
    throw new Error(`unexpected input: value should not contain the delimiter "${delimiter}"`);
  }
  appendFileSync(filePath, `${key}<<${delimiter}${EOL}${value}${EOL}${delimiter}${EOL}`, "utf8");
}
function rawInput(name) {
  const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "";
  return val.trim();
}
function getInput(name, opts = {}) {
  const val = rawInput(name);
  if (opts.required && val === "") {
    throw new Error(`Input required and not supplied: ${name}`);
  }
  return val;
}
function getBooleanInput(name, fallback) {
  const val = rawInput(name);
  if (val === "") return fallback;
  if (["true", "True", "TRUE"].includes(val)) return true;
  if (["false", "False", "FALSE"].includes(val)) return false;
  throw new Error(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}`);
}
function getListInput(name) {
  return rawInput(name).split(/[\n,]/).map((s) => s.trim()).filter((s) => s.length > 0);
}
function setOutput(name, value) {
  appendFileCommand("GITHUB_OUTPUT", name, value);
}
function exportVariable(name, value) {
  process.env[name] = value;
  appendFileCommand("GITHUB_ENV", name, value);
}
function setSecret(value) {
  if (value.length === 0) return;
  issueCommand("add-mask", {}, value);
  if (value.includes("\n")) {
    for (const line of value.split("\n")) {
      if (line.length > 0) issueCommand("add-mask", {}, line);
    }
  }
}
function info(message) {
  process.stdout.write(message + EOL);
}
function warning(message) {
  issueCommand("warning", {}, message);
}
function setFailed(message) {
  process.exitCode = 1;
  issueCommand("error", {}, message);
}
function appendJobSummary(markdown) {
  const filePath = process.env.GITHUB_STEP_SUMMARY;
  if (!filePath) return;
  try {
    appendFileSync(filePath, markdown + EOL, "utf8");
  } catch {
  }
}

// src/crypto.ts
import { webcrypto } from "node:crypto";
var { subtle } = webcrypto;
function fromBase64Url(text) {
  return new Uint8Array(Buffer.from(text, "base64url"));
}
function utf8Encode(text) {
  return new TextEncoder().encode(text);
}
function utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}
function splitBlob(blob, prefix, segments) {
  const parts = blob.split(".");
  if (parts[0] !== prefix) {
    throw new Error(`expected a "${prefix}" blob, got "${parts[0] ?? ""}"`);
  }
  if (parts.length !== segments + 1 || parts.some((p) => p.length === 0)) {
    throw new Error(`malformed "${prefix}" blob`);
  }
  return parts.slice(1);
}
var TOKEN_PREFIX = "skt";
function isServiceToken(value) {
  return value.startsWith(`${TOKEN_PREFIX}_`);
}
async function parseServiceToken(token) {
  const match = /^(skt_[0-9A-Za-z]+)_([A-Za-z0-9_-]+)$/.exec(token);
  if (!match) {
    throw new Error("not a valid seekrit service token");
  }
  const keyB64 = match[2];
  try {
    return await subtle.importKey(
      "pkcs8",
      fromBase64Url(keyB64),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
  } catch {
    throw new Error("service token private key is corrupted");
  }
}
var WRAP_PREFIX = "wd1";
var HKDF_INFO = "seekrit/wrap-dek/v1";
async function deriveWrappingKey(ownPrivateKey, peerPublicKey, salt) {
  const sharedBits = await subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    ownPrivateKey,
    256
  );
  const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8Encode(HKDF_INFO) },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}
async function unwrapDek(wrapped, privateKey) {
  const [ephB64, saltB64, ivB64, ctB64] = splitBlob(wrapped, WRAP_PREFIX, 4);
  const ephemeralKey = await subtle.importKey(
    "raw",
    fromBase64Url(ephB64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const wrappingKey = await deriveWrappingKey(privateKey, ephemeralKey, fromBase64Url(saltB64));
  try {
    const dek = await subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(ivB64) },
      wrappingKey,
      fromBase64Url(ctB64)
    );
    return new Uint8Array(dek);
  } catch {
    throw new Error("DEK unwrap failed: wrong private key or tampered grant");
  }
}
var SECRET_PREFIX = "sc1";
function secretAad(environmentId, secretName) {
  return `${environmentId}/${secretName}`;
}
async function decryptSecret(dek, blob, aad) {
  const [ivB64, ctB64] = splitBlob(blob, SECRET_PREFIX, 2);
  const key = await subtle.importKey("raw", dek, { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    const plaintext = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(ivB64),
        additionalData: utf8Encode(aad)
      },
      key,
      fromBase64Url(ctB64)
    );
    return utf8Decode(new Uint8Array(plaintext));
  } catch {
    throw new Error("secret decryption failed: wrong key, tampered data, or mismatched context");
  }
}

// src/inputs.ts
var DEFAULT_API_URL = "https://api.seekrit.dev";
function readConfig() {
  const token = getInput("token", { required: true });
  if (!isServiceToken(token)) {
    throw new Error('the "token" input is not a seekrit service token (expected an "skt_\u2026" value)');
  }
  const apiUrl = getInput("api-url") || DEFAULT_API_URL;
  const overrides = getListInput("with").map((entry) => {
    const idx = entry.indexOf(":");
    if (idx <= 0 || idx === entry.length - 1) {
      throw new Error(`invalid "with" override "${entry}" \u2014 expected "group:env"`);
    }
    return { group: entry.slice(0, idx), env: entry.slice(idx + 1) };
  });
  return {
    token,
    apiUrl,
    overrides,
    exportEnv: getBooleanInput("export-env", true),
    setOutputs: getBooleanInput("set-outputs", false),
    mask: getBooleanInput("mask", true),
    prefix: getInput("prefix"),
    include: getListInput("include"),
    exclude: getListInput("exclude")
  };
}

// src/interpolate.ts
var REFERENCE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
var MAX_EXPANDED_LENGTH = 1048576;
function* scan(text) {
  let i = 0;
  while (i < text.length) {
    const dollar = text.indexOf("$", i);
    if (dollar === -1) {
      yield { literal: text.slice(i) };
      return;
    }
    if (dollar > i) yield { literal: text.slice(i, dollar) };
    if (text[dollar + 1] === "$" && text[dollar + 2] === "{") {
      yield { literal: "${" };
      i = dollar + 3;
      continue;
    }
    const close = text[dollar + 1] === "{" ? text.indexOf("}", dollar + 2) : -1;
    const reference = close === -1 ? null : text.slice(dollar + 2, close);
    if (reference !== null && REFERENCE_NAME.test(reference)) {
      yield { reference, raw: text.slice(dollar, close + 1) };
      i = close + 1;
      continue;
    }
    yield { literal: "$" };
    i = dollar + 1;
  }
}
function interpolateSecrets(values) {
  const resolved = /* @__PURE__ */ new Map();
  const unresolved = /* @__PURE__ */ new Set();
  const stack = [];
  function resolve(name) {
    const cached = resolved.get(name);
    if (cached !== void 0) return cached;
    const cycleAt = stack.indexOf(name);
    if (cycleAt !== -1) {
      const chain = [...stack.slice(cycleAt), name];
      throw new Error(`secret reference cycle: ${chain.join(" -> ")}`);
    }
    stack.push(name);
    let out = "";
    for (const segment of scan(values[name])) {
      if ("literal" in segment) {
        out += segment.literal;
      } else if (Object.hasOwn(values, segment.reference)) {
        out += resolve(segment.reference);
      } else {
        unresolved.add(segment.reference);
        out += segment.raw;
      }
    }
    stack.pop();
    if (out.length > MAX_EXPANDED_LENGTH) {
      throw new Error(`${name} expands to more than ${MAX_EXPANDED_LENGTH} bytes`);
    }
    resolved.set(name, out);
    return out;
  }
  const result = {};
  for (const name of Object.keys(values)) result[name] = resolve(name);
  return { values: result, unresolved: [...unresolved].sort() };
}

// src/materialize.ts
async function materialize(resolved, privateKey) {
  const values = {};
  const provenance = {};
  for (const layer of resolved.layers) {
    const dek = await unwrapDek(layer.wrappedDek, privateKey);
    const label = layer.source === "group" ? `group:${layer.groupSlug}@${layer.slug}` : `app:${resolved.scope.appSlug}/${layer.slug}`;
    for (const secret of layer.secrets) {
      values[secret.name] = await decryptSecret(
        dek,
        secret.ciphertext,
        secretAad(layer.environmentId, secret.name)
      );
      provenance[secret.name] = label;
    }
  }
  const { values: expanded, unresolved } = interpolateSecrets(values);
  return { values: expanded, provenance, unresolved };
}
function filterValues(values, include, exclude) {
  const allow = include.length > 0 ? new Set(include) : null;
  const deny = new Set(exclude);
  const out = {};
  for (const [name, value] of Object.entries(values)) {
    if (allow && !allow.has(name)) continue;
    if (deny.has(name)) continue;
    out[name] = value;
  }
  return out;
}

// src/resolve.ts
var ResolveError = class extends Error {
  status;
  code;
  constructor(status, code, message) {
    super(message);
    this.name = "ResolveError";
    this.status = status;
    this.code = code;
  }
};
async function fetchResolve(opts) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = opts.apiUrl.replace(/\/+$/, "");
  const params = new URLSearchParams();
  for (const o of opts.overrides ?? []) params.append("with", `${o.group}:${o.env}`);
  const qs = params.size > 0 ? `?${params}` : "";
  let res;
  try {
    res = await fetchImpl(`${base}/v1/resolve${qs}`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${opts.token}`,
        accept: "application/json",
        "user-agent": opts.userAgent ?? "seekrit-github-action"
      }
    });
  } catch (err) {
    throw new ResolveError(0, "network", `could not reach ${base}: ${err.message}`);
  }
  if (!res.ok) {
    const fallback = { error: { code: "internal", message: `HTTP ${res.status}` } };
    const payload = await res.json().catch(() => fallback);
    throw new ResolveError(
      res.status,
      payload.error?.code ?? "internal",
      payload.error?.message ?? `HTTP ${res.status}`
    );
  }
  return await res.json();
}

// src/main.ts
async function run() {
  const config = readConfig();
  const privateKey = await parseServiceToken(config.token);
  const resolved = await fetchResolve({
    apiUrl: config.apiUrl,
    token: config.token,
    overrides: config.overrides
  });
  const { values, unresolved } = await materialize(resolved, privateKey);
  if (unresolved.length > 0) {
    warning(`seekrit: unresolved reference(s), left as literal text: ${unresolved.join(", ")}`);
  }
  const selected = filterValues(values, config.include, config.exclude);
  const names = Object.keys(selected).sort();
  if (config.mask) {
    for (const name of names) setSecret(selected[name]);
  }
  for (const name of names) {
    const outName = config.prefix + name;
    const value = selected[name];
    if (config.exportEnv) exportVariable(outName, value);
    if (config.setOutputs) setOutput(outName, value);
  }
  setOutput("secrets-count", String(names.length));
  const scope = resolved.scope;
  const target = `${scope.orgSlug}/${scope.appSlug}:${scope.envSlug}`;
  const sinks = [
    config.exportEnv ? "$GITHUB_ENV" : null,
    config.setOutputs ? "step outputs" : null
  ].filter(Boolean);
  info(
    `seekrit: injected ${names.length} secret(s) from ${target}` + (sinks.length ? ` into ${sinks.join(" + ")}` : "") + (config.mask ? "" : " (masking disabled)")
  );
  appendJobSummary(
    `### \u{1F510} seekrit

Injected **${names.length}** secret(s) from \`${target}\`` + (names.length ? `:

${names.map((n) => `- \`${config.prefix + n}\``).join("\n")}
` : ".\n")
  );
}
run().catch((err) => {
  if (err instanceof ResolveError) {
    setFailed(`seekrit resolve failed (${err.code}): ${err.message}`);
  } else {
    setFailed(`seekrit: ${err.message}`);
  }
});
