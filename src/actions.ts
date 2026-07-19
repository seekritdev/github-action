/**
 * A tiny, dependency-free implementation of the GitHub Actions runner
 * primitives this action needs — the small subset of `@actions/core` that
 * matters here. Kept in-repo (rather than pulling the toolkit) so a
 * secrets-handling action has zero third-party runtime dependencies and stays
 * fully auditable.
 *
 * Behavior matches the documented runner contract: inputs arrive as `INPUT_*`
 * env vars; env/output writes go through the `GITHUB_ENV` / `GITHUB_OUTPUT`
 * files using the heredoc form (so multi-line values are safe); everything
 * else is a `::workflow-command::` on stdout.
 */
import { randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import { EOL } from "node:os";

// ── workflow-command escaping (see the runner's command spec) ───────────────
function escapeData(s: string): string {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeProperty(s: string): string {
  return escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function issueCommand(command: string, properties: Record<string, string>, message: string): void {
  let cmd = `::${command}`;
  const entries = Object.entries(properties);
  if (entries.length > 0) {
    cmd += " ";
    cmd += entries.map(([k, v]) => `${k}=${escapeProperty(v)}`).join(",");
  }
  cmd += `::${escapeData(message)}`;
  process.stdout.write(cmd + EOL);
}

// ── file commands (GITHUB_ENV / GITHUB_OUTPUT) ──────────────────────────────
function appendFileCommand(envVar: string, key: string, value: string): void {
  const filePath = process.env[envVar];
  if (!filePath) {
    throw new Error(`unable to write to ${envVar}: the environment variable is not set`);
  }
  // Heredoc form so multi-line values round-trip. The delimiter is random per
  // write and both key and value are checked against it (matches @actions/core).
  const delimiter = `ghadelimiter_${randomUUID()}`;
  if (key.includes(delimiter)) {
    throw new Error(`unexpected input: name should not contain the delimiter "${delimiter}"`);
  }
  if (value.includes(delimiter)) {
    throw new Error(`unexpected input: value should not contain the delimiter "${delimiter}"`);
  }
  appendFileSync(filePath, `${key}<<${delimiter}${EOL}${value}${EOL}${delimiter}${EOL}`, "utf8");
}

// ── inputs ──────────────────────────────────────────────────────────────────
function rawInput(name: string): string {
  const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "";
  return val.trim();
}

export function getInput(name: string, opts: { required?: boolean } = {}): string {
  const val = rawInput(name);
  if (opts.required && val === "") {
    throw new Error(`Input required and not supplied: ${name}`);
  }
  return val;
}

export function getBooleanInput(name: string, fallback: boolean): boolean {
  const val = rawInput(name);
  if (val === "") return fallback;
  if (["true", "True", "TRUE"].includes(val)) return true;
  if (["false", "False", "FALSE"].includes(val)) return false;
  throw new Error(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}`);
}

/** Split a comma/newline-separated list input into trimmed, non-empty items. */
export function getListInput(name: string): string[] {
  return rawInput(name)
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// ── outputs / env / masking / logging ───────────────────────────────────────
export function setOutput(name: string, value: string): void {
  appendFileCommand("GITHUB_OUTPUT", name, value);
}

export function exportVariable(name: string, value: string): void {
  process.env[name] = value;
  appendFileCommand("GITHUB_ENV", name, value);
}

/** Register a value so the runner redacts it from all subsequent log output. */
export function setSecret(value: string): void {
  // The runner ignores empty masks (and warns); skip them. Multi-line values
  // are masked whole and per-line, since the runner matches line by line.
  if (value.length === 0) return;
  issueCommand("add-mask", {}, value);
  if (value.includes("\n")) {
    for (const line of value.split("\n")) {
      if (line.length > 0) issueCommand("add-mask", {}, line);
    }
  }
}

export function info(message: string): void {
  process.stdout.write(message + EOL);
}

export function warning(message: string): void {
  issueCommand("warning", {}, message);
}

export function setFailed(message: string): void {
  process.exitCode = 1;
  issueCommand("error", {}, message);
}

/** Append markdown to the job summary, if the runner provides one. */
export function appendJobSummary(markdown: string): void {
  const filePath = process.env.GITHUB_STEP_SUMMARY;
  if (!filePath) return;
  try {
    appendFileSync(filePath, markdown + EOL, "utf8");
  } catch {
    // A missing/unwritable summary file must never fail the action.
  }
}

// Exported for unit tests.
export const _internal = { escapeData, escapeProperty };
