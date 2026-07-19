/**
 * seekrit GitHub Action entrypoint.
 *
 * Flow: read inputs → resolve the service token's environment over the network
 * (ciphertext only) → decrypt every layer locally with the key carried in the
 * token → mask each value in the runner logs → inject into `$GITHUB_ENV`
 * (and/or step outputs). Plaintext never leaves the runner and is never logged.
 */
import {
  appendJobSummary,
  exportVariable,
  info,
  setFailed,
  setOutput,
  setSecret,
} from "./actions.js";
import { parseServiceToken } from "./crypto.js";
import { readConfig } from "./inputs.js";
import { filterValues, materialize } from "./materialize.js";
import { fetchResolve, ResolveError } from "./resolve.js";

async function run(): Promise<void> {
  const config = readConfig();

  // The token carries its own private key; parse it before any network call so
  // a malformed token fails fast and clearly.
  const privateKey = await parseServiceToken(config.token);

  const resolved = await fetchResolve({
    apiUrl: config.apiUrl,
    token: config.token,
    overrides: config.overrides,
  });

  const { values } = await materialize(resolved, privateKey);
  const selected = filterValues(values, config.include, config.exclude);
  const names = Object.keys(selected).sort();

  // Mask first — before writing anywhere — so a value can never surface in the
  // logs, even if a later step echoes the environment.
  if (config.mask) {
    for (const name of names) setSecret(selected[name] as string);
  }

  for (const name of names) {
    const outName = config.prefix + name;
    const value = selected[name] as string;
    if (config.exportEnv) exportVariable(outName, value);
    if (config.setOutputs) setOutput(outName, value);
  }

  setOutput("secrets-count", String(names.length));

  const scope = resolved.scope;
  const target = `${scope.orgSlug}/${scope.appSlug}:${scope.envSlug}`;
  const sinks = [
    config.exportEnv ? "$GITHUB_ENV" : null,
    config.setOutputs ? "step outputs" : null,
  ].filter(Boolean);
  info(
    `seekrit: injected ${names.length} secret(s) from ${target}` +
      (sinks.length ? ` into ${sinks.join(" + ")}` : "") +
      (config.mask ? "" : " (masking disabled)"),
  );

  appendJobSummary(
    `### 🔐 seekrit\n\nInjected **${names.length}** secret(s) from \`${target}\`` +
      (names.length
        ? `:\n\n${names.map((n) => `- \`${config.prefix + n}\``).join("\n")}\n`
        : ".\n"),
  );
}

run().catch((err: unknown) => {
  if (err instanceof ResolveError) {
    setFailed(`seekrit resolve failed (${err.code}): ${err.message}`);
  } else {
    setFailed(`seekrit: ${(err as Error).message}`);
  }
});
