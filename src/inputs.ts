/** Parse + validate the action's `inputs` into a typed config. */
import { getBooleanInput, getInput, getListInput } from "./actions.js";
import { isServiceToken } from "./crypto.js";
import type { GroupOverride } from "./resolve.js";

export const DEFAULT_API_URL = "https://api.seekrit.dev";

export interface ActionConfig {
  token: string;
  apiUrl: string;
  overrides: GroupOverride[];
  exportEnv: boolean;
  setOutputs: boolean;
  mask: boolean;
  prefix: string;
  include: string[];
  exclude: string[];
}

export function readConfig(): ActionConfig {
  const token = getInput("token", { required: true });
  if (!isServiceToken(token)) {
    throw new Error('the "token" input is not a seekrit service token (expected an "skt_…" value)');
  }

  const apiUrl = getInput("api-url") || DEFAULT_API_URL;

  const overrides = getListInput("with").map((entry) => {
    const idx = entry.indexOf(":");
    if (idx <= 0 || idx === entry.length - 1) {
      throw new Error(`invalid "with" override "${entry}" — expected "group:env"`);
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
    exclude: getListInput("exclude"),
  };
}
