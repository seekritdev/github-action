import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * GitHub evaluates `${{ … }}` everywhere in action.yml — input descriptions
 * included — while loading the action, before any step runs. For a node action
 * the only place an expression may appear is an input's `default:` (and only
 * the `github` context); anything else fails every consuming workflow at
 * "Set up job" with "Unrecognized named-value". Nothing in this repo loads the
 * action the way a runner does, so this is the only thing that catches it.
 */
const lines = readFileSync(new URL("../action.yml", import.meta.url), "utf8").split("\n");

describe("action.yml", () => {
  it("has no expressions outside an input default", () => {
    const offending = lines
      .map((line, i) => ({ line: i + 1, text: line }))
      .filter(({ text }) => text.includes("${{") && !/^\s*default:/.test(text));
    expect(offending).toEqual([]);
  });
});
