import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { interpolateSecrets } from "../src/interpolate.js";

/**
 * Secret-reference rules, pinned to the `interpolation` block of the shared
 * golden fixture — the same cases every seekrit client is tested against.
 */
interface Vectors {
  interpolation: {
    cases: {
      name: string;
      input: Record<string, string>;
      expected: Record<string, string>;
      unresolved: string[];
    }[];
    cycles: { name: string; input: Record<string, string> }[];
  };
}

const { interpolation } = JSON.parse(
  readFileSync(new URL("./fixtures/vectors.json", import.meta.url), "utf8"),
) as Vectors;

describe("interpolateSecrets (golden vectors)", () => {
  it.each(interpolation.cases)("$name", ({ input, expected, unresolved }) => {
    expect(interpolateSecrets(input)).toEqual({ values: expected, unresolved });
  });

  it.each(interpolation.cycles)("rejects $name", ({ input }) => {
    expect(() => interpolateSecrets(input)).toThrow(/cycle/);
  });
});
