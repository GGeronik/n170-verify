/**
 * A cost-drag ratio the record states as null (a withheld record's coaching leaf) prints
 * "not computed", never 0 or a default number, and nothing throws on it.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  DRAG_NOT_COMPUTED,
  dragBarGeometry,
  formatDragBps,
  lowerDragSide,
  sumDragBps,
} from "../src/lib/costDrag.ts";
import { extractTypedLeaves, type VerifyProofBundle } from "../src/lib/contracts.ts";
import { BUNDLE_COACHING_STUDIO_FULL } from "../src/lib/demoFixtures.ts";
import { resolveCounterfactualTwin, resolveQuantDnaProfile } from "../src/lib/wave4Analytics.ts";

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const NULL_DRAG = {
  commission_and_fee_drag_bps: null,
  margin_and_funding_drag_bps: null,
  fx_conversion_drag_bps: null,
  withholding_tax_drag_bps: null,
  total_friction_drag_bps: null,
  annualized_total_drag_bps: null,
};

function withNullDrag(bundle: VerifyProofBundle): VerifyProofBundle {
  const copy = JSON.parse(JSON.stringify(bundle)) as VerifyProofBundle;
  for (const leaf of copy.disclosed_leaves) {
    if (leaf.leaf_name === "coaching_and_context") {
      const payload = leaf.payload as Record<string, unknown>;
      payload.cost_drag = { ...NULL_DRAG };
      delete payload.counterfactual_twin;
      delete payload.quant_dna;
    }
  }
  return copy;
}

test("a null ratio prints 'not computed'; a number prints in bps", () => {
  assert.equal(formatDragBps(null), DRAG_NOT_COMPUTED);
  assert.equal(formatDragBps(undefined), DRAG_NOT_COMPUTED);
  assert.equal(formatDragBps(Number.NaN), DRAG_NOT_COMPUTED);
  assert.equal(formatDragBps(12.34), "-12.3 bps");
  assert.equal(formatDragBps(168, "bps / yr"), "-168.0 bps / yr");
  assert.equal(formatDragBps(0), "-0.0 bps");
});

test("a waterfall bar is drawn only from stated ratios", () => {
  assert.equal(dragBarGeometry(0, null, 41.5), null);
  assert.equal(dragBarGeometry(null, 4.1, 41.5), null);
  assert.equal(dragBarGeometry(0, 14.2, null), null);
  assert.deepEqual(dragBarGeometry(0, 14.2, 41.5)?.offsetPct, 0);
  assert.equal(sumDragBps([14.2, null]), null);
  assert.equal(sumDragBps([14.2, 19.8]), 34);
});

test("a head-to-head never names a winner on a ratio that was not computed", () => {
  assert.equal(lowerDragSide(null, 120), null);
  assert.equal(lowerDragSide(100, null), null);
  assert.equal(lowerDragSide(100, 120), "A");
});

test("no profile or twin is derived from a ratio that was not computed", () => {
  const bundle = withNullDrag(BUNDLE_COACHING_STUDIO_FULL);
  const leaves = extractTypedLeaves(bundle);
  assert.equal(leaves.coaching?.cost_drag.annualized_total_drag_bps, null);
  assert.equal(resolveQuantDnaProfile(bundle, leaves), null);
  assert.equal(resolveCounterfactualTwin(bundle, leaves), null);
});

test("the coaching and head-to-head views print stated ratios through the helper", () => {
  for (const file of ["components/CoachingStudioTab.tsx", "components/HeadToHeadArena.tsx"]) {
    const source = fs.readFileSync(path.join(WEB, "src", file), "utf-8");
    assert.equal(/_drag_bps\.toFixed/.test(source), false, `${file} formats a ratio that may be null`);
    assert.match(source, /formatDragBps\(/);
  }
  const analytics = fs.readFileSync(path.join(WEB, "src", "lib", "wave4Analytics.ts"), "utf-8");
  assert.equal(/_drag_bps \?\? \d/.test(analytics), false, "a default number stands in for a ratio");
});
