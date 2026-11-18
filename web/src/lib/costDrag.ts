/**
 * Cost-drag ratios from a record's coaching leaf. A ratio the record states as null
 * (for example on a record whose return was withheld) is shown as "not computed": never
 * as 0, never as a default number, and nothing here throws on it.
 */

export const DRAG_NOT_COMPUTED = "not computed";

export function isComputedDrag(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** "-12.3 bps" (or with another unit), or "not computed" for a null ratio. */
export function formatDragBps(value: number | null | undefined, unit = "bps"): string {
  return isComputedDrag(value) ? `-${value.toFixed(1)} ${unit}` : DRAG_NOT_COMPUTED;
}

/** The sum of the ratios, or null when any of them is not computed. */
export function sumDragBps(values: ReadonlyArray<number | null | undefined>): number | null {
  let total = 0;
  for (const value of values) {
    if (!isComputedDrag(value)) return null;
    total += value;
  }
  return total;
}

/**
 * Where a waterfall bar starts and how wide it is, as percentages of the total; null
 * (no bar drawn) when the step, its start or the total is not computed.
 */
export function dragBarGeometry(
  startBps: number | null,
  bps: number | null | undefined,
  totalBps: number | null | undefined,
): { offsetPct: number; widthPct: number } | null {
  if (!isComputedDrag(startBps) || !isComputedDrag(bps) || !isComputedDrag(totalBps)) return null;
  const total = Math.max(totalBps, 0.1);
  const offsetPct = Math.min((startBps / total) * 100, 96);
  const widthPct = Math.max((bps / total) * 100, bps > 0 ? 3 : 0);
  return { offsetPct, widthPct: Math.min(widthPct, 100 - offsetPct) };
}

/** Which side has the lower annualised drag; null when either side is not computed. */
export function lowerDragSide(
  a: number | null | undefined,
  b: number | null | undefined,
): "A" | "B" | null {
  if (!isComputedDrag(a) || !isComputedDrag(b)) return null;
  return a < b ? "A" : "B";
}
