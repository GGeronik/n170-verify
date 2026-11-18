"use client";

import { useMemo, useState } from "react";
import type { SessionExpectancyCell } from "@/lib/contracts.ts";

const WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;

export interface SessionExpectancyMatrixProps {
  cells: readonly SessionExpectancyCell[];
  compact?: boolean;
}

export function SessionExpectancyMatrix({
  cells,
  compact = false,
}: SessionExpectancyMatrixProps) {
  const [metricMode, setMetricMode] = useState<"bps" | "win_rate">("bps");
  const [hourScope, setHourScope] = useState<"active" | "full24">(
    compact ? "active" : "full24",
  );
  const [hovered, setHovered] = useState<SessionExpectancyCell | null>(null);

  const cellMap = useMemo(() => {
    const map = new Map<string, SessionExpectancyCell>();
    for (const c of cells) {
      map.set(`${c.weekday}:${c.hour_utc}`, c);
    }
    return map;
  }, [cells]);

  const activeHours = useMemo(() => {
    if (hourScope === "full24") {
      return Array.from({ length: 24 }, (_, idx) => idx);
    }
    const present = Array.from(new Set(cells.map((c) => c.hour_utc))).sort(
      (a, b) => a - b,
    );
    return present.length > 0
      ? present
      : [8, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20];
  }, [cells, hourScope]);

  const activeWeekdays = useMemo(() => {
    if (hourScope === "full24") {
      return [0, 1, 2, 3, 4, 5, 6];
    }
    const hasWeekend = cells.some((c) => c.weekday >= 5 && c.trade_count > 0);
    return hasWeekend ? [0, 1, 2, 3, 4, 5, 6] : [0, 1, 2, 3, 4];
  }, [cells, hourScope]);

  const { bestCell, chopCell, maxAbsBps } = useMemo(() => {
    let best: SessionExpectancyCell | null = null;
    let worst: SessionExpectancyCell | null = null;
    let maxBps = 15;
    for (const c of cells) {
      if (c.trade_count <= 0) continue;
      if (!best || c.expectancy_bps > best.expectancy_bps) best = c;
      if (!worst || c.expectancy_bps < worst.expectancy_bps) worst = c;
      if (Math.abs(c.expectancy_bps) > maxBps) {
        maxBps = Math.abs(c.expectancy_bps);
      }
    }
    return { bestCell: best, chopCell: worst, maxAbsBps: maxBps };
  }, [cells]);

  if (cells.length === 0) {
    return (
      <div className="inst-panel rounded-md p-5 text-xs text-ink-muted">
        No session expectancy observations available in this bundle.
      </div>
    );
  }

  return (
    <div className="inst-panel space-y-4 rounded-md p-5 print-avoid-break">
      <div className="flex flex-col justify-between gap-3 border-b border-hairline pb-3.5 lg:flex-row lg:items-center">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
              Microstructure Time-of-Day Attribution
            </span>
            <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 font-mono text-[10px] text-ink-secondary">
              7 × 24 UTC Session Matrix • Zero Notional Leak
            </span>
          </div>
          <h3 className="mt-1 text-sm font-semibold tracking-telemetry text-ink sm:text-base">
            Hour × Weekday Session Expectancy &amp; Win-Rate Matrix
          </h3>
        </div>

        <div className="no-print flex flex-wrap items-center gap-2 font-mono text-[10.5px]">
          <div className="inline-flex rounded border border-hairline-strong bg-elevated p-0.5">
            <button
              type="button"
              onClick={() => setMetricMode("bps")}
              className={`rounded-sm px-2.5 py-1 transition ${
                metricMode === "bps"
                  ? "bg-panel text-signal-emerald shadow-[inset_0_0_0_1px_var(--border-strong)]"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              Expectancy (bps)
            </button>
            <button
              type="button"
              onClick={() => setMetricMode("win_rate")}
              className={`rounded-sm px-2.5 py-1 transition ${
                metricMode === "win_rate"
                  ? "bg-panel text-signal-champagne shadow-[inset_0_0_0_1px_var(--border-strong)]"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              Win Rate (%)
            </button>
          </div>

          <div className="inline-flex rounded border border-hairline-strong bg-elevated p-0.5">
            <button
              type="button"
              onClick={() => setHourScope("active")}
              className={`rounded-sm px-2.5 py-1 transition ${
                hourScope === "active"
                  ? "bg-panel text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              Active Hours
            </button>
            <button
              type="button"
              onClick={() => setHourScope("full24")}
              className={`rounded-sm px-2.5 py-1 transition ${
                hourScope === "full24"
                  ? "bg-panel text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              7 × 24 Grid
            </button>
          </div>
        </div>
      </div>

      {/* Peak Alpha vs Chop Telemetry Strip */}
      <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] tabular-nums">
        <div className="flex flex-wrap items-center gap-2">
          {bestCell && (
            <span className="badge-emerald rounded px-2.5 py-1">
              Peak Alpha: {WEEKDAY_LABELS[bestCell.weekday] ?? "Day"}{" "}
              {String(bestCell.hour_utc).padStart(2, "0")}:00 UTC (
              {bestCell.expectancy_bps >= 0 ? "+" : ""}
              {bestCell.expectancy_bps.toFixed(1)} bps •{" "}
              {(bestCell.win_rate * 100).toFixed(0)}% win)
            </span>
          )}
          {chopCell && chopCell.expectancy_bps < 0 && (
            <span className="badge-vermilion rounded px-2.5 py-1">
              Chop Regime: {WEEKDAY_LABELS[chopCell.weekday] ?? "Day"}{" "}
              {String(chopCell.hour_utc).padStart(2, "0")}:00 UTC (
              {chopCell.expectancy_bps.toFixed(1)} bps •{" "}
              {(chopCell.win_rate * 100).toFixed(0)}% win)
            </span>
          )}
        </div>

        {hovered ? (
          <span className="rounded border border-hairline-strong bg-elevated px-2.5 py-1 text-ink">
            {WEEKDAY_LABELS[hovered.weekday]}{" "}
            {String(hovered.hour_utc).padStart(2, "0")}:00Z →{" "}
            <strong
              className={
                hovered.expectancy_bps >= 0
                  ? "text-signal-emerald"
                  : "text-signal-vermilion"
              }
            >
              {hovered.expectancy_bps >= 0 ? "+" : ""}
              {hovered.expectancy_bps.toFixed(1)} bps
            </strong>{" "}
            • {(hovered.win_rate * 100).toFixed(1)}% win • {hovered.trade_count} trades
          </span>
        ) : (
          <span className="text-ink-muted">
            Hover cell to inspect trade count &amp; expectancy
          </span>
        )}
      </div>

      {/* Scrollable Crisp 7 x 24 Matrix */}
      <div
        className="overflow-x-auto pb-1"
        onMouseLeave={() => setHovered(null)}
      >
        <div className="min-w-[620px]">
          {/* Column Hour Headers */}
          <div
            className="grid gap-1 font-mono text-[9.5px] text-ink-muted tabular-nums"
            style={{
              gridTemplateColumns: `44px repeat(${activeHours.length}, minmax(26px, 1fr))`,
            }}
          >
            <div className="py-1 text-left uppercase">UTC</div>
            {activeHours.map((hr) => (
              <div key={`hdr-${hr}`} className="py-1 text-center">
                {String(hr).padStart(2, "0")}h
              </div>
            ))}
          </div>

          {/* Weekday Rows */}
          <div className="mt-1 space-y-1">
            {activeWeekdays.map((wd) => (
              <div
                key={`wd-${wd}`}
                className="grid items-center gap-1 font-mono tabular-nums"
                style={{
                  gridTemplateColumns: `44px repeat(${activeHours.length}, minmax(26px, 1fr))`,
                }}
              >
                <div className="text-[10.5px] font-semibold text-ink-secondary">
                  {WEEKDAY_LABELS[wd]}
                </div>
                {activeHours.map((hr) => {
                  const cell = cellMap.get(`${wd}:${hr}`);
                  if (!cell || cell.trade_count === 0) {
                    return (
                      <div
                        key={`${wd}-${hr}`}
                        className="h-7 rounded-[3px] border border-hairline bg-elevated/35"
                        title={`${WEEKDAY_LABELS[wd]} ${String(hr).padStart(2, "0")}:00 UTC: 0 executions`}
                      />
                    );
                  }

                  const isPos =
                    metricMode === "bps"
                      ? cell.expectancy_bps >= 0
                      : cell.win_rate >= 0.5;
                  const intensity =
                    metricMode === "bps"
                      ? Math.min(Math.abs(cell.expectancy_bps) / maxAbsBps, 1)
                      : Math.min(Math.abs(cell.win_rate - 0.5) / 0.3, 1);

                  const mixPct = Math.round(12 + intensity * 42);
                  const bgStyle = isPos
                    ? {
                        backgroundColor: `color-mix(in srgb, var(--signal-emerald) ${mixPct}%, var(--bg-elevated))`,
                      }
                    : {
                        backgroundColor: `color-mix(in srgb, var(--signal-vermilion) ${mixPct}%, var(--bg-elevated))`,
                      };

                  const shortText =
                    metricMode === "bps"
                      ? `${cell.expectancy_bps >= 0 ? "+" : ""}${Math.round(cell.expectancy_bps)}`
                      : `${Math.round(cell.win_rate * 100)}%`;

                  return (
                    <button
                      key={`${wd}-${hr}`}
                      type="button"
                      style={bgStyle}
                      onMouseEnter={() => setHovered(cell)}
                      onFocus={() => setHovered(cell)}
                      className="flex h-7 items-center justify-center rounded-[3px] border border-hairline px-0.5 text-[9.5px] font-semibold transition hover:border-ink"
                    >
                      <span
                        className={
                          isPos ? "text-signal-emerald" : "text-signal-vermilion"
                        }
                      >
                        {hourScope === "full24" && activeHours.length > 16
                          ? Math.round(cell.expectancy_bps)
                          : shortText}
                      </span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
