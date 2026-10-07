import { useEffect, useRef } from 'react';
import { calculateRecordSeriesV2 } from './calculator.js';
export function download(text, name, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
export const percent = value => value == null ? 'Withheld' : `${(value * 100).toFixed(2)}%`;
export function Notice({ error = false, children }) { return children ? <div className={error ? 'notice error' : 'notice'} role={error ? 'alert' : 'status'}>{children}</div> : null; }
export function Dialog({ title, children, onCancel, busy = false }) {
  const ref = useRef(null);
  useEffect(() => { const previous = document.activeElement; ref.current.showModal(); return () => { previous?.focus(); }; }, []);
  function trapTab(event) {
    if(event.key !== 'Tab') return;
    const focusable=[...ref.current.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href],[tabindex="0"]')].filter(el=>el.getClientRects().length);
    const first=focusable[0], last=focusable.at(-1);
    if(!first) { event.preventDefault(); return; }
    if(event.shiftKey && document.activeElement===first) { event.preventDefault(); last.focus(); }
    else if(!event.shiftKey && document.activeElement===last) { event.preventDefault(); first.focus(); }
  }
  return <dialog ref={ref} onKeyDown={trapTab} onCancel={event => { event.preventDefault(); if(!busy) onCancel(); }} aria-labelledby="dialog-title"><h2 id="dialog-title">{title}</h2><fieldset disabled={busy} className="dialog-fieldset">{children}</fieldset></dialog>;
}
export function EvidenceRail({ inspection = null }) {
  const checks = inspection?.checks;
  return <aside className="evidence-rail"><h2>What the evidence establishes</h2><dl className="evidence-list">
    <div><dt>Calculations</dt><dd>{checks?.arithmetic_valid ? 'Reproduced from disclosed returns' : 'Reproducible after signing'}</dd></div>
    <div><dt>Signatures</dt><dd>{checks?.signatures_valid ? (inspection?.package ? 'Valid across the supplied key chain' : 'Valid for this key') : 'Checked on review'}</dd></div>
    <div><dt>Source</dt><dd>Self-reported · not authenticated</dd></div>
    <div><dt>Identity</dt><dd>{checks?.key_code === 'matched' ? 'Expected key matches; identity unchecked' : 'Not established'}</dd></div>
    <div><dt>Time</dt><dd>No independent evidence</dd></div>
    <div><dt>Coverage</dt><dd>Supplied observations only</dd></div>
  </dl><p className="boundary">A valid signature does not establish broker authenticity, all accounts, investment skill or suitability for employment.</p></aside>;
}
export function ReturnChart({ returns }) {
  if (!returns?.length) return null;
  let points;
  try { points = calculateRecordSeriesV2(returns, 252).map(point => point.wealth_e8 / 1e8); } catch { return <p>Chart unavailable under current numerical support limits. The record remains checkable using its original calculation rules.</p>; }
  const wealth = points.at(-1);
  const min = Math.min(...points), max = Math.max(...points), span = max - min || .02;
  const coords = points.map((point, i) => `${30 + i / (points.length - 1) * 620},${155 - (point - min) / span * 120}`).join(' ');
  return <figure className="return-chart"><figcaption>Growth of 1 · from disclosed returns</figcaption><svg viewBox="0 0 680 200" role="img" aria-label={`Normalized wealth changes from 1 to ${wealth.toFixed(4)} across ${returns.length} supplied intervals.`}><line x1="30" y1="160" x2="650" y2="160" stroke="var(--line)"/><polyline points={coords} fill="none" stroke="var(--accent)" strokeWidth="3" strokeLinejoin="round"/><text x="30" y="188">{returns[0].start}</text><text x="650" y="188" textAnchor="end">{returns.at(-1).end}</text></svg><p>Only supplied observations are shown; losses between them can be missing.</p></figure>;
}
export function Metrics({ metrics, units = false }) {
  const scale = units ? 1e8 : 1;
  const data = units ? [metrics.total_return_twr_e8, metrics.max_drawdown_e8, metrics.annualized_volatility_e8] : [metrics.total_return_twr, metrics.max_drawdown, metrics.annualized_volatility];
  return <dl className="metrics">{['Time-weighted return', 'Sampled maximum drawdown', 'Annualized volatility'].map((label, i) => <div key={label}><dt>{label}</dt><dd>{percent(data[i] == null ? null : data[i] / scale)}</dd></div>)}</dl>;
}
