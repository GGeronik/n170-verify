import { useMemo } from 'react';
import { effectiveStamps } from './trackRecord.js';
import {
  computeSingleBookPatternProfile,
  verifyCounterfactualAttribution,
} from './counterfactualAttribution.js';

const BOOK_ORDER = Object.freeze([
  'ACTUAL',
  'MIRROR_SHADOW',
  'CLEAN_SHADOW',
  'FIXED_BENCHMARK',
]);

function formatNumber(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return 'N/A';
  }
  return Number(value.toPrecision(6)).toString();
}

function formatPercent(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return 'N/A';
  }
  return `${Number((value * 100).toPrecision(6)).toString()}%`;
}

export function describePostDrawdownBehavior(code) {
  switch (code) {
    case 'DISCIPLINED_RISK_SCALING':
      return 'Disciplined post-drawdown risk scaling (in-drawdown RMS volatility < 0.95× high-water RMS volatility)';
    case 'NEUTRAL_RISK_SCALING':
      return 'Neutral post-drawdown risk scaling (0.95× to 1.15× high-water RMS volatility)';
    case 'ELEVATED_POST_DRAWDOWN_RISK':
      return 'Elevated post-drawdown risk scaling (> 1.15× high-water RMS volatility)';
    case 'INSUFFICIENT_REGIME_OBSERVATIONS':
      return 'Insufficient regime observations (fewer than 2 intervals in drawdown or at high-water mark)';
    default: {
      throw new Error(`Unhandled post_drawdown_behavior_code: ${String(code)}`);
    }
  }
}

export function describeCounterfactualStatus(status) {
  switch (status) {
    case 'OK':
      return 'Verified counterfactual attribution and behavioral pattern profile.';
    case 'CF_PROHIBITED_DISCLOSURE_FIELD':
      return 'Refused: input contains a prohibited portfolio or strategy disclosure field.';
    case 'CF_CALENDAR_MISMATCH':
      return 'Refused: interval dates are non-chronological or misaligned across books/logs.';
    case 'CF_DECISION_CHAIN_BROKEN':
      return 'Refused: pre-committed decision hash chain or head commitment failed verification.';
    case 'CF_LEAN_MANIFEST_INVALID':
      return 'Refused: QuantConnect LEAN replay manifest digest or Merkle binding is invalid.';
    case 'CF_INVALID_INPUT':
      return 'Refused: counterfactual input schema, frequency, book set, or return series is invalid.';
    default: {
      throw new Error(`Unhandled counterfactual status: ${String(status)}`);
    }
  }
}

export function describeBookLabel(bookName) {
  switch (bookName) {
    case 'ACTUAL':
      return 'ACTUAL (Realized Book)';
    case 'MIRROR_SHADOW':
      return 'MIRROR_SHADOW (Same Initial Book, Pure Rules)';
    case 'CLEAN_SHADOW':
      return 'CLEAN_SHADOW (Clean-Slate LEAN Replay)';
    case 'FIXED_BENCHMARK':
      return 'FIXED_BENCHMARK (Passive Benchmark)';
    default: {
      throw new Error(`Unhandled book name: ${String(bookName)}`);
    }
  }
}

export function PatternProfileRows({ pattern, periodsPerYear }) {
  if (!pattern) {
    return (
      <div className="counterfactual-pattern-rows">
        <p>
          Pattern profile withheld: at least 4 return intervals at a supported frequency are
          required.
        </p>
      </div>
    );
  }
  const recoveryText = pattern.max_drawdown_recovered
    ? `${pattern.max_drawdown_recovery_intervals} intervals`
    : 'Unrecovered in sample';
  return (
    <div className="counterfactual-pattern-rows">
      <p>
        {formatNumber(pattern.T)} return intervals
        {Number.isFinite(periodsPerYear) ? ` at ${formatNumber(periodsPerYear)} periods per year` : ''}:{' '}
        {pattern.win_intervals} wins, {pattern.loss_intervals} losses, {pattern.flat_intervals} flat
        (win rate {formatPercent(pattern.win_rate)}).
      </p>
      <p>
        Cumulative return {formatPercent(pattern.cumulative_return)}; annualised geometric return
        (CAGR) {formatPercent(pattern.cagr)}.
      </p>
      <p>
        Gain-to-pain ratio {formatNumber(pattern.gain_to_pain_ratio)}; payoff asymmetry (mean win /
        mean loss) {formatNumber(pattern.payoff_asymmetry)} (mean win {formatPercent(pattern.mean_win)}
        , mean absolute loss {formatPercent(pattern.mean_loss_abs)}).
      </p>
      <p>
        Maximum drawdown {formatPercent(pattern.max_drawdown)}; Ulcer index{' '}
        {formatPercent(pattern.ulcer_index)}; max drawdown duration{' '}
        {pattern.max_drawdown_duration_intervals} intervals; recovery from trough: {recoveryText}.
      </p>
      <p>
        Post-drawdown volatility-scaling ratio{' '}
        {formatNumber(pattern.post_drawdown_vol_scaling_ratio)} (in-drawdown RMS vol{' '}
        {formatPercent(pattern.post_drawdown_rms_vol)}, high-water RMS vol{' '}
        {formatPercent(pattern.high_water_rms_vol)}):{' '}
        <code>{pattern.post_drawdown_behavior_code}</code> —{' '}
        {describePostDrawdownBehavior(pattern.post_drawdown_behavior_code)}.
      </p>
      {pattern.upside_capture !== null || pattern.downside_capture !== null ? (
        <p>
          Benchmark capture: upside {formatPercent(pattern.upside_capture)}, downside{' '}
          {formatPercent(pattern.downside_capture)}, capture asymmetry{' '}
          {formatPercent(pattern.capture_asymmetry)}.
        </p>
      ) : null}
    </div>
  );
}

export function CounterfactualAttributionReport({ result }) {
  if (!result) return null;
  if (result.status !== 'OK') {
    return (
      <div className="counterfactual-report counterfactual-refusal" data-counterfactual-status={result.status}>
        <p>
          Status: <code>{result.status}</code>
          {result.reason_code ? (
            <>
              {' '}
              (reason: <code>{result.reason_code}</code>)
            </>
          ) : null}{' '}
          — {describeCounterfactualStatus(result.status)}
        </p>
      </div>
    );
  }

  const presentBooks = BOOK_ORDER.filter((b) => result.books && Object.hasOwn(result.books, b));
  const attr = result.attribution;
  const dcs = result.decision_chain_summary;
  const lean = result.lean_replay_verification;

  return (
    <div className="counterfactual-report" data-counterfactual-status="OK">
      <p>
        Status: <code>{result.status}</code> — {describeCounterfactualStatus(result.status)} (
        {formatNumber(result.T)} intervals at {formatNumber(result.periods_per_year)} periods/year;
        calendar commitment SHA-256 <code>{result.calendar_sha256}</code>
        {result.fixture ? (
          <>
            ; bundle ID <code>{result.fixture}</code>
          </>
        ) : null}
        ).
      </p>

      <h4>Book Return &amp; Regime Pattern Profiles</h4>
      <div className="table-wrap">
        <table className="counterfactual-books-table">
          <thead>
            <tr>
              <th scope="col">Book</th>
              <th scope="col">Cumulative Return</th>
              <th scope="col">CAGR</th>
              <th scope="col">Win Rate</th>
              <th scope="col">Gain-to-Pain</th>
              <th scope="col">Payoff Asymmetry</th>
              <th scope="col">Max Drawdown</th>
              <th scope="col">Ulcer Index</th>
              <th scope="col">Recovery Intervals</th>
              <th scope="col">Vol-Scaling Ratio</th>
              <th scope="col">Post-Drawdown Regime</th>
            </tr>
          </thead>
          <tbody>
            {presentBooks.map((bookName) => {
              const b = result.books[bookName];
              return (
                <tr key={bookName} data-book-row={bookName}>
                  <th scope="row">
                    <code>{bookName}</code>
                  </th>
                  <td>{formatPercent(b.cumulative_return)}</td>
                  <td>{formatPercent(b.cagr)}</td>
                  <td>{formatPercent(b.win_rate)}</td>
                  <td>{formatNumber(b.gain_to_pain_ratio)}</td>
                  <td>{formatNumber(b.payoff_asymmetry)}</td>
                  <td>{formatPercent(b.max_drawdown)}</td>
                  <td>{formatPercent(b.ulcer_index)}</td>
                  <td>
                    {b.max_drawdown_recovered
                      ? String(b.max_drawdown_recovery_intervals)
                      : 'Unrecovered'}
                  </td>
                  <td>{formatNumber(b.post_drawdown_vol_scaling_ratio)}</td>
                  <td>
                    <code>{b.post_drawdown_behavior_code}</code>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {attr ? (
        <div className="counterfactual-decomposition">
          <h4>Four-Book Counterfactual Attribution Decomposition</h4>
          <div className="table-wrap">
            <table className="counterfactual-attribution-table">
              <thead>
                <tr>
                  <th scope="col">Component</th>
                  <th scope="col">Book Pair</th>
                  <th scope="col">Additive Cumulative Wedge</th>
                  <th scope="col">Mean Interval Wedge</th>
                  <th scope="col">Geometric Wealth Factor</th>
                  <th scope="col">Interval Hit Rate</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">Systematic Process Edge</th>
                  <td>
                    <code>CLEAN_SHADOW</code> vs <code>FIXED_BENCHMARK</code>
                  </td>
                  <td>{formatPercent(attr.systematic_process_edge_cumulative)}</td>
                  <td>{formatPercent(attr.systematic_process_edge_mean)}</td>
                  <td>{formatPercent(attr.systematic_process_geometric_factor)}</td>
                  <td>{formatPercent(attr.systematic_hit_rate)}</td>
                </tr>
                <tr>
                  <th scope="row">Initial Book / Legacy Transition Drag</th>
                  <td>
                    <code>MIRROR_SHADOW</code> vs <code>CLEAN_SHADOW</code>
                  </td>
                  <td>{formatPercent(attr.legacy_transition_drag_cumulative)}</td>
                  <td>{formatPercent(attr.legacy_transition_drag_mean)}</td>
                  <td>{formatPercent(attr.legacy_transition_geometric_factor)}</td>
                  <td>—</td>
                </tr>
                <tr>
                  <th scope="row">Discretionary Execution &amp; Risk-Management Alpha</th>
                  <td>
                    <code>ACTUAL</code> vs <code>MIRROR_SHADOW</code>
                  </td>
                  <td>{formatPercent(attr.discretionary_execution_alpha_cumulative)}</td>
                  <td>{formatPercent(attr.discretionary_execution_alpha_mean)}</td>
                  <td>{formatPercent(attr.discretionary_alpha_geometric_factor)}</td>
                  <td>{formatPercent(attr.discretionary_override_hit_rate)}</td>
                </tr>
                <tr>
                  <th scope="row">Total Outperformance vs Benchmark</th>
                  <td>
                    <code>ACTUAL</code> vs <code>FIXED_BENCHMARK</code>
                  </td>
                  <td>{formatPercent(attr.total_outperformance_vs_benchmark)}</td>
                  <td>{formatPercent(attr.total_outperformance_mean)}</td>
                  <td>{formatPercent(attr.total_outperformance_geometric_factor)}</td>
                  <td>—</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {dcs ? (
        <div className="counterfactual-decision-chain">
          <h4>Pre-Committed Decision Log Hash-Chain Summary</h4>
          <p>
            Verified {dcs.intervals} interval commitments: {dcs.total_proposals} total proposals (
            {dcs.total_accepted} accepted [{formatPercent(dcs.acceptance_rate)}],{' '}
            {dcs.total_modified} modified [{formatPercent(dcs.modification_rate)}],{' '}
            {dcs.total_rejected} rejected [{formatPercent(dcs.rejection_rate)}]).
          </p>
          <p>
            Head chain SHA-256: <code>{dcs.head_chain_sha256}</code> · Decision-set Merkle root
            SHA-256: <code>{dcs.merkle_root_sha256}</code>.
          </p>
        </div>
      ) : null}

      {lean ? (
        <div className="counterfactual-lean-manifest">
          <h4>QuantConnect LEAN Replay Receipt Verification</h4>
          <p>
            Target book <code>{lean.target_book}</code> verified at cost policy{' '}
            {formatNumber(lean.cost_policy_bps)} bps · Engine image digest{' '}
            <code>{lean.engine_image_digest}</code>.
          </p>
          <p>
            Input commitments Merkle root <code>{lean.input_commitments_merkle_root}</code> ·
            Output returns SHA-256 <code>{lean.output_returns_sha256}</code> · Canonical manifest
            SHA-256 <code>{lean.manifest_sha256}</code>.
          </p>
        </div>
      ) : null}
    </div>
  );
}

function patternForStamp(stamp) {
  const p = stamp.payload;
  const returnsE8 = Array.isArray(p.relative_returns)
    ? p.relative_returns.map((interval) => interval.return_e8)
    : [];
  return {
    sequence: p.sequence,
    period: p.period,
    periodsPerYear: p.periods_per_year,
    pattern: computeSingleBookPatternProfile(returnsE8, null, p.periods_per_year),
  };
}

export default function CounterfactualAttributionPanel({
  profile,
  counterfactualInput = '',
  onCounterfactualInputChange,
  attributionResult,
}) {
  const stampPatterns = useMemo(
    () => (profile ? effectiveStamps(profile).map(patternForStamp) : []),
    [profile],
  );

  const evaluatedBundle = useMemo(() => {
    if (attributionResult) return attributionResult;
    if (typeof counterfactualInput === 'string') {
      const trimmed = counterfactualInput.trim();
      if (!trimmed) return null;
      return verifyCounterfactualAttribution(trimmed);
    }
    if (counterfactualInput && typeof counterfactualInput === 'object') {
      return verifyCounterfactualAttribution(counterfactualInput);
    }
    return null;
  }, [attributionResult, counterfactualInput]);

  return (
    <section
      className="paper counterfactual-attribution-panel"
      aria-label="Behavioral pattern profile and counterfactual attribution (unsigned)"
    >
      <h3>Behavioral pattern profile and counterfactual attribution (unsigned)</h3>
      {profile ? (
        <div className="counterfactual-profile-patterns">
          {stampPatterns.map((item) => (
            <article className="counterfactual-record" key={item.sequence}>
              <h4>
                Record {item.sequence} · {item.period.start} – {item.period.end}
              </h4>
              <PatternProfileRows pattern={item.pattern} periodsPerYear={item.periodsPerYear} />
            </article>
          ))}
        </div>
      ) : null}

      {typeof onCounterfactualInputChange === 'function' ? (
        <div className="counterfactual-input-controls">
          <label htmlFor="counterfactual-bundle-input">
            Optional 4-book counterfactual &amp; LEAN replay bundle (
            <code>n170.verify.counterfactual-input.v1</code>)
          </label>
          <textarea
            id="counterfactual-bundle-input"
            rows={4}
            value={typeof counterfactualInput === 'string' ? counterfactualInput : ''}
            onChange={(event) => onCounterfactualInputChange(event.target.value)}
            placeholder='Paste {"schema":"n170.verify.counterfactual-input.v1", ...} JSON bundle to verify 4-book counterfactual attribution and LEAN replay receipts.'
          />
        </div>
      ) : null}

      {evaluatedBundle ? <CounterfactualAttributionReport result={evaluatedBundle} /> : null}

      <p>
        Pattern profiles and counterfactual decompositions are zero-disclosure derived figures over
        relative return intervals and cryptographic hash commitments; no holdings, tickers, account
        identifiers, or strategy source code are accepted.
      </p>
    </section>
  );
}
