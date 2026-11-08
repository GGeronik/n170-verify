import { useMemo } from 'react';
import { analyzeObservationSchedule } from './calculator.js';
import { effectiveStamps } from './trackRecord.js';
import { computeStatistics } from './statistics.js';

const REASONS = Object.freeze({
  STATS_SAMPLE_INSUFFICIENT: 'Statistics are withheld: fewer than 20 return intervals.',
  STATS_ZERO_VARIANCE: 'Statistics are withheld: every interval return is identical.',
  STATS_NON_FINITE: 'Statistics are withheld: an intermediate value was not a finite number.',
  SCHEDULE_ANNUALIZATION_REFUSED: 'Annualised figures are withheld: the observation dates do not support the declared frequency.',
  MINTRL_UNDEFINED_NONPOSITIVE_EXCESS: 'Minimum track record length is undefined because the mean excess return is not positive.',
  STATS_INFERENCE_ASSUMES_IID: 'This figure assumes independent returns; lag-1 autocorrelation is significant.',
});

function number(value) {
  return Number(value.toPrecision(6)).toString();
}

function StatusReason({ code }) {
  return <><code>{code}</code> {REASONS[code]}</>;
}

function InferenceNotice({ code }) {
  return code ? <> <StatusReason code={code}/></> : null;
}

// This also accepts an engine result directly, without access to signed data.
export function StatisticsRows({ statistics }) {
  const s = statistics;
  const rfLabel = Number.isFinite(s.rf_per_interval) ? `excess over ${number(s.rf_per_interval)}` : s.labels.rf;
  if (s.status !== 'OK') {
    return <div className="statistics-rows">
      <p>{s.T === null ? 'Sample size unavailable' : `${number(s.T)} return intervals`} at {s.periods_per_year === null ? 'an unavailable frequency' : `${number(s.periods_per_year)} periods per year`}.</p>
      {[
        'Mean and standard deviation per interval',
        'Skewness and standard error',
        'Excess kurtosis and standard error',
        'Lag-1 autocorrelation, band and significance',
        `Annualised Sharpe ratio, ${rfLabel}: nominal and adjusted for lag-1 autocorrelation`,
        'Probabilistic Sharpe ratio against 0, at observed moments',
        'Minimum track record length at 95% confidence, at observed moments',
      ].map(label => <p key={label}>{label}: <StatusReason code={s.status}/></p>)}
    </div>;
  }
  return <div className="statistics-rows">
    <p>{number(s.T)} return intervals at {number(s.periods_per_year)} periods per year.</p>
    <p>Mean per interval {number(100 * s.mean)}%; standard deviation per interval {number(100 * s.sd)}%.</p>
    <p>Skewness {number(s.skewness)} (standard error {number(s.skewness_se)}).</p>
    <p>Excess kurtosis {number(s.excess_kurtosis)} (standard error {number(s.excess_kurtosis_se)}).</p>
    <p>Lag-1 autocorrelation {number(s.rho1)} (band ±{number(s.rho1_band)}; significant: {s.autocorr_significant ? 'yes' : 'no'}).</p>
    <p>Annualised Sharpe ratio, {rfLabel}: {s.annualization_code
      ? <StatusReason code={s.annualization_code}/>
      : <>nominal {number(s.sharpe_annualized_nominal)}; adjusted for lag-1 autocorrelation {number(s.sharpe_annualized_adjusted)}.</>}</p>
    <p>Probabilistic Sharpe ratio against 0, at observed moments: {number(s.psr0)}.<InferenceNotice code={s.inference_code}/></p>
    <p>Minimum track record length at 95% confidence, at observed moments: {s.mintrl_code
      ? <StatusReason code={s.mintrl_code}/>
      : <>{number(s.mintrl)} intervals.</>}<InferenceNotice code={s.inference_code}/></p>
  </div>;
}

function statisticsForStamp(stamp) {
  const p = stamp.payload;
  let scheduleCompatible = false;
  try {
    const { status } = analyzeObservationSchedule(p.relative_returns, p.periods_per_year);
    scheduleCompatible = status === 'eligible' || status === 'insufficient_observations';
  } catch {
    // A schedule failure withholds annualisation; per-interval inference remains.
  }
  return {
    sequence: p.sequence,
    period: p.period,
    statistics: computeStatistics(p.relative_returns.map(interval => interval.return_e8), {
      periodsPerYear: p.periods_per_year,
      scheduleCompatible,
      rfPerInterval: 0,
    }),
  };
}

// Integration: place <StatisticsPanel profile={profile}/> immediately after the
// six-row evidence ladder in EmployerReview. The headline receives no statistics.
export default function StatisticsPanel({ profile, statistics }) {
  const panels = useMemo(() => profile ? effectiveStamps(profile).map(statisticsForStamp) : [], [profile]);
  return <section className="paper statistics-panel" aria-label="Derived statistics (unsigned)">
    <h3>Derived statistics (unsigned)</h3>
    {profile ? panels.map(panel => <article className="statistics-record" key={panel.sequence}>
      <h4>Record {panel.sequence} · {panel.period.start} – {panel.period.end}</h4>
      <StatisticsRows statistics={panel.statistics}/>
    </article>) : statistics ? <StatisticsRows statistics={statistics}/> : null}
    <p>These figures are derived from the signed returns, are not signed, and change with future returns.</p>
  </section>;
}
