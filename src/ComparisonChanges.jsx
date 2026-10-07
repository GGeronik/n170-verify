const percent = value => value === null ? 'Withheld' : `${(value / 1000000).toFixed(6)}%`;
const fields = [
  ['account_scope', 'Declared account scope'], ['currency', 'Reporting currency'],
  ['source_kind', 'Source declaration'], ['source_format', 'Source format'],
  ['reviewed', 'Owner review claim'], ['periods_per_year', 'Observations per year'],
  ['calculation_version', 'Calculation rules'],
];
const labels = { synthetic_demo: 'Synthetic example', self_reported: 'Self-reported' };
const display = (value, field) => value == null ? 'Not recorded in this format' : value === true ? 'Owner says reviewed' : value === false ? 'No owner review claim' : field === 'source_kind' && Object.hasOwn(labels, value) ? labels[value] : String(value);

export default function ComparisonChanges({ comparison, effectiveSequences }) {
  const changes = comparison?.changes;
  if (!changes) return null;
  const corrections = changes.events.filter(event => event.kind === 'correction').length;
  const additions = changes.events.length - corrections;
  return <section className="comparison-changes" aria-labelledby="changes-heading">
    <h3 id="changes-heading">Changed since your copy</h3>
    {!changes.events.length ? <p>No signed events changed or were added. This only compares the two supplied copies.</p> : <>
      <p>{additions} added period{additions === 1 ? '' : 's'} · {corrections} correction{corrections === 1 ? '' : 's'}. Both copies passed calculation and signature checks. Earlier events are preserved.</p>
      <p>These are changes to signed claims. Account labels, source declarations and correction reasons remain supplied by the owner.</p>
      <ol className="change-list">{changes.events.map(event => {
        const correction = event.kind === 'correction';
        const changed = event.before ? fields.filter(([field]) => event.before[field] !== event.after[field]) : [];
        return <li key={event.sequence} className="change-card">
          <h4><a href={`#record-${event.sequence}`}>Record {event.sequence}</a> · {correction ? `corrects record ${event.target_sequence}` : 'added period'}</h4>
          <p>{event.period.start} — {event.period.end}{!effectiveSequences.includes(event.sequence) ? ' · superseded by a later correction below' : ''}</p>
          {correction ? <>
            <p><strong>Owner’s reason:</strong> {event.reason}</p>
            <div className="table-scroll"><table>
              <caption>Same period · signed results before and after correction</caption>
              <thead><tr><th>Result</th><th>Record {event.target_sequence}</th><th>Record {event.sequence}</th></tr></thead>
              <tbody>{[['total_return_twr_e8', 'Time-weighted return'], ['max_drawdown_e8', 'Sampled maximum drawdown'], ['annualized_volatility_e8', 'Annualized volatility']].map(([key, label]) => <tr key={key}><th scope="row">{label}</th><td>{percent(event.before.metrics[key])}</td><td>{percent(event.after.metrics[key])}</td></tr>)}
                <tr><th scope="row">Disclosed return intervals</th><td>{event.before.return_observations}</td><td>{event.after.return_observations}</td></tr>
              </tbody>
            </table></div>
            <p>Unchanged totals can still contain changed interval returns. The complete series and retained originals appear in the records below.</p>
          </> : <p>Declared scope: <strong>{display(event.after.account_scope)}</strong> · {display(event.after.currency)}. This adds a period; it is not a correction to the preceding period.</p>}
          {changed.length > 0 ? <div className="declaration-changes"><p><strong>Declarations changed {correction ? `from record ${event.target_sequence}` : `from the preceding period, record ${event.before.sequence}`}:</strong></p>
            <dl>{changed.map(([field, label]) => <div key={field}><dt>{label}</dt><dd><span>Before: {display(event.before[field], field)}</span><span>Now: {display(event.after[field], field)}</span></dd></div>)}</dl>
            {changed.some(([field]) => field === 'currency' || field === 'account_scope') && <p>Scope or currency changes can affect comparability. No account completeness or currency conversion has been established.</p>}
          </div> : event.before && <p>No change to the compared scope, currency, source declaration and format, owner-review claim, frequency or calculation rules. Check full source details below.</p>}
        </li>;
      })}</ol>
    </>}
  </section>;
}
