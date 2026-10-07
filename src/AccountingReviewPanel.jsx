const words = value => String(value || 'NOT_ASSESSED').toLowerCase().replaceAll('_', ' ');
const names = { cash: 'Cash', quantity: 'Asset quantity', cost_basis: 'FIFO cost basis', fees: 'Modeled quote fees', realized_pnl: 'Gross realized P&L',
  unrealized_pnl: 'Unrealized P&L', external_flows: 'External flows', net_pnl: 'Net P&L', nav: 'Closing NAV' };
const statusText = {
  SUPPORTED: 'Supported captured orders', UNSUPPORTED: 'Outside the supported accounting scope', INVALID: 'Capture relationships are inconsistent',
  MISSING: 'Capture not supplied', MATCHES_ENGINE_NUMERIC_POLICY: 'Binary64 replay agrees', MISMATCH: 'Binary64 replay differs', NOT_ASSESSABLE: 'Not fully assessable',
  NOT_RUN: 'Not run here', NOT_SUPPLIED: 'Not supplied', EXACT_MATCH: 'Exact decimal match', EXACT_DIFFERENCE: 'Exact decimal difference',
};
const label = status => statusText[status] || words(status);
const oracleLabel = status => ({ NOT_RUN: 'No oracle evidence supplied', MISSING: 'Oracle evidence is incomplete',
  INVALID: 'Oracle evidence is inconsistent', UNAVAILABLE: 'Supplied oracle is unavailable',
  SUPPLIED_MATCHED: 'Supplied oracle evidence agrees; execution not witnessed here',
  SUPPLIED_DISCREPANCIES: 'Supplied oracle evidence differs from the exact model or reports validation errors' }[status] || words(status));

export default function AccountingReviewPanel({ accounting }) {
  if (!accounting) return <section aria-labelledby="legacy-accounting-heading"><h3 id="legacy-accounting-heading">Accounting is unavailable for this receipt version</h3>
    <p>A v1 detector receipt does not capture the ordered fills and native balances needed for independent accounting. No financial result is inferred from its findings or hashes.</p></section>;
  return <section aria-labelledby="accounting-review-heading">
    <h3 id="accounting-review-heading">Accounting, with separate checks</h3>
    <p>These results are computed in this browser from supplied capture bytes. Detector findings, captured order consistency, exact decimal calculations, native arithmetic and an external oracle answer different questions.</p>
    <p className="boundary"><strong>Overall reconciliation remains not fully assessable.</strong> This format does not supply every native metric. A matching native replay does not establish exact decimal equality or authenticate execution.</p>
    {(accounting.attempts || []).map(attempt => <article key={attempt.id} aria-labelledby={`accounting-attempt-${attempt.id}`}>
      <h4 id={`accounting-attempt-${attempt.id}`}>Attempt {attempt.id}</h4>
      <dl className="tool-scope">
        <div><dt>Detector</dt><dd>{words(attempt.detector_status)}</dd></div>
        <div><dt>Captured orders</dt><dd>{label(attempt.capture?.status)}</dd></div>
        <div><dt>Exact decimal model</dt><dd>{attempt.exact_model?.computed ? 'Computed from captured operands' : 'Unavailable'}</dd></div>
        <div><dt>Native arithmetic</dt><dd>{attempt.native_compatibility ? label(attempt.native_compatibility.status) : 'Not assessed'}</dd></div>
        <div><dt>External oracle</dt><dd>{oracleLabel(attempt.oracle?.status || 'NOT_RUN')}</dd></div>
      </dl>
      {(attempt.reason_codes || []).length > 0 && <ul aria-label={`Accounting reasons for attempt ${attempt.id}`}>{attempt.reason_codes.map((code, index) => <li key={`${code}-${index}`}>{words(code)}.</li>)}</ul>}
      {attempt.oracle?.status !== 'NOT_RUN' && attempt.oracle?.reason_codes?.length > 0 && <p>Oracle reasons: {attempt.oracle.reason_codes.map(words).join('; ')}.</p>}
      {attempt.exact_model?.computed && <>
        <div className="table-scroll" role="region" aria-label={`Accounting metrics for attempt ${attempt.id}`} tabIndex={0}>
          <table><caption>Exact model values and separately supplied native observations. Decimal amounts are shown without display rounding.</caption>
            <thead><tr><th>Metric</th><th>Exact model</th><th>Native observation</th><th>Comparison</th></tr></thead>
            <tbody>{Object.entries(attempt.exact_model.computed).map(([metric, value]) => <tr key={metric}><th scope="row">{names[metric] || words(metric)}</th>
              <td><code>{value}</code></td><td><code>{attempt.native_metrics?.[metric]?.native_repr ?? 'Not supplied'}</code></td>
              <td>{label(attempt.native_metrics?.[metric]?.status || 'NOT_SUPPLIED')}</td></tr>)}</tbody>
          </table>
        </div>
        <p>Fees are modeled as filled quantity × captured price × 0.001 in quote currency. They are expensed immediately; they are not broker fee receipts. Gross FIFO cost excludes fees.</p>
        <details><summary>Inspect binary values and calculation checkpoints</summary>
          <p>A native float’s printed decimal is a display spelling. Its exact binary value can differ. The differences below keep those two comparisons separate.</p>
          {Object.entries(attempt.native_metrics || {}).filter(([, item]) => item.native_hex).map(([key, item]) => <div key={key}>
            <h5>{names[key] || words(key)}</h5>
            <p>Captured binary64: <code>{item.native_hex}</code></p>
            <p>Exact binary minus model: <code>{item.exact_binary_difference_decimal}</code> <span>(rational <code>{item.exact_binary_difference?.numerator}/{item.exact_binary_difference?.denominator}</code>)</span></p>
            <p>Printed decimal minus model: <code>{item.display_decimal_difference}</code></p>
          </div>)}
          {attempt.native_compatibility && <><p>Native policy: <code>{attempt.native_compatibility.policy}</code>. Decimal fee legs are converted separately, subtracted as binary64, rounded to eight decimal places using the exact binary rational with ties to even, then accumulated in captured close order. No tolerance is used.</p>
            <ul>{(attempt.native_compatibility.reason_codes || []).map(code => <li key={code}>{words(code)}.</li>)}</ul></>}
          <div className="table-scroll" role="region" aria-label={`FIFO checkpoints for attempt ${attempt.id}`} tabIndex={0}>
            <table><caption>Supplied order is preserved, including equal timestamps.</caption><thead><tr><th>Event</th><th>Cash</th><th>Quantity</th><th>FIFO basis</th><th>Gross realized P&L</th><th>Fees</th></tr></thead>
              <tbody>{(attempt.exact_model.event_checkpoints || []).map(row => <tr key={row.event_id}><th scope="row">{row.event_id}</th>{['cash', 'quantity', 'fifo_cost_basis', 'gross_realized_pnl', 'fees'].map(key => <td key={key}><code>{row[key]}</code></td>)}</tr>)}</tbody>
            </table>
          </div>
        </details>
      </>}
    </article>)}
    <p className="boundary">The supported bridge covers one synthetic BTC/USDT spot pair with full market entries and natural full exits. Forced liquidation, open holdings, partial fills, base-currency fees and unsupported runtime behavior stay explicit. A consistently rewritten unsigned capture can still omit history.</p>
  </section>;
}
