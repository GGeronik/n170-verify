export default function AccountPreparationHelp() {
  return <details className="account-preparation-help"><summary>What to reconcile: losses, flows and coverage</summary>
    <ul>
      <li><strong>Keep every observed gain and loss.</strong> Use total account NAV, including cash and holdings, for the same declared accounts and one reporting currency. There is no currency conversion. A trade list or cash balance alone is not portfolio NAV.</li>
      <li><strong>Classify all cash activity.</strong> Cash deposits and transfers into the declared account scope are positive external flows; withdrawals and transfers out are negative. Transfers entirely within that scope, trades, retained dividends and interest stay in NAV. Fees and taxes affect returns only when already included in NAV. In-kind transfers and any event reported as unsupported need a reviewed treatment; do not substitute invented cash flows.</li>
      <li><strong>Check timing and offsetting flows.</strong> Each external flow must occur at an interval end with a matching valuation. A zero net flow does not prove that no deposits or withdrawals occurred. If timing is unknown or flows occur within an interval, obtain the missing valuations; do not guess or net them away.</li>
      <li><strong>Keep missing coverage visible.</strong> Check all source pages, dates, accounts and unsupported events. Missing observations are not filled in, and losses between observations remain unknown. Source authenticity, freshness and completeness are not established by passing reconciliation.</li>
      <li><strong>Respect the calculation limits.</strong> Ordinary losses are supported within the documented numeric limits. Zero or negative NAV, total loss, and unsupported recapitalization require a separate accounting review. Keep those source rows; do not remove them to obtain a result.</li>
      <li><strong>Correct with a reason.</strong> Before signing, use the row’s Correct button. After signing, choose the original record under Record purpose and sign a correction with the same period boundaries. The original stays in the signed history; correction reasons are shared.</li>
    </ul>
  </details>;
}
