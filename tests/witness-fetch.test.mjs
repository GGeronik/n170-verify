import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IBKR_BASE_URL,
  BACKOFF_SCHEDULE_MS,
  parseScaledDecimal,
  normalizeDecimalString,
  normalizeDateString,
  normalizeDateTimeString,
  validateDateWindow,
  classifyFlexError,
  canonicalizeFlexXml,
  canonicalizeFlexCsv,
  validateFixtureF05,
  executeFlexWorkflow,
  runCli,
} from '../scripts/witness-fetch.mjs';

test('ADV-01 (F05-A): External deposit masquerading as return is isolated into ExternalCapitalFlows', () => {
  const res = validateFixtureF05(
    { startingValue: '100000', depositsWithdrawals: '50000', mtm: '2000', endingValue: '152000' },
    [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '50000', internalTransfers: '0' }],
    [],
    { cashTransactionRows: [{ type: 'Deposits/Withdrawals', amount: '50000' }] }
  );
  assert.equal(res.netExternalCapitalFlowsScaled, 50000_00000000n);
  assert.equal(res.economicInvestmentReturnScaled, 2000_00000000n);
  assert.ok(res.flags.includes('F05_DEPOSIT_ISOLATED'));
});

test('ADV-02 (F05-B): Internal cash & ACATS position transfer conflation is isolated from return', () => {
  const res = validateFixtureF05(
    {
      startingValue: '100000',
      depositsWithdrawals: '0',
      internalCashTransfers: '25000',
      assetTransfers: '75000',
      mtm: '1500',
      endingValue: '201500',
    },
    [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '25000' }],
    []
  );
  assert.equal(res.netExternalCapitalFlowsScaled, 100000_00000000n);
  assert.equal(res.economicInvestmentReturnScaled, 1500_00000000n);
  assert.ok(res.flags.includes('F05_TRANSFER_ISOLATED'));
});

test('ADV-03 (F05-C): Mid-period account linking adjustment is isolated in NetExternalCapitalFlows', () => {
  const res = validateFixtureF05(
    {
      startingValue: '50000',
      depositsWithdrawals: '0',
      internalCashTransfers: '0',
      linkingAdjustments: '120000',
      mtm: '500',
      endingValue: '170500',
    },
    [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '0' }],
    []
  );
  assert.equal(res.netExternalCapitalFlowsScaled, 120000_00000000n);
  assert.equal(res.economicInvestmentReturnScaled, 500_00000000n);
  assert.ok(res.flags.includes('F05_LINKING_ISOLATED'));
});

test('ADV-04 (F05-D): Cross-section deposit/transfer desynchronization refuses with REFUSE_F05_CASH_TIEOUT_MISMATCH', () => {
  assert.throws(
    () =>
      validateFixtureF05(
        { startingValue: '100000', depositsWithdrawals: '10000', internalCashTransfers: '5000', endingValue: '115000' },
        [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '15000', internalTransfers: '0' }],
        []
      ),
    /REFUSE_F05_CASH_TIEOUT_MISMATCH/
  );
  assert.throws(
    () =>
      validateFixtureF05(
        { startingValue: '100000', depositsWithdrawals: '10000', internalCashTransfers: '5000', endingValue: '115000' },
        [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '10000', internalTransfers: '4999.90' }],
        []
      ),
    /REFUSE_F05_CASH_TIEOUT_MISMATCH/
  );
});

test('ADV-05 (F05-E): Dividend accrual (CDIV) vs settled cash overlap emits FLAG_ACCRUAL_CASH_OVERLAP', () => {
  const res = validateFixtureF05(
    { startingValue: '10000', depositsWithdrawals: '0', internalCashTransfers: '0', endingValue: '10100' },
    [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '0', dividends: '100.00' }],
    [],
    {
      cashTransactionRows: [{ type: 'Dividends', amount: '100.00' }],
      dividendAccrualRows: [{ grossAmount: '100.00' }],
    }
  );
  assert.ok(res.flags.includes('FLAG_ACCRUAL_CASH_OVERLAP'));
});

test('ADV-06 (F05-F): Corporate action cash folded into netTradesSales emits FLAG_CORP_ACTION_CASH_IN_TRADES', () => {
  const res = validateFixtureF05(
    { startingValue: '100000', depositsWithdrawals: '0', internalCashTransfers: '0', endingValue: '110000' },
    [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '0', netTradesSales: '10000.00' }],
    [{ type: 'TC', amount: '10000.00', proceeds: '10000.00' }]
  );
  assert.ok(res.flags.includes('FLAG_CORP_ACTION_CASH_IN_TRADES'));
});

test('ADV-07 (F05-G): Unknown Corporate Action (UE) or unclassified NAV other refuses with REFUSE_UNCLASSIFIED_RETURN_EVENT', () => {
  assert.throws(
    () =>
      validateFixtureF05(
        { startingValue: '10000', depositsWithdrawals: '0', internalCashTransfers: '0', endingValue: '10450' },
        [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '0' }],
        [{ type: 'UE', amount: '450.00' }]
      ),
    /REFUSE_UNCLASSIFIED_RETURN_EVENT/
  );
  assert.throws(
    () =>
      validateFixtureF05(
        { startingValue: '10000', depositsWithdrawals: '0', internalCashTransfers: '0', other: '450.00', endingValue: '10450' },
        [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '0' }],
        []
      ),
    /REFUSE_UNCLASSIFIED_RETURN_EVENT/
  );
});

test('ADV-08 (F05-H): Multi-currency BASE_SUMMARY and currency rows are partitioned without double aggregation', () => {
  const res = validateFixtureF05(
    { startingValue: '80000', depositsWithdrawals: '5000', internalCashTransfers: '0', endingValue: '88436.87' },
    [
      { currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '5000', internalTransfers: '0', endingCash: '88436.87' },
      { currency: 'USD', levelOfDetail: 'Currency', depositWithdrawals: '5400', internalTransfers: '0', endingCash: '96190.85' },
    ],
    []
  );
  assert.ok(res.flags.includes('PARTITION_BY_LEVEL_OF_DETAIL'));
  assert.equal(res.partitionedCashReport.baseSummary.endingCash, '88436.87');
  assert.equal(res.partitionedCashReport.currencies.length, 1);
  assert.equal(res.partitionedCashReport.currencies[0].currency, 'USD');
});

test('ADV-09: Legacy gdcdyn SSRF / host downgrade in <Url> is ignored and ndcdyn host is enforced', () => {
  const xml =
    '<FlexStatementResponse timestamp="01 November, 2026 10:00 AM EDT">' +
    '<Status>Success</Status>' +
    '<ReferenceCode>7729029235</ReferenceCode>' +
    '<Url>https://gdcdyn.interactivebrokers.com/Universal/servlet/FlexStatementService.GetStatement</Url>' +
    '</FlexStatementResponse>';
  const res = classifyFlexError(xml);
  assert.equal(res.action, 'POLL_GET_STATEMENT');
  assert.equal(res.referenceCode, '7729029235');
  assert.equal(res.enforcedEndpoint, `${IBKR_BASE_URL}/GetStatement`);
  assert.equal(res.hostPolicy, 'ENFORCE_NDCDYN_HOST');
});

test('ADV-10: Error 1025 accumulated-failure lockout triggers immediate circuit breaker REFUSE_LOCKOUT_1025', () => {
  const xml =
    '<FlexStatementResponse timestamp="01 November, 2026 10:00 AM EDT">' +
    '<Status>Fail</Status>' +
    '<ErrorCode>1025</ErrorCode>' +
    '<ErrorMessage>Too many failed attempts.</ErrorMessage>' +
    '</FlexStatementResponse>';
  const res = classifyFlexError(xml);
  assert.equal(res.action, 'REFUSE_LOCKOUT_1025');
  assert.equal(res.retryable, false);
  assert.equal(res.circuitBreaker, true);
  assert.equal(res.maxRetries, 0);
});

test('ADV-11: Version 2 fallback <code> root tag on GetStatement is refused with REFUSE_PROTOCOL_DOWNGRADE_V2', () => {
  const v2Body = '<code>Statement generation in progress</code>';
  const classified = classifyFlexError(v2Body);
  assert.equal(classified.action, 'REFUSE_PROTOCOL_DOWNGRADE_V2');
  assert.throws(() => canonicalizeFlexXml(v2Body), /REFUSE_PROTOCOL_DOWNGRADE_V2/);
});

test('ADV-12: Activity Flex infinite Warn 1019 server hang aborts after 6 backoff polls (62s) with REFUSE_AF_GENERATION_TIMEOUT', async () => {
  const calls = [];
  const sleeps = [];
  const warn1019 =
    '<FlexStatementResponse timestamp="01 November, 2026 10:00 AM EDT">' +
    '<Status>Warn</Status><ErrorCode>1019</ErrorCode>' +
    '<ErrorMessage>Statement generation in progress. Please try again shortly.</ErrorMessage>' +
    '</FlexStatementResponse>';
  const sendOk =
    '<FlexStatementResponse timestamp="01 November, 2026 10:00 AM EDT">' +
    '<Status>Success</Status><ReferenceCode>99887766</ReferenceCode>' +
    '<Url>https://gdcdyn.interactivebrokers.com/Universal/servlet/FlexStatementService.GetStatement</Url>' +
    '</FlexStatementResponse>';

  await assert.rejects(
    () =>
      executeFlexWorkflow({
        token: '123456789012345678901234',
        queryId: '555666',
        fd: '20250101',
        td: '20250131',
        transport: async (url) => {
          calls.push(url);
          return url.includes('/SendRequest') ? sendOk : warn1019;
        },
        sleep: async (ms) => {
          sleeps.push(ms);
        },
      }),
    /REFUSE_AF_GENERATION_TIMEOUT/
  );
  assert.deepEqual(sleeps, BACKOFF_SCHEDULE_MS);
  assert.equal(calls.length, 7);
  for (const pollUrl of calls.slice(1)) {
    assert.ok(pollUrl.startsWith(`${IBKR_BASE_URL}/GetStatement?`));
    assert.ok(pollUrl.includes('v=3'));
  }
});

test('ADV-13: European ambiguous slash date format (dd/MM/yyyy) is refused with REFUSE_AMBIGUOUS_DATE_FORMAT', () => {
  assert.throws(() => normalizeDateString('04/05/2025', 'reportDate'), /REFUSE_AMBIGUOUS_DATE_FORMAT/);
  assert.throws(() => normalizeDateTimeString('04/05/2025;10:00:00', 'dateTime'), /REFUSE_AMBIGUOUS_DATE_FORMAT/);
});

test('ADV-14: Malformed numeric attribute weight="0.0 ()" is sanitized while corrupt monetary decimals refuse', () => {
  assert.equal(normalizeDecimalString('0.0 ()', 'weight'), '0');
  assert.equal(normalizeDecimalString('522.00', 'amount'), '522');
  assert.equal(normalizeDecimalString('-0.00', 'amount'), '0');
  assert.throws(() => normalizeDecimalString('100.00 ()', 'amount'), /REFUSE_CORRUPT_DECIMAL/);
  assert.throws(() => parseScaledDecimal('12.34.56', 'amount'), /REFUSE_CORRUPT_DECIMAL/);
});

test('ADV-15: Account alias substitution and virtual account ID emit FLAG_ALIAS_OR_VIRTUAL_ID', () => {
  const resAlias = validateFixtureF05(
    { accountId: 'MyTradingAlias', startingValue: '1000', depositsWithdrawals: '0', internalCashTransfers: '0', endingValue: '1100' },
    [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '0' }],
    []
  );
  assert.ok(resAlias.flags.includes('FLAG_ALIAS_OR_VIRTUAL_ID'));

  const resVirtual = validateFixtureF05(
    { accountId: 'U9999999-WM01-MM02', startingValue: '1000', depositsWithdrawals: '0', internalCashTransfers: '0', endingValue: '1100' },
    [{ currency: 'BASE_SUMMARY', levelOfDetail: 'BaseCurrency', depositWithdrawals: '0', internalTransfers: '0' }],
    []
  );
  assert.ok(resVirtual.flags.includes('FLAG_ALIAS_OR_VIRTUAL_ID'));
});

test('ADV-16: CSV EOS record or amount checksum corruption refuses with REFUSE_CSV_EOS_CHECKSUM_MISMATCH', () => {
  const badRecordCountCsv = [
    'BOF,U1234567,4,20250101,20250131,20260201;100000,100,100',
    'BOS,ACCT,Account Information',
    'HEADER,ACCT,ClientAccountID,CurrencyPrimary',
    'DATA,ACCT,U1234567,USD',
    'EOS,ACCT,2,0',
    'EOF,1',
  ].join('\n');
  assert.throws(() => canonicalizeFlexCsv(badRecordCountCsv, { allowPartialSections: true }), /REFUSE_CSV_EOS_CHECKSUM_MISMATCH/);

  const badAmountCsv = [
    'BOF,U1234567,1,20250101,20250131,20260201;100000,100,100',
    'BOS,TRNT,Trades',
    'HEADER,TRNT,ClientAccountID,NetTradeMoney',
    'DATA,TRNT,U1234567,100.50',
    'EOS,TRNT,1,999.99',
    'EOF,1',
  ].join('\n');
  assert.throws(() => canonicalizeFlexCsv(badAmountCsv, { allowPartialSections: true }), /REFUSE_CSV_EOS_CHECKSUM_MISMATCH/);
});

test('ADV-17: CSV and XML missing required section (BOS census failure) refuses with REFUSE_MISSING_REQUIRED_SECTION', () => {
  const incompleteCsv = [
    'BOF,U1234567,3,20250101,20250131,20260201;100000,100,100',
    'BOS,ACCT,Account Information',
    'HEADER,ACCT,ClientAccountID,CurrencyPrimary',
    'DATA,ACCT,U1234567,USD',
    'EOS,ACCT,1,0',
    'BOS,EQUT,Change in NAV',
    'HEADER,EQUT,ClientAccountID,StartingValue,EndingValue',
    'DATA,EQUT,U1234567,1000,1100',
    'EOS,EQUT,1,0',
    'BOS,CRTT,Cash Report',
    'HEADER,CRTT,ClientAccountID,CurrencyPrimary,StartingCash,EndingCash',
    'DATA,CRTT,U1234567,BASE_SUMMARY,1000,1100',
    'EOS,CRTT,1,0',
    'EOF,3',
  ].join('\n');
  assert.throws(() => canonicalizeFlexCsv(incompleteCsv), /REFUSE_MISSING_REQUIRED_SECTION/);

  const incompleteXml =
    '<FlexQueryResponse queryName="Test" type="AF"><FlexStatements count="1">' +
    '<FlexStatement accountId="U1234567" fromDate="2025-01-01" toDate="2025-01-31" whenGenerated="2026-02-01;10:00:00">' +
    '<AccountInformation accountId="U1234567" currency="USD" />' +
    '<ChangeInNAV accountId="U1234567" startingValue="1000" endingValue="1100" />' +
    '<CashReport><CashReportCurrency currency="BASE_SUMMARY" levelOfDetail="BaseCurrency" depositWithdrawals="0" internalTransfers="0" /></CashReport>' +
    '</FlexStatement></FlexStatements></FlexQueryResponse>';
  assert.throws(() => canonicalizeFlexXml(incompleteXml), /REFUSE_MISSING_REQUIRED_SECTION/);
});

test('ADV-18: 365-day window violation or p + fd/td collision refuses pre-flight with REFUSE_INVALID_DATE_WINDOW', () => {
  assert.throws(() => validateDateWindow({ fd: '20240101', td: '20250105' }), /REFUSE_INVALID_DATE_WINDOW/);
  assert.throws(() => validateDateWindow({ fd: '20240101', td: '20241231' }), /REFUSE_INVALID_DATE_WINDOW/); // 2024 is leap year (366 days)
  assert.throws(() => validateDateWindow({ p: 30, fd: '20250101', td: '20250131' }), /REFUSE_INVALID_DATE_WINDOW/);
  assert.throws(() => validateDateWindow({ fd: '20250101' }), /REFUSE_INVALID_DATE_WINDOW/);
  const ok = validateDateWindow({ fd: '20250101', td: '20251231' });
  assert.equal(ok.inclusiveDays, 365);
});

test('XML & CSV canonicalization determinism across two fetches with different volatile timestamps and column inversions', async () => {
  const xmlT1 =
    '\uFEFF<FlexQueryResponse type="AF" queryName="N170Witness">\r\n' +
    '<FlexStatements count="1">\r\n' +
    '<FlexStatement accountId="U1234567" fromDate="20250101" toDate="20250131" period="LastMonth" whenGenerated="20260201;101500">\r\n' +
    '<AccountInformation currency="USD" accountId="U1234567" dateOpened="20230101" lastTradedDate="2026-01-30" dateClosed="" syepEnrollmentStatus="Y" />\r\n' +
    '<ChangeInNAV endingValue="152000.00" startingValue="100000.0" depositsWithdrawals="50000.00" internalCashTransfers="0.0" mtm="2000.000" accountId="U1234567" />\r\n' +
    '<CashReport>\r\n' +
    '<CashReportCurrency levelOfDetail="Currency" currency="USD" depositWithdrawals="50000.00" internalTransfers="0.00" endingCash="152000.00" />\r\n' +
    '<CashReportCurrency currency="BASE_SUMMARY" levelOfDetail="BaseCurrency" depositWithdrawals="50000.0" internalTransfers="-0.00" endingCash="152000.0" />\r\n' +
    '</CashReport>\r\n' +
    '<CashTransactions>\r\n' +
    '<CashTransaction type="Dividends" amount="200.00" transactionID="TX2" dateTime="20250120;160000 EST" accountId="U1234567" currency="USD" weight="0.0 ()" />\r\n' +
    '<CashTransaction accountId="U1234567" currency="USD" transactionID="TX1" dateTime="2025-01-10;09:30:00 EDT" type="Deposits/Withdrawals" amount="50000.0" />\r\n' +
    '</CashTransactions>\r\n' +
    '<EquitySummaryInBase>   </EquitySummaryInBase>\r\n' +
    '</FlexStatement>\r\n' +
    '</FlexStatements>\r\n' +
    '</FlexQueryResponse>\r\n';

  const xmlT2 =
    '<FlexQueryResponse queryName="N170Witness" type="AF">\n' +
    '<FlexStatements count="1">\n' +
    '<FlexStatement toDate="2025-01-31" fromDate="2025-01-01" accountId="U1234567" whenGenerated="2026-11-02;22:45:19" period="">\n' +
    '<AccountInformation accountId="U1234567" currency="USD" dateOpened="2023-01-01" lastTradedDate="2026-11-01" accountRepName="Jane Doe" unsignedPendingDocumentsStatus="N" />\n' +
    '<ChangeInNAV accountId="U1234567" startingValue="100000" depositsWithdrawals="50000" internalCashTransfers="0" mtm="2000" endingValue="152000" />\n' +
    '<CashReport>\n' +
    '<CashReportCurrency currency="BASE_SUMMARY" levelOfDetail="BaseCurrency" depositWithdrawals="50000" internalTransfers="0" endingCash="152000" />\n' +
    '<CashReportCurrency currency="USD" levelOfDetail="Currency" depositWithdrawals="50000" internalTransfers="0" endingCash="152000" />\n' +
    '</CashReport>\n' +
    '<CashTransactions>\n' +
    '<CashTransaction accountId="U1234567" currency="USD" transactionID="TX1" dateTime="2025-01-10;09:30:00" type="Deposits/Withdrawals" amount="50000" />\n' +
    '<CashTransaction accountId="U1234567" currency="USD" transactionID="TX2" dateTime="2025-01-20;16:00:00" type="Dividends" amount="200" weight="0" />\n' +
    '</CashTransactions>\n' +
    '<EquitySummaryInBase></EquitySummaryInBase>\n' +
    '</FlexStatement>\n' +
    '</FlexStatements>\n' +
    '</FlexQueryResponse>\n';

  const c1 = canonicalizeFlexXml(xmlT1, { requestedFrom: '2025-01-01', requestedTo: '2025-01-31' });
  const c2 = canonicalizeFlexXml(xmlT2, { requestedFrom: '20250101', requestedTo: '20250131' });
  assert.equal(c1.canonicalXml, c2.canonicalXml);
  assert.equal(c1.canonicalSha256, c2.canonicalSha256);

  const csvT1 = [
    'BOF,U1234567,4,20250101,20250131,20260201;101500,98,99',
    'ACCT,BOS,Account Information',
    'ACCT,HEADER,ClientAccountID,CurrencyPrimary,LastTradedDate',
    'ACCT,DATA,U1234567,USD,2026-01-30',
    'ACCT,EOS,1,0',
    'EQUT,BOS,Change in NAV',
    'EQUT,HEADER,ClientAccountID,StartingValue,EndingValue',
    'EQUT,DATA,U1234567,100000.00,152000.0',
    'EQUT,EOS,1,0',
    'CRTT,BOS,Cash Report',
    'CRTT,HEADER,ClientAccountID,CurrencyPrimary,EndingCash',
    'CRTT,DATA,U1234567,BASE_SUMMARY,152000.00',
    'CRTT,EOS,1,0',
    'CTRN,BOS,Cash Transactions',
    'CTRN,HEADER,ClientAccountID,TransactionID,Amount',
    'CTRN,DATA,U1234567,TX2,200.00',
    'CTRN,DATA,U1234567,TX1,50000.0',
    'CTRN,EOS,2,0',
    'EOF,4',
  ].join('\r\n');

  const csvT2 = [
    'BOF,U1234567,4,2025-01-01,2025-01-31,20261102;224519,105,108',
    'BOS,ACCT,Account Information',
    'HEADER,ACCT,ClientAccountID,CurrencyPrimary,LastTradedDate',
    'DATA,ACCT,U1234567,USD,2026-11-01',
    'EOS,ACCT,1,0',
    'BOS,EQUT,Change in NAV',
    'HEADER,EQUT,ClientAccountID,StartingValue,EndingValue',
    'DATA,EQUT,U1234567,100000,152000',
    'EOS,EQUT,1,0',
    'BOS,CRTT,Cash Report',
    'HEADER,CRTT,ClientAccountID,CurrencyPrimary,EndingCash',
    'DATA,CRTT,U1234567,BASE_SUMMARY,152000',
    'EOS,CRTT,1,0',
    'BOS,CTRN,Cash Transactions',
    'HEADER,CTRN,ClientAccountID,TransactionID,Amount',
    'DATA,CTRN,U1234567,TX1,50000',
    'DATA,CTRN,U1234567,TX2,200',
    'EOS,CTRN,2,0',
    'EOF,4',
  ].join('\n');

  const csvCanon1 = canonicalizeFlexCsv(csvT1);
  const csvCanon2 = canonicalizeFlexCsv(csvT2);
  assert.equal(csvCanon1.canonicalCsv, csvCanon2.canonicalCsv);
  assert.equal(csvCanon1.canonicalSha256, csvCanon2.canonicalSha256);

  // Also test local mock two-step Flex workflow succeeding on Poll 2 after one Warn 1019
  let pollCount = 0;
  const workflowRes = await executeFlexWorkflow({
    token: '123456789012345678901234',
    queryId: '777888',
    fd: '20250101',
    td: '20250131',
    transport: async (url) => {
      if (url.includes('/SendRequest')) {
        return '<FlexStatementResponse timestamp="01 Nov 2026"><Status>Success</Status><ReferenceCode>334455</ReferenceCode><Url>https://gdcdyn.interactivebrokers.com/Universal/servlet/FlexStatementService.GetStatement</Url></FlexStatementResponse>';
      }
      pollCount++;
      if (pollCount === 1) {
        return '<FlexStatementResponse timestamp="01 Nov 2026"><Status>Warn</Status><ErrorCode>1019</ErrorCode><ErrorMessage>Statement generation in progress.</ErrorMessage></FlexStatementResponse>';
      }
      return xmlT1;
    },
    sleep: async () => {},
  });
  assert.equal(workflowRes.status, 'VERIFIED_UNDER_WITNESS');
  assert.equal(workflowRes.polls, 2);
  assert.equal(workflowRes.canonicalSha256, c1.canonicalSha256);
  assert.equal(workflowRes.f05.economicInvestmentReturnScaled, 2000_00000000n);
});

test('CLI --help and keygen subcommand succeed cleanly', () => {
  const help = runCli(['--help']);
  assert.equal(help.exitCode, 0);
  assert.ok(help.output.startsWith('Usage: node scripts/witness-fetch.mjs '));
  const kg = runCli(['keygen']);
  assert.equal(kg.exitCode, 0);
  const parsed = JSON.parse(kg.output);
  assert.match(parsed.witness_key_id, /^[0-9a-f]{64}$/);
  assert.match(parsed.witness_key_code, /^[0-9a-f]{4}(?:-[0-9a-f]{4}){4}$/);
});
