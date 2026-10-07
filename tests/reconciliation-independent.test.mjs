// Independent original synthetic challenge cases. Expected values were derived
// with Python fractions.Fraction in track2-evidence/independent-oracles.py,
// which imports no application code. This is agent validation, not an audit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildStampObservationEvidence } from '../src/calculator.js';
import { captureSource, reconcileAccount, makeReconciliationArtifact } from '../src/reconciliation.js';

// Literal expectations keep this suite portable independently of private reports.
const arithmeticCases = [
  {
    "id": "gain",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "110",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,110,0",
    "explanation": "110 / 100 - 1 = 10%.",
    "expected": {
      "exact_gross_factors": [
        "11/10"
      ],
      "return_e8": [
        10000000
      ],
      "total_return_twr_e8": 10000000,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "valid_loss",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "80",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,80,0",
    "explanation": "80 / 100 - 1 = -20%; retain the losing interval.",
    "expected": {
      "exact_gross_factors": [
        "4/5"
      ],
      "return_e8": [
        -20000000
      ],
      "total_return_twr_e8": -20000000,
      "max_drawdown_e8": -20000000,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "deposit_dominated_gain",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "1010",
        "900"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,1010,900",
    "explanation": "Subtract the 900 end deposit: 110 / 100 - 1 = 10%, not 910%.",
    "expected": {
      "exact_gross_factors": [
        "11/10"
      ],
      "return_e8": [
        10000000
      ],
      "total_return_twr_e8": 10000000,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "deposit_dominated_loss",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "980",
        "900"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,980,900",
    "explanation": "Subtract the 900 end deposit: 80 / 100 - 1 = -20% despite increasing NAV.",
    "expected": {
      "exact_gross_factors": [
        "4/5"
      ],
      "return_e8": [
        -20000000
      ],
      "total_return_twr_e8": -20000000,
      "max_drawdown_e8": -20000000,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "withdrawal_dominated_loss",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "20",
        "-70"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,20,-70",
    "explanation": "Subtracting the negative 70 withdrawal restores 90: 90 / 100 - 1 = -10%.",
    "expected": {
      "exact_gross_factors": [
        "9/10"
      ],
      "return_e8": [
        -10000000
      ],
      "total_return_twr_e8": -10000000,
      "max_drawdown_e8": -10000000,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "withdrawal_with_gain",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "40",
        "-70"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,40,-70",
    "explanation": "40 - (-70) = 110; falling NAV still has a +10% investment return.",
    "expected": {
      "exact_gross_factors": [
        "11/10"
      ],
      "return_e8": [
        10000000
      ],
      "total_return_twr_e8": 10000000,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "known_end_offsetting_flows",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "100",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,100,0",
    "explanation": "A reviewed +60 deposit and -60 withdrawal both at the interval end net to zero; gross flows must still be retained.",
    "expected": {
      "exact_gross_factors": [
        "1"
      ],
      "return_e8": [
        0
      ],
      "total_return_twr_e8": 0,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "known_end_multiple_flows",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "910",
        "800"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,910,800",
    "explanation": "A reviewed +900 deposit and -100 withdrawal both at interval end net to 800; adjusted NAV 110 gives +10%.",
    "expected": {
      "exact_gross_factors": [
        "11/10"
      ],
      "return_e8": [
        10000000
      ],
      "total_return_twr_e8": 10000000,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "exact_decimal_cancellation",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "0.1",
        "0"
      ],
      [
        "2026-01-06",
        "0.3",
        "0.2"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,0.1,0\n2026-01-06,0.3,0.2",
    "explanation": "Exact decimal 0.3 - 0.2 = 0.1; return is exactly zero.",
    "expected": {
      "exact_gross_factors": [
        "1"
      ],
      "return_e8": [
        0
      ],
      "total_return_twr_e8": 0,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "positive_half_tie",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "1",
        "0"
      ],
      [
        "2026-01-06",
        "1.000000005",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,1,0\n2026-01-06,1.000000005,0",
    "explanation": "Exactly +0.5 of a 10^-8 return unit rounds to +1.",
    "expected": {
      "exact_gross_factors": [
        "200000001/200000000"
      ],
      "return_e8": [
        1
      ],
      "total_return_twr_e8": 1,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "negative_half_tie",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "1",
        "0"
      ],
      [
        "2026-01-06",
        "0.999999995",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,1,0\n2026-01-06,0.999999995,0",
    "explanation": "Exactly -0.5 of a 10^-8 return unit rounds toward positive infinity to 0.",
    "expected": {
      "exact_gross_factors": [
        "199999999/200000000"
      ],
      "return_e8": [
        0
      ],
      "total_return_twr_e8": 0,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "rational_loss",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "3",
        "0"
      ],
      [
        "2026-01-06",
        "2",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,3,0\n2026-01-06,2,0",
    "explanation": "Exact -1/3 return quantizes to -33333333 units.",
    "expected": {
      "exact_gross_factors": [
        "2/3"
      ],
      "return_e8": [
        -33333333
      ],
      "total_return_twr_e8": -33333333,
      "max_drawdown_e8": -33333333,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "gain_then_loss",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "110",
        "0"
      ],
      [
        "2026-01-07",
        "99",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,110,0\n2026-01-07,99,0",
    "explanation": "1.1 * 0.9 = 0.99; total -1%, drawdown -10%.",
    "expected": {
      "exact_gross_factors": [
        "11/10",
        "9/10"
      ],
      "return_e8": [
        10000000,
        -10000000
      ],
      "total_return_twr_e8": -1000000,
      "max_drawdown_e8": -10000000,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "loss_then_recovery",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "80",
        "0"
      ],
      [
        "2026-01-07",
        "100",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,80,0\n2026-01-07,100,0",
    "explanation": "0.8 * 1.25 = 1; total 0%, drawdown -20%.",
    "expected": {
      "exact_gross_factors": [
        "4/5",
        "5/4"
      ],
      "return_e8": [
        -20000000,
        25000000
      ],
      "total_return_twr_e8": 0,
      "max_drawdown_e8": -20000000,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "two_deposit_and_market_losses",
    "currency": "USD",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "1080",
        "1000"
      ],
      [
        "2026-01-07",
        "864",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,1080,1000\n2026-01-07,864,0",
    "explanation": "Two factors of 0.8 give 0.64; total -36%, never discard the first deposit-dominated loss.",
    "expected": {
      "exact_gross_factors": [
        "4/5",
        "4/5"
      ],
      "return_e8": [
        -20000000,
        -20000000
      ],
      "total_return_twr_e8": -36000000,
      "max_drawdown_e8": -36000000,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "eur_identical_arithmetic",
    "currency": "EUR",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "110",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,110,0",
    "explanation": "Same-currency EUR inputs use the same ratio with no FX conversion.",
    "expected": {
      "exact_gross_factors": [
        "11/10"
      ],
      "return_e8": [
        10000000
      ],
      "total_return_twr_e8": 10000000,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  },
  {
    "id": "jpy_identical_arithmetic",
    "currency": "JPY",
    "rows": [
      [
        "2026-01-05",
        "100",
        "0"
      ],
      [
        "2026-01-06",
        "110",
        "0"
      ]
    ],
    "csv": "date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,110,0",
    "explanation": "Same-currency JPY inputs use the same ratio with no forced cents rounding.",
    "expected": {
      "exact_gross_factors": [
        "11/10"
      ],
      "return_e8": [
        10000000
      ],
      "total_return_twr_e8": 10000000,
      "max_drawdown_e8": 0,
      "annualized_volatility_e8": null
    }
  }
];

for (const vector of arithmeticCases) {
  test(`independent rational oracle: ${vector.id}`, () => {
    const actual = buildStampObservationEvidence(vector.csv, 365);
    assert.deepEqual(actual.relative_returns.map(interval => interval.return_e8), vector.expected.return_e8, vector.explanation);
    for (const key of ['total_return_twr_e8', 'max_drawdown_e8', 'annualized_volatility_e8']) {
      assert.equal(actual.metrics[key], vector.expected[key], `${vector.id}: ${key}`);
    }
  });
}

const sha = value => createHash('sha256').update(value).digest('hex');
const csv = 'date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,110,0';
const prepare = (input = csv, options = {}) => reconcileAccount({
  input, format: 'n170', currency: 'USD', frequency: 365,
  accountScope: 'Original synthetic single account', flowTimingConfirmed: true,
  flowActivity: 'reviewed_no_hidden', flowTiming: 'interval_end',
  expectedSchedule: 'observed_boundaries', ...options,
});
function blocked(result, pattern) {
  assert.equal(result.canCalculate, false);
  assert.equal(result.selected_scope_status, 'blocked');
  assert.ok(result.blocking_issues.length > 0, 'A blocker must have an actionable explanation.');
  if (pattern) assert.match(JSON.stringify(result.blocking_issues), pattern);
}
function unresolved(result, pattern) {
  blocked(result, pattern);
  assert.ok(result.intervals.some(interval => interval.status === 'unresolved'), 'Retain an unresolved interval.');
  for (const interval of result.intervals.filter(item => item.status === 'unresolved')) {
    assert.equal(interval.return_e8, null, 'An unresolved return must never be reported as zero.');
    assert.ok(interval.blocking_reasons.length > 0);
  }
}

for (const vector of arithmeticCases) {
  test(`reconciliation against independent rational oracle: ${vector.id}`, async () => {
    const result = await prepare(vector.csv, { currency: vector.currency });
    assert.equal(result.canCalculate, true, JSON.stringify(result.blocking_issues));
    assert.equal(result.selected_scope_status, 'calculable_under_owner_assumptions');
    assert.deepEqual(result.intervals.map(interval => interval.return_e8), vector.expected.return_e8);
    assert.ok(result.intervals.every(interval => interval.status === 'calculable'));
  });
}

test('the exact bridge retains deposits, withdrawals and decimal cancellation', async () => {
  for (const [closing, flow, adjusted, economic] of [
    ['980', '900', '80', '-20'], ['20', '-70', '90', '-10'], ['40', '-70', '110', '10'],
  ]) {
    const result = await prepare(`date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,${closing},${flow}`);
    const interval = result.intervals[0];
    assert.equal(interval.opening_nav, '100');
    assert.equal(interval.closing_nav, closing);
    assert.equal(interval.external_flow, flow);
    assert.equal(interval.adjusted_closing_nav, adjusted);
    assert.equal(interval.economic_change, economic);
  }
  const exact = await prepare('date,nav,external_flow\n2026-01-05,0.1,0\n2026-01-06,0.3,0.2');
  assert.equal(exact.intervals[0].adjusted_closing_nav, '0.1');
  assert.equal(exact.intervals[0].economic_change, '0');
});

test('interval reconciliation preserves the existing full-series wealth support boundary', async () => {
  // Independent algebra: 10 * 0.0000001 = 0.000001 opening wealth.
  // The cumulative floor is met. It must not be reapplied independently to
  // the second interval as though its own opening wealth were the record start.
  const input = 'date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,1000,0\n2026-01-07,0.0001,0';
  const baseline = buildStampObservationEvidence(input, 365);
  assert.deepEqual(baseline.relative_returns.map(item => item.return_e8), [900000000, -99999990]);
  assert.equal(baseline.metrics.total_return_twr_e8, -99999900);
  assert.equal(baseline.metrics.max_drawdown_e8, -99999990);
  const result = await prepare(input);
  assert.equal(result.canCalculate, true, JSON.stringify(result.blocking_issues));
  assert.deepEqual(result.intervals.map(item => item.return_e8), [900000000, -99999990]);
});

test('per-interval arithmetic cannot bypass an unsupported cumulative wealth path', async () => {
  const input = 'date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,0.001,0\n2026-01-07,0.00001,0';
  // 0.00001 * 0.01 = 0.0000001, below the 0.000001 cumulative floor.
  assert.throws(() => buildStampObservationEvidence(input, 365), /wealth range/);
  blocked(await prepare(input), /series|wealth|range/i);
});

for (const [name, closing, flow, expectedEconomic] of [
  ['total loss', '0', '0', '-100'],
  ['zero adjusted wealth', '50', '50', '-100'],
  ['cashflow-dominated unsupported loss', '50', '100', '-150'],
  ['negative NAV', '-1', '0', '-101'],
  ['unsupported near-total-loss precision', '0.000000001', '0', '-99.999999999'],
]) {
  test(`unsupported economic history remains visible: ${name}`, async () => {
    const result = await prepare(`date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,${closing},${flow}`);
    unresolved(result, /loss|positive|precision|unsupported|range|nonpositive/i);
    assert.equal(result.intervals.at(-1).closing_nav, closing);
    assert.equal(result.intervals.at(-1).economic_change, expectedEconomic);
  });
}

for (const [name, options] of [
  ['unreviewed activity', { flowActivity: 'unknown' }],
  ['known offsetting gross flows', { flowActivity: 'offsetting' }],
  ['unknown timing', { flowTiming: 'unknown' }],
  ['intraperiod timing', { flowTiming: 'intraperiod' }],
]) {
  test(`net zero cannot hide ${name}`, async () => {
    const result = await prepare(csv.replace('110,0', '120,0'), options);
    unresolved(result, /flow|timing|activity|offset/i);
    assert.equal(result.intervals[0].external_flow, '0');
    assert.notEqual(result.intervals[0].return_e8, 20000000, 'Unsupported netting must not publish the incorrect 20% return.');
  });
}

test('selected leading and trailing boundaries survive as missing observations', async () => {
  const result = await prepare(csv, { period: { start: '2026-01-04', end: '2026-01-07' } });
  unresolved(result, /missing|valuation|boundary|observation/i);
  const leading = result.intervals.find(interval => interval.start === '2026-01-04');
  const trailing = result.intervals.find(interval => interval.end === '2026-01-07');
  assert.ok(leading); assert.ok(trailing);
  assert.equal(leading.opening_nav, null);
  assert.equal(trailing.closing_nav, null);
  assert.equal(leading.return_e8, null);
  assert.equal(trailing.return_e8, null);
});

test('calendar daily gaps preserve an unobserved date without inventing NAV or zero flow', async () => {
  const result = await prepare(csv.replace('2026-01-06', '2026-01-07'), { expectedSchedule: 'calendar_daily' });
  unresolved(result, /missing|valuation|observation|gap/i);
  assert.ok(result.intervals.some(interval => interval.start === '2026-01-06' || interval.end === '2026-01-06'));
  assert.ok(result.intervals.some(interval => interval.opening_nav === null || interval.closing_nav === null));
  assert.ok(result.intervals.every(interval => interval.return_e8 === null));
});

test('observed boundaries permit sparse evidence while an explicit weekday schedule requires missing weekdays', async () => {
  const sparse = csv.replace('2026-01-06', '2026-01-07');
  assert.equal((await prepare(sparse)).canCalculate, true);
  unresolved(await prepare(sparse, { expectedSchedule: 'weekdays' }), /missing|valuation|observation|gap/i);
  const weekend = 'date,nav,external_flow\n2026-01-09,100,0\n2026-01-12,110,0';
  assert.equal((await prepare(weekend, { expectedSchedule: 'weekdays' })).canCalculate, true);
});

test('shrinking the selected period cannot silently discard a supplied loss', async () => {
  const input = 'date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,80,0\n2026-01-07,88,0';
  const result = await prepare(input, { period: { start: '2026-01-06', end: '2026-01-07' } });
  blocked(result, /outside|scope|period|boundar/i);
  assert.ok(JSON.stringify(result.source_inventory).includes('100'));
  assert.ok(JSON.stringify(result.source_inventory).includes('80'));
});

test('complete depletion and recapitalization remain unresolved through period-narrowing attempts', async () => {
  const input = 'date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,0,0\n2026-01-07,100,100';
  const result = await prepare(input);
  unresolved(result, /loss|positive|unsupported|nonpositive|zero/i);
  assert.equal(result.intervals.length, 2);
  assert.ok(result.intervals.every(interval => interval.return_e8 === null));
  assert.equal(result.intervals[0].closing_nav, '0');
  assert.equal(result.intervals[1].opening_nav, '0');
  for (const period of [
    { start: '2026-01-05', end: '2026-01-06' },
    { start: '2026-01-06', end: '2026-01-07' },
  ]) blocked(await prepare(input, { period }), /scope|period|outside|boundar|loss|positive|unsupported/i);
  const prefix = 'date,nav,external_flow\n2026-01-04,90,0\n2026-01-05,100,0\n2026-01-06,0,0\n2026-01-07,100,100';
  const narrowed = await prepare(prefix, { period: { start: '2026-01-04', end: '2026-01-05' } });
  blocked(narrowed, /scope|period|outside|boundar|loss|positive|unsupported/i);
  assert.ok(narrowed.source_inventory.some(item => item.text === prefix));
});

test('conflicting same-date observations remain in the source inventory', async () => {
  const input = csv + '\n2026-01-06,120,0';
  const result = await prepare(input);
  blocked(result, /duplicate|conflict|overlap|order/i);
  const source = result.source_inventory.find(item => item.sha256 === sha(input));
  assert.ok(source);
  assert.ok(JSON.stringify(source.rows).includes('110'));
  assert.ok(JSON.stringify(source.rows).includes('120'));
});

test('rejected row is retained and a valid adjacent interval does not authorize the selected account', async () => {
  const input = csv + '\n2026-01-07,not-a-number,0\n2026-01-08,121,0';
  const result = await prepare(input);
  blocked(result, /invalid|decimal|row|observation/i);
  assert.ok(JSON.stringify(result.source_inventory).includes('not-a-number'));
  assert.ok(result.intervals.some(interval => interval.status === 'unresolved'));
});

test('unresolved rejected file remains a selected-scope blocker beside good working observations', async () => {
  const bad = 'date,nav,external_flow\n"unclosed';
  const result = await prepare(csv, { sources: [{ text: bad, fileName: 'rejected-original-synthetic.csv', disposition: 'unresolved', reason: '' }] });
  blocked(result, /source|unresolved|import|invalid/i);
  const rejected = result.source_inventory.find(item => item.sha256 === sha(bad));
  assert.ok(rejected);
  assert.equal(rejected.text, bad);
  assert.ok(rejected.issues.length > 0);
});

test('excluding a rejected attempt requires an explanation and remains recorded', async () => {
  const entry = { text: 'a,b\n1,2', fileName: 'wrong-synthetic-file.csv', disposition: 'excluded', reason: '' };
  blocked(await prepare(csv, { sources: [entry] }), /reason|exclu|source/i);
  const result = await prepare(csv, { sources: [{ ...entry, reason: 'Wrong synthetic account selected; kept here as an excluded attempt.' }] });
  assert.equal(result.canCalculate, true, JSON.stringify(result.blocking_issues));
  const retained = result.source_inventory.find(item => item.sha256 === sha(entry.text));
  assert.ok(retained);
  assert.equal(retained.disposition, 'excluded');
  assert.match(retained.reason, /Wrong synthetic account/);
});

test('capture hashes exact UTF-8 bytes, including BOM and CRLF', async () => {
  const lf = new TextEncoder().encode(csv);
  const bomCrlf = new TextEncoder().encode('\uFEFF' + csv.replaceAll('\n', '\r\n'));
  const first = await captureSource({ bytes: lf, fileName: 'original-lf.csv', currency: 'USD', frequency: 365, flowTimingConfirmed: true });
  const second = await captureSource({ bytes: bomCrlf, fileName: 'original-bom-crlf.csv', currency: 'USD', frequency: 365, flowTimingConfirmed: true });
  assert.equal(first.sha256, sha(lf)); assert.equal(second.sha256, sha(bomCrlf));
  assert.notEqual(first.sha256, second.sha256);
  assert.equal(first.byte_length, lf.byteLength); assert.equal(second.byte_length, bomCrlf.byteLength);
  assert.deepEqual(Buffer.from(first.bytes_base64, 'base64'), Buffer.from(lf));
  assert.deepEqual(Buffer.from(second.bytes_base64, 'base64'), Buffer.from(bomCrlf));
  assert.equal(second.text.charCodeAt(0), 0xFEFF);
  assert.equal(first.review.normalizedCsv, second.review.normalizedCsv);
});

test('inventory row spans identify exact original UTF-8 bytes with multiline and Unicode cells', async () => {
  const text = '\uFEFFdate,nav,external_flow,note\r\n2026-01-05,100,0,"α first\nline"\r\n2026-01-06,110,0,"β ""quoted"""\r\n';
  const bytes = new TextEncoder().encode(text);
  const captured = await captureSource({ bytes, fileName: 'original-multiline-synthetic.csv' });
  assert.equal(captured.sha256, sha(bytes));
  assert.equal(captured.rows.length, 2);
  for (const row of captured.rows) {
    assert.equal(new TextDecoder().decode(bytes.slice(row.byte_start, row.byte_end)), row.raw_text);
  }
  assert.equal(captured.rows[0].source_row, 2);
  assert.equal(captured.rows[1].source_row, 3);
  assert.equal(captured.rows[0].raw_cells[3], 'α first\nline');
  assert.equal(captured.rows[1].raw_cells[3], 'β "quoted"');
  assert.equal(captured.rows[0].physical_line, 2);
  assert.equal(captured.rows[1].physical_line, 4);
});

test('invalid UTF-8 bytes are retained, rejected and cannot be laundered through replacement decoding', async () => {
  const bytes = Uint8Array.of(0xff, 0xfe, 0x41);
  const captured = await captureSource({ bytes, fileName: 'invalid-utf8.csv' });
  assert.equal(captured.sha256, sha(bytes));
  assert.deepEqual(Buffer.from(captured.bytes_base64, 'base64'), Buffer.from(bytes));
  assert.ok(captured.issues.some(item => /utf|decod/i.test(JSON.stringify(item))));
  const result = await prepare(csv, { sources: [{ ...captured, disposition: 'unresolved' }] });
  blocked(result, /source|utf|decod|unresolved/i);
  assert.ok(result.source_inventory.some(item => item.sha256 === sha(bytes)));
});

test('mismatched supplied text and bytes cannot be accepted as one source', async () => {
  const captured = await captureSource({ text: csv, bytes: new TextEncoder().encode(csv.replace('110,0', '120,0')) });
  assert.ok(captured.issues.some(item => /mismatch|differ|bytes|text/i.test(JSON.stringify(item))));
});

test('provenance binds both endpoint observations and the contributing closing flow', async () => {
  const result = await prepare(csv);
  const interval = result.intervals[0];
  assert.deepEqual(new Set(interval.dependencies.map(item => item.role)), new Set(['opening', 'closing', 'flow']));
  assert.equal(interval.dependencies.find(item => item.role === 'opening').source_row, 2);
  assert.equal(interval.dependencies.find(item => item.role === 'closing').source_row, 3);
  assert.equal(interval.dependencies.find(item => item.role === 'flow').source_row, 3);
  assert.ok(interval.dependencies.every(item => item.source_sha256 === sha(csv)));
  assert.match(interval.dependency_sha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(result).includes('"authenticated":true'), false);
});

test('changing any opening, closing or flow dependency changes the bound interval', async () => {
  const original = await prepare(csv);
  for (const [input, row, field, expectedReturn] of [
    [csv.replace('100,0', '200,0'), 1, 'nav', -45000000],
    [csv.replace('110,0', '120,0'), 2, 'nav', 20000000],
    [csv.replace('110,0', '110,10'), 2, 'external_flow', 0],
  ]) {
    const correction = { row, field, reason: 'Original synthetic correction control', before: csv, after: input, previous_sha256: sha(csv), replacement_sha256: sha(input) };
    const result = await prepare(input, { original: csv, corrections: [correction] });
    assert.equal(result.canCalculate, true, JSON.stringify(result.blocking_issues));
    assert.equal(result.intervals[0].return_e8, expectedReturn);
    assert.notEqual(result.intervals[0].dependency_sha256, original.intervals[0].dependency_sha256);
    assert.notEqual(result.normalized_sha256, original.normalized_sha256);
    assert.ok(result.intervals[0].dependencies.some(item => item.correction_steps.length > 0));
  }
});

test('correct source hashes do not authorize undeclared or tampered corrections', async () => {
  const input = csv.replace('110,0', '120,0');
  blocked(await prepare(input, { original: csv }), /correction|match|source|history/i);
  const correction = { row: 1, field: 'nav', reason: 'Incorrect row declaration', before: csv, after: input, previous_sha256: sha(csv), replacement_sha256: sha(input) };
  blocked(await prepare(input, { original: csv, corrections: [correction] }), /correction|history/i);
});

test('forged cached source success, hashes and authentication have no authority', async () => {
  const text = 'date,nav,external_flow\n2026-01-05,100,0\n2026-01-06,invalid,0';
  const forged = { text, file_name: 'synthetic-cache-forgery.csv', sha256: 'a'.repeat(64), authenticated: true,
    disposition: 'unresolved', issues: [], rows: [], review: { canCalculate: true, source: { authenticated: true } } };
  const result = await prepare(csv, { sources: [forged] });
  blocked(result, /source|invalid|unresolved/i);
  const retained = result.source_inventory.find(item => item.sha256 === sha(text));
  assert.ok(retained);
  assert.ok(retained.issues.length > 0);
  assert.equal(JSON.stringify(result).includes('"authenticated":true'), false);
});

function handoff(overrides = {}) {
  return {
    schema_version: 'n170.agent-handoff.v1', synthetic: true,
    source: { broker: 'Original synthetic source', connector: 'Original test fixture', tools: ['synthetic.read'], retrieved_at: '2026-01-07T12:00:00Z' },
    account_scope: 'Original synthetic single account', currency: 'USD', frequency: 365,
    requested_period: { start: '2026-01-05', end: '2026-01-06' },
    coverage: { pagination: 'complete', missing_periods: [], unsupported_events: [] }, flow_timing: 'interval_end',
    observations: [
      { date: '2026-01-05', nav: '100', external_flow: '0', source_ref: 'Original synthetic observation 1' },
      { date: '2026-01-06', nav: '110', external_flow: '0', source_ref: 'Original synthetic observation 2' },
    ],
    mapping: { date: 'Synthetic observation date', nav: 'Synthetic account NAV', external_flow: 'Synthetic end flow' }, ...overrides,
  };
}

test('handoff currency conflict is blocked without inventing FX conversion', async () => {
  const original = JSON.stringify(handoff());
  const result = await prepare(csv, { original, format: 'agent-handoff', currency: 'EUR' });
  blocked(result, /currency|convert|source/i);
  assert.ok(JSON.stringify(result.source_inventory).includes('USD'));
});

test('declared missing source periods and incomplete pagination cannot be erased by valid endpoints', async () => {
  for (const coverage of [
    { pagination: 'incomplete', missing_periods: [], unsupported_events: [] },
    { pagination: 'complete', missing_periods: [{ start: '2026-01-05', end: '2026-01-06', reason: 'Original synthetic missing activity page' }], unsupported_events: [] },
  ]) {
    const original = JSON.stringify(handoff({ coverage }));
    const result = await prepare(csv, { original, format: 'agent-handoff' });
    blocked(result, /pagination|missing|source/i);
    assert.ok(result.intervals.every(interval => interval.status === 'unresolved' && interval.return_e8 === null), 'Source-wide gaps must not leave an affected interval marked calculable.');
    assert.ok(JSON.stringify(result.source_inventory).includes(JSON.stringify(coverage).slice(1, -1)) || result.source_inventory.some(item => item.text === original));
  }
});

test('source-reported intraperiod timing cannot be overridden by a later owner end-flow assertion', async () => {
  const original = JSON.stringify(handoff({ flow_timing: 'intraperiod' }));
  const result = await prepare(csv, { original, format: 'agent-handoff' });
  unresolved(result, /timing|flow/i);
  assert.ok(result.intervals.every(interval => interval.status === 'unresolved' && interval.return_e8 === null));
  assert.ok(result.intervals.every(interval => /timing|flow/i.test(JSON.stringify(interval.blocking_reasons))));
});

test('valid working numbers cannot authenticate an unparsable original or produce resolved dependencies', async () => {
  const original = 'date,nav,external_flow\n"unterminated original source';
  const result = await prepare(csv, { original });
  unresolved(result, /source|invalid|quote/i);
  assert.ok(result.intervals.every(interval => interval.status === 'unresolved' && interval.return_e8 === null));
  assert.ok(result.source_inventory.some(item => item.text === original));
});

test('source overlaps across unresolved attempts produce a conflict without silently choosing one value', async () => {
  const overlap = csv.replace('110,0', '120,0');
  const result = await prepare(csv, { sources: [{ text: overlap, fileName: 'overlapping-original-synthetic.csv', disposition: 'unresolved' }] });
  blocked(result, /conflicting_source_overlap|conflict|overlap/i);
  assert.ok(result.source_inventory.some(item => item.sha256 === sha(csv)));
  assert.ok(result.source_inventory.some(item => item.sha256 === sha(overlap)));
});

test('large requested schedule is bounded and remains blocked', async () => {
  const result = await prepare(csv, { period: { start: '1900-01-01', end: '2100-01-01' }, expectedSchedule: 'calendar_daily' });
  blocked(result, /schedule_range_limit|schedule|boundar|limit/i);
  assert.ok(result.intervals.length < 5001, 'Do not allocate every date in an unbounded requested schedule.');
});

test('source-count overflow retains excess entries and cannot masquerade as a successful truncated inventory', async () => {
  const sources = Array.from({ length: 22 }, (_, index) => ({ text: `synthetic,attempt\n${index},rejected`, fileName: `original-synthetic-${index}.csv`, disposition: 'excluded', reason: 'Explicitly unrelated original synthetic file.' }));
  const result = await prepare(csv, { sources });
  blocked(result, /source_count_limit|20 sources|limit/i);
  const recoveredTexts = new Set([...result.source_inventory, ...(result.rejected_source_entries || [])].map(item => item.text));
  for (const entry of sources) assert.ok(recoveredTexts.has(entry.text), `Missing retained source attempt ${entry.fileName}`);
});

test('explicit private export contains the exact source and arithmetic but no signing key', async () => {
  const result = await prepare(csv, { fileName: 'original-synthetic-private.csv' });
  const artifact = makeReconciliationArtifact(result);
  const encoded = typeof artifact === 'string' ? artifact : JSON.stringify(artifact);
  assert.match(encoded, /private/i);
  assert.ok(encoded.includes('original-synthetic-private.csv'));
  assert.ok(encoded.includes(Buffer.from(csv).toString('base64')));
  assert.ok(encoded.includes('opening_nav'));
  assert.ok(encoded.includes('economic_change'));
  assert.doesNotMatch(encoded, /privateKey|private_key|BEGIN PRIVATE KEY/);
});
