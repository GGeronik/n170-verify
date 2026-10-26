import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { erfc, normalCdf } from '../src/erfc.js';
import { computeStatistics, inferenceFromMoments, fsum, STATISTICS_VERSION } from '../src/statistics.js';
import { analyzeObservationSchedule } from '../src/calculator.js';
import { effectiveStamps } from '../src/trackRecord.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = path.join(ROOT, 'tests/fixtures/stats');
const read = name => JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf8'));
const manifest = read('MANIFEST.json');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const CLOSED_STATUSES = new Set(['OK', 'STATS_SAMPLE_INSUFFICIENT', 'STATS_ZERO_VARIANCE', 'STATS_NON_FINITE']);
const INPUT_FIELDS = ['T', 'periods_per_year', 'schedule_compatible', 'rf_per_interval'];
const FIGURE_FIELDS = ['mean', 'sd', 'variance', 'm2', 'm3', 'm4', 'skewness', 'skewness_se', 'excess_kurtosis', 'excess_kurtosis_se', 'rho1', 'rho1_se', 'rho1_band', 'autocorr_significant', 'sharpe_per_interval', 'sharpe_annualized_nominal', 'lo_eta', 'sharpe_annualized_adjusted', 'annualization_code', 'V', 'sigma_sr', 'z', 'psr0', 'mintrl', 'mintrl_code', 'inference_code'];
const EXPECTED_KEYS = ['version', 'status', ...INPUT_FIELDS, ...FIGURE_FIELDS, 'labels'].sort();
const optionsFor = fixture => ({ periodsPerYear: fixture.periods_per_year, scheduleCompatible: fixture.schedule_compatible, rfPerInterval: fixture.rf_per_interval });
const decode = value => value === 'NaN' ? NaN : value === '+Infinity' ? Infinity : value;
const options = { periodsPerYear: 252, scheduleCompatible: true };

function compareNumber(actual, expected, field, expectedResult) {
  assert.equal(typeof actual, 'number', `${field}: number`);
  assert(Number.isFinite(actual), `${field}: finite`);
  if (field === 'mintrl' || INPUT_FIELDS.includes(field)) {
    assert.equal(actual, expected, `${field}: exact`);
  } else if (field === 'psr0' || field === 'phi') {
    const z = expectedResult.z;
    const tolerance = Math.abs(z) <= 8 ? 1e-15 : 1e-12 * Math.abs(expected);
    assert(Math.abs(actual - expected) <= tolerance, `${field}: ${actual} versus ${expected}, tolerance ${tolerance}`);
  } else if (expected === 0) {
    assert.equal(actual, 0, `${field}: exact zero`);
  } else {
    assert(Math.abs(actual - expected) <= 1e-12 * Math.abs(expected), `${field}: ${actual} versus ${expected}`);
  }
}

function compareStatistics(actual, expected) {
  assert.deepEqual(Object.keys(actual).sort(), EXPECTED_KEYS);
  assert.equal(actual.version, STATISTICS_VERSION);
  assert.equal(actual.version, expected.schema);
  assert(Object.isFrozen(actual));
  for (const [field, value] of Object.entries(expected)) {
    if (['schema', 'fixture', 'fixture_sha256'].includes(field)) continue;
    if (typeof value === 'number') compareNumber(actual[field], value, field, expected);
    else assert.deepEqual(actual[field], value, field);
  }
  if (actual.status !== 'OK') for (const field of FIGURE_FIELDS) assert.equal(actual[field], null, field);
}

function phiPoints(points) {
  for (const point of points) compareNumber(normalCdf(point.z), point.phi, 'phi', point);
}

function ulpDistance(actual, expected) {
  const bytes = new DataView(new ArrayBuffer(8));
  bytes.setFloat64(0, actual); const first = bytes.getBigUint64(0);
  bytes.setFloat64(0, expected); const second = bytes.getBigUint64(0);
  return first >= second ? first - second : second - first;
}

test('statistics fixture manifest seals all 81 files without additions or omissions', () => {
  const bytes = fs.readFileSync(path.join(FIXTURES, 'MANIFEST.json'));
  assert.equal(digest(bytes), '4f43f4286c7121796c21007d36a0cddf9256c4b9dd1dd70a448ae97601cad539');
  assert.equal(manifest.files.length, 81);
  const listed = manifest.files.map(entry => path.basename(entry.path));
  assert.equal(new Set(listed).size, listed.length);
  assert.deepEqual(fs.readdirSync(FIXTURES).filter(name => name !== 'MANIFEST.json').sort(), listed.slice().sort());
  for (const entry of manifest.files) {
    assert.equal(entry.path, `tests/fixtures/stats/${path.basename(entry.path)}`);
    const data = fs.readFileSync(path.join(ROOT, entry.path));
    assert.equal(data.length, entry.bytes, entry.path);
    assert.equal(digest(data), entry.sha256, entry.path);
  }
});

for (const entry of manifest.files.filter(file => file.role === 'expected')) {
  const expected = read(path.basename(entry.path));
  test(`statistics engine matches sealed fixture ${expected.fixture}`, () => {
    const inputName = `${expected.fixture}.input.json`;
    const inputBytes = fs.readFileSync(path.join(FIXTURES, inputName));
    assert.equal(digest(inputBytes), expected.fixture_sha256);
    const input = JSON.parse(inputBytes);
    if (expected.points) {
      assert.equal(expected.fixture === 'F16' ? input.count : input.z_values.length, expected.points.length);
      if (input.z_values) assert.deepEqual(input.z_values, expected.points.map(point => point.z));
      phiPoints(expected.points);
    } else {
      compareStatistics(computeStatistics(input.returns_e8.map(decode), optionsFor(input)), expected);
    }
  });
}

test('Cody erfc passes both signed boundary vectors within four ULP and is non-increasing', () => {
  for (const boundary of read('erfc-boundaries.json').boundaries) {
    const values = boundary.points.flatMap(point => [{ x: point.x, expected: point.erfc }, { x: point.negative_x, expected: point.erfc_negative }]);
    values.sort((first, second) => first.x - second.x);
    let previous = Infinity;
    for (const point of values) {
      const actual = erfc(point.x);
      assert(ulpDistance(actual, point.expected) <= 4n, `${point.x}: ${actual} versus ${point.expected}`);
      assert(actual <= previous, `${point.x}: erfc must be non-increasing`);
      previous = actual;
    }
  }
  assert.equal(erfc(Infinity), 0);
  assert.equal(erfc(-Infinity), 2);
  assert(Number.isNaN(erfc(NaN)));
  assert.equal(normalCdf(-Infinity), 0);
  assert.equal(normalCdf(Infinity), 1);
  assert.equal(normalCdf(0), 0.5);
});

test('sealed auxiliary Phi vectors exactly match their F11 and F16 expectations', () => {
  const points = read('phi-points.json');
  const vector = read('phi-vector.json');
  assert.deepEqual(points, read('F11.expected.json').points);
  assert.equal(vector.count, 10000);
  assert.equal(vector.points.length, 10000);
  assert.deepEqual(vector.points, read('F16.expected.json').points);
  phiPoints(points);
  phiPoints(vector.points);
});

test('exact partial sums pass E2 cancellation and rounding controls', () => {
  assert.equal(fsum(Array(10).fill(0.1)), 1);
  assert.equal(fsum([1e100, 1, -1e100, 1e-100, 1e50, -1, -1e50]), 1e-100);
  assert.equal(fsum([2 ** 53, 1, -(2 ** 53)]), 1);
  assert.equal(fsum([]), 0);
  // The final partial must round ties to even without double rounding.
  assert.equal(fsum([1e16, 1, 1e-16]), 10000000000000002);
});

test('F09a refuses non-finite and invalid inference without clamping V', () => {
  const guards = read('F09a-guards.json');
  for (const guard of guards.cases) {
    const result = inferenceFromMoments({ T: guard.T, sharpePerInterval: guard.sharpe_per_interval, skewness: decode(guard.skewness), excessKurtosis: decode(guard.excess_kurtosis), autocorrSignificant: false });
    assert.equal(result.status, guards.expected_status, guard.id);
    for (const field of ['V', 'sigma_sr', 'z', 'psr0', 'mintrl', 'mintrl_code', 'inference_code']) assert.equal(result[field], null, `${guard.id}: ${field}`);
  }
  assert.equal(computeStatistics([NaN, ...Array(19).fill(0)], options).status, guards.expected_status);
});

test('statistics refusals preserve integer-equality precedence and null all figures', () => {
  const cases = [
    [Array(19).fill(7), options, 'STATS_SAMPLE_INSUFFICIENT'],
    [Array(20).fill(-7), { ...options, rfPerInterval: Number.MAX_VALUE }, 'STATS_ZERO_VARIANCE'],
    [[], options, 'STATS_SAMPLE_INSUFFICIENT'],
    [Array.from({ length: 20 }, (_, index) => index), { ...options, rfPerInterval: Number.MAX_VALUE }, 'STATS_NON_FINITE'],
    [Array(20).fill(7), { ...options, rfPerInterval: NaN }, 'STATS_NON_FINITE'],
    [[9007199254740990, ...Array(19).fill(9007199254740991)], options, 'STATS_NON_FINITE'],
  ];
  for (const [returns, settings, status] of cases) {
    const result = computeStatistics(returns, settings);
    assert.equal(result.status, status);
    assert(Object.isFrozen(result));
    for (const field of FIGURE_FIELDS) assert.equal(result[field], null, field);
  }
});

test('one thousand generated statistics calls never throw and return only closed statuses', () => {
  let state = 0x170;
  const random = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
  const hostile = new Proxy({}, { get() { throw new Error('unreadable option'); } });
  const malformed = [undefined, null, false, 1, 'returns', {}, new Int32Array(20), [NaN], [Infinity], [1.1], [Number.MAX_SAFE_INTEGER + 1], [1n], Array(20)];
  const settings = [undefined, null, false, 1, 'options', {}, hostile, { ...options, periodsPerYear: 0 }, { ...options, periodsPerYear: -1 }, { ...options, periodsPerYear: 1.5 }, { ...options, periodsPerYear: Infinity }, { ...options, scheduleCompatible: 'true' }, { ...options, rfPerInterval: NaN }, { ...options, rfPerInterval: Infinity }, { ...options, rfPerInterval: '0' }];
  for (let index = 0; index < 1000; index++) {
    const length = random() % 80;
    const returns = Array.from({ length }, () => (random() % 2000001) - 1000000);
    let series = returns, inputOptions = options;
    switch (index % 5) {
      case 0: series = malformed[random() % malformed.length]; break;
      case 1: inputOptions = settings[random() % settings.length]; break;
      case 2: series = Array(length).fill((random() % 2001) - 1000); break;
      case 3: inputOptions = { ...options, periodsPerYear: [1, 4, 12, 13, 52, 252, 365, 366][random() % 8], scheduleCompatible: !!(random() % 2) }; break;
      default: break;
    }
    let result;
    assert.doesNotThrow(() => { result = computeStatistics(series, inputOptions); }, `argument ${index}`);
    assert(CLOSED_STATUSES.has(result.status), `argument ${index}: ${result.status}`);
    assert.deepEqual(Object.keys(result).sort(), EXPECTED_KEYS, `argument ${index}`);
    assert(Object.isFrozen(result));
    if (result.status !== 'OK') for (const field of FIGURE_FIELDS) assert.equal(result[field], null, `${index}: ${field}`);
  }
});

test('signed integration records derive their sealed per-slot inputs', () => {
  for (const id of ['F12-R', 'S60-R']) {
    const record = read(`${id}.record.json`), input = read(`${id}.input.json`);
    const [slot] = effectiveStamps(record);
    assert.equal(effectiveStamps(record).length, 1);
    const payload = slot.payload;
    const schedule = analyzeObservationSchedule(payload.relative_returns, payload.periods_per_year);
    assert.deepEqual(payload.relative_returns.map(interval => interval.return_e8), input.returns_e8);
    assert.equal(payload.periods_per_year, input.periods_per_year);
    assert.equal(['eligible', 'insufficient_observations'].includes(schedule.status), input.schedule_compatible);
    compareStatistics(computeStatistics(payload.relative_returns.map(interval => interval.return_e8), { periodsPerYear: payload.periods_per_year, scheduleCompatible: input.schedule_compatible }), read(`${id}.expected.json`));
  }
});

test('statistics engine imports only the numerical erfc module and has no browser side effects', () => {
  const source = fs.readFileSync(path.join(ROOT, 'src/statistics.js'), 'utf8');
  const imports = [...source.matchAll(/(?:import|export)\s[^;]*?from\s*['"]([^'"]+)['"]/g)].map(match => match[1]);
  assert(imports.every(name => name === './erfc.js'));
  assert(!/\b(?:document|window|fetch|localStorage|sessionStorage|WebSocket|XMLHttpRequest)\b/.test(source));
});

let renderPanel;
async function statisticsMarkup(props) {
  if (!renderPanel) {
    const [{ build }, { createElement }, { renderToStaticMarkup }] = await Promise.all([import('esbuild'), import('react'), import('react-dom/server')]);
    const bundle = await build({ entryPoints: [path.join(ROOT, 'src/StatisticsPanel.jsx')], bundle: true, platform: 'node', format: 'esm', jsx: 'automatic', write: false, logLevel: 'silent',
      // Keep React hooks on the same instance as the server renderer. The data
      // module needs file URLs because it has no package-resolution directory.
      plugins: [{ name: 'shared-react', setup(builder) { builder.onResolve({ filter: /^react(?:\/|$)/ }, args => ({ path: import.meta.resolve(args.path), external: true })); } }],
    });
    const { default: StatisticsPanel } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString('base64')}`);
    renderPanel = value => renderToStaticMarkup(createElement(StatisticsPanel, value));
  }
  return renderPanel(props);
}
const visibleText = html => html.replace(/<[^>]*>/g, '');
const number = value => Number(value.toPrecision(6)).toString();

test('statistics panel renders ordered declarative rows with six significant digits', async () => {
  const statistics = { version: STATISTICS_VERSION, ...read('G60.expected.json') };
  const html = await statisticsMarkup({ statistics });
  const text = visibleText(html);
  const rows = [
    'Derived statistics (unsigned)',
    '60 return intervals at 252 periods per year.',
    `Mean per interval ${number(100 * statistics.mean)}%; standard deviation per interval ${number(100 * statistics.sd)}%.`,
    `Skewness ${number(statistics.skewness)} (standard error ${number(statistics.skewness_se)}).`,
    `Excess kurtosis ${number(statistics.excess_kurtosis)} (standard error ${number(statistics.excess_kurtosis_se)}).`,
    `Lag-1 autocorrelation ${number(statistics.rho1)} (band ±${number(statistics.rho1_band)}; significant: no).`,
    `Annualised Sharpe ratio, excess over 0: nominal ${number(statistics.sharpe_annualized_nominal)}; adjusted for lag-1 autocorrelation ${number(statistics.sharpe_annualized_adjusted)}.`,
    `Probabilistic Sharpe ratio against 0, at observed moments: ${number(statistics.psr0)}.`,
    `Minimum track record length at 95% confidence, at observed moments: ${number(statistics.mintrl)} intervals.`,
    'These figures are derived from the signed returns, are not signed, and change with future returns.',
  ];
  let previous = -1;
  for (const row of rows) {
    const position = text.indexOf(row);
    assert(position > previous, row);
    previous = position;
  }
  assert(!/<(?:progress|meter|h1|h2)\b/.test(html));
});

test('statistics panel displays every withholding code with its exact reason', async () => {
  const cases = [
    ['B19', 'STATS_SAMPLE_INSUFFICIENT', 'Statistics are withheld: fewer than 20 return intervals.', 7],
    ['Z60', 'STATS_ZERO_VARIANCE', 'Statistics are withheld: every interval return is identical.', 7],
    ['F09a', 'STATS_NON_FINITE', 'Statistics are withheld: an intermediate value was not a finite number.', 7],
    ['S60', 'SCHEDULE_ANNUALIZATION_REFUSED', 'Annualised figures are withheld: the observation dates do not support the declared frequency.', 1],
    ['N60', 'MINTRL_UNDEFINED_NONPOSITIVE_EXCESS', 'Minimum track record length is undefined because the mean excess return is not positive.', 1],
    ['F03', 'STATS_INFERENCE_ASSUMES_IID', 'This figure assumes independent returns; lag-1 autocorrelation is significant.', 2],
  ];
  for (const [id, code, reason, count] of cases) {
    const html = await statisticsMarkup({ statistics: read(`${id}.expected.json`) });
    assert.equal(html.split(`<code>${code}</code> ${reason}`).length - 1, count, id);
    assert(!/\b(?:NaN|Infinity|undefined|null)\b/.test(visibleText(html).replace('undefined because', 'not defined because')), id);
  }
});

test('statistics panel derives each signed integration record independently', async () => {
  const short = visibleText(await statisticsMarkup({ profile: read('F12-R.record.json') }));
  assert(short.includes('Record 1 · 2024-01-31 – 2025-03-31'));
  assert(short.includes('14 return intervals at 12 periods per year.'));
  assert(short.includes('STATS_SAMPLE_INSUFFICIENT Statistics are withheld: fewer than 20 return intervals.'));
  const incompatible = visibleText(await statisticsMarkup({ profile: read('S60-R.record.json') }));
  assert(incompatible.includes('60 return intervals at 252 periods per year.'));
  assert(incompatible.includes('SCHEDULE_ANNUALIZATION_REFUSED Annualised figures are withheld: the observation dates do not support the declared frequency.'));
  assert(incompatible.includes('Probabilistic Sharpe ratio against 0, at observed moments:'));
});

test('statistics panel replaces corrected slots and preserves performance-slot order', async () => {
  const first = structuredClone(read('F12-R.record.json').stamps[0]);
  const second = structuredClone(read('S60-R.record.json').stamps[0]);
  second.payload.sequence = 2;
  const correction = structuredClone(second);
  correction.payload.sequence = 3;
  correction.payload.event_type = 'correction';
  correction.payload.correction = { target_sequence: 1, reason: 'Synthetic rendering-only replacement' };
  const profile = { ...read('F12-R.record.json'), stamps: [first, second, correction] };
  const html = await statisticsMarkup({ profile });
  const text = visibleText(html);
  assert.equal((html.match(/class="statistics-record"/g) || []).length, 2);
  assert(!text.includes('Record 1 ·'));
  assert(text.indexOf('Record 3 ·') < text.indexOf('Record 2 ·'));
  assert.equal(text.split('60 return intervals at 252 periods per year.').length - 1, 2);
  assert(!text.includes('120 return intervals'));
});
