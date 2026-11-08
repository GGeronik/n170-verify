import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import {
  verifyDkimStatementEml,
  signDkimEml,
  runCli,
} from '../scripts/verify-dkim-statement.mjs';

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const STATEMENT_HTML =
  '<!DOCTYPE html><html><head><title>Activity Statement</title></head>' +
  '<body><table><tr><td>Net Asset Value</td><td>100000.00 USD</td><td>152000.00 USD</td></tr>' +
  '<tr><td>Deposits &amp; Withdrawals</td><td>50000.00 USD</td></tr></table></body></html>';
const STATEMENT_B64 = Buffer.from(STATEMENT_HTML, 'utf8').toString('base64');
const STATEMENT_SHA256 = createHash('sha256').update(STATEMENT_HTML, 'utf8').digest('hex');

const BOUNDARY = '----=_Part_N170_IBKR_20261102';
const MIME_BODY = [
  `--${BOUNDARY}`,
  'Content-Type: text/plain; charset=UTF-8',
  'Content-Transfer-Encoding: 7bit',
  '',
  'Attached is your Interactive Brokers Daily Activity Statement.',
  `--${BOUNDARY}`,
  'Content-Type: text/html; name="ActivityStatement_20250131.html"',
  'Content-Transfer-Encoding: base64',
  'Content-Disposition: attachment; filename="ActivityStatement_20250131.html"',
  '',
  STATEMENT_B64,
  `--${BOUNDARY}--`,
  '',
].join('\r\n');

const BASE_HEADERS = [
  { name: 'From', value: 'donotreply@interactivebrokers.com' },
  { name: 'To', value: 'investor@example.com' },
  { name: 'Subject', value: 'Interactive Brokers Activity Statement for January 2025' },
  { name: 'Date', value: 'Mon, 02 Nov 2026 10:00:00 +0000' },
  { name: 'MIME-Version', value: '1.0' },
  { name: 'Content-Type', value: `multipart/mixed; boundary="${BOUNDARY}"` },
];

test('Valid RSA-2048 DKIM-signed IBKR Activity Statement .eml verifies and extracts base64 attachment', () => {
  const eml = signDkimEml({
    headers: BASE_HEADERS,
    body: MIME_BODY,
    domain: 'interactivebrokers.com',
    selector: 'ibkr2026',
    privateKeyPem: privateKey,
    canonicalization: 'relaxed/relaxed',
  });

  const res = verifyDkimStatementEml(eml, {
    expectedDomain: 'interactivebrokers.com',
    trustedKeys: {
      'ibkr2026._domainkey.interactivebrokers.com': publicKey,
    },
  });

  assert.equal(res.ok, true);
  assert.equal(res.status, 'DKIM_VERIFIED');
  assert.equal(res.domain, 'interactivebrokers.com');
  assert.equal(res.selector, 'ibkr2026');
  assert.equal(res.attachments.length, 1);
  assert.equal(res.attachments[0].filename, 'ActivityStatement_20250131.html');
  assert.equal(res.attachments[0].sha256, STATEMENT_SHA256);
  assert.equal(res.attachments[0].bytes.toString('utf8'), STATEMENT_HTML);
});

test('DKIM signature with l= body-length tag is immediately rejected with DKIM_BODY_LENGTH_TAG_FORBIDDEN', () => {
  const emlWithL = signDkimEml({
    headers: BASE_HEADERS,
    body: MIME_BODY,
    domain: 'interactivebrokers.com',
    selector: 'ibkr2026',
    privateKeyPem: privateKey,
    extraTags: 'l=128',
  });

  assert.throws(
    () =>
      verifyDkimStatementEml(emlWithL, {
        expectedDomain: 'interactivebrokers.com',
        publicKeyPem: publicKey,
      }),
    (err) => err.code === 'DKIM_BODY_LENGTH_TAG_FORBIDDEN'
  );
});

test('Tampered MIME attachment body fails bh= verification with DKIM_BODY_HASH_MISMATCH', () => {
  const validEml = signDkimEml({
    headers: BASE_HEADERS,
    body: MIME_BODY,
    domain: 'interactivebrokers.com',
    selector: 'ibkr2026',
    privateKeyPem: privateKey,
  });

  const forgedHtml = STATEMENT_HTML.replace('152000.00 USD', '999999.00 USD');
  const forgedB64 = Buffer.from(forgedHtml, 'utf8').toString('base64');
  const tamperedEml = validEml.replace(STATEMENT_B64, forgedB64);

  assert.throws(
    () =>
      verifyDkimStatementEml(tamperedEml, {
        expectedDomain: 'interactivebrokers.com',
        publicKeyPem: publicKey,
      }),
    (err) => err.code === 'DKIM_BODY_HASH_MISMATCH'
  );
});

test('Duplicate unsigned header injection (second From: or Subject: prepended) is rejected with DKIM_UNSIGNED_DUPLICATE_HEADER', () => {
  const validEml = signDkimEml({
    headers: BASE_HEADERS,
    body: MIME_BODY,
    domain: 'interactivebrokers.com',
    selector: 'ibkr2026',
    privateKeyPem: privateKey,
  });

  const injectedEml = `Subject: Forged Statement Header\r\n${validEml}`;
  assert.throws(
    () =>
      verifyDkimStatementEml(injectedEml, {
        expectedDomain: 'interactivebrokers.com',
        publicKeyPem: publicKey,
      }),
    (err) => err.code === 'DKIM_UNSIGNED_DUPLICATE_HEADER'
  );
});

test('Self-emailed / wrong-domain (d=gmail.com when interactivebrokers.com expected) is rejected with DKIM_DOMAIN_MISMATCH', () => {
  const selfEmailed = signDkimEml({
    headers: [
      { name: 'From', value: 'user@gmail.com' },
      ...BASE_HEADERS.slice(1),
    ],
    body: MIME_BODY,
    domain: 'gmail.com',
    selector: '20230601',
    privateKeyPem: privateKey,
  });

  assert.throws(
    () =>
      verifyDkimStatementEml(selfEmailed, {
        expectedDomain: 'interactivebrokers.com',
        publicKeyPem: publicKey,
      }),
    (err) => err.code === 'DKIM_DOMAIN_MISMATCH'
  );
});

test('CLI --help outputs usage cleanly', () => {
  const res = runCli(['--help']);
  assert.equal(res.exitCode, 0);
  assert.ok(res.output.startsWith('Usage: node scripts/verify-dkim-statement.mjs '));
});
