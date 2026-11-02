import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signDkimEml } from '../scripts/verify-dkim-statement.mjs';
import {
  DIGEST_SHA256,
  SIG_RSA_SHA256,
  generateTestBankCertificate,
  signEch0196TaxStatementXml,
  verifyEch0196StatementXml,
  runCli as runEch0196Cli,
} from '../scripts/verify-ech0196-statement.mjs';
import {
  BROKER_PROVENANCE_MATRIX,
  CONSUMER_AND_RELAY_DOMAINS,
  inspectPdfCryptographicSignature,
  signWiseWebhookPayload,
  verifyDirectBrokerArtifact,
  verifyWiseWebhookSignature,
  runCli as runBrokerSourceCli,
} from '../scripts/verify-broker-source.mjs';
import {
  BROKER_PROVENANCE_MATRIX as WEB_BROKER_MATRIX,
  inspectPdfCryptographicSignature as inspectPdfWeb,
  verifyDirectBrokerArtifactWeb,
  verifyWiseWebhookSignatureWeb,
} from '../src/directBrokerSource.js';

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const IBKR_FLEX_V3_XML = [
  '<FlexQueryResponse queryName="N170_Verify_Flex" type="AF">',
  '<FlexStatements count="1">',
  '<FlexStatement accountId="U0000000" fromDate="20250101" toDate="20250131" period="Month" whenGenerated="20250201;090000">',
  '<AccountInformation accountId="U0000000" currency="USD" dateOpened="20200101" />',
  '<ChangeInNAV accountId="U0000000" fromDate="20250101" toDate="20250131" startingValue="100000.00" endingValue="155000.00" depositsWithdrawals="50000.00" mtm="5000.00" />',
  '<CashReport>',
  '<CashReportCurrency accountId="U0000000" currency="BASE_SUMMARY" startingCash="10000.00" endingCash="65000.00" depositWithdrawals="50000.00" />',
  '</CashReport>',
  '<OpenPositions></OpenPositions>',
  '<Trades></Trades>',
  '<CashTransactions></CashTransactions>',
  '<CorporateActions></CorporateActions>',
  '<ChangeInDividendAccruals></ChangeInDividendAccruals>',
  '</FlexStatement>',
  '</FlexStatements>',
  '</FlexQueryResponse>',
].join('\n');

test('BROKER_PROVENANCE_MATRIX covers all 9 audited institutions identically in CLI and browser modules', () => {
  const expectedBrokers = [
    'IBKR',
    'SAXO',
    'SWISSQUOTE',
    'SCHWAB',
    'VANGUARD',
    'WISE',
    'REVOLUT',
    'FIDELITY',
    'TRADESTATION',
  ];
  assert.deepEqual(Object.keys(BROKER_PROVENANCE_MATRIX), expectedBrokers);
  assert.deepEqual(Object.keys(WEB_BROKER_MATRIX), expectedBrokers);
  for (const code of expectedBrokers) {
    assert.deepEqual(WEB_BROKER_MATRIX[code], BROKER_PROVENANCE_MATRIX[code]);
  }
  assert.ok(CONSUMER_AND_RELAY_DOMAINS.has('gmail.com'));
  assert.ok(CONSUMER_AND_RELAY_DOMAINS.has('outlook.com'));
});

test('SAXO Bank and Swissquote eCH-0196 v2.2.0 XMLDSIG statements verify with rsa-sha1 and rsa-sha256', () => {
  const saxoCert = generateTestBankCertificate({
    institution: 'SAXO',
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
  });
  const saxoXml = signEch0196TaxStatementXml({
    institution: 'SAXO',
    canton: 'ZH',
    taxPeriod: '2025',
    totalTaxValue: '250000.00',
    totalGrossRevenueA: '3500.00',
    totalGrossRevenueB: '1200.00',
    privateKeyPem: saxoCert.privateKeyPem,
    certificatePem: saxoCert.certificatePem,
    subjectName: saxoCert.subjectName,
  });

  const saxoRes = verifyEch0196StatementXml(saxoXml, {
    trustedCertsPem: [saxoCert.certificatePem],
  });
  assert.equal(saxoRes.ok, true);
  assert.equal(saxoRes.status, 'ECH0196_VERIFIED');
  assert.equal(saxoRes.institution, 'SAXO');
  assert.equal(saxoRes.currency, 'CHF');
  assert.equal(saxoRes.totalTaxValueScaled, 25000000000000n);
  assert.equal(saxoRes.totalGrossRevenueAScaled, 350000000000n);
  assert.equal(saxoRes.totalGrossRevenueBScaled, 120000000000n);

  const sqCert = generateTestBankCertificate({
    institution: 'SWISSQUOTE',
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
  });
  const sqXml = signEch0196TaxStatementXml({
    institution: 'SWISSQUOTE',
    canton: 'VD',
    taxPeriod: '2025',
    totalTaxValue: '420000.50',
    digestMethod: DIGEST_SHA256,
    signatureMethod: SIG_RSA_SHA256,
    privateKeyPem: sqCert.privateKeyPem,
    certificatePem: sqCert.certificatePem,
    subjectName: sqCert.subjectName,
  });

  const brokerRes = verifyDirectBrokerArtifact(
    { institution: 'SWISSQUOTE', xmlText: sqXml },
    { trustedCertsPem: [sqCert.certificatePem] }
  );
  assert.equal(brokerRes.ok, true);
  assert.equal(brokerRes.status, 'BROKER_PROVENANCE_VERIFIED');
  assert.equal(brokerRes.artifactType, 'ECH0196_XMLDSIG');
  assert.equal(brokerRes.scope, 'ANNUAL_ECH0196_TAX_STATEMENT');
  assert.equal(brokerRes.qualification, 'ANNUAL_SWISS_TAX_STATEMENT_SCOPE');
  assert.equal(brokerRes.totalTaxValueScaled, 42000050000000n);
});

test('eCH-0196 XMLDSIG rejects tampering, missing <Signature>, missing <X509Data>, non-CHF currency, and untrusted issuer', () => {
  const saxoCert = generateTestBankCertificate({
    institution: 'SAXO',
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
  });
  const validXml = signEch0196TaxStatementXml({
    institution: 'SAXO',
    privateKeyPem: saxoCert.privateKeyPem,
    certificatePem: saxoCert.certificatePem,
    subjectName: saxoCert.subjectName,
  });

  // 1. Tampered attribute on <taxStatement>
  const tamperedAttrXml = validXml.replace('totalTaxValue="250000.00"', 'totalTaxValue="999999.00"');
  assert.throws(
    () => verifyEch0196StatementXml(tamperedAttrXml, { trustedCertsPem: [saxoCert.certificatePem] }),
    (err) => err.code === 'REFUSE_XMLDSIG_DIGEST_MISMATCH'
  );

  // 2. Tampered <SignatureValue>
  const tamperedSigXml = validXml.replace(
    /<SignatureValue>([^<]+)<\/SignatureValue>/,
    (_m, sig) => `<SignatureValue>${sig.slice(0, -4)}AAAA</SignatureValue>`
  );
  assert.throws(
    () => verifyEch0196StatementXml(tamperedSigXml, { trustedCertsPem: [saxoCert.certificatePem] }),
    (err) => err.code === 'REFUSE_XMLDSIG_SIGNATURE_INVALID'
  );

  // 3. Unsigned opensteuerauszug XML (no <Signature>)
  const unsignedXml = validXml.replace(/<Signature[\s\S]*?<\/Signature>/, '');
  assert.throws(
    () => verifyEch0196StatementXml(unsignedXml),
    (err) => err.code === 'REFUSE_UNSIGNED_ECH0196_XML'
  );

  // 4. <KeyInfo> with <KeyValue> only (missing <X509Data>)
  const noX509Xml = signEch0196TaxStatementXml({
    institution: 'SAXO',
    includeX509Data: false,
    privateKeyPem: saxoCert.privateKeyPem,
    certificatePem: saxoCert.certificatePem,
  });
  assert.throws(
    () => verifyEch0196StatementXml(noX509Xml),
    (err) => err.code === 'REFUSE_MISSING_X509_DATA'
  );

  // 5. Non-CHF currency on Swissquote eSteuerauszug
  const usdXml = signEch0196TaxStatementXml({
    institution: 'SWISSQUOTE',
    currency: 'USD',
    privateKeyPem: saxoCert.privateKeyPem,
    certificatePem: saxoCert.certificatePem,
  });
  assert.throws(
    () => verifyEch0196StatementXml(usdXml, { trustedCertsPem: [saxoCert.certificatePem] }),
    (err) => err.code === 'REFUSE_NON_CHF_ECH0196_CURRENCY'
  );

  // 6. Missing trustedCertsPem (no implicit DN regex trust) or untrusted certificate subject / issuer
  assert.throws(
    () => verifyEch0196StatementXml(validXml),
    (err) => err.code === 'REFUSE_UNTRUSTED_CERT_ISSUER'
  );
  const untrustedCert = generateTestBankCertificate({
    institution: 'SAXO',
    organization: 'Self-Generated Tax Tool Org',
    commonName: 'Untrusted Self-Signer',
    issuerOrganization: 'Self-Generated Tax Tool Org',
    issuerCommonName: 'Untrusted Self-Signer',
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
  });
  const untrustedXml = signEch0196TaxStatementXml({
    institution: 'SAXO',
    privateKeyPem: untrustedCert.privateKeyPem,
    certificatePem: untrustedCert.certificatePem,
    subjectName: untrustedCert.subjectName,
  });
  assert.throws(
    () => verifyEch0196StatementXml(untrustedXml, { trustedCertsPem: [saxoCert.certificatePem] }),
    (err) => err.code === 'REFUSE_UNTRUSTED_CERT_ISSUER'
  );

  // 7. Cross-institution mismatch (SAXO statement verified as SWISSQUOTE)
  assert.throws(
    () =>
      verifyDirectBrokerArtifact(
        { institution: 'SWISSQUOTE', xmlText: validXml },
        { trustedCertsPem: [saxoCert.certificatePem] }
      ),
    (err) => err.code === 'REFUSE_INSTITUTION_MISMATCH'
  );
});

test('Direct IBKR Email with Attachment .eml verifies RFC 6376 DKIM and F05 Capital Flow Conservation tie-out', async () => {
  const boundary = '----=_Part_IBKR_Flex_20261102';
  const flexB64 = Buffer.from(IBKR_FLEX_V3_XML, 'utf8').toString('base64');
  const flexSha256 = createHash('sha256').update(IBKR_FLEX_V3_XML, 'utf8').digest('hex');
  const body = [
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    '',
    'Attached is your scheduled Interactive Brokers Flex Statement.',
    `--${boundary}`,
    'Content-Type: text/xml; name="FlexStatement_202501.xml"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="FlexStatement_202501.xml"',
    '',
    flexB64,
    `--${boundary}--`,
    '',
  ].join('\r\n');

  const eml = signDkimEml({
    headers: [
      { name: 'From', value: 'donotreply@interactivebrokers.com' },
      { name: 'To', value: 'portfolio@example.org' },
      { name: 'Subject', value: 'Interactive Brokers Activity Flex Statement' },
      { name: 'Date', value: 'Mon, 02 Nov 2026 12:00:00 +0000' },
      { name: 'MIME-Version', value: '1.0' },
      { name: 'Content-Type', value: `multipart/mixed; boundary="${boundary}"` },
    ],
    body,
    domain: 'interactivebrokers.com',
    selector: 'ibkr2026',
    privateKeyPem: privateKey,
  });

  const res = verifyDirectBrokerArtifact(
    { institution: 'IBKR', rawEml: eml },
    { publicKeyPem: publicKey }
  );
  assert.equal(res.ok, true);
  assert.equal(res.status, 'BROKER_PROVENANCE_VERIFIED');
  assert.equal(res.institution, 'IBKR');
  assert.equal(res.scope, 'FULL_PERIOD_NAV_AND_FLOWS');
  assert.equal(res.qualification, null);
  assert.equal(res.attachmentSha256, flexSha256);
  assert.equal(res.flexValidation.format, 'XML');
  assert.equal(res.flexValidation.f05.netExternalCapitalFlowsScaled, 5000000000000n);
  assert.equal(res.flexValidation.f05.economicInvestmentReturnScaled, 500000000000n);

  const webRes = await verifyDirectBrokerArtifactWeb(
    { institution: 'IBKR', rawEml: eml },
    { publicKeyPem: publicKey }
  );
  assert.equal(webRes.status, 'BROKER_PROVENANCE_VERIFIED');
  assert.equal(webRes.scope, 'FULL_PERIOD_NAV_AND_FLOWS');
});

test('Schwab, Vanguard, and Swissquote DKIM trade confirmations verify with SINGLE_TRADE_ONLY_NO_FULL_NAV qualification', async () => {
  const cases = [
    { institution: 'SCHWAB', domain: 'schwab.com', from: 'alerts@schwab.com' },
    { institution: 'VANGUARD', domain: 'vanguard.com', from: 'confirmations@vanguard.com' },
    { institution: 'SWISSQUOTE', domain: 'swissquote.ch', from: 'trading@swissquote.ch' },
  ];

  for (const c of cases) {
    const eml = signDkimEml({
      headers: [
        { name: 'From', value: c.from },
        { name: 'To', value: 'investor@example.org' },
        { name: 'Subject', value: `${c.institution} Trade Confirmation Contract Note` },
        { name: 'Date', value: 'Mon, 02 Nov 2026 12:00:00 +0000' },
        { name: 'MIME-Version', value: '1.0' },
        { name: 'Content-Type', value: 'text/plain; charset=UTF-8' },
      ],
      body: 'Trade Confirmation\r\nAction: BOUGHT\r\nQuantity: 100\r\nPrice: $125.50\r\nNet Amount: $12550.00\r\n',
      domain: c.domain,
      selector: 'selector1',
      privateKeyPem: privateKey,
    });

    const res = verifyDirectBrokerArtifact(
      { institution: c.institution, rawEml: eml },
      { publicKeyPem: publicKey }
    );
    assert.equal(res.status, 'BROKER_PROVENANCE_VERIFIED');
    assert.equal(res.scope, 'SINGLE_TRADE_CONFIRMATION');
    assert.equal(res.qualification, 'SINGLE_TRADE_ONLY_NO_FULL_NAV');
    assert.equal(res.tradeSummary.action, 'BOUGHT');
    assert.equal(res.tradeSummary.quantity, '100');

    const webRes = await verifyDirectBrokerArtifactWeb(
      { institution: c.institution, rawEml: eml },
      { publicKeyPem: publicKey }
    );
    assert.equal(webRes.qualification, 'SINGLE_TRADE_ONLY_NO_FULL_NAV');
  }
});

test('Wise X-Signature-SHA256 webhook and Wise/Revolut DKIM transfer receipts verify offline and reject tampered JSON', async () => {
  const webhookJson = JSON.stringify({
    event_type: 'transfers#state-change',
    data: {
      resource: { id: 987654321, type: 'transfer' },
      current_state: 'outgoing_payment_sent',
    },
  });
  const sigB64 = signWiseWebhookPayload(webhookJson, privateKey);

  const cliRes = verifyWiseWebhookSignature(webhookJson, sigB64, publicKey);
  assert.equal(cliRes.status, 'BROKER_PROVENANCE_VERIFIED');
  assert.equal(cliRes.scope, 'SINGLE_TRANSFER_WEBHOOK');
  assert.equal(cliRes.qualification, 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV');
  assert.equal(cliRes.transferId, '987654321');

  const webRes = await verifyWiseWebhookSignatureWeb(webhookJson, sigB64, publicKey);
  assert.equal(webRes.status, 'BROKER_PROVENANCE_VERIFIED');
  assert.equal(webRes.payloadSha256, cliRes.payloadSha256);

  // Tampered JSON body must fail
  assert.throws(
    () => verifyWiseWebhookSignature(webhookJson.replace('987654321', '111111111'), sigB64, publicKey),
    (err) => err.code === 'REFUSE_WISE_WEBHOOK_SIGNATURE_INVALID'
  );

  // Wise DKIM transfer receipt
  const wiseEml = signDkimEml({
    headers: [
      { name: 'From', value: 'noreply@wise.com' },
      { name: 'To', value: 'investor@example.org' },
      { name: 'Subject', value: "We've paid your transfer out" },
      { name: 'Date', value: 'Mon, 02 Nov 2026 12:00:00 +0000' },
      { name: 'MIME-Version', value: '1.0' },
      { name: 'Content-Type', value: 'text/plain; charset=UTF-8' },
    ],
    body: 'Transfer ID: WISE-2026-0091\r\nWe have paid out 25000.00 CHF from your account.\r\n',
    domain: 'wise.com',
    selector: 'wise2026',
    privateKeyPem: privateKey,
  });
  const wiseDkimRes = verifyDirectBrokerArtifact(
    { institution: 'WISE', rawEml: wiseEml },
    { publicKeyPem: publicKey }
  );
  assert.equal(wiseDkimRes.status, 'BROKER_PROVENANCE_VERIFIED');
  assert.equal(wiseDkimRes.scope, 'SINGLE_TRANSFER_RECEIPT');
  assert.equal(wiseDkimRes.qualification, 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV');
  assert.equal(wiseDkimRes.transferSummary.currency, 'CHF');
});

test('Hard Cross-Contamination Refusal Gate 1: REFUSE_SELF_EMAILED_RELAY_CONTAMINATION on Gmail/Outlook or domain mismatch', async () => {
  // User downloads Fidelity or SAXO PDF and emails it via Gmail or Outlook
  for (const relay of [
    { institution: 'FIDELITY', domain: 'gmail.com', from: 'trader@gmail.com' },
    { institution: 'SAXO', domain: 'outlook.com', from: 'trader@outlook.com' },
    { institution: 'IBKR', domain: 'yahoo.com', from: 'trader@yahoo.com' },
    { institution: 'SCHWAB', domain: 'icloud.com', from: 'trader@icloud.com' },
  ]) {
    const relayedEml = signDkimEml({
      headers: [
        { name: 'From', value: relay.from },
        { name: 'To', value: 'importer@sharesight.example' },
        { name: 'Subject', value: 'Fwd: Trade Confirmation PDF' },
        { name: 'Date', value: 'Mon, 02 Nov 2026 12:00:00 +0000' },
        { name: 'MIME-Version', value: '1.0' },
        { name: 'Content-Type', value: 'text/plain; charset=UTF-8' },
      ],
      body: 'Self-forwarded confirmation PDF.',
      domain: relay.domain,
      selector: 's2026',
      privateKeyPem: privateKey,
    });

    assert.throws(
      () => verifyDirectBrokerArtifact({ institution: relay.institution, rawEml: relayedEml }, { publicKeyPem: publicKey }),
      (err) => err.code === 'REFUSE_SELF_EMAILED_RELAY_CONTAMINATION'
    );
    await assert.rejects(
      () => verifyDirectBrokerArtifactWeb({ institution: relay.institution, rawEml: relayedEml }, { publicKeyPem: publicKey }),
      (err) => err.code === 'REFUSE_SELF_EMAILED_RELAY_CONTAMINATION'
    );
  }
});

test('Hard Cross-Contamination Refusal Gate 2: REFUSE_USER_SMTP_SELF_ATTESTATION on TradeStation user-SMTP alerts (From == To)', async () => {
  const tsSelfEml = signDkimEml({
    headers: [
      { name: 'From', value: 'user_trader@gmail.com' },
      { name: 'To', value: 'user_trader@gmail.com' },
      { name: 'Subject', value: 'TradeManager Order Fill Alert' },
      { name: 'Date', value: 'Mon, 02 Nov 2026 12:00:00 +0000' },
      { name: 'MIME-Version', value: '1.0' },
      { name: 'Content-Type', value: 'text/plain; charset=UTF-8' },
    ],
    body: 'Order Filled: Bought 100 Shares at 50.00',
    domain: 'gmail.com',
    selector: 'google2026',
    privateKeyPem: privateKey,
  });

  assert.throws(
    () => verifyDirectBrokerArtifact({ institution: 'TRADESTATION', rawEml: tsSelfEml }, { publicKeyPem: publicKey }),
    (err) => err.code === 'REFUSE_USER_SMTP_SELF_ATTESTATION'
  );
  await assert.rejects(
    () => verifyDirectBrokerArtifactWeb({ institution: 'TRADESTATION', rawEml: tsSelfEml }, { publicKeyPem: publicKey }),
    (err) => err.code === 'REFUSE_USER_SMTP_SELF_ATTESTATION'
  );
});

test('Hard Cross-Contamination Refusal Gate 3: REFUSE_VISUAL_STAMP_NOT_CRYPTOGRAPHIC on Revolut/Wise stamped PDFs and unsigned portal PDFs', async () => {
  const revolutStampedPdf = Buffer.from(
    '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% Revolut Business Statement - Signed and stamped visual overlay\n%%EOF\n',
    'latin1'
  );
  const wiseStampedPdf = Buffer.from(
    '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% Wise Statement - Stamp and sign this document facsimile overlay\n%%EOF\n',
    'latin1'
  );
  const plainPortalPdf = Buffer.from(
    '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% Monthly eStatement PDF\n%%EOF\n',
    'latin1'
  );

  assert.equal(inspectPdfCryptographicSignature(revolutStampedPdf).reason, 'VISUAL_STAMP_NOT_CRYPTOGRAPHIC');
  assert.equal(inspectPdfWeb(wiseStampedPdf).reason, 'VISUAL_STAMP_NOT_CRYPTOGRAPHIC');
  assert.equal(inspectPdfCryptographicSignature(plainPortalPdf).reason, 'UNSIGNED_PDF');

  assert.throws(
    () => verifyDirectBrokerArtifact({ institution: 'REVOLUT', pdfBytes: revolutStampedPdf }),
    (err) => err.code === 'REFUSE_VISUAL_STAMP_NOT_CRYPTOGRAPHIC'
  );
  assert.throws(
    () => verifyDirectBrokerArtifact({ institution: 'WISE', pdfBytes: wiseStampedPdf }),
    (err) => err.code === 'REFUSE_VISUAL_STAMP_NOT_CRYPTOGRAPHIC'
  );
  await assert.rejects(
    () => verifyDirectBrokerArtifactWeb({ institution: 'REVOLUT', pdfBytes: revolutStampedPdf }),
    (err) => err.code === 'REFUSE_VISUAL_STAMP_NOT_CRYPTOGRAPHIC'
  );

  // Plain unsigned portal PDF on Schwab/IBKR/Fidelity -> REFUSE_UNSIGNED_PORTAL_PDF
  assert.throws(
    () => verifyDirectBrokerArtifact({ institution: 'SCHWAB', pdfBytes: plainPortalPdf }),
    (err) => err.code === 'REFUSE_UNSIGNED_PORTAL_PDF'
  );
});

test('Hard Cross-Contamination Refusal Gate 4: REFUSE_NOTIFICATION_LINK_ONLY_NO_PAYLOAD on Fidelity eDelivery login-link emails', async () => {
  const fidelityLinkEml = signDkimEml({
    headers: [
      { name: 'From', value: 'Fidelity.Investments@mail.fidelity.com' },
      { name: 'To', value: 'investor@example.org' },
      { name: 'Subject', value: 'Fidelity eDelivery Notification: Your Monthly Statement is Available' },
      { name: 'Date', value: 'Mon, 02 Nov 2026 12:00:00 +0000' },
      { name: 'MIME-Version', value: '1.0' },
      { name: 'Content-Type', value: 'text/plain; charset=UTF-8' },
    ],
    body: 'Please log in to Fidelity.com or NetBenefits to view your statement online.\r\n',
    domain: 'mail.fidelity.com',
    selector: '2022-02-04',
    privateKeyPem: privateKey,
  });

  assert.throws(
    () => verifyDirectBrokerArtifact({ institution: 'FIDELITY', rawEml: fidelityLinkEml }, { publicKeyPem: publicKey }),
    (err) => err.code === 'REFUSE_NOTIFICATION_LINK_ONLY_NO_PAYLOAD'
  );
  await assert.rejects(
    () => verifyDirectBrokerArtifactWeb({ institution: 'FIDELITY', rawEml: fidelityLinkEml }, { publicKeyPem: publicKey }),
    (err) => err.code === 'REFUSE_NOTIFICATION_LINK_ONLY_NO_PAYLOAD'
  );
});

test('CLI entrypoints verify-ech0196-statement.mjs and verify-broker-source.mjs support --help and exit codes 0, 1, 3', () => {
  const echHelp = runEch0196Cli(['--help']);
  assert.equal(echHelp.exitCode, 0);
  assert.ok(echHelp.output.startsWith('Usage: node scripts/verify-ech0196-statement.mjs '));

  const brokerHelp = runBrokerSourceCli(['--help']);
  assert.equal(brokerHelp.exitCode, 0);
  assert.ok(brokerHelp.output.startsWith('Usage: node scripts/verify-broker-source.mjs '));

  assert.equal(runEch0196Cli([]).exitCode, 3);
  assert.equal(runBrokerSourceCli(['only-one-arg']).exitCode, 3);

  const tmp = mkdtempSync(join(tmpdir(), 'n170-broker-cli-'));
  try {
    const cert = generateTestBankCertificate({
      institution: 'SAXO',
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });
    const signedXml = signEch0196TaxStatementXml({
      institution: 'SAXO',
      privateKeyPem: cert.privateKeyPem,
      certificatePem: cert.certificatePem,
      subjectName: cert.subjectName,
    });
    const xmlPath = join(tmp, 'saxo-ech0196.xml');
    const certPath = join(tmp, 'saxo-cert.pem');
    const badXmlPath = join(tmp, 'unsigned.xml');
    writeFileSync(xmlPath, signedXml, 'utf8');
    writeFileSync(certPath, cert.certificatePem, 'utf8');
    writeFileSync(badXmlPath, signedXml.replace(/<Signature[\s\S]*?<\/Signature>/, ''), 'utf8');

    const okEch = runEch0196Cli([xmlPath, '--trusted-cert', certPath, '--institution', 'SAXO']);
    assert.equal(okEch.exitCode, 0);
    assert.equal(JSON.parse(okEch.output).status, 'ECH0196_VERIFIED');

    const failEch = runEch0196Cli([badXmlPath]);
    assert.equal(failEch.exitCode, 1);
    assert.equal(JSON.parse(failEch.output).code, 'REFUSE_UNSIGNED_ECH0196_XML');

    const okBroker = runBrokerSourceCli([xmlPath, '--institution', 'SAXO', '--trusted-cert', certPath]);
    assert.equal(okBroker.exitCode, 0);
    assert.equal(JSON.parse(okBroker.output).status, 'BROKER_PROVENANCE_VERIFIED');

    const failBroker = runBrokerSourceCli([badXmlPath, '--institution', 'SAXO']);
    assert.equal(failBroker.exitCode, 1);
    assert.equal(JSON.parse(failBroker.output).code, 'REFUSE_UNSIGNED_ECH0196_XML');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
