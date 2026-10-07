import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { calculateEvidence, RETURN_UNITS, sampleInput } from "../src/calculator.js";
import { createSigner, decodeBase64Url, formatKeyCode, generateProfileKey } from "../src/signing.js";
import { appendPerformanceStamp, createProfile, extendsByOneRecord, inspectProfile, MAX_COMMITMENT_CHARACTERS, MAX_COMMITMENT_LINES, MAX_PROFILE_CHARACTERS, MAX_PROFILE_STAMPS, PROFILE_SCHEMA, publishedFingerprint, STAMP_SCHEMA } from "../src/trackRecord.js";

const csv = (...rows) => `date,nav,external_flow\n${rows.join("\n")}`;
const zero = csv("2025-01-01,100,0", "2025-01-02,150,50", "2025-01-03,80,-70");
const following = csv("2025-01-03,100,0", "2025-01-04,90,0");
const hash = (payload) => createHash("sha256").update(JSON.stringify(payload)).digest("hex");
const mutate = (profile, edit) => { const copy = structuredClone(profile); edit(copy); return copy; };
const close = (actual, expected, tolerance = 1e-10) => assert.ok(Math.abs(actual - expected) <= tolerance, `${actual} != ${expected}`);
const inspect = (profile, options) => inspectProfile(JSON.stringify(profile), options);
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const nonCanonical = (text) => text.slice(0, -1) + alphabet[alphabet.indexOf(text.at(-1)) | 1];
const char = (code) => String.fromCharCode(code);
const numbersIn = (text) => {
  const found = [];
  JSON.parse(text, (_key, value) => { if (typeof value === "number") found.push(value); return value; });
  return found;
};

async function newSigner() {
  const key = await generateProfileKey();
  return createSigner(key.privateKey, key.publicKey);
}

async function newProfile(name = "Example") {
  const signer = await newSigner();
  return { signer, profile: await createProfile(name, signer) };
}

async function signedProfile(input = zero, periodsPerYear = 252) {
  const { signer, profile } = await newProfile();
  return { signer, profile: await appendPerformanceStamp(profile, input, periodsPerYear, signer) };
}

test("profile IDs derive from their own public key and aliases can't hide characters", async () => {
  const a = await newProfile("Alex");
  const b = await newProfile("Alex");
  assert.equal(a.profile.schema_version, PROFILE_SCHEMA);
  assert.notEqual(a.profile.profile_id, b.profile.profile_id);
  const raw = Buffer.from(decodeBase64Url(a.profile.public_key, 65));
  assert.equal(a.profile.profile_id, createHash("sha256").update(Buffer.concat([Buffer.from("n170.verify.profile-key.v3\n"), raw])).digest("hex"));
  assert.deepEqual(a.profile.stamps, []);
  const joinedEmoji = `Dev ${String.fromCodePoint(0x1f469)}${char(0x200d)}${String.fromCodePoint(0x1f4bb)}`;
  for (const name of ["", " Alex", "Alex ", "x".repeat(81), "a\nb", `a${char(0x202e)}b`, `A${char(0x200b)}lex`, `A${char(0xad)}lex`, `Alex${char(0xd800)}`, `Alex${char(0xa0)}Smith`, `Al${char(0x2003)}ex`, `Desk${char(0xe000)}`, `Alex${char(0x378)}`, joinedEmoji, null, {}]) {
    await assert.rejects(createProfile(name, a.signer), /display name/);
  }
  for (const name of ["José 📈", "🇬🇧 Macro desk"]) assert.equal((await createProfile(name, a.signer)).display_name, name);
  await assert.rejects(createProfile("Alex", null), /signing key is required/);
});

test("signed records verify and reproduce return, volatility and drawdown", async () => {
  const { profile } = await signedProfile(sampleInput);
  const { payload, sha256, signature } = profile.stamps[0];
  const prior = calculateEvidence(sampleInput);
  close(payload.metrics.total_return_twr_e8 / RETURN_UNITS, prior.metrics.total_return_twr, 1e-7);
  close(payload.metrics.annualized_volatility_e8 / RETURN_UNITS, prior.metrics.annualized_volatility, 1e-7);
  close(payload.metrics.max_drawdown_e8 / RETURN_UNITS, prior.metrics.max_drawdown, 1e-7);
  assert.equal(payload.schema_version, STAMP_SCHEMA);
  assert.equal(payload.source_kind, "synthetic_demo");
  assert.deepEqual(payload.period, { start: "2025-01-02", end: "2025-01-07" });
  assert.equal(hash(payload), sha256);
  assert.equal(decodeBase64Url(signature, 64)?.length, 64);
  const checked = await inspect(profile);
  assert.deepEqual(checked.checks, {
    schema_valid: true,
    arithmetic_valid: true,
    chain_valid: true,
    signatures_valid: true,
    key_code: "not_supplied",
    published_fingerprints: { supplied: 0, matched: 0, latest_record: 0 },
    provider_authenticated: false,
    independent_timestamp: false,
    identity_established: false,
    checkpoint: {checked:false,sequence:null,end:null,sha256:null,source:null,publication_time_established:false},
    previous_copy: {status:"not_supplied",shared_records:0,previous_records:0,current_records:1,changes:null},
  });
  assert.equal(checked.key_code, formatKeyCode(profile.profile_id));
  assert.deepEqual(checked.profile, profile);
});

test("signed returns and metrics are integers in units of 10^-8, so exact balances can't be reconstructed", async () => {
  const input = csv("2025-03-11,12345.67,0", "2025-03-12,12400,13.37", "2025-03-13,12391.05,0");
  const { profile } = await signedProfile(input);
  const { payload } = profile.stamps[0];
  const exact = [(12400 - 13.37) / 12345.67 - 1, 12391.05 / 12400 - 1];
  payload.relative_returns.forEach(({ return_e8 }, index) => {
    assert.ok(Number.isSafeInteger(return_e8));
    close(return_e8 / RETURN_UNITS, exact[index], 0.5 / RETURN_UNITS + 1e-15);
  });
  const numbers = numbersIn(JSON.stringify(profile));
  assert.ok(numbers.length > 0 && numbers.every((value) => Number.isSafeInteger(value)), "a signed profile contains only integers");
});

test("append is immutable and links shared boundaries; later gaps remain explicit", async () => {
  const { signer, profile: empty } = await newProfile();
  const first = await appendPerformanceStamp(empty, zero, 252, signer);
  const second = await appendPerformanceStamp(first, following, 252, signer);
  const third = await appendPerformanceStamp(second, csv("2025-02-01,100,0", "2025-02-02,110,0"), 252, signer);
  assert.equal(empty.stamps.length, 0);
  assert.equal(first.stamps.length, 1);
  assert.equal(second.stamps.length, 2);
  assert.equal(second.stamps[1].payload.previous_sha256, first.stamps[0].sha256);
  const { summary } = await inspect(third);
  assert.deepEqual(summary.gaps, [{ start: "2025-01-04", end: "2025-02-01" }]);
  assert.equal(summary.first_date, "2025-01-01");
  assert.equal(summary.last_date, "2025-02-02");
  assert.equal(summary.stamp_count, 3);
});

test("overlap, duplicates and backward periods are rejected without mutating the profile", async () => {
  const { signer, profile } = await signedProfile();
  for (const input of [zero, csv("2024-01-01,100,0", "2024-01-02,110,0"), csv("2025-01-02,100,0", "2025-01-04,110,0")]) {
    await assert.rejects(appendPerformanceStamp(profile, input, 252, signer), /must start on or after/);
  }
  assert.equal(profile.stamps.length, 1);
  await assert.rejects(inspect(mutate(profile, (p) => { p.stamps.push(structuredClone(p.stamps[0])); })), /sequence or period order/);
});

test("only the profile's own signing key can append records", async () => {
  const { profile } = await newProfile();
  const stranger = await newSigner();
  await assert.rejects(appendPerformanceStamp(profile, zero, 252, stranger), /signing key for this profile/);
  await assert.rejects(appendPerformanceStamp(profile, zero, 252, null), /signing key for this profile/);
});

test("a stored copy only accepts its own next record: no forks, alias swaps, rollbacks or other keys", async () => {
  const { signer, profile: empty } = await newProfile("Alex");
  const first = await appendPerformanceStamp(empty, zero, 252, signer);
  const second = await appendPerformanceStamp(first, following, 252, signer);
  const sibling = await appendPerformanceStamp(first, csv("2025-01-03,100,0", "2025-01-04,130,0"), 252, signer);
  const forked = await appendPerformanceStamp(sibling, csv("2025-01-04,130,0", "2025-01-05,131,0"), 252, signer);
  const stranger = await newProfile("Alex");
  const other = await appendPerformanceStamp(stranger.profile, zero, 252, stranger.signer);
  assert.equal(extendsByOneRecord(empty, first), true);
  assert.equal(extendsByOneRecord(first, second), true);
  assert.equal(extendsByOneRecord(first, sibling), true, "whichever record is stored first is the one kept");
  assert.equal(extendsByOneRecord(second, sibling), false);
  assert.equal(extendsByOneRecord(second, forked), false);
  assert.equal(extendsByOneRecord(first, mutate(second, (p) => { p.display_name = "Alex - broker verified"; })), false);
  assert.equal(extendsByOneRecord(second, first), false);
  assert.equal(extendsByOneRecord(empty, second), false);
  assert.equal(extendsByOneRecord(second, second), false);
  assert.equal(extendsByOneRecord(empty, other), false);
  assert.equal(extendsByOneRecord(null, first), false);
});

test("metric tampering fails even when an attacker recomputes the payload digest", async () => {
  const { profile } = await signedProfile();
  for (const recompute of [false, true]) {
    const altered = mutate(profile, (p) => {
      p.stamps[0].payload.metrics.total_return_twr_e8 = 50000000;
      if (recompute) p.stamps[0].sha256 = hash(p.stamps[0].payload);
    });
    await assert.rejects(inspect(altered), /does not match the disclosed return series/);
  }
});

test("an edited record fails its signature even when its hash is recomputed", async () => {
  const { profile } = await signedProfile();
  const rehashed = mutate(profile, (p) => { p.stamps[0].payload.coverage.external_cash_flow_count = 1; p.stamps[0].sha256 = hash(p.stamps[0].payload); });
  await assert.rejects(inspect(rehashed), /signature is invalid/);
  const unhashed = mutate(profile, (p) => { p.stamps[0].payload.coverage.external_cash_flow_count = 1; });
  await assert.rejects(inspect(unhashed), /integrity check failed/);
  const renamed = mutate(profile, (p) => { p.display_name = "Someone else"; p.stamps[0].payload.display_name = "Someone else"; p.stamps[0].sha256 = hash(p.stamps[0].payload); });
  await assert.rejects(inspect(renamed), /signature is invalid/);
  await assert.rejects(inspect(mutate(profile, (p) => { p.display_name = "Someone else"; })), /invalid or unsupported/);
});

test("swapping in another public key without its matching profile ID is rejected", async () => {
  const { profile } = await signedProfile();
  const stranger = await newSigner();
  await assert.rejects(inspect(mutate(profile, (p) => { p.public_key = stranger.publicKey; })), /does not match its public key/);
});

test("a history re-signed with a new key is caught by the expected key code or a published fingerprint", async () => {
  const owner = await newProfile("Alex");
  const original = await appendPerformanceStamp(owner.profile, zero, 252, owner.signer);
  const forger = await newProfile("Alex");
  const forged = await appendPerformanceStamp(forger.profile, zero, 252, forger.signer);
  assert.equal((await inspect(forged)).checks.signatures_valid, true);
  const ownerCode = formatKeyCode(original.profile_id);
  await assert.rejects(inspect(forged, { expectedKeyCode: ownerCode }), /different key than the expected key code/);
  await assert.rejects(inspect(forged, { publishedFingerprints: publishedFingerprint(original) }), /belongs to a different key/);
  assert.equal((await inspect(original, { expectedKeyCode: ` ${ownerCode.toUpperCase()} ` })).checks.key_code, "matched");
});

test("published fingerprints detect records changed or removed after publication", async () => {
  const { signer, profile: empty } = await newProfile();
  const first = await appendPerformanceStamp(empty, zero, 252, signer);
  const second = await appendPerformanceStamp(first, following, 252, signer);
  const published = [publishedFingerprint(second, 0), publishedFingerprint(second)].join("\n");
  assert.match(publishedFingerprint(second), /^n170-verify key=[a-f0-9]{4}(-[a-f0-9]{4}){4} record=2 end=2025-01-04 sha256=[a-f0-9]{64}$/);
  assert.deepEqual((await inspect(second, { publishedFingerprints: `\n${published}\n\n` })).checks.published_fingerprints, { supplied: 2, matched: 2, latest_record: 2 });
  assert.deepEqual((await inspect(second, { publishedFingerprints: `${published}\n${published}\n${publishedFingerprint(second).toUpperCase()}` })).checks.published_fingerprints, { supplied: 2, matched: 2, latest_record: 2 });
  const later = await appendPerformanceStamp(second, csv("2025-01-04,90,0", "2025-01-05,80,0"), 252, signer);
  assert.deepEqual((await inspect(later, { publishedFingerprints: published })).checks.published_fingerprints, { supplied: 2, matched: 2, latest_record: 2 });
  assert.deepEqual((await inspect(later, { publishedFingerprints: publishedFingerprint(later, 0) })).checks.published_fingerprints, { supplied: 1, matched: 1, latest_record: 1 });
  await assert.rejects(inspect(first, { publishedFingerprints: published }), /fewer records than a published fingerprint/);
  const rewritten = await appendPerformanceStamp(first, csv("2025-01-03,100,0", "2025-01-04,130,0"), 252, signer);
  await assert.rejects(inspect(rewritten, { publishedFingerprints: published }), /does not match the supplied fingerprint/);
  assert.equal((await inspect(rewritten, { publishedFingerprints: publishedFingerprint(second, 0) })).checks.published_fingerprints.matched, 1);
});

test("key code and fingerprint inputs are strict, bounded and never echoed", async () => {
  const { profile } = await signedProfile();
  const line = publishedFingerprint(profile);
  for (const code of ["abcd", "zzzz-zzzz-zzzz-zzzz-zzzz", "SECRET-VALUE", "a".repeat(100)]) {
    await assert.rejects(inspect(profile, { expectedKeyCode: code }), (error) => /five groups/.test(error.message) && !error.message.includes(code));
  }
  for (const text of ["hello private note", line.replace("sha256=", "sha256=x"), line.replace("record=1", "record=0"), line.replace("end=2025-01-03", "end=2025-02-30"), line.replace("record=1", "record=121")]) {
    await assert.rejects(inspect(profile, { publishedFingerprints: text }), (error) => /line 1 /.test(error.message) && !error.message.includes("private"));
  }
  await assert.rejects(inspect(profile, { publishedFingerprints: `${line}\n`.repeat(MAX_COMMITMENT_LINES + 1) }), /at most 120 fingerprint lines/);
  await assert.rejects(inspect(profile, { publishedFingerprints: "x".repeat(MAX_COMMITMENT_CHARACTERS + 1) }), /at most 120 fingerprint lines/);
  await assert.rejects(inspect(profile, { publishedFingerprints: line.replace("end=2025-01-03", "end=2025-01-04") }), /does not match the supplied fingerprint/);
  for (const options of [null, 1, [], { expectedKeyCode: 1 }, { publishedFingerprints: [] }]) {
    await assert.rejects(inspectProfile(JSON.stringify(profile), options), /Inspection options are invalid/);
  }
});

test("files that repeat a field name are rejected, however the name is spelled", async () => {
  const { profile } = await signedProfile();
  const text = JSON.stringify(profile);
  const escapedName = `"display${char(92)}u005fname"`;
  for (const repeated of [
    text.replace('"display_name":"Example"', '"display_name":"Warren B.","display_name":"Example"'),
    text.replace('"return_e8":0', '"return_e8":42000000,"return_e8":0'),
    text.replace('"display_name":"Example"', `${escapedName}:"Warren B.","display_name":"Example"`),
  ]) {
    assert.notEqual(repeated, text);
    await assert.rejects(inspectProfile(repeated), /repeats a field name/);
  }
  assert.equal((await inspectProfile(JSON.stringify(profile, null, 2))).checks.signatures_valid, true);
});

test("numbers must be written as plain integers, so every JSON reader gets the same values", async () => {
  const { profile } = await signedProfile();
  const text = JSON.stringify(profile);
  for (const form of ["0.0", "0e0", "0E+1", "-0"]) {
    const altered = text.replace('"return_e8":0', `"return_e8":${form}`);
    assert.notEqual(altered, text);
    await assert.rejects(inspectProfile(altered), { message: "Profile format is invalid or unsupported." });
  }
  await assert.rejects(inspectProfile(text.replace('"sequence":1', '"sequence":1.0')), { message: "Profile format is invalid or unsupported." });
  assert.equal((await inspectProfile(text.replaceAll('"return_e8":0', '"return_e8": 0'))).checks.signatures_valid, true);
});

test("an annualization frequency that doesn't fit the dates is flagged without failing the check", async () => {
  const { signer, profile: empty } = await newProfile();
  const daily = csv("2025-01-01,100,0", "2025-01-02,101,0", "2025-01-03,99,0", "2025-01-06,100,0");
  const yearly = await appendPerformanceStamp(empty, daily, 1, signer);
  assert.deepEqual((await inspect(yearly)).summary.frequency_warnings, [{ sequence: 1, declared: 1, implied: 365 }]);
  const tradingDays = await appendPerformanceStamp(empty, daily, 252, signer);
  assert.deepEqual((await inspect(tradingDays)).summary.frequency_warnings, []);
  const monthly = await appendPerformanceStamp(empty, csv("2025-01-31,100,0", "2025-02-28,101,0", "2025-03-31,99,0"), 12, signer);
  assert.deepEqual((await inspect(monthly)).summary.frequency_warnings, []);
  const single = await appendPerformanceStamp(empty, csv("2025-01-10,100,0", "2025-01-13,98,0"), 252, signer);
  assert.deepEqual((await inspect(single)).summary.frequency_warnings, [], "one return has no volatility for the frequency to distort");
});

test("keys and signatures must use canonical base64url", async () => {
  const { profile } = await signedProfile();
  await assert.rejects(inspect(mutate(profile, (p) => { p.stamps[0].signature = nonCanonical(p.stamps[0].signature); })), /invalid or unsupported/);
  await assert.rejects(inspect(mutate(profile, (p) => { p.public_key = nonCanonical(p.public_key); })), /invalid or unsupported/);
  await assert.rejects(inspect(mutate(profile, (p) => { p.stamps[0].signature = `${p.stamps[0].signature.slice(0, -2)}==`; })), /invalid or unsupported/);
});

test("files in earlier, unreleased formats are rejected", async () => {
  const { profile } = await signedProfile();
  const earlier = mutate(profile, (p) => {
    p.schema_version = "n170.verify.track-record.v2";
    for (const interval of p.stamps[0].payload.relative_returns) { interval.value = interval.return_e8 / RETURN_UNITS; delete interval.return_e8; }
  });
  await assert.rejects(inspect(earlier), /invalid or unsupported/);
});

test("source escalation, false timestamp claims and extra or missing keys are rejected", async () => {
  const { profile } = await signedProfile();
  const edits = [
    (p) => { p.claim = "verified"; },
    (p) => { p.stamps[0].certificate = "invented"; },
    (p) => { p.stamps[0].payload.source_kind = "broker_authenticated"; },
    (p) => { p.stamps[0].payload.provider_authenticated = true; },
    (p) => { p.stamps[0].payload.independent_timestamp = true; },
    (p) => { p.stamps[0].payload.device_created_at = "2025-01-03"; },
    (p) => { p.stamps[0].payload.period.timezone = "UTC"; },
    (p) => { p.stamps[0].payload.relative_returns[0].nav = 100; },
    (p) => { p.stamps[0].payload.coverage.complete = true; },
    (p) => { p.stamps[0].payload.metrics.sharpe = 3; },
    (p) => { delete p.stamps[0].signature; },
    (p) => { delete p.public_key; },
  ];
  for (const edit of edits) {
    const altered = mutate(profile, edit);
    if (altered.stamps[0]?.payload) altered.stamps[0].sha256 = hash(altered.stamps[0].payload);
    await assert.rejects(inspect(altered), /invalid or unsupported/);
  }
});

test("all integer, date, coverage, frequency and sequence fields validate before hashing", async () => {
  const { profile } = await signedProfile();
  const edits = [
    (p) => { p.stamps[0].payload.relative_returns[0].return_e8 = "0"; },
    (p) => { p.stamps[0].payload.relative_returns[0].return_e8 = -RETURN_UNITS; },
    (p) => { p.stamps[0].payload.relative_returns[0].return_e8 = null; },
    (p) => { p.stamps[0].payload.relative_returns[0].return_e8 = 1.5; },
    (p) => { p.stamps[0].payload.relative_returns[0].return_e8 = Number.MAX_SAFE_INTEGER + 2; },
    (p) => { p.stamps[0].payload.relative_returns[0].end = "2025-02-30"; },
    (p) => { p.stamps[0].payload.relative_returns[1].start = "2025-01-01"; },
    (p) => { p.stamps[0].payload.period.end = "2025-01-04"; },
    (p) => { p.stamps[0].payload.coverage.return_observations = 999; },
    (p) => { p.stamps[0].payload.coverage.external_cash_flow_count = -1; },
    (p) => { p.stamps[0].payload.coverage.external_cash_flow_count = 3; },
    (p) => { p.stamps[0].payload.periods_per_year = 1.5; },
    (p) => { p.stamps[0].payload.periods_per_year = 367; },
    (p) => { p.stamps[0].payload.sequence = 0; },
    (p) => { p.stamps[0].payload.calculation_version = "9.0.0"; },
    (p) => { p.stamps[0].payload.metrics.annualized_volatility_e8 = 123; },
    (p) => { p.stamps[0].payload.metrics.max_drawdown_e8 = 0.5; },
  ];
  for (const edit of edits) await assert.rejects(inspect(mutate(profile, edit)));
  await assert.rejects(inspectProfile(JSON.stringify(profile).replace('"return_e8":0', '"return_e8":1e999')), /invalid or unsupported/);
});

test("malformed and oversized input fails with bounded messages and no raw-value reflection", async () => {
  for (const input of [null, "", "{secret:123456789}", "null", "[]", "1", '"private"', "[".repeat(10000) + "]".repeat(10000)]) {
    await assert.rejects(inspectProfile(input), { message: "Profile format is invalid or unsupported." });
  }
  await assert.rejects(inspectProfile(" ".repeat(MAX_PROFILE_CHARACTERS + 1)), /500,000/);
  const { profile } = await signedProfile();
  await assert.rejects(inspect(mutate(profile, (p) => { p.stamps = Array.from({ length: MAX_PROFILE_STAMPS + 1 }, () => p.stamps[0]); })), /120 records/);
  await assert.rejects(inspect(mutate(profile, (p) => { p.stamps[0].payload.relative_returns = Array.from({ length: 500 }, () => p.stamps[0].payload.relative_returns[0]); })), /invalid or unsupported/);
});

test("public profile retains periods and relative returns but omits raw balances, flows and account data", async () => {
  const { profile } = await signedProfile(csv("2025-03-11,12345.67,0", "2025-03-12,12400,13.37"));
  const exported = JSON.stringify(profile);
  const numbers = numbersIn(exported);
  for (const raw of [12345.67, 12400, 13.37]) assert.equal(numbers.includes(raw), false);
  for (const field of ["holdings", "account_id", "device_created_at", '"nav":', '"external_flow":']) assert.equal(exported.includes(field), false);
  assert.equal(exported.includes("2025-03-11"), true);
  assert.equal(profile.stamps[0].payload.coverage.external_cash_flow_count, 1);
  assert.equal(profile.stamps[0].payload.metrics.annualized_volatility_e8, null);
  await inspect(profile);
});

test("canonical hashing ignores imported key order and formatting but covers all defined data", async () => {
  const { profile } = await signedProfile(zero, 12);
  const reversed = JSON.parse(JSON.stringify(profile), (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) return Object.fromEntries(Object.entries(value).reverse());
    return value;
  });
  assert.deepEqual((await inspect(reversed)).profile, profile);
  await assert.rejects(inspect(mutate(profile, (p) => { p.stamps[0].payload.coverage.external_cash_flow_count = 0; })), /integrity/);
});

test("unsupported extreme inputs and invalid observation chronology cannot create records", async () => {
  const { signer, profile } = await newProfile();
  for (const input of [
    csv("2025-01-01,100,0", "2025-01-02,10,10"),
    csv("2025-01-02,100,0", "2025-01-01,110,0"),
    csv("2025-01-01,1000000000000000,0", "2025-01-02,0.000000000001,0"),
    csv("2025-01-01,100,0", "2025-01-02,0.0000001,0"),
  ]) await assert.rejects(appendPerformanceStamp(profile, input, 252, signer));
});
