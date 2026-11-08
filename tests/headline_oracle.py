"""Private until HEADLINE_CANDIDATE_1 is recorded. SPEC-04 §§6.1–6.2, 6.8.

Standard library only. No product implementation imported. The exhaustive
file projects the decision over all enums with a neutral display context;
full-context vectors use derive_headline and strict completeness validation.
"""
import argparse
import copy
import datetime
import itertools
import json
import pathlib
import re

ENUMS = {
    'parse': ['OK', 'INVALID_INPUT'],
    'payload_hash': ['MATCH', 'MISMATCH'],
    'signatures': ['VALID', 'INVALID'],
    'chain': ['VALID', 'BROKEN'],
    'continuity': ['NONE', 'VALID', 'CONFLICT'],
    'comparison': ['NONE', 'IDENTICAL', 'EXTENDED', 'TRUNCATION', 'REPLACEMENT', 'CONFLICT'],
    'reconciliation': ['NONE', 'VERIFIED_UNDER_OWNER_ASSERTIONS', 'MISMATCH', 'NOT_ASSESSABLE', 'INVALID_INPUT'],
    'witness': ['NONE', 'WITNESSED', 'WITNESS_MISMATCH', 'WITNESS_NOT_ASSESSABLE', 'WITNESS_RECEIPT_INVALID'],
}
BASE_FACTS = {k: v[0] for k, v in ENUMS.items()}
BASE_CONTEXT = {
    'record_reasons': [], 'selected_event': None, 'witness_host': None,
    'witness_key_code': None, 'other_effective_slots': 0,
    'selected_event_superseded': False, 'continuity_anchor': None,
    'reconciliation_reasons': [], 'witness_reasons': [], 'timestamp_proof': 'NONE',
    'expected_key': 'not_supplied', 'checkpoint_checked': False, 'gaps': [],
}
SELF = 'SELF-REPORTED RECORD · arithmetic and signatures verified'
SOURCE = 'SOURCE-RECONCILED RECORD · under owner assertions'
WITNESS = 'WITNESSED RECORD'
SOURCE_SUB = 'owner-supplied source bytes matched the signed event; the source is not authenticated'
RECORD_FAILURES = [('parse', 'INVALID_INPUT', 'INVALID_INPUT'),
                   ('payload_hash', 'MISMATCH', 'PAYLOAD_HASH_MISMATCH'),
                   ('signatures', 'INVALID', 'SIGNATURE_INVALID'),
                   ('chain', 'BROKEN', 'CHAIN_BROKEN')]
CODES = ['INVALID_INPUT', 'PAYLOAD_HASH_MISMATCH', 'SIGNATURE_INVALID', 'CHAIN_BROKEN',
         'FACTS_INCOMPLETE', 'PRIVATE_SOURCE_MISMATCH', 'WITNESS_MISMATCH', 'WITNESS_RECEIPT_INVALID']
CONFLICTS = ['TRUNCATION', 'REPLACEMENT', 'CONFLICTING_HISTORY', 'CONTINUITY_CONFLICT']
CLOSED = {'REJECTED: ' + c for c in CODES} | {'CONFLICT: ' + c for c in CONFLICTS} | {SELF, SOURCE, WITNESS}
QUALIFICATIONS = {
    'WITNESS_NOT_ASSESSABLE': 'The supplied witness receipt could not establish the source.',
    'PRIVATE_SOURCE_NOT_ASSESSABLE': 'The supplied private-source check could not assess the selected event.',
    'PRIVATE_SOURCE_INPUT_INVALID': 'The supplied private-source input was invalid and was not used.',
    'CONTINUITY_ANCHOR_PARTIAL': 'Key linkage is valid; retained history anchors only part of the chain.',
    'CONTINUITY_ANCHOR_NOT_SUPPLIED': 'Key linkage is valid; no retained history anchor was supplied.',
    'OTHER_PERIODS_NOT_WITNESSED': '{n} other effective periods in this record are not witnessed.',
    'OTHER_PERIODS_NOT_RECONCILED': '{n} other effective periods in this record are not source-reconciled.',
}


def valid_date(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
        return False
    try:
        datetime.date.fromisoformat(value)
        return True
    except ValueError:
        return False


def valid_context(c):
    if not isinstance(c, dict) or c.keys() != BASE_CONTEXT.keys():
        return False
    for k in ['record_reasons', 'reconciliation_reasons', 'witness_reasons']:
        if not isinstance(c[k], list) or any(not isinstance(x, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,79}', x) for x in c[k]):
            return False
    for k in ['witness_host', 'witness_key_code']:
        if c[k] is not None and not isinstance(c[k], str):
            return False
    if type(c['other_effective_slots']) is not int or not 0 <= c['other_effective_slots'] <= 9007199254740991:
        return False
    if type(c['selected_event_superseded']) is not bool or type(c['checkpoint_checked']) is not bool:
        return False
    if c['continuity_anchor'] not in ('matched', 'partial', 'not_supplied', None):
        return False
    if c['timestamp_proof'] not in ('NONE', 'PENDING', 'CONFIRMED', 'INVALID') or c['expected_key'] not in ('matched', 'not_supplied'):
        return False
    e = c['selected_event']
    if e is not None and (not isinstance(e, dict) or set(e) != {'sequence', 'start', 'end'} or type(e['sequence']) is not int or not 1 <= e['sequence'] <= 9007199254740991 or not valid_date(e['start']) or not valid_date(e['end']) or e['start'] >= e['end']):
        return False
    if not isinstance(c['gaps'], list):
        return False
    for g in c['gaps']:
        if not isinstance(g, dict) or set(g) != {'start', 'end'} or not valid_date(g['start']) or not valid_date(g['end']) or g['start'] >= g['end']:
            return False
    return True


def decide(facts, context_ok=True):
    """Ordered §§6.1–6.2 decision; rule 1 precedes all completeness errors."""
    f = facts if isinstance(facts, dict) else {}
    for key, value, code in RECORD_FAILURES:
        if f.get(key) == value:
            return {'headline': 'REJECTED: ' + code, 'code': code, 'exit': 1}
    if set(f) != set(ENUMS) or any(not isinstance(f[k], str) or f[k] not in ENUMS[k] for k in ENUMS) or not context_ok:
        return {'headline': 'REJECTED: FACTS_INCOMPLETE', 'code': 'FACTS_INCOMPLETE', 'exit': 1}
    comparison_code = {'TRUNCATION': 'TRUNCATION', 'REPLACEMENT': 'REPLACEMENT', 'CONFLICT': 'CONFLICTING_HISTORY'}.get(f['comparison'])
    if comparison_code or f['continuity'] == 'CONFLICT':
        code = comparison_code or 'CONTINUITY_CONFLICT'
        return {'headline': 'CONFLICT: ' + code, 'code': code, 'exit': 2}
    if f['reconciliation'] == 'MISMATCH':
        code = 'PRIVATE_SOURCE_MISMATCH'
    elif f['witness'] in ('WITNESS_MISMATCH', 'WITNESS_RECEIPT_INVALID'):
        code = f['witness']
    else:
        code = None
    if code:
        return {'headline': 'REJECTED: ' + code, 'code': code, 'exit': 1}
    headline = WITNESS if f['witness'] == 'WITNESSED' else SOURCE if f['reconciliation'] == 'VERIFIED_UNDER_OWNER_ASSERTIONS' else SELF
    return {'headline': headline, 'code': None, 'exit': 0}


def derive_headline(facts, context):
    result = decide(facts, valid_context(context))
    f = facts if isinstance(facts, dict) else {}
    # Invalid display input is never reflected. Valid context can still explain
    # a rule-1 failure, which takes priority over incomplete later facts.
    c = context if valid_context(context) else copy.deepcopy(BASE_CONTEXT)
    rule1 = any(f.get(k) == v for k, v, _ in RECORD_FAILURES)
    headline = result['headline']
    sublabel = None
    quals = []

    def qualify(code, reasons=None):
        sentence = QUALIFICATIONS[code].format(n=c['other_effective_slots'])
        quals.append({'code': code, 'reasons': list(reasons or []), 'text': code + ': ' + sentence})

    if headline == WITNESS:
        e = c['selected_event'] or {'sequence': None, 'start': None, 'end': None}
        sublabel = f"Record {e['sequence']} ({e['start']} – {e['end']}) fetched from {c['witness_host']}; witness key {c['witness_key_code']}."
        if c['other_effective_slots']:
            qualify('OTHER_PERIODS_NOT_WITNESSED')
    elif headline == SOURCE:
        sublabel = SOURCE_SUB
        if c['other_effective_slots']:
            qualify('OTHER_PERIODS_NOT_RECONCILED')
    if result['exit'] == 0:
        if f.get('witness') == 'WITNESS_NOT_ASSESSABLE':
            qualify('WITNESS_NOT_ASSESSABLE', c['witness_reasons'])
        if f.get('reconciliation') == 'NOT_ASSESSABLE':
            qualify('PRIVATE_SOURCE_NOT_ASSESSABLE', c['reconciliation_reasons'])
        if f.get('reconciliation') == 'INVALID_INPUT':
            qualify('PRIVATE_SOURCE_INPUT_INVALID', c['reconciliation_reasons'])
        if c['continuity_anchor'] == 'partial':
            qualify('CONTINUITY_ANCHOR_PARTIAL')
        if c['continuity_anchor'] == 'not_supplied':
            qualify('CONTINUITY_ANCHOR_NOT_SUPPLIED')
    calc = 'Not reproduced' if 'ARITHMETIC_NOT_REPRODUCED' in c['record_reasons'] else 'Not established' if rule1 else 'Reproduced from disclosed returns'
    if rule1:
        history = 'Not established'
    else:
        history = 'Valid across the supplied key chain' if f.get('continuity') in ('VALID', 'CONFLICT') else 'Valid for this key'
        suffix = 'conflicts with your retained copy' if result['exit'] == 2 else {'IDENTICAL': 'same as your retained copy', 'EXTENDED': 'extends your retained copy', 'NONE': 'no retained copy checked'}.get(f.get('comparison'))
        if suffix:
            history += ' · ' + suffix
    source = f"Fetched by the witness from {c['witness_host']}; broker responses are not signed" if headline == WITNESS else SOURCE_SUB[0].upper() + SOURCE_SUB[1:] if headline == SOURCE else 'Self-reported · not authenticated'
    time = {'PENDING': 'Receipt timestamp proof binds the receipt; confirmation not verified', 'INVALID': 'Supplied timestamp proof does not bind the receipt'}.get(c['timestamp_proof'], 'No independent evidence')
    coverage = 'Supplied observations for the declared account only; lifetime inception unverified'
    if c['gaps']:
        coverage += f" · {len(c['gaps'])} gap(s) between disclosed periods"
    ladder = [
        {'row': 'Calculations', 'text': calc}, {'row': 'Signatures and history', 'text': history},
        {'row': 'Source', 'text': source}, {'row': 'Key', 'text': 'Expected key matches; identity unchecked' if c['expected_key'] == 'matched' else 'Not established'},
        {'row': 'Time', 'text': time}, {'row': 'Coverage', 'text': coverage},
    ]
    assert headline in CLOSED and not headline.lower().startswith('verified')
    return {'version': 'n170.verify.headline.v1', **result, 'sublabel': sublabel, 'qualifications': quals, 'ladder': ladder}


def context_vectors():
    rows = []
    def add(id, fp=None, cp=None, facts=None, context=None):
        f = copy.deepcopy(BASE_FACTS) if facts is None else copy.deepcopy(facts)
        c = copy.deepcopy(BASE_CONTEXT) if context is None else copy.deepcopy(context)
        f.update(fp or {})
        c.update(cp or {})
        rows.append({'id': id, 'facts': f, 'context': c, 'expected': derive_headline(f, c)})
    add('CTX-SELF')
    wc = {'selected_event': {'sequence': 2, 'start': '2026-01-02', 'end': '2026-01-03'}, 'witness_host': 'ndcdyn.interactivebrokers.com', 'witness_key_code': '1234-5678-90ab-cdef-1234'}
    add('CTX-WITNESSED', {'witness': 'WITNESSED'}, wc)
    add('CTX-SOURCE', {'reconciliation': 'VERIFIED_UNDER_OWNER_ASSERTIONS'})
    add('CTX-MULTI-W', {'witness': 'WITNESSED'}, {**wc, 'other_effective_slots': 2})
    add('CTX-MULTI-R', {'reconciliation': 'VERIFIED_UNDER_OWNER_ASSERTIONS'}, {'selected_event': wc['selected_event'], 'other_effective_slots': 2})
    add('CTX-W-NA', {'witness': 'WITNESS_NOT_ASSESSABLE'}, {'witness_reasons': ['BROKER_HOST_NOT_ALLOWED']})
    add('CTX-R-NA', {'reconciliation': 'NOT_ASSESSABLE'}, {'reconciliation_reasons': ['SOURCE_BYTES_UNAVAILABLE']})
    add('CTX-R-INVALID', {'reconciliation': 'INVALID_INPUT'}, {'reconciliation_reasons': ['INVALID_PRIVATE_SCHEMA']})
    for anchor in ['matched', 'partial', 'not_supplied']:
        add('CTX-ANCHOR-' + anchor.upper(), {'continuity': 'VALID'}, {'continuity_anchor': anchor})
    for comparison in ['IDENTICAL', 'EXTENDED', 'TRUNCATION', 'REPLACEMENT', 'CONFLICT']:
        add('CTX-COPY-' + comparison, {'comparison': comparison})
        add('CTX-CHAIN-COPY-' + comparison, {'continuity': 'VALID', 'comparison': comparison}, {'continuity_anchor': 'matched'})
    add('CTX-CONTINUITY-CONFLICT', {'continuity': 'CONFLICT'})
    add('CTX-EXPECTED-KEY', cp={'expected_key': 'matched', 'checkpoint_checked': True})
    for ts in ['PENDING', 'INVALID', 'CONFIRMED']:
        add('CTX-TIME-' + ts, cp={'timestamp_proof': ts})
    add('CTX-GAPS', cp={'gaps': [{'start': '2026-01-02', 'end': '2026-01-16'}]})
    add('CTX-ARITHMETIC', {'parse': 'INVALID_INPUT'}, {'record_reasons': ['ARITHMETIC_NOT_REPRODUCED']})
    add('CTX-UNCLASSIFIED', {'parse': 'INVALID_INPUT'}, {'record_reasons': ['UNCLASSIFIED_VERIFIER_FAILURE']})
    add('CTX-PREVIOUS-INVALID', {'parse': 'INVALID_INPUT'}, {'record_reasons': ['PREVIOUS_COPY_INVALID']})
    for k, v, _ in RECORD_FAILURES:
        add('CTX-FAIL-' + k.upper(), {k: v})
    f = copy.deepcopy(BASE_FACTS); del f['witness']; add('CTX-MISSING', facts=f)
    add('CTX-EXTRA', {'extra': 'NONE'})
    add('CTX-UNKNOWN', {'comparison': 'PASS'})
    add('CTX-NONSTRING', {'witness': False})
    for bad in [None, [], {}, {'unexpected': True}]:
        # Keep malformed contexts intact (add uses update on object contexts).
        rows.append({'id': 'CTX-MALFORMED-' + str(len(rows)), 'facts': BASE_FACTS.copy(), 'context': bad, 'expected': derive_headline(BASE_FACTS, bad)})
    for key, bad in [('other_effective_slots', True), ('selected_event_superseded', 1), ('timestamp_proof', 'PASS'), ('gaps', [{'start': '2026-02-30', 'end': '2026-03-01'}]), ('record_reasons', ['free text']), ('selected_event', {'sequence': 0, 'start': '2026-01-01', 'end': '2026-01-02'})]:
        add('CTX-MALFORMED-' + key, cp={key: bad})
    add('CTX-EARLY-FAIL-MISSING', facts={'parse': 'INVALID_INPUT'})
    rows.append({'id': 'CTX-EARLY-FAIL-BAD-CONTEXT', 'facts': {'chain': 'BROKEN'}, 'context': {}, 'expected': derive_headline({'chain': 'BROKEN'}, {})})
    add('CTX-PRECEDENCE-PRIVATE', {'witness': 'WITNESSED', 'reconciliation': 'MISMATCH'}, wc)
    add('CTX-PRECEDENCE-FORGED', {'witness': 'WITNESS_RECEIPT_INVALID', 'reconciliation': 'VERIFIED_UNDER_OWNER_ASSERTIONS'})
    add('CTX-PRECEDENCE-NA', {'witness': 'WITNESS_NOT_ASSESSABLE', 'reconciliation': 'VERIFIED_UNDER_OWNER_ASSERTIONS'}, {'witness_reasons': ['BROKER_HOST_NOT_ALLOWED']})
    add('CTX-PRECEDENCE-COPY', {'witness': 'WITNESSED', 'comparison': 'CONFLICT'}, wc)
    add('CTX-PRECEDENCE-CONTINUITY', {'comparison': 'TRUNCATION', 'continuity': 'CONFLICT'})
    add('CTX-PRECEDENCE-REJECTION', {'reconciliation': 'MISMATCH', 'witness': 'WITNESS_RECEIPT_INVALID'})
    add('CTX-ALL-QUALIFICATIONS', {'witness': 'WITNESS_NOT_ASSESSABLE', 'reconciliation': 'NOT_ASSESSABLE', 'continuity': 'VALID'}, {'continuity_anchor': 'partial', 'witness_reasons': ['SELECTED_EVENT_SUPERSEDED'], 'reconciliation_reasons': ['SELECTED_EVENT_SUPERSEDED'], 'selected_event_superseded': True})
    return rows


def sanity():
    assert len(CLOSED) == 15
    assert decide({'parse': 'INVALID_INPUT'})['code'] == 'INVALID_INPUT'
    assert decide(BASE_FACTS, False)['code'] == 'FACTS_INCOMPLETE'
    assert decide({**BASE_FACTS, 'comparison': 'TRUNCATION', 'continuity': 'CONFLICT'})['code'] == 'TRUNCATION'
    assert decide({**BASE_FACTS, 'witness': 'WITNESSED', 'reconciliation': 'MISMATCH'})['code'] == 'PRIVATE_SOURCE_MISMATCH'
    assert decide({**BASE_FACTS, 'reconciliation': 'VERIFIED_UNDER_OWNER_ASSERTIONS', 'witness': 'WITNESS_RECEIPT_INVALID'})['code'] == 'WITNESS_RECEIPT_INVALID'
    for row in context_vectors():
        assert len(row['expected']['ladder']) == 6
        assert row['expected']['headline'] in CLOSED
        if row['expected']['exit']:
            assert not row['expected']['qualifications']
    assert {q['code'] for r in context_vectors() for q in r['expected']['qualifications']} == set(QUALIFICATIONS)


def emit(root):
    if (pathlib.Path(__file__).resolve().parents[3] / 'HEADLINE_FIXTURES_SEAL.json').exists():
        raise RuntimeError('Sealed v1 is immutable. Create a new retained version before emitting again.')
    sanity()
    out = pathlib.Path(root)
    out.mkdir(parents=True, exist_ok=True)
    vectors = []
    for i, values in enumerate(itertools.product(*ENUMS.values()), 1):
        facts = dict(zip(ENUMS, values))
        vectors.append({'id': f'E{i:04d}', 'facts': facts, 'context': copy.deepcopy(BASE_CONTEXT), 'expected': decide(facts)})
    assert len(vectors) == 7200
    assert {r['expected']['headline'] for r in vectors} == CLOSED - {'REJECTED: FACTS_INCOMPLETE'}
    for name, data in [('facts-exhaustive.json', vectors), ('facts-context.json', context_vectors())]:
        (out / name).write_text(json.dumps(data, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    print(json.dumps({'sanity': 'PASS', 'exhaustive_cases': len(vectors), 'context_cases': len(context_vectors())}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['sanity', 'emit'])
    parser.add_argument('--output', default=str(pathlib.Path(__file__).parent / 'fixtures/headline'))
    args = parser.parse_args()
    if args.command == 'emit':
        emit(args.output)
    else:
        sanity()
        print('PASS')
