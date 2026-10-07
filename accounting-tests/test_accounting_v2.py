"""Frozen implementation-blind challenges; no expected values derived by candidate."""
import copy
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from verify_accounting import core
from verify_accounting import v2, native_numeric as native, oracle_v2

FROZEN = Path(__file__).with_name('accounting_v2_challenges.json')
assert hashlib.sha256(FROZEN.read_bytes()).hexdigest() == '7174e250f0f4955c4943d1fa84087615ada39d31f9c416eb6fcf8b6931358986'
CASES = json.loads(FROZEN.read_bytes())
RUNTIME = dict(native.PINNED_RUNTIME, image_id='sha256:' + 'a' * 64)


def document(case, reported=True):
    events = []
    for source in case['completion_events']:
        q, p = source['quantity'], source['price']
        events.append({'event_id': source['event_id'], 'timestamp': source['timestamp'], 'type': source['side'], 'quantity': q, 'price': p, 'fee': source['exact_modeled_fee'], 'fee_currency': 'USDT', 'fee_model': {'kind': 'modeled_fee', 'quantity': q, 'price': p, 'rate': '0.001', 'sources': ['capture/completions/' + str(source['completion_sequence'])]}})
    return {'schema': v2.SCHEMA, 'evidence_class': 'synthetic_fixture', 'asset': 'BTC', 'cash_currency': 'USDT', 'opening': {'timestamp': '2026-02-01T00:00:00Z', 'cash': case['opening_cash']}, 'events': events, 'closing': {'timestamp': '2026-02-02T00:00:00Z', 'mark_price': case['closing_mark'], 'reported': dict(case['expected_decimal']) if reported else {}}}


def simple_trade():
    return {'trade_id': 'T1', 'entry_quantity': '2', 'entry_price': '100', 'exit_quantity': '2', 'exit_price': '110', 'fee_rate': '0.001', 'native_profit': native.dto(19.58)}


class ExactV2Tests(unittest.TestCase):
    def test_all_frozen_ledger_totals_and_fifo_checkpoints(self):
        for case in CASES['ledger_cases']:
            with self.subTest(case=case['id']):
                report = v2.assess_document(document(case))
                self.assertEqual(report['status'], 'RECONCILED_UNDER_ASSUMPTIONS', report)
                self.assertEqual(report['computed'], case['expected_decimal'])
                self.assertEqual(report['event_checkpoints'], case['expected_event_checkpoints'])
                self.assertEqual(report['source_authenticity'], 'not_established')
                self.assertEqual(report['selected_source_completeness'], 'unknown')

    def test_v1_refuses_v2_and_v2_does_not_widen_v1(self):
        doc = document(CASES['ledger_cases'][2])
        self.assertEqual(core.assess_document(doc)['reason_codes'], ['UNSUPPORTED_SCHEMA'])
        doc['schema'] = core.SCHEMA
        self.assertEqual(v2.assess_document(doc)['reason_codes'], ['UNSUPPORTED_SCHEMA'])
        with self.assertRaises(core.AccountingError): core.number('0.0010000000200000001')

    def test_full_fee_precision_and_single_nineteenth_place_residual(self):
        doc = document(CASES['ledger_cases'][2])
        self.assertEqual(doc['events'][0]['fee'], '0.0010000000200000001')
        changed = copy.deepcopy(doc); changed['events'][0]['fee'] = '0.001'
        self.assertEqual(v2.assess_document(changed)['reason_codes'], ['MODELED_FEE_MISMATCH'])
        doc['closing']['reported']['cash'] = '9.9980000199400001997'
        report = v2.assess_document(doc)
        self.assertEqual(report['checks']['cash']['difference_reported_minus_computed'], '0.0000000000000000001')
        self.assertEqual(report['status'], 'DISCREPANCIES_FOUND')

    def test_numeric_boundaries_and_no_rounding_admission(self):
        for text, kind in [('1.000000001','operand'), ('0.00000000000000000001','fee'), ('1000000000000000000000.0000000000000000001','fee'), ('1000000000000000000000000000000.0000000000000000001','result'), ('1e-19','fee'), ('NaN','result'), (True,'operand')]:
            with self.subTest(text=text), self.assertRaises(core.AccountingError): v2.number(text, kind=kind)
        self.assertEqual(v2.number('1000000000000000000000', kind='fee'), Decimal('1e21'))
        self.assertEqual(v2.number('0.0000000000000000001',kind='fee'), Decimal('1e-19'))
        self.assertEqual(v2.modeled_fee('1000000000000','1000000000000'), '1000000000000000000000')

    def test_exact_context_independent_of_ambient_and_fraction_sum(self):
        with localcontext() as context:
            context.prec = 2; context.Emax = 3; context.Emin = -3
            report = v2.assess_document(document(CASES['ledger_cases'][2]))
            self.assertEqual(report['computed'], CASES['ledger_cases'][2]['expected_decimal'])
            with v2.exact_context():
                fee = Decimal('0.0010000000200000001')
                total = sum((fee for _ in range(10000)), Decimal(0))
                self.assertEqual(Fraction(total), Fraction('0.0010000000200000001') * 10000)

    def test_missing_claims_and_supplied_discrepancy_preserved(self):
        doc = document(CASES['ledger_cases'][0], reported=False)
        result = v2.assess_document(doc)
        self.assertEqual(result['status'], 'NOT_ASSESSABLE')
        self.assertTrue(all(c['status'] == 'NOT_SUPPLIED' for c in result['checks'].values()))
        doc['closing']['reported']['fees'] = '0'
        self.assertEqual(v2.assess_document(doc)['status'], 'DISCREPANCIES_FOUND')

    def test_models_and_sources_cannot_be_silently_substituted(self):
        for field,value in [('rate','0.002'),('kind','observed_fee'),('quantity','3'),('sources',[])]:
            doc = document(CASES['ledger_cases'][0]);doc['events'][0]['fee_model'][field]=value
            self.assertEqual(v2.assess_document(doc)['status'],'NOT_ASSESSABLE')

    def test_exact_source_hash_and_duplicate_json_keys(self):
        raw=core.canonical(document(CASES['ledger_cases'][0]))
        self.assertEqual(v2.assess_bytes(raw)['source_inventory'][0]['sha256'],hashlib.sha256(raw).hexdigest())
        duplicate=raw.rstrip()[:-1]+b',"schema":"n170.accounting.events.v2"}'
        self.assertEqual(v2.assess_bytes(duplicate)['reason_codes'],['DUPLICATE_JSON_FIELD'])


class NativePolicyTests(unittest.TestCase):
    def test_frozen_binary_rounding_ties_adjacent_and_exact_errors(self):
        count=0
        for case in CASES['numeric_cases']:
            if 'expected_output_binary64' in case:
                count+=1
                value=float.fromhex(case['input_binary64']['hex'])
                self.assertEqual(native.round8(value).hex(),case['expected_output_binary64']['hex'],case['id'])
                expected=case['expected_quantization_error']
                error=Fraction(case['expected_decimal_quantized'])-Fraction(value)
                self.assertEqual(native.rational(error),expected)
        self.assertEqual(count,6)

    def test_conversion_before_subtraction_and_serial_order(self):
        for case in CASES['numeric_cases']:
            if 'close_leg_decimal' in case:
                value=native.subtract64(native.rn64(Fraction(case['close_leg_decimal'])),native.rn64(Fraction(case['open_leg_decimal'])))
                self.assertEqual(value.hex(),case['expected_native_difference']['hex'])
            if 'ordered_profit_integers' in case:
                total=0.0
                for value,expected in zip(case['ordered_profit_integers'],case['expected_trace']):
                    total=native.add64(total,native.rn64(Fraction(value)))
                    self.assertEqual(total.hex(),expected['hex'])
                self.assertEqual(total.hex(),case['expected_native_sum']['hex'])
            if case['id']=='round_each_trade_before_accumulation':
                values=[native.round8(float.fromhex(x['hex'])) for x in case['unrounded_trade_binary64']]
                self.assertEqual(native.serial_total(values).hex(),case['expected_sum']['hex'])

    def test_large_opening_does_not_erase_profit_and_exact_differences(self):
        for case in CASES['numeric_cases']:
            if case['id'].startswith('large_opening'):
                profit=float.fromhex(case['trade_profit_binary64']['hex'])
                cash=native.add64(native.rn64(Fraction(case['opening_cash'])),profit)
                self.assertEqual(cash.hex(),case['expected_native_cash']['hex'])
                comparison=native.compare_native_metric(native.dto(cash),cash,Fraction(case['exact_model_cash']))
                self.assertEqual(comparison['exact_binary_minus_model'],case['expected_native_cash_minus_exact_model'])
                self.assertFalse(comparison['decimal_model_equal'])
                self.assertNotEqual(profit,0)

    def test_native_encoding_normalization_and_signed_zero(self):
        self.assertEqual(native.decode_native({'encoding':'binary64','repr':'1e-08','hex':'0x1.5798ee2308c3ap-27'}),1e-8)
        for value in [{'encoding':'binary64','repr':'np.float64(1e-08)','hex':'0x1.5798ee2308c3ap-27'}, {'encoding':'binary64','repr':'0.1','hex':'0x1.999999999999ap-3'}, {'encoding':'binary64','repr':'NaN','hex':'nan'}]:
            with self.assertRaises(core.AccountingError):native.decode_native(value)
        self.assertEqual(native.decode_native(native.dto(-0.0)).hex(),'-0x0.0p+0')
        self.assertEqual(native.round8(-0.0).hex(),'-0x0.0p+0')
        self.assertEqual(native.add64(0.0,native.round8(-0.0)).hex(),'0x0.0p+0')
        self.assertEqual(native.round8(5e-9),1e-8)
        self.assertEqual(native.round8(1.5e-8),1e-8)

    def test_runtime_mismatch_missing_native_and_one_ulp_tamper(self):
        trade=simple_trade()
        valid=native.replay_native('1000',[trade],native.dto(19.58),native.dto(1019.58),runtime=RUNTIME)
        self.assertEqual(valid['status'],'MATCHES_ENGINE_NUMERIC_POLICY',valid)
        self.assertEqual(native.replay_native('1000',[trade],runtime=RUNTIME)['status'],'NOT_ASSESSABLE')
        wrong=dict(RUNTIME,ccxt='unknown')
        self.assertEqual(native.replay_native('1000',[trade],native.dto(19.58),native.dto(1019.58),runtime=wrong)['reason_codes'],['UNSUPPORTED_NATIVE_RUNTIME'])
        trade['native_profit']=native.dto(math.nextafter(19.58,math.inf))
        self.assertEqual(native.replay_native('1000',[trade],native.dto(19.58),native.dto(1019.58),runtime=RUNTIME)['status'],'MISMATCH')

    def test_retained_smooth_exact_binary_difference_not_printed_difference(self):
        case=next(c for c in CASES['retained_controls'] if c['id']=='retained_smooth')
        observed=case['observed_native_cash']; observed={'encoding':'binary64','repr':observed['repr'],'hex':observed['hex']}
        value=native.decode_native(observed)
        checked=native.compare_native_metric(observed,value,Fraction(case['expected_decimal']['cash']))
        self.assertEqual(checked['exact_binary_minus_model'],case['expected_exact_binary_minus_model'])
        self.assertEqual(checked['exact_binary_minus_model_decimal'],case['expected_exact_binary_minus_model_decimal'])
        self.assertEqual(checked['printed_decimal_minus_model'],case['expected_display_decimal_minus_model'])


class OracleV2Tests(unittest.TestCase):
    def test_ledger_preserves_fees_and_never_invents_assertions_or_gain(self):
        doc=document(CASES['ledger_cases'][2]);doc['closing']['reported']['cash']='0'
        ledger=oracle_v2.generate_ledger(doc).decode()
        self.assertIn('Expenses:Fees 0.0010000000200000001 USDT',ledger)
        self.assertIn('\n  Income:Trading\n',ledger)
        self.assertNotIn(' balance ',ledger)
        for word in ('plugin ','include ',' pad '):self.assertNotIn(word,ledger)
        doc['events']=[];doc['opening']['cash']='-0.00';doc['closing']['reported']={}
        self.assertNotIn('--0',oracle_v2.generate_ledger(doc).decode())

    def test_unavailable_and_malformed_external_process_never_match(self):
        raw=core.canonical(document(CASES['ledger_cases'][0],reported=False))
        cases=[subprocess.CompletedProcess([],0,b'{"status":"EXECUTED","status":"EXECUTED"}',b''),subprocess.CompletedProcess([],0,b'not json',b''),subprocess.CompletedProcess([],1,b'{}',b'failed')]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            for i,response in enumerate(cases):
                with patch.object(oracle_v2.subprocess,'run',return_value=response):
                    report=oracle_v2.run_beancount(raw,python_executable='/trusted/selected',output_directory=root/str(i))
                    self.assertEqual(report['oracle']['status'],'UNAVAILABLE')
                    self.assertEqual(report['status'],'NOT_ASSESSABLE')
            report=oracle_v2.run_beancount(raw,python_executable='/no/such/interpreter',output_directory=root/'missing')
            self.assertEqual(report['oracle']['status'],'UNAVAILABLE')

    def test_unavailable_unsupported_never_launches(self):
        with patch.object(oracle_v2.subprocess,'run',side_effect=AssertionError('must not execute')):
            self.assertEqual(oracle_v2.run_beancount(b'{}',python_executable='/none',output_directory='/none')['oracle']['status'],'NOT_RUN')

    @unittest.skipUnless(os.environ.get('N170_BEANCOUNT_PYTHON'),'Actual pinned oracle not selected; never simulated')
    def test_actual_pinned_oracle_frozen_independent_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            for case in CASES['ledger_cases']:
                report=oracle_v2.run_beancount(core.canonical(document(case,reported=False)),python_executable=os.environ['N170_BEANCOUNT_PYTHON'],output_directory=Path(tmp).resolve()/case['id'])
                self.assertEqual(report['oracle']['status'],'MATCHED',report['oracle'])
                self.assertEqual(report['computed'],case['expected_decimal'])
                self.assertEqual(report['status'],'NOT_ASSESSABLE')
                self.assertTrue(all(c['status']=='NOT_SUPPLIED' for c in report['checks'].values()))
                for field, malformed in [('python', None), ('packages', []), ('limits', 'not a list'), ('validation_error_types', ['UnreportedError']), ('installed_code_inventory_sha256', '0' * 64)]:
                    observation = copy.deepcopy(report['oracle']['observation'])
                    observation[field] = malformed
                    with self.subTest(case=case['id'], field=field), self.assertRaises(core.AccountingError):
                        oracle_v2._validate_observation(observation)
