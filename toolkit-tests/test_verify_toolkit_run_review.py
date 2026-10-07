"""Original synthetic package/parser controls. These never claim an engine ran.

Actual pinned-engine CLI journey evidence is maintained separately by the release
validation task. The scripted fixture below exists to challenge the verifier.
"""
import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_verify_toolkit_runner as fixtures
from verify_toolkit.__main__ import main
from verify_toolkit import run_contract as contract
from verify_toolkit import run_review as review


def raw_package(package):
    return contract.json_bytes(package)


def descriptor(path, raw):
    return dict(contract.inventory_entry(path, raw), base64=base64.b64encode(raw).decode())


def unpack(package):
    return json.loads(base64.b64decode(package['manifest']['base64'])), {
        item['path']: base64.b64decode(item['base64']) for item in package['artifacts']}


def repack(manifest, buffers):
    manifest = copy.deepcopy(manifest)
    inventory = [contract.inventory_entry(path, data) for path, data in sorted(buffers.items())]
    manifest['artifacts'] = inventory
    manifest['inputs'] = [item for item in inventory if '/input/' in item['path']]
    for attempt in manifest['attempts']:
        attempt['artifacts'] = [item for item in inventory if item['path'].startswith('attempts/' + attempt['id'] + '/')]
    manifest['summary'] = contract.summarize(manifest['attempts'])
    return {'schema': review.SCHEMA, 'manifest': descriptor('manifest.json', contract.json_bytes(manifest)),
            'artifacts': [descriptor(path, data) for path, data in sorted(buffers.items())]}


def transport(buffers, prefix='attempts/000/'):
    outputs = {path[len(prefix + 'output/'):]: base64.b64encode(data).decode()
               for path, data in buffers.items() if path.startswith(prefix + 'output/')}
    original = buffers[prefix + 'stdout.log']
    lines = [line for line in original.splitlines(keepends=True) if not line.startswith(review.BUNDLE_PREFIX)]
    buffers[prefix + 'stdout.log'] = b''.join(lines) + review.BUNDLE_PREFIX + base64.b64encode(contract.json_bytes(outputs)) + b'\n'


class RunReviewTests(unittest.TestCase):
    def fixture(self, outcomes=('NO_FINDINGS_REPORTED',)):
        helper = fixtures.RunBundleVerificationTests()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        helper.fixture(outcomes)
        return helper, review.export_run_review(helper.directory)

    def verify(self, package, expected='VALID', **kwargs):
        result = review.verify_run_review(raw_package(package), **kwargs)
        self.assertEqual(result['integrity'], expected, result)
        json.dumps(result, allow_nan=False)
        return result

    def invalid(self, package, reason=None):
        result = self.verify(package, 'INVALID')
        self.assertEqual(result['status'], 'NOT_ASSESSABLE')
        self.assertEqual(result['reproducibility']['status'], 'NOT_REPRODUCIBLE')
        self.assertIsNone(result['summary'])
        self.assertEqual(result['attempts'], [])
        if reason:
            self.assertIn(reason, result['reason_codes'])
        return result

    def test_roundtrip_pins_every_byte_and_never_authenticates_author(self):
        helper, package = self.fixture()
        report = self.verify(package, manifest_sha256=package['manifest']['sha256'])
        self.assertEqual(report['manifest_pin'], 'matched')
        self.assertEqual(report['status'], 'NO_FINDINGS_REPORTED')
        self.assertEqual(report['reproducibility']['status'], 'READY_TO_RERUN')
        self.assertIn('attacker-authored', report['trust']['integrity'])
        self.assertIn('unsigned', report['trust']['authenticity'])
        self.assertIn('not witnessed', report['trust']['execution'])
        for item in package['artifacts']:
            self.assertEqual(base64.b64decode(item['base64']), (helper.directory / item['path']).read_bytes())
        self.assertEqual(base64.b64decode(package['manifest']['base64']), (helper.directory / 'manifest.json').read_bytes())

    def test_every_recorded_outcome_remains_visible(self):
        for outcome in sorted(contract.OUTCOMES):
            with self.subTest(outcome=outcome):
                _, package = self.fixture((outcome,))
                report = self.verify(package)
                self.assertEqual(report['attempts'][0]['outcome'], outcome)
                if outcome not in contract.ASSESSABLE:
                    self.assertEqual(report['status'], 'NOT_ASSESSABLE')
                    self.assertIn('UNASSESSABLE_ATTEMPTS', report['reason_codes'])

    def test_mixed_findings_and_failure_never_collapse_to_clean(self):
        _, package = self.fixture(('FINDINGS_REPORTED', 'FAILED'))
        report = self.verify(package)
        self.assertEqual(report['status'], 'NOT_ASSESSABLE')
        self.assertEqual(report['summary']['findings_count'], 1)
        self.assertEqual(report['summary']['outcome_counts']['FAILED'], 1)

    def test_skipped_inputs_are_explicit_and_not_comparable(self):
        _, package = self.fixture(('SKIPPED',))
        report = self.verify(package)
        self.assertEqual(report['reproducibility']['status'], 'NOT_REPRODUCIBLE')
        self.assertEqual(len(report['reproducibility']['missing']), 5)
        comparison = review.compare_run_reviews(raw_package(package), raw_package(package))
        self.assertEqual(comparison['status'], 'NOT_COMPARABLE')

    def test_wrong_pin_cannot_become_valid_after_rewrite(self):
        _, package = self.fixture()
        self.invalid_with_pin = review.verify_run_review(raw_package(package), 'f' * 64)
        self.assertEqual(self.invalid_with_pin['integrity'], 'INVALID')
        self.assertEqual(self.invalid_with_pin['reason_codes'], ['MANIFEST_PIN_MISMATCH'])
        for pin in ('', True, [], 'A' * 64):
            self.assertEqual(review.verify_run_review(raw_package(package), pin)['integrity'], 'INVALID')

    def test_descriptor_digest_and_size_recomputed(self):
        _, original = self.fixture()
        for key, value in [('sha256', '0' * 64), ('size', 0), ('size', True), ('size', -1), ('size', 2**53), ('sha256', 'A' * 64)]:
            package = copy.deepcopy(original)
            package['artifacts'][0][key] = value
            self.invalid(package)
        package = copy.deepcopy(original)
        package['manifest']['base64'] = base64.b64encode(b'{}').decode()
        self.invalid(package, 'ARTIFACT_MISMATCH')

    def test_canonical_base64_and_descriptor_keys(self):
        _, original = self.fixture()
        for mutation in (lambda d: d.update(base64=d['base64'] + '\n'),
                         lambda d: d.update(base64=d['base64'] + '='),
                         lambda d: d.update(extra=True),
                         lambda d: d.pop('size'),
                         lambda d: d.update(base64=[])):
            package = copy.deepcopy(original)
            mutation(package['artifacts'][0])
            self.invalid(package)
        self.assertRaises(review.ReviewError, review._descriptor,
                          {'path': 'x', 'size': 1, 'sha256': contract.digest(b'f'), 'base64': 'Zh=='})

    def test_exact_envelope_schema(self):
        _, original = self.fixture()
        for mutation in (lambda p: p.update(extra=True), lambda p: p.update(schema='n170.run-review.v2'),
                         lambda p: p.update(artifacts={}), lambda p: p.pop('manifest')):
            package = copy.deepcopy(original)
            mutation(package)
            self.invalid(package)

    def test_paths_traversal_casefold_sort_and_prefix_ambiguity(self):
        _, original = self.fixture()
        for path in ('../escape', '/absolute', 'a//b', 'a/./b', 'a/../b', 'C:\\file', 'é', 'manifest.json', 'Manifest.json', 'x' * 241):
            package = copy.deepcopy(original)
            package['artifacts'][0]['path'] = path
            self.invalid(package)
        for paths in (['a', 'A'], ['a', 'a/b'], ['a', 'a'], ['b', 'a']):
            package = copy.deepcopy(original)
            package['artifacts'] = [descriptor(path, b'') for path in paths]
            self.invalid(package)

    def test_missing_extra_or_unordered_artifact_inventory(self):
        _, original = self.fixture()
        package = copy.deepcopy(original)
        package['artifacts'].pop()
        missing = self.invalid(package, 'MANIFEST_INVENTORY_MISMATCH')
        self.assertIn(original['artifacts'][-1]['path'], missing['reproducibility']['missing'])
        package = copy.deepcopy(original)
        package['artifacts'].reverse()
        self.invalid(package, 'UNSORTED_ARTIFACT_PATHS')
        manifest, buffers = unpack(original)
        buffers['attempts/001/input/hidden.py'] = b'# omitted attempt'
        self.invalid(repack(manifest, buffers), 'UNEXPECTED_ARTIFACT')

    def test_manifest_duplicate_keys_and_unsafe_json(self):
        _, original = self.fixture()
        for raw in (b'{"schema":1,"schema":2}', b'\xef\xbb\xbf{}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":1e400}', b'{"x":9007199254740992}', b'{"x":1e100}', b'{"x":-0}',
                    b'{"x":-0.0}', b'{"x":"\\ud800"}', b'{"constructor":0}', b'{"x":\xff}',
                    b'[' * 25 + b'0' + b']' * 25):
            package = copy.deepcopy(original)
            package['manifest'] = descriptor('manifest.json', raw)
            self.invalid(package)
        for raw in (b'{} trailing', b'{"schema":"x","schema":"y"}', b'\xef\xbb\xbf{}'):
            self.assertEqual(review.verify_run_review(raw)['integrity'], 'INVALID')
        self.assertEqual(review.verify_run_review({})['integrity'], 'INVALID')

    def test_json_node_depth_string_and_size_limits(self):
        for raw in (b'[' + b'0,' * review.MAX_NODES + b'0]', b'"' + b'x' * (review.MAX_STRING + 1) + b'"'):
            self.assertRaises(review.ReviewError, review.strict_json, raw)
        with patch.object(review, 'MAX_ENVELOPE', 5):
            self.assertEqual(review.verify_run_review(b'{"long":true}')['integrity'], 'INVALID')
        _, package = self.fixture()
        with patch.object(review, 'MAX_TOTAL', 1):
            self.invalid(package, 'TOTAL_DECODED_SIZE_LIMIT')
        with patch.object(review, 'MAX_ARTIFACTS', 1):
            self.invalid(package, 'ARTIFACT_COUNT_LIMIT')

    def test_summary_and_types_not_boolean_number_equivalent(self):
        _, package = self.fixture()
        manifest, buffers = unpack(package)
        manifest['summary']['selected_count'] = True
        changed = copy.deepcopy(package)
        changed['manifest'] = descriptor('manifest.json', contract.json_bytes(manifest))
        self.invalid(changed, 'SUMMARY_MISMATCH')
        for key in ('minimum_trade_amount', 'timeout_seconds'):
            m = copy.deepcopy(manifest)
            m['request'][key] = True
            self.invalid(repack(m, buffers), 'INVALID_REQUEST')

    def test_worker_output_relationships_even_for_failed_or_insufficient(self):
        for outcome in ('FAILED', 'INSUFFICIENT'):
            _, package = self.fixture((outcome,))
            manifest, buffers = unpack(package)
            buffers['attempts/000/output/effective-config.json'] = b'{}\n'
            transport(buffers)
            self.invalid(repack(manifest, buffers), 'OUTPUT_DIGEST_MISMATCH')
            manifest, buffers = unpack(package)
            worker = json.loads(buffers['attempts/000/output/worker-result.json'])
            worker['request_sha256'] = '0' * 64
            buffers['attempts/000/output/worker-result.json'] = contract.json_bytes(worker)
            transport(buffers)
            self.invalid(repack(manifest, buffers), 'WORKER_INPUT_MISMATCH')

    def test_stdout_transport_matches_all_retained_outputs(self):
        _, package = self.fixture()
        manifest, buffers = unpack(package)
        buffers['attempts/000/stdout.log'] = b'no transport here\n'
        self.invalid(repack(manifest, buffers), 'OUTPUT_TRANSPORT_MISMATCH')
        _, package = self.fixture(('INSUFFICIENT',))
        manifest, buffers = unpack(package)
        buffers['attempts/000/stdout.log'] *= 2
        self.invalid(repack(manifest, buffers), 'OUTPUT_TRANSPORT_MISMATCH')

    def test_consistently_malformed_worker_remains_invalid_output(self):
        _, package = self.fixture()
        manifest, buffers = unpack(package)
        manifest['attempts'][0]['outcome'] = 'INVALID_OUTPUT'
        manifest['attempts'][0]['reason_codes'] = ['INVALID_OUTPUT']
        buffers['attempts/000/output/worker-result.json'] = b'not json\n'
        transport(buffers)
        report = self.verify(repack(manifest, buffers))
        self.assertEqual(report['attempts'][0]['outcome'], 'INVALID_OUTPUT')
        self.assertEqual(report['status'], 'NOT_ASSESSABLE')

    def test_import_verification_never_executes_supplied_source(self):
        helper, package = self.fixture()
        with patch('subprocess.Popen', side_effect=AssertionError('must never execute')), \
             patch.object(Path, 'write_bytes', side_effect=AssertionError('must never extract')):
            self.verify(package)
            self.assertEqual(review.compare_run_reviews(raw_package(package), raw_package(package))['status'], 'SAME')

    def test_export_rejects_symlinks_uninventoried_files_and_existing_cli_output(self):
        helper, package = self.fixture()
        extra = helper.directory / 'extra.txt'
        extra.write_text('extra')
        self.assertRaises(review.ReviewError, review.export_run_review, helper.directory)
        extra.unlink()
        extra.symlink_to(helper.directory / 'manifest.json')
        self.assertRaises((OSError, ValueError), review.export_run_review, helper.directory)
        extra.unlink()
        output = helper.root / 'protected.json'
        output.write_text('preserve me')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['export-run', str(helper.directory), '--output', str(output)]), 2)
        self.assertEqual(output.read_text(), 'preserve me')

    def test_comparison_ignores_only_declared_run_metadata(self):
        _, package = self.fixture()
        manifest, buffers = unpack(package)
        manifest['run_id'] = 'b' * 32
        manifest['execution_root'] = '/tmp/another-reviewed-run'
        manifest['started_at'] = manifest['finished_at'] = '2026-12-10T00:00:00Z'
        attempt = manifest['attempts'][0]
        attempt['container_name'] = 'n170-' + manifest['run_id'] + '-000'
        attempt['started_at'] = attempt['finished_at'] = '2026-12-10T00:00:00Z'
        from verify_toolkit.runner import _argv
        attempt['argv'] = _argv('/other/docker', manifest['engine']['image_id'], Path(manifest['execution_root']) / 'attempts/000/input', attempt['container_name'])
        other = repack(manifest, buffers)
        self.verify(other)
        result = review.compare_run_reviews(raw_package(package), raw_package(other))
        self.assertEqual(result['status'], 'SAME', result)
        self.assertEqual(result['evidence_differences'], ['manifest.json'])

    def test_comparison_known_log_times_only(self):
        _, package = self.fixture()
        manifest, buffers = unpack(package)
        templates = [b'%s - freqtrade.optimize.backtesting - INFO - Engine message\n',
                     b'%s INFO freqtrade Engine message\n']
        for template in templates:
            buffers['attempts/000/stderr.log'] = template % b'2026-09-18 01:02:03,456'
            left = repack(manifest, buffers)
            buffers['attempts/000/stderr.log'] = template % b'2027-01-19 09:08:07,654'
            right = repack(manifest, buffers)
            comparison = review.compare_run_reviews(raw_package(left), raw_package(right))
            self.assertEqual(comparison['status'], 'SAME')
            self.assertIn('attempts/000/stderr.log', comparison['evidence_differences'])
        for template in (b'%s strategy signal\n', b'2026-09-18 01:02:03,456 - custom - INFO - %s\n',
                         b'2026-09-18 01:02:03,456 - freqtrade - INFO - message date %s\n'):
            buffers['attempts/000/stderr.log'] = template % b'2026-09-18 01:02:03,456'
            left = repack(manifest, buffers)
            buffers['attempts/000/stderr.log'] = template % b'2027-01-19 09:08:07,654'
            right = repack(manifest, buffers)
            self.assertEqual(review.compare_run_reviews(raw_package(left), raw_package(right))['status'], 'DIFFERENT')

    def test_comparison_preserves_engine_unknown_worker_and_failure(self):
        _, package = self.fixture(('FAILED',))
        result = review.compare_run_reviews(raw_package(package), raw_package(package))
        self.assertEqual(result['status'], 'SAME')
        self.assertEqual(result['outcome_status'], {'left': 'NOT_ASSESSABLE', 'right': 'NOT_ASSESSABLE'})
        self.assertIn('not established', result['reproduction'])
        manifest, buffers = unpack(package)
        worker = json.loads(buffers['attempts/000/output/worker-result.json'])
        worker['new_unknown_semantics'] = {'method': 'changed'}
        buffers['attempts/000/output/worker-result.json'] = contract.json_bytes(worker)
        transport(buffers)
        changed = repack(manifest, buffers)
        self.verify(changed)
        self.assertEqual(review.compare_run_reviews(raw_package(package), raw_package(changed))['status'], 'DIFFERENT')
        manifest, buffers = unpack(package)
        manifest['engine']['image_id'] = 'sha256:' + 'b' * 64
        manifest['attempts'][0]['argv'][-3] = manifest['engine']['image_id']
        changed = repack(manifest, buffers)
        self.verify(changed)
        self.assertIn('receipt.engine', review.compare_run_reviews(raw_package(package), raw_package(changed))['differences'])

    def test_integral_number_spelling_matches_browser_without_equating_booleans(self):
        self.assertEqual(review.strict_json(b'{"size":1.2e2,"count":120.0}'), {'size': 120, 'count': 120})
        self.assertIs(type(review.strict_json(b'120.0')), int)
        self.assertFalse(review._typed_equal(True, 1))

    def test_cli_oversize_export_is_explicit_and_writes_nothing(self):
        helper, _ = self.fixture()
        output = helper.root / 'never-written.json'
        with patch.object(review, 'MAX_MANIFEST', 1), contextlib.redirect_stdout(io.StringIO()) as capture:
            self.assertEqual(main(['export-run', str(helper.directory), '--output', str(output)]), 2)
        self.assertEqual(json.loads(capture.getvalue())['reason_codes'], ['EXPORT_FILE_SIZE_LIMIT'])
        self.assertFalse(output.exists())

    def test_cli_export_verify_compare_exit_codes_and_exact_source(self):
        helper, package = self.fixture(('FINDINGS_REPORTED',))
        output = helper.root / 'review.json'
        with contextlib.redirect_stdout(io.StringIO()) as capture:
            self.assertEqual(main(['export-run', str(helper.directory), '--output', str(output)]), 0)
        self.assertTrue(json.loads(capture.getvalue())['exported'])
        self.assertEqual(json.loads(output.read_bytes()), package)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['verify-review', str(output), '--manifest-sha256', package['manifest']['sha256']]), 1)
            self.assertEqual(main(['compare-runs', str(output), str(output)]), 0)
            self.assertEqual(main(['verify-review', str(output), '--manifest-sha256', '0' * 64]), 2)


if __name__ == '__main__':
    unittest.main()
