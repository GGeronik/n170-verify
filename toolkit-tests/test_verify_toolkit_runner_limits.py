"""Additional malformed receipt and explicit input-inventory controls."""
import json
import unittest
from unittest.mock import patch

from test_verify_toolkit_runner import RunBundleVerificationTests
from verify_toolkit import runner
from verify_toolkit.run_contract import classify_worker


class ReceiptLimitTests(RunBundleVerificationTests):
    # Only these added methods are selected below; inherited suite runs separately.
    def test_reinventoried_request_must_remain_in_input_inventory(self):
        self.fixture()
        self.manifest['inputs'] = [item for item in self.manifest['inputs']
                                   if not item['path'].endswith('/request.json')]
        self.save()
        self.check('NOT_ASSESSABLE')

    def test_deeply_nested_worker_output_is_finalized_invalid(self):
        original = runner._unpack
        def deep_output(stdout, output_dir):
            found = original(stdout, output_dir)
            (output_dir / 'worker-result.json').write_bytes(b'{"nested":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}')
            return found
        with patch.object(runner, '_unpack', side_effect=deep_output):
            self.fixture()
        self.assertEqual(self.manifest['state'], 'FINALIZED')
        self.assertEqual(self.manifest['attempts'][0]['outcome'], 'INVALID_OUTPUT')
        self.check('NOT_ASSESSABLE')

    def test_nested_source_metadata_is_safely_invalid(self):
        self.fixture()
        worker_path = 'attempts/000/output/worker-result.json'
        worker = json.loads(self.buffers[worker_path])
        worker['engine']['source_files'][0]['path'] = [[[]]]
        request_raw = self.buffers['attempts/000/input/request.json']
        request = json.loads(request_raw)
        self.assertEqual(classify_worker(worker, self.buffers['attempts/000/output/lookahead.csv'],
                                        request['strategy'], request, request['input_inventory'], request_raw), 'INVALID_OUTPUT')


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for name in ('test_reinventoried_request_must_remain_in_input_inventory',
                 'test_nested_source_metadata_is_safely_invalid',
                 'test_deeply_nested_worker_output_is_finalized_invalid'):
        suite.addTest(ReceiptLimitTests(name))
    return suite
