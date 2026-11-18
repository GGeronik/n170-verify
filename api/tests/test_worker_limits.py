"""Limits on verification workers shared by every route that signs a record.

Rules covered here:
- at most ``MAX_CONCURRENT_VERIFICATION_WORKERS`` workers run at once; a request that
  arrives while all are busy is refused at once with 503 ``verification_busy`` and a
  retry delay, without waiting for a slot;
- a worker that runs out of time is answered with 503 ``verification_timed_out``, never 500;
- a statement over ``MAX_STATEMENT_INPUT_BYTES`` or ``MAX_STATEMENT_INPUT_ROWS`` is refused
  before any worker starts, with 413 ``statement_too_large``.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from typing import Any
import unittest

from app import worker_isolation
from app.main import VerifyApiTestClient, create_app

try:
    from tests.test_verify_input_allowlist import DUMMY_WALLET, SCHWAB_CSV
    from tests.test_verify_request_surface import _config, picklable_fixed_result_pipeline
except ImportError:  # pragma: no cover - run from inside api/tests
    from test_verify_input_allowlist import DUMMY_WALLET, SCHWAB_CSV  # type: ignore[no-redef]
    from test_verify_request_surface import (  # type: ignore[no-redef]
        _config,
        picklable_fixed_result_pipeline,
    )


def picklable_slow_pipeline(job: dict[str, Any]) -> dict[str, Any]:
    """Worker stand-in that holds its slot for a few seconds, then returns a fixed record."""
    time.sleep(3.0)
    return picklable_fixed_result_pipeline(job)


_SLOW_SPEC = f"{__name__}:picklable_slow_pipeline"
_FAST_SPEC = (
    f"{picklable_fixed_result_pipeline.__module__}:{picklable_fixed_result_pipeline.__name__}"
)
_LIVE = {"broker_id": "hyperliquid", "wallet_address": DUMMY_WALLET}


class WorkerLimitTests(unittest.TestCase):
    def _app(self, spec: str, **overrides: Any) -> Any:
        cfg = dataclasses.replace(_config(hosted=True), **overrides)
        app = create_app(cfg, pipeline_spec=spec, prefer_fastapi=False)
        self.addCleanup(app.verify_app.close)
        return app

    def test_a_request_beyond_the_worker_limit_is_refused_at_once(self) -> None:
        limit = int(getattr(worker_isolation, "MAX_CONCURRENT_VERIFICATION_WORKERS", 2))
        app = self._app(_SLOW_SPEC)
        client = VerifyApiTestClient(app)
        results: list[int] = []

        def occupy() -> None:
            results.append(client.post("/api/v1/verify", json=_LIVE).status_code)

        threads = [threading.Thread(target=occupy) for _ in range(limit)]
        for t in threads:
            t.start()
        time.sleep(1.0)
        started = time.monotonic()
        extra = client.post("/api/v1/verify", json=_LIVE)
        elapsed = time.monotonic() - started
        for t in threads:
            t.join()

        self.assertEqual(extra.status_code, 503, extra.text)
        body = extra.json()
        self.assertEqual(body["error"], "verification_busy")
        self.assertGreater(int(body["retry_after_seconds"]), 0)
        self.assertLess(elapsed, 1.0)
        self.assertEqual(results, [200] * limit)

        # Slots are returned once the workers finish.
        self.assertEqual(VerifyApiTestClient(self._app(_FAST_SPEC)).post("/api/v1/verify", json=_LIVE).status_code, 200)

    def test_a_worker_that_runs_out_of_time_is_answered_503(self) -> None:
        app = self._app(_SLOW_SPEC, worker_timeout_seconds=1.0)
        resp = VerifyApiTestClient(app).post("/api/v1/verify", json=_LIVE)
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertEqual(resp.json()["error"], "verification_timed_out")
        self.assertGreater(int(resp.json()["retry_after_seconds"]), 0)

    def test_a_statement_over_the_stated_limits_is_refused_with_413(self) -> None:
        max_rows = int(getattr(worker_isolation, "MAX_STATEMENT_INPUT_ROWS", 10_000))
        max_bytes = int(getattr(worker_isolation, "MAX_STATEMENT_INPUT_BYTES", 2 * 1024 * 1024))
        client = VerifyApiTestClient(self._app(_FAST_SPEC))
        header, first_row = SCHWAB_CSV.splitlines()[:2]
        too_many_rows = "\n".join([header] + [first_row] * (max_rows + 1)) + "\n"
        too_many_bytes = header + "\n" + first_row + "," + ("x" * (max_bytes + 1)) + "\n"
        for label, text in (("rows", too_many_rows), ("bytes", too_many_bytes)):
            with self.subTest(limit=label):
                resp = client.post("/api/v1/verify", json={"broker_id": "schwab_csv", "raw_statement_text": text})
                self.assertEqual(resp.status_code, 413, resp.text[:300])
                self.assertEqual(resp.json()["error"], "statement_too_large")
                self.assertIn(label, resp.json()["detail"])

        within = "\n".join([header] + [first_row] * 50) + "\n"
        ok = client.post("/api/v1/verify", json={"broker_id": "schwab_csv", "raw_statement_text": within})
        self.assertEqual(ok.status_code, 200, ok.text[:300])


if __name__ == "__main__":
    unittest.main()
