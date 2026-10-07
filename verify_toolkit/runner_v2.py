"""Original v2 orchestration derived from accepted original v1; v1 is unchanged.

Opt-in, local-only Docker orchestration; engine remains separately installed.

No uploaded-code API, shell commands, live trading, credentials or network path.
The host and Docker daemon are trusted; receipts are unsigned local evidence.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
import uuid

from .freqtrade import UPSTREAM_REVISION
from .run_contract_v2 import (SCHEMA, TRUST, classify_worker, decode_bundle, digest, execution_environment, inventory_entry,
                           json_bytes, read_file, strict_json, summarize)

DEFAULT_IMAGE = "freqtradeorg/freqtrade@sha256:289f403917e170ecced1f3c537a2580435a581f2b21311c488c4efcb1694f666"
LOG_LIMIT = 8 * 1024 * 1024
BUNDLE_PREFIX = b"N170_RESULT_BUNDLE_V2:"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _new_file(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as target:
        target.write(raw)


def _save_manifest(root, manifest):
    temporary = root / (".manifest-" + uuid.uuid4().hex)
    _new_file(temporary, json_bytes(manifest))
    os.replace(temporary, root / "manifest.json")


def _docker_env():
    # Preserve only transport context, never FREQTRADE__ settings or proxy secrets.
    allowed = {"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _image_identity(docker, image):
    if not re.fullmatch(r"(?:[a-zA-Z0-9./_-]+@)?sha256:[a-f0-9]{64}", image):
        raise ValueError("Immutable installed image required")
    result = subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=15, env=_docker_env(), check=True)
    if len(result.stdout) > 1024 * 1024:
        raise ValueError("Oversized image metadata")
    obj = strict_json(result.stdout)[0]
    if obj.get("Config", {}).get("Volumes"):
        raise ValueError("Images with implicit writable volumes are unsupported")
    if obj.get("Os") != "linux" or not re.fullmatch(r"sha256:[a-f0-9]{64}", obj["Id"]):
        raise ValueError("Linux image required")
    version = subprocess.run([docker, "version", "--format", "{{json .}}"], capture_output=True, timeout=15, env=_docker_env(), check=True)
    return {"image_id": obj["Id"], "reference": image, "os": obj["Os"], "architecture": obj["Architecture"], "docker_version": strict_json(version.stdout)}


def _cleanup_container(docker, name):
    try:
        result = subprocess.run([docker, "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=15, env=_docker_env(), check=False)
    except (OSError, subprocess.SubprocessError):
        # The attempted command remains in the receipt; failure never becomes clean.
        return False
    return result.returncode == 0


def _execute(argv, *, stdout_path, stderr_path, timeout_seconds, docker, container_name, cancel_event=None):
    """Drain bounded pipes; kill container itself on every interruption/limit."""
    stdout_data = bytearray()
    termination, process, code = None, None, None
    cleanup_confirmed = None
    with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
        os.chmod(stdout_path, 0o600)
        os.chmod(stderr_path, 0o600)
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=_docker_env(), start_new_session=True)
            for stream, target in ((process.stdout, stdout_file), (process.stderr, stderr_file)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, target)
            deadline = time.monotonic() + timeout_seconds
            total = 0
            while selector.get_map():
                if cancel_event is not None and cancel_event.is_set():
                    termination = "CANCELLED"
                    break
                if time.monotonic() >= deadline:
                    termination = "TIMED_OUT"
                    break
                for key, _ in selector.select(0.1):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    retained = block[:max(0, LOG_LIMIT - total)]
                    key.data.write(retained)
                    if key.data is stdout_file:
                        stdout_data.extend(retained)
                    total += len(block)
                    if total > LOG_LIMIT:
                        termination = "OUTPUT_LIMIT"
                        break
                if termination:
                    break
            while not termination and process.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    termination = "CANCELLED"
                elif time.monotonic() >= deadline:
                    termination = "TIMED_OUT"
                else:
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            if termination:
                cleanup_confirmed = _cleanup_container(docker, container_name)
                process.kill()
            code = process.wait(timeout=15)
        except (KeyboardInterrupt, InterruptedError):
            termination = "CANCELLED"
            cleanup_confirmed = _cleanup_container(docker, container_name)
            if process:
                process.kill()
                code = process.wait(timeout=15)
        except (OSError, subprocess.SubprocessError):
            termination = "PROCESS_ERROR"
            cleanup_confirmed = _cleanup_container(docker, container_name)
            if process:
                process.kill()
                code = process.wait(timeout=15)
        finally:
            selector.close()
            for stream in (getattr(process, "stdout", None), getattr(process, "stderr", None)):
                if stream and not stream.closed:
                    stream.close()
    return {"exit_code": code, "termination": termination, "stdout": bytes(stdout_data), "cleanup_confirmed": cleanup_confirmed}


def _argv(docker, image_id, input_dir, name):
    return [docker, "run", "--rm", "--pull", "never", "--name", name,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", "1000:1000",
            "--pids-limit", "64", "--memory", "1g", "--memory-swap", "1g", "--cpus", "1",
            "--ulimit", "nofile=256:256", "--ulimit", "fsize=16777216:16777216",
            "--log-driver", "none", "--ipc", "none",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=134217728,uid=1000,gid=1000,mode=0700",
            "--tmpfs", "/output:rw,noexec,nosuid,size=16777216,uid=1000,gid=1000,mode=0700",
            "--mount", f"type=bind,src={input_dir},dst=/input,readonly",
            "--workdir", "/output", "--env", "PYTHONPATH=/freqtrade", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--env", "PYTHONHASHSEED=0", "--env", "OMP_NUM_THREADS=1",
            "--env", "OPENBLAS_NUM_THREADS=1", "--env", "NUMEXPR_MAX_THREADS=1", "--env", "HOME=/home/ftuser",
            "--entrypoint", "python", image_id, "-B", "/input/engine_worker.py"]


def _unpack(stdout, output_dir):
    files = decode_bundle(stdout)
    if files is None:
        return False
    for name, raw in files.items():
        _new_file(output_dir / name, raw)
    return True


def _collect(root):
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Unexpected symlink")
        if path.is_file() and path.name != "manifest.json":
            entries.append(inventory_entry(path.relative_to(root).as_posix(), read_file(path)))
    return entries


def run_freqtrade(destination, *, image=DEFAULT_IMAGE, strategies, data, acknowledge_local_code=False,
                  timeout_seconds=120, minimum_trade_amount=5, targeted_trade_amount=10,
                  timerange="20260101-20260103", docker="docker", cancel_event=None):
    """Run explicit trusted local strategies, one process each. No directory scanning.

    Data contract is one BTC/USDT 5-minute spot JSON OHLCV file. Synthetic market
    metadata are fixed in the separately executed worker; this is engineering
    evidence, not an assertion of accurate real-market execution.
    """
    if acknowledge_local_code is not True:
        raise ValueError("Explicit trusted local code opt-in required")
    if type(strategies) is not dict or not 1 <= len(strategies) <= 8:
        raise ValueError("Select one to eight strategies")
    if any(type(name) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) for name in strategies):
        raise ValueError("Invalid strategy name")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("Unsupported time budget")
    if type(minimum_trade_amount) is not int or type(targeted_trade_amount) is not int or not 1 <= minimum_trade_amount < targeted_trade_amount <= 100:
        raise ValueError("Unsupported signal budget")
    if type(timerange) is not str or not re.fullmatch(r"[0-9]{8}-[0-9]{8}", timerange):
        raise ValueError("Unsupported timerange")
    # Capture bytes BEFORE launch; no later reopening of user-provided paths.
    sources = {name: read_file(path, 256 * 1024) for name, path in strategies.items()}
    market_data = read_file(data, 8 * 1024 * 1024)
    candles = strict_json(market_data)
    if type(candles) is not list or not 100 <= len(candles) <= 10000:
        raise ValueError("Unsupported candle count")
    import math
    previous = -1
    for candle in candles:
        if type(candle) is not list or len(candle) != 6 or any(type(v) not in (int, float) or not math.isfinite(v) for v in candle):
            raise ValueError("Invalid candle")
        timestamp, opened, high, low, closed, volume = candle
        if type(timestamp) is not int or timestamp <= previous or timestamp % 300000 or min(opened, high, low, closed) <= 0 or volume < 0 or high < max(opened, closed, low) or low > min(opened, closed):
            raise ValueError("Invalid candle values")
        previous = timestamp
    root = Path(os.path.abspath(destination))
    if "," in str(root) or "\n" in str(root):
        raise ValueError("Unsupported destination")
    # No reuse, no resume: a partial receipt remains independently inspectable.
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Reject symlink parents before mounting a host path.
    probe = root / "path-probe"
    _new_file(probe, b"")
    read_file(probe)
    probe.unlink()
    run_id = uuid.uuid4().hex
    manifest = {"schema": SCHEMA, "run_id": run_id, "execution_root": str(root), "state": "RUNNING", "started_at": _now(), "finished_at": None,
                "engine": {"version": "2026.8", "revision": UPSTREAM_REVISION, "image_id": "sha256:" + "0" * 64, "reference": image},
                "request": {"strategies": list(strategies), "timeout_seconds": timeout_seconds,
                            "minimum_trade_amount": minimum_trade_amount, "targeted_trade_amount": targeted_trade_amount,
                            "timerange": timerange, "timeframe": "5m", "fee": 0.001, "market_metadata": "original_synthetic_spot_BTC_USDT"},
                "inputs": [], "artifacts": [], "attempts": [], "summary": None, "trust": dict(TRUST)}
    for index, name in enumerate(strategies):
        manifest["attempts"].append({"id": f"{index:03d}", "strategy": name, "state": "PENDING", "outcome": None,
                                     "reason_codes": [], "argv": [], "environment": {}, "started_at": None,
                                     "finished_at": None, "exit_code": None, "artifacts": [], "capture": None})
    _save_manifest(root, manifest)
    stop = False
    try:
        identity = _image_identity(docker, image)
        manifest["engine"].update(identity)
        from .synthetic import build_config
        worker_raw = read_file(Path(__file__).parent / "engine_worker_v2.py", 256 * 1024)
        helper_raw = read_file(Path(__file__).parent / "engine_worker.py", 256 * 1024)
        collector_raw = read_file(Path(__file__).parent / "accounting_collector.py", 256 * 1024)
        for attempt in manifest["attempts"]:
            if stop or (cancel_event is not None and cancel_event.is_set()):
                attempt.update(state="FINALIZED", outcome="SKIPPED", reason_codes=["RUN_CANCELLED"], finished_at=_now())
                continue
            prefix = f"attempts/{attempt['id']}"
            folder = root / prefix
            input_dir = folder / "input"
            output_dir = folder / "output"
            output_dir.mkdir(parents=True)
            request = {key: value for key, value in manifest["request"].items() if key != "strategies"}
            request["strategy"] = attempt["strategy"]
            request.update(schema="n170.freqtrade-request.v2", run_id=run_id, attempt_id=attempt["id"])
            captured = {"engine_worker.py": worker_raw, "engine_worker_v1.py": helper_raw, "accounting_collector.py": collector_raw, "config.json": json_bytes(build_config(request)),
                        "data/BTC_USDT-5m.json": market_data,
                        f"strategies/{attempt['strategy']}.py": sources[attempt["strategy"]]}
            expected = [inventory_entry(path, raw) for path, raw in sorted(captured.items())]
            request["input_inventory"] = expected
            captured["request.json"] = json_bytes(request)
            for relative, raw in sorted(captured.items()):
                _new_file(input_dir / relative, raw, 0o444)
                manifest["inputs"].append(inventory_entry(prefix + "/input/" + relative, raw))
            for path in input_dir.rglob("*"):
                if path.is_dir():
                    os.chmod(path, 0o555)
            os.chmod(input_dir, 0o555)
            name = "n170-" + run_id + "-" + attempt["id"]
            argv = _argv(docker, identity["image_id"], input_dir, name)
            attempt.update(state="RUNNING", started_at=_now(), argv=argv,
                           environment=execution_environment(timeout_seconds))
            _save_manifest(root, manifest)
            execution = _execute(argv, stdout_path=folder / "stdout.log", stderr_path=folder / "stderr.log",
                                 timeout_seconds=timeout_seconds, docker=docker, container_name=name, cancel_event=cancel_event)
            attempt["exit_code"] = execution["exit_code"]
            attempt["container_name"] = name
            attempt["cleanup_confirmed"] = execution.get("cleanup_confirmed")
            if execution["termination"]:
                outcome = {"TIMED_OUT": "TIMED_OUT", "CANCELLED": "CANCELLED"}.get(execution["termination"], "FAILED")
                stop = outcome == "CANCELLED" or execution.get("cleanup_confirmed") is False
                attempt["reason_codes"] = [execution["termination"]]
                if execution.get("cleanup_confirmed") is False:
                    attempt["reason_codes"].append("CONTAINER_CLEANUP_UNCONFIRMED")
            else:
                try:
                    found = _unpack(execution["stdout"], output_dir)
                    if not found:
                        outcome = "MISSING_OUTPUT"
                    else:
                        worker = strict_json(read_file(output_dir / "worker-result.json"))
                        csv_path = output_dir / "lookahead.csv"
                        csv_raw = read_file(csv_path) if csv_path.exists() else None
                        outcome = classify_worker(worker, csv_raw, attempt["strategy"], request, expected, captured["request.json"])
                        attempt["environment"]["observed"] = worker.get("environment", {})
                        attempt["capture"] = worker.get("capture")
                        if outcome in {"NO_FINDINGS_REPORTED", "FINDINGS_REPORTED"}:
                            if (digest(read_file(output_dir / "effective-config.json")) != worker.get("effective_config_sha256")
                                    or digest(read_file(output_dir / "market-metadata.json")) != worker.get("offline_adapter", {}).get("market_metadata_sha256")):
                                outcome = "INVALID_OUTPUT"
                except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
                    outcome = "INVALID_OUTPUT"
                if execution["exit_code"] != 0:
                    outcome = "FAILED"
            if any(read_file(input_dir / path) != raw for path, raw in captured.items()):
                outcome = "INPUT_CHANGED"
            attempt.update(state="FINALIZED", outcome=outcome, finished_at=_now())
            if not attempt["reason_codes"]:
                attempt["reason_codes"] = [outcome]
            _save_manifest(root, manifest)
    except (KeyboardInterrupt, InterruptedError):
        for attempt in manifest["attempts"]:
            if attempt["state"] == "RUNNING":
                attempt["container_name"] = "n170-" + run_id + "-" + attempt["id"]
                attempt["cleanup_confirmed"] = _cleanup_container(docker, attempt["container_name"])
                reasons = ["RUN_CANCELLED"] + ([] if attempt["cleanup_confirmed"] else ["CONTAINER_CLEANUP_UNCONFIRMED"])
                attempt.update(state="FINALIZED", outcome="CANCELLED", reason_codes=reasons, finished_at=_now())
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, subprocess.SubprocessError):
        for attempt in manifest["attempts"]:
            if attempt["state"] == "RUNNING":
                attempt["container_name"] = "n170-" + run_id + "-" + attempt["id"]
                attempt["cleanup_confirmed"] = _cleanup_container(docker, attempt["container_name"])
                reasons = ["RUNNER_ERROR"] + ([] if attempt["cleanup_confirmed"] else ["CONTAINER_CLEANUP_UNCONFIRMED"])
                attempt.update(state="FINALIZED", outcome="FAILED", reason_codes=reasons, finished_at=_now())
    finally:
        for attempt in manifest["attempts"]:
            if attempt["state"] != "FINALIZED":
                attempt.update(state="FINALIZED", outcome="SKIPPED", reason_codes=["PREPARATION_OR_PREVIOUS_ATTEMPT_FAILED"], finished_at=_now())
        manifest["artifacts"] = _collect(root)
        for attempt in manifest["attempts"]:
            attempt["artifacts"] = [entry for entry in manifest["artifacts"] if entry["path"].startswith(f"attempts/{attempt['id']}/")]
        manifest.update(state="FINALIZED", finished_at=_now(), summary=summarize(manifest["attempts"]))
        _save_manifest(root, manifest)
    return manifest
