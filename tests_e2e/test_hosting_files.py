"""Every setting docker-compose.yml passes to the API container is one the code reads.

A name the code never reads is a setting an operator fills in to no effect, so each
environment name in the api service must appear as a string in the api or core source.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _api_environment_names() -> list[str]:
    text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    lines = text.splitlines()
    names: list[str] = []
    in_api = in_env = False
    for line in lines:
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            in_api = line.strip() == "api:"
            in_env = False
            continue
        if in_api and re.match(r"^    environment:\s*$", line):
            in_env = True
            continue
        if in_env:
            match = re.match(r"^      ([A-Z][A-Z0-9_]*):", line)
            if match:
                names.append(match.group(1))
            elif re.match(r"^    \S", line):
                in_env = False
    return names


def _source_text() -> str:
    parts: list[str] = []
    for folder in ("api/app", "core/n170_verify"):
        for path in sorted((REPO_ROOT / folder).rglob("*.py")):
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


class ComposeSettingsAreReadTests(unittest.TestCase):
    def test_every_api_container_setting_is_read_by_the_code(self) -> None:
        names = _api_environment_names()
        self.assertIn("N170_VERIFY_HOSTED_MODE", names)
        source = _source_text()
        unread = [name for name in names if f'"{name}"' not in source and f"'{name}'" not in source]
        self.assertEqual(unread, [], f"settings passed to the API container that no code reads: {unread}")


if __name__ == "__main__":
    unittest.main()
