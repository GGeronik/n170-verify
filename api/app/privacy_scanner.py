"""Outbound privacy scanner for N170 Verify v3 HTTP responses.

Actively scans outgoing public response payloads to block synthetic leaks:
- Raw brokerage account numbers and broker account IDs
- Raw trade execution payloads and unredacted statement excerpts
- Ephemeral credentials, private keys, and bearer tokens
"""

from __future__ import annotations

import json
import re
from typing import Any


class PrivacyLeakError(ValueError):
    """Raised when the outbound privacy scanner detects sensitive data in a response."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        super().__init__(
            f"Outbound privacy scanner detected {len(violations)} leak(s): "
            + "; ".join(violations)
        )


_ACCOUNT_NUMBER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ibkr_account_id", re.compile(r"\bU\d{6,}\b")),
    ("ibkr_paper_account_id", re.compile(r"\bDU\d{6,}\b")),
    ("alpaca_paper_account_id", re.compile(r"\bPA[A-Z0-9]{6,}\b")),
    ("tradier_account_id", re.compile(r"\b6YA\d{6,}\b")),
    (
        "raw_account_field",
        re.compile(
            r'"(?:raw_account_id|broker_account_id|account_number)"\s*:\s*"[^"]+"'
        ),
    ),
    (
        "raw_account_xml_attribute",
        re.compile(r'\baccountId="[A-Za-z0-9_-]{5,}"'),
    ),
)

_RAW_STATEMENT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("flex_statement_xml", re.compile(r"<FlexStatements|<FlexStatement", re.IGNORECASE)),
    (
        "equity_summary_xml",
        re.compile(r"<EquitySummaryByReportDateInBase", re.IGNORECASE),
    ),
    ("trade_ticket_xml", re.compile(r"<Trade\s+accountId=", re.IGNORECASE)),
    (
        "raw_statement_field",
        re.compile(
            r'"(?:raw_statement_text|raw_statement_b64|raw_trades)"\s*:\s*"[^"]{16,}"'
        ),
    ),
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stripe_secret_key", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("github_token", re.compile(r"(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9_.-]{24,}")),
    ("private_key_block", re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----")),
    (
        "credential_field",
        re.compile(
            r'"(?:flex_token|client_secret|api_secret)"\s*:\s*"[^"]{8,}"',
            re.IGNORECASE,
        ),
    ),
)


class OutboundPrivacyScanner:
    """Scans response bodies to actively block leakage of account numbers, broker IDs, and trade payloads."""

    def __init__(
        self,
        *,
        allowlist_blinded_tags: bool = True,
    ) -> None:
        self.allowlist_blinded_tags = allowlist_blinded_tags

    def scan_text(self, text: str) -> list[str]:
        """Inspect plain text or serialized JSON string and return any detected violation descriptions."""
        violations: list[str] = []
        if not text:
            return violations

        for rule_name, pattern in _ACCOUNT_NUMBER_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                violations.append(f"Synthetic account leak ({rule_name}): {len(matches)} match(es)")

        for rule_name, pattern in _RAW_STATEMENT_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                violations.append(f"Raw statement/trade payload leak ({rule_name}): {len(matches)} match(es)")

        for rule_name, pattern in _SECRET_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                violations.append(f"Secret credential leak ({rule_name}): {len(matches)} match(es)")

        return violations

    def scan_payload(self, data: Any) -> list[str]:
        """Serialize a data structure to JSON and scan for privacy leaks."""
        try:
            text = json.dumps(data, default=str)
        except Exception:
            text = str(data)
        return self.scan_text(text)

    def is_clean(self, target: Any) -> bool:
        """Return True if no privacy violations are detected in target."""
        if isinstance(target, (str, bytes)):
            text = target.decode("utf-8", errors="replace") if isinstance(target, bytes) else target
            return len(self.scan_text(text)) == 0
        return len(self.scan_payload(target)) == 0

    def assert_clean(self, target: Any) -> None:
        """Raise ``PrivacyLeakError`` if any privacy violations are detected."""
        if isinstance(target, (str, bytes)):
            text = target.decode("utf-8", errors="replace") if isinstance(target, bytes) else target
            violations = self.scan_text(text)
        else:
            violations = self.scan_payload(target)
        if violations:
            raise PrivacyLeakError(violations)


__all__ = [
    "OutboundPrivacyScanner",
    "PrivacyLeakError",
]
