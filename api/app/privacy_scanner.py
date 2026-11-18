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


# Account-id shapes. Each needs digits, so ordinary upper-case words never match:
#   ibkr_account_id          U + 6 or more digits             (U1234567)
#   ibkr_paper_account_id    DU + 6 or more digits            (DU1234567)
#   alpaca_paper_account_id  PA + 8 to 10 letters or digits, at least two of them digits:
#                            the whole token is 10 to 12 characters (PA3K9XZ1ABCD,
#                            PA12345678). Not a word (PATTERNS), not a setup tag with one
#                            digit (PAUSE1MIN) and not a compact option symbol, whose root,
#                            expiry, C or P and strike make a token of 16 or more
#                            characters (PANW260320C00150000)
#   tradier_account_id       6YA + 6 or more digits           (6YA123456)
_ACCOUNT_NUMBER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ibkr_account_id", re.compile(r"\bU\d{6,}\b", re.IGNORECASE)),
    ("ibkr_paper_account_id", re.compile(r"\bDU\d{6,}\b", re.IGNORECASE)),
    (
        "alpaca_paper_account_id",
        re.compile(r"\bPA(?=(?:[A-Z]{0,9}\d){2})[A-Z0-9]{8,10}\b", re.IGNORECASE),
    ),
    ("tradier_account_id", re.compile(r"\b6YA\d{6,}\b", re.IGNORECASE)),
    (
        "raw_account_field",
        re.compile(
            r'"(?:raw_account_id|broker_account_id|account_number|wallet_address)"\s*:\s*"[^"]+"'
        ),
    ),
    (
        "raw_account_xml_attribute",
        re.compile(r'\baccountId="[A-Za-z0-9_-]{5,}"'),
    ),
)

_ISIN_UPPER_RE = re.compile(r"^[A-Z]{2}[A-Z0-9]{9}[0-9]$")


def is_valid_iso6166_isin(token: str) -> bool:
    """Return True when ``token`` is an uppercase 12-char ISO 6166 ISIN with valid mod-10 check digit."""
    if len(token) != 12 or _ISIN_UPPER_RE.match(token) is None:
        return False
    digits = "".join(str(ord(ch) - 55) if "A" <= ch <= "Z" else ch for ch in token)
    total = 0
    for idx, ch in enumerate(reversed(digits)):
        val = (ord(ch) - 48) * (2 if idx % 2 == 1 else 1)
        total += val - 9 if val > 9 else val
    return total % 10 == 0

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
            r'"(?:flex_token|client_secret|api_secret|user_secret|userSecret|consumer_key|consumerKey)"\s*:\s*"[^"]{6,}"',
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
            if rule_name == "alpaca_paper_account_id" and matches:
                matches = [m for m in matches if not is_valid_iso6166_isin(m)]
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
