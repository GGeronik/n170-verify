"""Comprehensive tests for redaction functions, safety checks, and disclosure allowlists."""

import dataclasses
import pytest
from n170_verify.connectors.mcp_allowlist_firewall import (
    redact_sensitive_text,
    _ALLOWED_STATIC_ACCOUNT_SEGMENTS,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    TranscriptCommitmentKind,
    build_salted_merkle_tree,
    create_signed_witness_attestation,
    generate_ed25519_keypair,
    inspect_transcript_safety,
    verify_selective_disclosure,
)


class TestRedactSensitiveText:
    """Test suite for redact_sensitive_text covering all privacy guardrails."""

    def test_redact_sensitive_query_parameters(self):
        url = "https://example.com/api/v1/data?token=my-secret-token-123&format=json"
        redacted = redact_sensitive_text(url)
        assert "[REDACTED]" in redacted
        assert "my-secret-token-123" not in redacted
        assert "format=json" in redacted

        # IBKR Flex query parameters
        flex_url = "/AccountManagement/FlexWebService/GetStatement?t=1092830192830192&q=981273981273&v=3"
        redacted_flex = redact_sensitive_text(flex_url)
        assert "t=[REDACTED]" in redacted_flex
        assert "q=[REDACTED]" in redacted_flex
        assert "1092830192830192" not in redacted_flex
        assert "v=3" in redacted_flex

    def test_redact_key_value_secrets(self):
        raw = "Error connecting: api_key=ak_live_abcdef123456 client_secret=cs_987654321 session=ok"
        redacted = redact_sensitive_text(raw)
        assert "api_key=[REDACTED]" in redacted
        assert "client_secret=[REDACTED]" in redacted
        assert "ak_live_abcdef123456" not in redacted
        assert "cs_987654321" not in redacted
        assert "session=ok" in redacted

    def test_redact_auth_headers(self):
        hdr1 = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
        assert redact_sensitive_text(hdr1) == "Authorization: Bearer [REDACTED]"

        hdr2 = "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
        assert redact_sensitive_text(hdr2) == "Authorization: Basic [REDACTED]"

        hdr3 = "Proxy-Authorization: Basic c2VjcmV0"
        assert redact_sensitive_text(hdr3) == "Proxy-Authorization: Basic [REDACTED]"

        hdr4 = "X-API-Key: super-secret-api-key"
        assert redact_sensitive_text(hdr4) == "X-API-Key: [REDACTED]"

    def test_redact_cookie_headers(self):
        cookie = "Cookie: sessionid=abc123xyz; csrftoken=secret456"
        assert redact_sensitive_text(cookie) == "Cookie: [REDACTED]"

        set_cookie = "Set-Cookie: auth=token789; Path=/; Secure; HttpOnly"
        redacted_set = redact_sensitive_text(set_cookie)
        assert "[REDACTED]" in redacted_set
        assert "token789" not in redacted_set

    def test_redact_account_identifiers_in_paths(self):
        path1 = "/v1/accounts/U1234567/summary"
        redacted1 = redact_sensitive_text(path1)
        assert "/v1/accounts/[REDACTED]/summary" == redacted1
        assert "U1234567" not in redacted1

        path2 = "/portfolio/U1234567/positions"
        redacted2 = redact_sensitive_text(path2)
        assert "/portfolio/[REDACTED]/positions" == redacted2
        assert "U1234567" not in redacted2

    def test_preserve_static_allowed_account_segments(self):
        for seg in ("accountnumbers", "subaccounts", "summary", "[redacted]"):
            path = f"/v1/accounts/{seg}/orders"
            redacted = redact_sensitive_text(path)
            assert f"/v1/accounts/{seg}/orders" == redacted

    def test_extra_secrets_redaction(self):
        text = "Connected to DB with pass myVerySecretDbPassword123 at host internal.db"
        redacted = redact_sensitive_text(text, extra_secrets=["myVerySecretDbPassword123"])
        assert "[REDACTED]" in redacted
        assert "myVerySecretDbPassword123" not in redacted

        # Short secrets (< 4 chars) are ignored to avoid false positives
        text2 = "abc is safe"
        assert redact_sensitive_text(text2, extra_secrets=["abc"]) == "abc is safe"

    def test_edge_cases(self):
        assert redact_sensitive_text("") == ""
        assert redact_sensitive_text(None) == ""
        plain = "Plain log message with no secrets."
        assert redact_sensitive_text(plain) == plain


class TestWitnessTranscriptSafetyAllowlist:
    """Test suite for inspect_transcript_safety and witness allowlists."""

    @pytest.fixture
    def base_attestation(self):
        key = generate_ed25519_keypair()
        return create_signed_witness_attestation(
            notary_private_key_hex=key.private_key_hex,
            notary_id="notary-pse-eu",
            server_sni="ndcdyn.interactivebrokers.com",
            sanitized_request_target="/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3",
            redacted_headers=["Authorization: [REDACTED]"],
            commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
            response_body_sha256="a" * 64,
            session_timestamp_utc="2026-04-01T03:10:00Z",
        )

    def test_valid_attestation_passes_safety_check(self, base_attestation):
        is_safe, violations = inspect_transcript_safety(base_attestation)
        assert is_safe is True
        assert len(violations) == 0

    def test_unredacted_sensitive_query_parameter_fails(self, base_attestation):
        att = dataclasses.replace(
            base_attestation,
            sanitized_request_target="/GetStatement?t=1234567890123456&q=[REDACTED]",
        )
        is_safe, violations = inspect_transcript_safety(att)
        assert is_safe is False
        assert any("sensitive query parameter" in v.lower() for v in violations)

    def test_unredacted_account_id_in_path_fails(self, base_attestation):
        att = dataclasses.replace(
            base_attestation,
            sanitized_request_target="/v1/accounts/99887766/trades",
        )
        is_safe, violations = inspect_transcript_safety(att)
        assert is_safe is False
        assert any("account identifier" in v.lower() for v in violations)

    def test_missing_redacted_headers_fails(self, base_attestation):
        att = dataclasses.replace(base_attestation, redacted_headers=[])
        is_safe, violations = inspect_transcript_safety(att)
        assert is_safe is False
        assert any("redacted_headers" in v for v in violations)

    def test_unredacted_sensitive_header_value_fails(self, base_attestation):
        att = dataclasses.replace(
            base_attestation,
            redacted_headers=["Authorization: Bearer secret-token-value"],
        )
        is_safe, violations = inspect_transcript_safety(att)
        assert is_safe is False
        assert any("unredacted sensitive header value" in v.lower() for v in violations)

    def test_variable_span_commitment_is_rejected(self, base_attestation):
        att = dataclasses.replace(
            base_attestation,
            commitment_kind=TranscriptCommitmentKind.UNPADDED_VARIABLE_SPAN_REJECTED,
        )
        is_safe, violations = inspect_transcript_safety(att)
        assert is_safe is False
        assert any("variable-span" in v.lower() for v in violations)

    def test_unsupported_protocol_or_tls_version_fails(self, base_attestation):
        att1 = dataclasses.replace(base_attestation, protocol="tlsn_v0.0.1_legacy")
        is_safe1, violations1 = inspect_transcript_safety(att1)
        assert is_safe1 is False
        assert any("protocol" in v.lower() for v in violations1)

        att2 = dataclasses.replace(base_attestation, tls_version="TLSv1.2")
        is_safe2, violations2 = inspect_transcript_safety(att2)
        assert is_safe2 is False
        assert any("version" in v.lower() for v in violations2)

    def test_defer_decryption_must_be_true(self, base_attestation):
        att = dataclasses.replace(base_attestation, defer_decryption_from_start=False)
        is_safe, violations = inspect_transcript_safety(att)
        assert is_safe is False
        assert any("defer_decryption_from_start" in v for v in violations)


class TestMerkleLeafDisclosureAllowlist:
    """Test suite for canonical leaf allowlist and selective disclosure verification."""

    def test_canonical_leaf_names_integrity(self):
        expected_leaves = {
            "core_metrics",
            "indexed_curve",
            "reconciliation",
            "coaching_and_context",
            "capital_bracket",
            "benchmark_alpha",
            "delayed_closed_trades",
        }
        assert set(CANONICAL_LEAF_NAMES) == expected_leaves
        assert len(CANONICAL_LEAF_NAMES) == 7

    def test_selective_disclosure_full_tree(self):
        payloads = {name: {"leaf_name": name, "value": 42} for name in CANONICAL_LEAF_NAMES}
        tree = build_salted_merkle_tree(payloads)

        disclosed, undisclosed = tree.selectively_disclose()
        valid, reasons = verify_selective_disclosure(
            tree.merkle_root,
            disclosed,
            undisclosed,
        )
        assert valid is True
        assert len(reasons) == 0

    def test_selective_disclosure_partial_subset(self):
        payloads = {name: {"leaf_name": name, "value": idx} for idx, name in enumerate(CANONICAL_LEAF_NAMES)}
        tree = build_salted_merkle_tree(payloads)

        disclosed_names = ["core_metrics", "reconciliation"]
        disclosed, undisclosed = tree.selectively_disclose(disclose_leaf_names=disclosed_names)

        valid, reasons = verify_selective_disclosure(
            tree.merkle_root,
            disclosed,
            undisclosed,
        )
        assert valid is True
        assert len(reasons) == 0

    def test_selective_disclosure_tampered_payload_rejected(self):
        payloads = {name: {"leaf_name": name, "value": 100} for name in CANONICAL_LEAF_NAMES}
        tree = build_salted_merkle_tree(payloads)

        disclosed, undisclosed = tree.selectively_disclose()
        # Tamper with core_metrics payload
        bad_leaf = dataclasses.replace(
            disclosed[0],
            payload={"leaf_name": disclosed[0].leaf_name, "value": 999999},
        )
        disclosed[0] = bad_leaf

        valid, reasons = verify_selective_disclosure(
            tree.merkle_root,
            disclosed,
            undisclosed,
        )
        assert valid is False
        assert any("verification failed" in r.lower() or "audit path" in r.lower() for r in reasons)
