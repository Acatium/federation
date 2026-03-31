"""Unit tests for the Glue/IAM policy extractor."""

from __future__ import annotations

import logging
from unittest.mock import patch, MagicMock

import pytest

from src.extractors.glue_iam_to_ranger import (
    GlueIamExtractor,
    _arn_to_ranger_principal,
    _map_glue_action,
)

logger = logging.getLogger(__name__)


class TestArnToRangerPrincipal:
    """Tests for _arn_to_ranger_principal."""

    def test_iam_role_to_group(self) -> None:
        """IAM role ARN maps to Ranger group with short name."""
        users, groups = _arn_to_ranger_principal("arn:aws:iam::123456789012:role/SpectrumRole")
        assert users == []
        assert groups == ["SpectrumRole"]
        logger.info("IAM role ARN -> Ranger group: users=%s, groups=%s", users, groups)

    def test_iam_user_to_user(self) -> None:
        """IAM user ARN maps to Ranger user with short name."""
        users, groups = _arn_to_ranger_principal("arn:aws:iam::123456789012:user/matt")
        assert users == ["matt"]
        assert groups == []
        logger.info("IAM user ARN -> Ranger user: users=%s, groups=%s", users, groups)

    def test_plain_name_to_user(self) -> None:
        """Plain name (no ARN) maps to Ranger user."""
        users, groups = _arn_to_ranger_principal("test_user")
        assert users == ["test_user"]
        assert groups == []
        logger.info("Plain name -> Ranger user: users=%s, groups=%s", users, groups)

    def test_malformed_arn_raises(self) -> None:
        """Unrecognized ARN format raises ValueError."""
        with pytest.raises(ValueError, match="Unrecognized IAM ARN"):
            _arn_to_ranger_principal("arn:aws:s3:::my-bucket")
        logger.info("Malformed ARN 'arn:aws:s3:::my-bucket' correctly raised ValueError")

    def test_role_with_path(self) -> None:
        """IAM role with path extracts the role name after last slash."""
        users, groups = _arn_to_ranger_principal(
            "arn:aws:iam::123456789012:role/service-role/GlueRole"
        )
        assert groups == ["GlueRole"]
        logger.info("IAM role with path -> Ranger group: groups=%s", groups)


class TestMapGlueAction:
    """Tests for _map_glue_action."""

    def test_get_table_maps_to_select(self) -> None:
        """glue:GetTable maps to select."""
        result = _map_glue_action("glue:GetTable")
        assert result == "select"
        logger.info("glue:GetTable -> %s", result)

    def test_create_table_maps_to_create(self) -> None:
        """glue:CreateTable maps to create."""
        result = _map_glue_action("glue:CreateTable")
        assert result == "create"
        logger.info("glue:CreateTable -> %s", result)

    def test_update_table_maps_to_alter(self) -> None:
        """glue:UpdateTable maps to alter."""
        result = _map_glue_action("glue:UpdateTable")
        assert result == "alter"
        logger.info("glue:UpdateTable -> %s", result)

    def test_delete_table_maps_to_drop(self) -> None:
        """glue:DeleteTable maps to drop."""
        result = _map_glue_action("glue:DeleteTable")
        assert result == "drop"
        logger.info("glue:DeleteTable -> %s", result)

    def test_wildcard_maps_to_all(self) -> None:
        """glue:* maps to all."""
        result = _map_glue_action("glue:*")
        assert result == "all"
        logger.info("glue:* -> %s", result)

    def test_unknown_action_defaults_to_select(self) -> None:
        """Unknown action defaults to select."""
        result = _map_glue_action("glue:SomeFutureAction")
        assert result == "select"
        logger.info("glue:SomeFutureAction (unknown) -> %s", result)


class TestGlueIamExtractorResourcePolicies:
    """Tests for _parse_resource_statement and Glue resource policy parsing."""

    @pytest.fixture()
    def extractor(self) -> GlueIamExtractor:
        """Create a GlueIamExtractor with mocked boto3 clients."""
        with patch("src.extractors.glue_iam_to_ranger.boto3") as mock_boto3:
            mock_boto3.client.return_value = MagicMock()
            ext = GlueIamExtractor()
            ext.account_id = "123456789012"
            ext.database = "federation_demo"
            return ext

    def test_parse_allow_statement(self, extractor: GlueIamExtractor) -> None:
        """Allow statement creates access policy with policyItems."""
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/SpectrumRole"},
            "Action": ["glue:GetTable", "glue:GetTables"],
            "Resource": [
                "arn:aws:glue:us-east-2:123456789012:table/federation_demo/ledger_entries"
            ],
        }
        policies = extractor._parse_resource_statement(statement)
        assert len(policies) >= 1
        p = policies[0]
        assert p["policyType"] == 0
        assert len(p["policyItems"]) > 0
        assert p["policyItems"][0]["groups"] == ["SpectrumRole"]
        logger.info(
            "Allow statement -> %d Ranger policies, policyType=%d, groups=%s",
            len(policies), p["policyType"], p["policyItems"][0]["groups"],
        )

    def test_parse_deny_statement(self, extractor: GlueIamExtractor) -> None:
        """Deny statement creates policy with denyPolicyItems."""
        statement = {
            "Effect": "Deny",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/RestrictedRole"},
            "Action": "glue:DeleteTable",
            "Resource": "arn:aws:glue:us-east-2:123456789012:table/federation_demo/entities",
        }
        policies = extractor._parse_resource_statement(statement)
        assert len(policies) >= 1
        p = policies[0]
        assert "denyPolicyItems" in p
        assert len(p["denyPolicyItems"]) > 0
        logger.info(
            "Deny statement -> %d Ranger policies, denyPolicyItems=%d",
            len(policies), len(p["denyPolicyItems"]),
        )

    def test_arn_validation_rejects_bad_input(self, extractor: GlueIamExtractor) -> None:
        """Malformed ARN in statement is skipped with warning."""
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:s3:::my-bucket"},
            "Action": "glue:GetTable",
            "Resource": "arn:aws:glue:us-east-2:123456789012:table/federation_demo/ledger_entries",
        }
        # Should not raise — just logs warning and skips
        policies = extractor._parse_resource_statement(statement)
        assert len(policies) == 0

    def test_extract_tables_from_arns(self, extractor: GlueIamExtractor) -> None:
        """Table names extracted from Glue resource ARNs."""
        arns = [
            "arn:aws:glue:us-east-2:123456789012:table/federation_demo/ledger_entries",
            "arn:aws:glue:us-east-2:123456789012:table/federation_demo/entities",
        ]
        tables = extractor._extract_tables_from_arns(arns)
        assert tables == ["ledger_entries", "entities"]
        logger.info("Extracted tables from %d ARNs: %s", len(arns), tables)


class TestGlueIamExtractorGracefulFallback:
    """Tests for graceful error handling."""

    def test_graceful_fallback_on_client_error(self) -> None:
        """boto3 ClientError returns empty list, no crash."""
        from botocore.exceptions import ClientError

        with patch("src.extractors.glue_iam_to_ranger.boto3") as mock_boto3:
            mock_glue = MagicMock()
            mock_iam = MagicMock()
            mock_boto3.client.side_effect = lambda svc, **kw: (
                mock_glue if svc == "glue" else mock_iam
            )

            # Mock paginator to raise ClientError
            mock_paginator = MagicMock()
            mock_paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
                "GetResourcePolicies",
            )
            mock_glue.get_paginator.return_value = mock_paginator

            ext = GlueIamExtractor()
            ext.account_id = ""  # Skip IAM simulation too
            policies = ext.extract_policies()
            assert isinstance(policies, list)
            assert len(policies) == 0

    def test_extract_policies_returns_list(self) -> None:
        """extract_policies always returns a list."""
        with patch("src.extractors.glue_iam_to_ranger.boto3") as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.client.return_value = mock_client
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [{"GetResourcePoliciesResponseList": []}]
            mock_client.get_paginator.return_value = mock_paginator

            ext = GlueIamExtractor()
            ext.account_id = ""
            result = ext.extract_policies()
            assert isinstance(result, list)
