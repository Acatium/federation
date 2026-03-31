"""SQL safety utilities — identifier validation and sanitization.

Prevents SQL injection in contexts where parameterized queries are not
supported (e.g., Snowflake SHOW commands, DDL statements). All SQL-constructing
code should validate identifiers through these functions.
"""
from __future__ import annotations

import re
import logging

logger = logging.getLogger(__name__)

# Strict pattern: alphanumeric + underscores, must start with letter or underscore
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# S3 bucket name pattern (per AWS spec)
_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")

# IAM role ARN pattern
_IAM_ROLE_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@\-/]+$")


def validate_identifier(name: str) -> str:
    """Validate a SQL identifier (database, schema, table, column name).

    Raises ValueError if the identifier contains characters outside
    [A-Za-z0-9_] or does not start with a letter/underscore.

    Args:
        name: The identifier to validate.

    Returns:
        The validated identifier (unchanged).
    """
    if not name:
        raise ValueError("SQL identifier must not be empty")
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(
            f"Invalid SQL identifier: {name!r}. "
            f"Must match [A-Za-z_][A-Za-z0-9_]*"
        )
    return name


def validate_non_negative_int(val: int) -> int:
    """Validate that a value is a non-negative integer (>= 0).

    Args:
        val: The value to validate.

    Returns:
        The validated integer.
    """
    if not isinstance(val, int) or val < 0:
        raise ValueError(f"Expected a non-negative integer, got {val!r}")
    return val



def validate_s3_bucket(bucket: str) -> str:
    """Validate an S3 bucket name against the AWS naming spec.

    Args:
        bucket: The bucket name to validate.

    Returns:
        The validated bucket name.
    """
    if not bucket:
        raise ValueError("S3 bucket name must not be empty")
    if not _S3_BUCKET_RE.match(bucket):
        raise ValueError(f"Invalid S3 bucket name: {bucket!r}")
    return bucket


# Patterns that indicate SQL injection attempts in row filter expressions
_ROW_FILTER_DENY_RE = re.compile(
    r"(;\s*|--\s|/\*"
    r"|(?<!\w)(?:DROP|ALTER|CREATE|TRUNCATE|INSERT|UPDATE|DELETE|GRANT|REVOKE|UNION|EXEC)\s)",
    re.IGNORECASE,
)


def validate_row_filter_expr(expr: str) -> str:
    """Validate a row filter expression before passing it to Ranger.

    Rejects expressions containing semicolons, SQL comments, or DDL keywords
    that should never appear in a row-level filter predicate.

    Args:
        expr: The filter expression to validate.

    Returns:
        The validated expression (unchanged).
    """
    if not expr:
        raise ValueError("Row filter expression must not be empty")
    if _ROW_FILTER_DENY_RE.search(expr):
        raise ValueError(
            f"Potentially unsafe row filter expression: {expr!r}. "
            "Semicolons, comments (-- or /*), and DDL keywords are not allowed."
        )
    return expr


def validate_iam_role_arn(arn: str) -> str:
    """Validate an IAM role ARN.

    Args:
        arn: The ARN to validate.

    Returns:
        The validated ARN.
    """
    if not arn:
        raise ValueError("IAM role ARN must not be empty")
    if not _IAM_ROLE_RE.match(arn):
        raise ValueError(f"Invalid IAM role ARN: {arn!r}")
    return arn
