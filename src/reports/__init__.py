"""Reports package — unified views across all federated policy data."""

from src.reports.entitlement_matrix import EntitlementMatrix
from src.reports.final_report import render_report

__all__ = ["EntitlementMatrix", "render_report"]
