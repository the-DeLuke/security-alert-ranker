"""Security Alert Risk-Ranking Prototype package (Student ID: 2419, Group C)."""

from .models import AlertRecord, AuthEvent, RankedAlert, TestCaseResult, ValidationErrorRecord
from .loader import load_alerts_file, load_auth_events_file, load_soc_test_cases_file
from .scorer import (
    CorrelationConfig,
    classify_auth_events_in_context,
    correlate_alert_with_auth_events,
    evaluate_soc_test_cases,
    explain_alert_correlations,
    generate_incident_timeline,
    generate_strict_incident_timeline,
    hosts_match,
    rank_alerts,
    score_alert,
)

__all__ = [
    "AlertRecord",
    "AuthEvent",
    "CorrelationConfig",
    "RankedAlert",
    "TestCaseResult",
    "ValidationErrorRecord",
    "load_alerts_file",
    "load_auth_events_file",
    "load_soc_test_cases_file",
    "classify_auth_events_in_context",
    "correlate_alert_with_auth_events",
    "explain_alert_correlations",
    "generate_incident_timeline",
    "generate_strict_incident_timeline",
    "hosts_match",
    "score_alert",
    "rank_alerts",
    "evaluate_soc_test_cases",
]
