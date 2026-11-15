"""Data models and input validation for the Security Alert Risk-Ranking Prototype.

Student ID: 2419 (Group C — SOC Operations & Threat Detection)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_CRITICALITIES = {"low", "medium", "high", "critical"}
VALID_ACTIONS = {"blocked", "rate_limited", "logged", "allowed"}

REQUIRED_ALERT_FIELDS = (
    "alert_id",
    "timestamp_utc",
    "host",
    "user",
    "severity",
    "rule",
    "process",
    "action",
)


@dataclass(frozen=True)
class AlertRecord:
    """Validated security alert record matching 03_SOC_LOGS/endpoint_alerts.json."""

    alert_id: str
    timestamp_utc: str
    host: str
    user: str
    severity: str
    rule: str
    process: str
    action: str
    ticket: str = "UNASSIGNED"
    analyst_note: str = ""
    asset_criticality: Optional[str] = None
    confidence: Optional[float] = None


@dataclass(frozen=True)
class ValidationErrorRecord:
    """Captures details of a malformed or incomplete alert record without crashing."""

    index: int
    raw_record: Any
    errors: List[str]


@dataclass(frozen=True)
class RankedAlert:
    """Scored and prioritized alert with full component breakdown, correlation notes, and assumptions."""

    rank: int
    alert: AlertRecord
    risk_score: float
    priority: str
    severity_score: float
    criticality_level: str
    criticality_score: float
    confidence_score: float
    action_score: float
    correlated_events: List[str] = field(default_factory=list)
    correlation_notes: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    explanation: str = ""
    recommended_action: str = ""


@dataclass(frozen=True)
class AuthEvent:
    """Validated authentication log event from 03_SOC_LOGS/authentication_events.csv."""

    timestamp_utc: str
    event_id: str
    username: str
    event_type: str
    source_ip: str
    target_system: str
    auth_method: str
    notes: str


@dataclass(frozen=True)
class TestCaseResult:
    """Evaluation result against 03_SOC_LOGS/soc_detection_test_cases.csv."""

    case_id: str
    input_pattern: str
    expected_class: str
    actual_class: str
    passed: bool
    matched_events: List[str]
    reason: str
    evidence_summary: str
    evaluation_mode: str = "full_dataset"


def parse_iso_timestamp(ts_value: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp string (e.g. '2026-10-19T08:18:02Z')."""
    if not isinstance(ts_value, str) or not ts_value.strip():
        raise ValueError("Timestamp must be a non-empty string.")
    normalized = ts_value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized)


def validate_alert_dict(
    raw: Any, index: int = 0
) -> Tuple[Optional[AlertRecord], Optional[ValidationErrorRecord]]:
    """Validate a raw dictionary from JSON and return either AlertRecord or ValidationErrorRecord."""
    if not isinstance(raw, dict):
        return None, ValidationErrorRecord(
            index=index,
            raw_record=raw,
            errors=[f"Record at index {index} is not a JSON object (got {type(raw).__name__})."],
        )

    errors: List[str] = []

    for req_field in REQUIRED_ALERT_FIELDS:
        val = raw.get(req_field)
        if val is None or not isinstance(val, str) or not val.strip():
            errors.append(f"Missing or empty required string field '{req_field}'.")

    # Validate timestamp format if present
    ts_raw = raw.get("timestamp_utc")
    if isinstance(ts_raw, str) and ts_raw.strip():
        try:
            parse_iso_timestamp(ts_raw)
        except ValueError:
            errors.append(f"Invalid ISO-8601 timestamp_utc '{ts_raw}'.")

    # Validate severity
    sev_raw = raw.get("severity")
    severity_norm = ""
    if isinstance(sev_raw, str) and sev_raw.strip():
        severity_norm = sev_raw.strip().lower()
        if severity_norm not in VALID_SEVERITIES:
            errors.append(
                f"Invalid severity '{sev_raw}'. Must be one of {sorted(VALID_SEVERITIES)}."
            )

    # Validate optional explicit asset_criticality if supplied
    crit_raw = raw.get("asset_criticality")
    crit_norm: Optional[str] = None
    if crit_raw is not None:
        if not isinstance(crit_raw, str) or crit_raw.strip().lower() not in VALID_CRITICALITIES:
            errors.append(
                f"Invalid asset_criticality '{crit_raw}'. Must be one of {sorted(VALID_CRITICALITIES)}."
            )
        else:
            crit_norm = crit_raw.strip().lower()

    # Validate optional explicit confidence if supplied (accepts 0.0-1.0 or 0-100 numeric, or low/medium/high)
    conf_raw = raw.get("confidence")
    conf_norm: Optional[float] = None
    if conf_raw is not None:
        if isinstance(conf_raw, (int, float)) and not isinstance(conf_raw, bool):
            val_f = float(conf_raw)
            if 0.0 <= val_f <= 1.0:
                conf_norm = round(val_f * 100.0, 2)
            elif 1.0 < val_f <= 100.0:
                conf_norm = round(val_f, 2)
            else:
                errors.append(
                    f"Numeric confidence '{conf_raw}' out of range (must be 0.0-1.0 or 0-100)."
                )
        elif isinstance(conf_raw, str):
            label_map = {"low": 30.0, "medium": 65.0, "high": 90.0}
            c_lower = conf_raw.strip().lower()
            if c_lower in label_map:
                conf_norm = label_map[c_lower]
            else:
                errors.append(
                    f"String confidence '{conf_raw}' invalid (must be low, medium, or high)."
                )
        else:
            errors.append(f"Invalid confidence type '{type(conf_raw).__name__}'.")

    if errors:
        return None, ValidationErrorRecord(index=index, raw_record=raw, errors=errors)

    ticket_val = raw.get("ticket")
    ticket_str = (
        ticket_val.strip()
        if isinstance(ticket_val, str) and ticket_val.strip()
        else "UNASSIGNED"
    )

    note_val = raw.get("analyst_note")
    note_str = note_val.strip() if isinstance(note_val, str) else ""

    return (
        AlertRecord(
            alert_id=raw["alert_id"].strip(),
            timestamp_utc=raw["timestamp_utc"].strip(),
            host=raw["host"].strip(),
            user=raw["user"].strip(),
            severity=severity_norm,
            rule=raw["rule"].strip(),
            process=raw["process"].strip(),
            action=raw["action"].strip().lower(),
            ticket=ticket_str,
            analyst_note=note_str,
            asset_criticality=crit_norm,
            confidence=conf_norm,
        ),
        None,
    )
