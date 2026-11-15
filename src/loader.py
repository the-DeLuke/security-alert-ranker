"""Safe file loaders for JSON endpoint alerts and CSV SOC logs/test cases.

Student ID: 2419 (Group C — SOC Operations & Threat Detection)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

from .models import (
    AlertRecord,
    AuthEvent,
    ValidationErrorRecord,
    parse_iso_timestamp,
    validate_alert_dict,
)


def load_alerts_file(
    path: Union[str, Path]
) -> Tuple[Dict[str, Any], List[AlertRecord], List[ValidationErrorRecord]]:
    """Load and validate alerts from endpoint_alerts.json safely.

    Supports either a top-level dict with an 'alerts' list (matching
    03_SOC_LOGS/endpoint_alerts.json) or a top-level JSON list of alert objects.
    Returns (metadata, valid_alerts, validation_errors).
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Alert file not found: {file_path}")

    raw_text = file_path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in {file_path}: {exc}") from exc

    metadata: Dict[str, Any] = {}
    raw_alerts: List[Any] = []

    if isinstance(payload, dict):
        metadata = {
            "dataset_name": payload.get("dataset_name", "Unnamed dataset"),
            "notice": payload.get("notice", ""),
        }
        alerts_field = payload.get("alerts")
        if not isinstance(alerts_field, list):
            raise ValueError(
                f"Expected 'alerts' key in {file_path} to contain a list, got {type(alerts_field).__name__}."
            )
        raw_alerts = alerts_field
    elif isinstance(payload, list):
        metadata = {"dataset_name": file_path.name, "notice": ""}
        raw_alerts = payload
    else:
        raise ValueError(
            f"Unsupported JSON root structure in {file_path}: expected object or array."
        )

    valid_alerts: List[AlertRecord] = []
    errors: List[ValidationErrorRecord] = []

    for idx, item in enumerate(raw_alerts):
        record, err = validate_alert_dict(item, index=idx)
        if record is not None:
            valid_alerts.append(record)
        if err is not None:
            errors.append(err)

    return metadata, valid_alerts, errors


def load_auth_events_file(
    path: Union[str, Path]
) -> Tuple[List[AuthEvent], List[ValidationErrorRecord]]:
    """Load and validate authentication events from authentication_events.csv."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Authentication events file not found: {file_path}")

    required_cols = (
        "timestamp_utc",
        "event_id",
        "username",
        "event_type",
        "source_ip",
        "target_system",
        "auth_method",
        "notes",
    )

    events: List[AuthEvent] = []
    errors: List[ValidationErrorRecord] = []

    with file_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"CSV file {file_path} has no header row.")
        missing_headers = [c for c in required_cols if c not in reader.fieldnames]
        if missing_headers:
            raise ValueError(
                f"CSV file {file_path} is missing required columns: {missing_headers}"
            )

        for idx, row in enumerate(reader):
            row_errors: List[str] = []
            for col in required_cols:
                val = row.get(col)
                if val is None or not str(val).strip():
                    row_errors.append(f"Missing or empty column '{col}'.")
            ts_val = row.get("timestamp_utc", "")
            if ts_val and str(ts_val).strip():
                try:
                    parse_iso_timestamp(str(ts_val).strip())
                except ValueError:
                    row_errors.append(f"Invalid timestamp_utc '{ts_val}'.")

            if row_errors:
                errors.append(
                    ValidationErrorRecord(index=idx, raw_record=row, errors=row_errors)
                )
            else:
                events.append(
                    AuthEvent(
                        timestamp_utc=row["timestamp_utc"].strip(),
                        event_id=row["event_id"].strip(),
                        username=row["username"].strip(),
                        event_type=row["event_type"].strip(),
                        source_ip=row["source_ip"].strip(),
                        target_system=row["target_system"].strip(),
                        auth_method=row["auth_method"].strip(),
                        notes=row["notes"].strip(),
                    )
                )

    return events, errors


def load_soc_test_cases_file(path: Union[str, Path]) -> List[Dict[str, str]]:
    """Load SOC detection test cases from soc_detection_test_cases.csv."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"SOC test cases file not found: {file_path}")

    required_cols = ("case_id", "input_pattern", "expected_class", "reason")
    cases: List[Dict[str, str]] = []

    with file_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"CSV file {file_path} has no header row.")
        missing_headers = [c for c in required_cols if c not in reader.fieldnames]
        if missing_headers:
            raise ValueError(
                f"CSV file {file_path} is missing required columns: {missing_headers}"
            )
        for row in reader:
            cases.append({k: (row.get(k) or "").strip() for k in required_cols})

    return cases
