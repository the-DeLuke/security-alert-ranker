"""Command-line interface for the Security Alert Risk-Ranking Prototype.

Student ID: 2419 (Group C — SOC Operations & Threat Detection)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional, Sequence

from .loader import load_alerts_file, load_auth_events_file, load_soc_test_cases_file
from .models import RankedAlert, TestCaseResult, ValidationErrorRecord
from .scorer import (
    DEFAULT_INCIDENT_WINDOW_UTC,
    evaluate_soc_test_cases,
    generate_incident_timeline,
    generate_strict_incident_timeline,
    rank_alerts,
)


def _format_test_results_section(
    title: str, test_results: Sequence[TestCaseResult]
) -> List[str]:
    lines: List[str] = []
    lines.append("\n" + "=" * 88)
    lines.append(title)
    lines.append("=" * 88)
    for tr in test_results:
        status = "PASS" if tr.passed else "DISCREPANCY/REVIEW"
        ev_str = ", ".join(tr.matched_events) if tr.matched_events else "None"
        lines.append(
            f"[{status}] {tr.case_id} (mode={tr.evaluation_mode}): "
            f"expected='{tr.expected_class}', actual='{tr.actual_class}' | Matched: {ev_str}"
        )
        lines.append(f"       Pattern : {tr.input_pattern}")
        lines.append(f"       Evidence: {tr.evidence_summary}")
    return lines


def format_ranked_report(
    dataset_name: str,
    notice: str,
    ranked_alerts: Sequence[RankedAlert],
    validation_errors: Sequence[ValidationErrorRecord],
    test_results: Optional[Sequence[TestCaseResult]] = None,
    strict_test_results: Optional[Sequence[TestCaseResult]] = None,
    strict_timeline: Optional[Sequence[dict]] = None,
    full_timeline: Optional[Sequence[dict]] = None,
) -> str:
    """Format a clear, reproducible text report of ranked alerts, Mode A/B test evaluations, and separate timelines."""
    lines: List[str] = []
    lines.append("=" * 88)
    lines.append("SECURITY ALERT RISK-RANKING PROTOTYPE — SOC TRIAGE REPORT (STUDENT ID: 2419)")
    lines.append("=" * 88)
    lines.append(f"Dataset : {dataset_name}")
    if notice:
        lines.append(f"Notice  : {notice}")
    lines.append(
        "Official Incident Window (INC-2026-104): 2026-10-19T08:00:00Z to 2026-10-19T10:30:00Z"
    )
    lines.append(
        "Methodology Note: Confidence values are heuristic prioritisation scores, not calibrated"
    )
    lines.append(
        "probabilities. Hostname-derived asset criticality is an assumption; production deployments"
    )
    lines.append(
        "should query an approved asset inventory or CMDB. Alerts and correlations are investigative"
    )
    lines.append("indicators, not proof of compromise.")
    lines.append(
        f"Summary : {len(ranked_alerts)} valid alert(s) ranked | "
        f"{len(validation_errors)} malformed record(s) skipped"
    )
    lines.append("-" * 88)
    lines.append(
        f"{'Rank':<5} {'Alert ID':<10} {'Priority':<15} {'Score':<8} "
        f"{'Sev':<8} {'Crit':<10} {'Conf':<6} {'Action':<13} {'Host':<14} {'User'}"
    )
    lines.append("-" * 88)

    for r in ranked_alerts:
        a = r.alert
        lines.append(
            f"#{r.rank:<4} {a.alert_id:<10} {r.priority:<15} {r.risk_score:<8.2f} "
            f"{a.severity:<8} {r.criticality_level:<10} {r.confidence_score:<6.0f} "
            f"{a.action:<13} {a.host:<14} {a.user}"
        )

    lines.append("-" * 88)
    lines.append("\nDETAILED SCORING EXPLANATIONS, CORRELATION AUDIT & TRIAGE GUIDANCE:")
    for r in ranked_alerts:
        a = r.alert
        lines.append(f"\n[#{r.rank}] {a.alert_id} — {a.rule} ({a.timestamp_utc})")
        lines.append(f"  Host / User / Process : {a.host} | {a.user} | {a.process}")
        lines.append(f"  Ticket / Analyst Note : {a.ticket} | {a.analyst_note}")
        lines.append(f"  Scoring Breakdown     : {r.explanation}")
        if r.assumptions:
            lines.append("  Documented Assumptions:")
            for assumption in r.assumptions:
                lines.append(f"    - {assumption}")
        if r.correlation_notes:
            lines.append("  Correlation Audit (Matched & Excluded Candidates):")
            for c_note in r.correlation_notes:
                lines.append(f"    - {c_note}")
        lines.append(f"  Recommended Triage    : {r.recommended_action}")

    if validation_errors:
        lines.append("\n" + "-" * 88)
        lines.append("SKIPPED MALFORMED / INCOMPLETE RECORDS:")
        for err in validation_errors:
            lines.append(f"  - Index {err.index}: {'; '.join(err.errors)}")

    if test_results:
        lines.extend(
            _format_test_results_section(
                "MODE A: FULL-DATASET SOC DETECTION TEST EVALUATION (ALL 20 AUTH EVENTS)",
                test_results,
            )
        )

    if strict_test_results:
        lines.extend(
            _format_test_results_section(
                "MODE B: STRICT INCIDENT-WINDOW SOC TEST EVALUATION (08:00:00Z–10:30:00Z ONLY; AUTH-0020 EXCLUDED)",
                strict_test_results,
            )
        )

    if strict_timeline:
        lines.append("\n" + "=" * 88)
        lines.append(
            f"OFFICIAL STRICT INCIDENT-WINDOW TIMELINE (2026-10-19 08:00:00Z TO 10:30:00Z — "
            f"{len(strict_timeline)} EVENTS; POST-10:30Z EVENTS EXCLUDED)"
        )
        lines.append("=" * 88)
        for item in strict_timeline:
            lines.append(
                f"{item['timestamp_utc']} | {item['id']:<9} | {item['classification']:<26} | "
                f"{item['entity']:<32} | {item['summary']}"
            )

    if full_timeline:
        lines.append("\n" + "=" * 88)
        lines.append(
            f"FULL-DATASET TIMELINE (ALL SUPPLIED TELEMETRY — {len(full_timeline)} EVENTS "
            f"INCLUDING POST-10:30Z CONTEXT)"
        )
        lines.append("=" * 88)
        for item in full_timeline:
            lines.append(
                f"{item['timestamp_utc']} | {item['id']:<9} | {item['classification']:<26} | "
                f"{item['entity']:<32} | {item['summary']}"
            )

    lines.append("=" * 88)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alert_ranker",
        description="Rank synthetic security alerts using explainable risk scoring (Student ID: 2419).",
    )
    parser.add_argument(
        "--alerts",
        default="03_SOC_LOGS/endpoint_alerts.json",
        help="Path to endpoint_alerts.json (default: 03_SOC_LOGS/endpoint_alerts.json)",
    )
    parser.add_argument(
        "--auth-events",
        default=None,
        help="Optional path to authentication_events.csv for cross-log correlation",
    )
    parser.add_argument(
        "--test-cases",
        default=None,
        help="Optional path to soc_detection_test_cases.csv to verify detection rules",
    )
    parser.add_argument(
        "--include-timeline",
        action="store_true",
        help="Include separate Strict Incident-Window (08:00-10:30 UTC) and Full-Dataset timelines",
    )
    parser.add_argument(
        "--correlation-window-minutes",
        type=float,
        default=None,
        help="Optional override for alert-to-auth correlation window in minutes",
    )
    parser.add_argument(
        "--strict-incident-window",
        action="store_true",
        help="Run SOC test evaluation in Mode B (strictly 08:00:00Z-10:30:00Z) as primary test output",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional file path to export structured JSON output",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        metadata, alerts, alert_errors = load_alerts_file(args.alerts)
        auth_events = None
        if args.auth_events:
            auth_events, _ = load_auth_events_file(args.auth_events)

        ranked = rank_alerts(
            alerts,
            auth_events=auth_events,
            correlation_window_minutes=args.correlation_window_minutes,
        )

        full_test_results = None
        strict_test_results = None
        if args.test_cases and auth_events is not None:
            cases = load_soc_test_cases_file(args.test_cases)
            full_test_results = evaluate_soc_test_cases(
                cases,
                auth_events,
                evaluation_mode="full_dataset",
            )
            strict_test_results = evaluate_soc_test_cases(
                cases,
                auth_events,
                window_start_utc=DEFAULT_INCIDENT_WINDOW_UTC[0],
                window_end_utc=DEFAULT_INCIDENT_WINDOW_UTC[1],
                evaluation_mode="strict_incident_window",
            )

        strict_timeline = None
        full_timeline = None
        if args.include_timeline and auth_events is not None:
            strict_timeline = generate_strict_incident_timeline(ranked, auth_events)
            full_timeline = generate_incident_timeline(
                ranked, auth_events, strict_window=False
            )

        report_text = format_ranked_report(
            dataset_name=metadata.get("dataset_name", ""),
            notice=metadata.get("notice", ""),
            ranked_alerts=ranked,
            validation_errors=alert_errors,
            test_results=None if args.strict_incident_window else full_test_results,
            strict_test_results=strict_test_results,
            strict_timeline=strict_timeline,
            full_timeline=full_timeline,
        )
        print(report_text)

        if args.json_out:
            out_path = Path(args.json_out)
            primary_tests = (
                strict_test_results if args.strict_incident_window else full_test_results
            )
            payload = {
                "metadata": metadata,
                "incident_window_utc": {
                    "start": DEFAULT_INCIDENT_WINDOW_UTC[0],
                    "end": DEFAULT_INCIDENT_WINDOW_UTC[1],
                },
                "ranked_alerts": [asdict(r) for r in ranked],
                "validation_errors": [asdict(e) for e in alert_errors],
                "soc_test_results": [asdict(t) for t in primary_tests] if primary_tests else [],
                "soc_test_results_mode_a_full": (
                    [asdict(t) for t in full_test_results] if full_test_results else []
                ),
                "soc_test_results_mode_b_strict": (
                    [asdict(t) for t in strict_test_results] if strict_test_results else []
                ),
                "strict_incident_timeline": strict_timeline or [],
                "full_dataset_timeline": full_timeline or [],
                "timeline": full_timeline or [],
            }
            out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())


