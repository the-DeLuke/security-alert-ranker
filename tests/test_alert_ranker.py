"""Automated test suite for the Security Alert Risk-Ranking Prototype.

Student ID: 2419 (Group C — SOC Operations & Threat Detection)
Compatible with both `pytest` and `python3 -m unittest`.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure src/ is on sys.path when executed directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from alert_ranker.cli import main as cli_main
from alert_ranker.loader import (
    load_alerts_file,
    load_auth_events_file,
    load_soc_test_cases_file,
)
from alert_ranker.models import AlertRecord, AuthEvent, validate_alert_dict
from alert_ranker.scorer import (
    CorrelationConfig,
    assign_priority_band,
    build_recommendation,
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

STARTER_PACK_DIR = PROJECT_ROOT / "03_SOC_LOGS"
ALERTS_JSON_PATH = STARTER_PACK_DIR / "endpoint_alerts.json"
AUTH_CSV_PATH = STARTER_PACK_DIR / "authentication_events.csv"
SOC_TESTS_CSV_PATH = STARTER_PACK_DIR / "soc_detection_test_cases.csv"


class TestStarterPackRankingAndCorrelation(unittest.TestCase):
    """Comprehensive tests covering starter-pack ranking, Mode A vs Mode B evaluation, separate timelines, directional correlation, and assumptions."""

    def test_01_load_and_rank_real_endpoint_alerts(self) -> None:
        """Verify that endpoint_alerts.json loads cleanly and ranks EDR-1004 -> EDR-1002 -> EDR-1003 -> EDR-1001."""
        metadata, alerts, errors = load_alerts_file(ALERTS_JSON_PATH)
        auth_events, auth_errors = load_auth_events_file(AUTH_CSV_PATH)

        self.assertEqual(metadata["dataset_name"], "RedKross synthetic endpoint alerts")
        self.assertEqual(len(alerts), 4)
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(auth_events), 20)
        self.assertEqual(len(auth_errors), 0)

        ranked = rank_alerts(alerts, auth_events=auth_events)
        ranked_ids = [r.alert.alert_id for r in ranked]
        self.assertEqual(ranked_ids, ["EDR-1004", "EDR-1002", "EDR-1003", "EDR-1001"])

        # Check exact explainable scores and priorities remain unchanged
        self.assertEqual(ranked[0].risk_score, 90.50)
        self.assertEqual(ranked[0].priority, "P1 (Critical)")
        self.assertEqual(ranked[0].correlated_events, ["AUTH-0016", "AUTH-0017"])

        self.assertEqual(ranked[1].risk_score, 66.25)
        self.assertEqual(ranked[1].priority, "P2 (High)")
        self.assertEqual(ranked[1].correlated_events, ["AUTH-0009", "AUTH-0010"])

        self.assertEqual(ranked[2].risk_score, 66.00)
        self.assertEqual(ranked[2].priority, "P2 (High)")
        self.assertEqual(
            ranked[2].correlated_events, ["AUTH-0012", "AUTH-0013", "AUTH-0014"]
        )

        self.assertEqual(ranked[3].risk_score, 32.75)
        self.assertEqual(ranked[3].priority, "P4 (Low)")
        self.assertEqual(ranked[3].correlated_events, [])

    def test_02_soc_detection_test_cases_csv_all_pass_in_mode_a_full_dataset(self) -> None:
        """Verify all 5 test cases (SOC-T01 through SOC-T05) pass in Mode A (full-dataset evaluation)."""
        auth_events, _ = load_auth_events_file(AUTH_CSV_PATH)
        soc_cases = load_soc_test_cases_file(SOC_TESTS_CSV_PATH)
        self.assertEqual(len(soc_cases), 5)

        results = evaluate_soc_test_cases(
            soc_cases, auth_events, evaluation_mode="full_dataset"
        )
        for res in results:
            self.assertTrue(
                res.passed,
                msg=f"{res.case_id} failed: expected {res.expected_class}, got {res.actual_class}",
            )
            self.assertEqual(res.evaluation_mode, "full_dataset")

        by_id = {r.case_id: r for r in results}
        self.assertEqual(
            by_id["SOC-T01"].matched_events,
            ["AUTH-0003", "AUTH-0004", "AUTH-0005", "AUTH-0006"],
        )
        self.assertEqual(by_id["SOC-T02"].matched_events, ["AUTH-0009", "AUTH-0010"])
        self.assertEqual(by_id["SOC-T03"].matched_events, ["AUTH-0017"])
        self.assertEqual(by_id["SOC-T04"].matched_events, ["AUTH-0019", "AUTH-0020"])
        self.assertEqual(by_id["SOC-T05"].matched_events, ["AUTH-0008"])

    def test_03_false_positive_and_training_alert_deprioritized(self) -> None:
        """Verify that blocked training simulation alert EDR-1001 is assigned P4 (Low) with documented assumption."""
        _, alerts, _ = load_alerts_file(ALERTS_JSON_PATH)
        edr_1001 = next(a for a in alerts if a.alert_id == "EDR-1001")
        scored = score_alert(edr_1001)

        self.assertEqual(scored.priority, "P4 (Low)")
        self.assertLess(scored.risk_score, 40.0)
        self.assertTrue(
            any("Training simulation" in a for a in scored.assumptions),
            "Expected training simulation assumption to be documented.",
        )

    def test_04_explicit_criticality_and_confidence_override_inferences(self) -> None:
        """Verify that explicit asset_criticality and confidence fields override host/note heuristics."""
        custom_raw = {
            "alert_id": "EDR-2001",
            "timestamp_utc": "2026-10-19T11:00:00Z",
            "host": "WKSTN-099",
            "user": "c.admin",
            "severity": "critical",
            "rule": "Credential dumping detected",
            "process": "lsass.exe",
            "action": "allowed",
            "asset_criticality": "critical",
            "confidence": 0.95,
        }
        record, err = validate_alert_dict(custom_raw)
        self.assertIsNone(err)
        assert record is not None

        scored = score_alert(record)
        self.assertEqual(scored.risk_score, 99.00)
        self.assertEqual(scored.priority, "P1 (Critical)")
        self.assertEqual(
            len(scored.assumptions),
            0,
            "No assumptions should be logged when criticality and confidence are explicitly supplied.",
        )

    def test_05_malformed_and_missing_fields_handled_safely(self) -> None:
        """Verify that malformed records are isolated into ValidationErrorRecord without crashing."""
        mixed_payload = {
            "dataset_name": "Mixed validation test",
            "alerts": [
                {
                    "alert_id": "EDR-VALID",
                    "timestamp_utc": "2026-10-19T12:00:00Z",
                    "host": "VPN-GW-01",
                    "user": "a.user",
                    "severity": "medium",
                    "rule": "Test rule",
                    "process": "sshd",
                    "action": "rate_limited",
                },
                {
                    "alert_id": "EDR-BAD-SEV",
                    "timestamp_utc": "not-a-timestamp",
                    "host": "",
                    "user": "a.user",
                    "severity": "extreme_invalid",
                    "rule": "Test rule",
                    "process": "sshd",
                    "action": "blocked",
                    "confidence": 250,
                },
                "not_even_a_dict_record",
            ],
        }
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", encoding="utf-8", delete=False
        ) as tmp:
            json.dump(mixed_payload, tmp)
            tmp_path = Path(tmp.name)

        try:
            _, valid_alerts, errors = load_alerts_file(tmp_path)
            self.assertEqual(len(valid_alerts), 1)
            self.assertEqual(valid_alerts[0].alert_id, "EDR-VALID")
            self.assertEqual(len(errors), 2)
            self.assertEqual(errors[0].index, 1)
            self.assertTrue(any("Invalid severity" in e for e in errors[0].errors))
            self.assertTrue(any("Invalid ISO-8601" in e for e in errors[0].errors))
            self.assertEqual(errors[1].index, 2)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_06_priority_threshold_boundaries_and_tie_breaking(self) -> None:
        """Regression test for exact priority boundaries (75.0, 60.0, 40.0) and deterministic sorting."""
        self.assertEqual(assign_priority_band(75.0), "P1 (Critical)")
        self.assertEqual(assign_priority_band(74.99), "P2 (High)")
        self.assertEqual(assign_priority_band(60.0), "P2 (High)")
        self.assertEqual(assign_priority_band(59.99), "P3 (Medium)")
        self.assertEqual(assign_priority_band(40.0), "P3 (Medium)")
        self.assertEqual(assign_priority_band(39.99), "P4 (Low)")

        a1 = AlertRecord(
            alert_id="EDR-B",
            timestamp_utc="2026-10-19T09:00:00Z",
            host="WKSTN-01",
            user="u1",
            severity="medium",
            rule="R1",
            process="p1",
            action="logged",
        )
        a2 = AlertRecord(
            alert_id="EDR-A",
            timestamp_utc="2026-10-19T08:00:00Z",
            host="WKSTN-02",
            user="u2",
            severity="medium",
            rule="R1",
            process="p1",
            action="logged",
        )
        ranked = rank_alerts([a1, a2])
        self.assertEqual(ranked[0].alert.alert_id, "EDR-A")
        self.assertEqual(ranked[1].alert.alert_id, "EDR-B")

    def test_07_cli_end_to_end_and_dual_timeline_export(self) -> None:
        """Verify end-to-end CLI execution exports both Mode A/B test results and separate Strict vs Full timelines."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_json = Path(tmp.name)

        try:
            exit_code = cli_main(
                [
                    "--alerts",
                    str(ALERTS_JSON_PATH),
                    "--auth-events",
                    str(AUTH_CSV_PATH),
                    "--test-cases",
                    str(SOC_TESTS_CSV_PATH),
                    "--include-timeline",
                    "--json-out",
                    str(out_json),
                ]
            )
            self.assertEqual(exit_code, 0)
            exported = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(len(exported["ranked_alerts"]), 4)
            self.assertEqual(len(exported["soc_test_results_mode_a_full"]), 5)
            self.assertEqual(len(exported["soc_test_results_mode_b_strict"]), 5)
            # Strict timeline excludes AUTH-0020 (23 events); full timeline includes all 24 events
            self.assertEqual(len(exported["strict_incident_timeline"]), 23)
            self.assertEqual(len(exported["full_dataset_timeline"]), 24)
            strict_ids = [item["id"] for item in exported["strict_incident_timeline"]]
            self.assertNotIn("AUTH-0020", strict_ids)
        finally:
            out_json.unlink(missing_ok=True)

    def test_08_correlation_time_window_and_directional_matching(self) -> None:
        """Verify directional correlation windows and diagnostic match/exclusion notes."""
        mfa_alert = AlertRecord(
            alert_id="EDR-1002",
            timestamp_utc="2026-10-19T08:31:47Z",
            host="WKSTN-008",
            user="t.garcia",
            severity="medium",
            rule="Repeated MFA denial",
            process="browser.exe",
            action="allowed",
        )
        near_event = AuthEvent(
            timestamp_utc="2026-10-19T08:35:29Z",  # +3m 42s (inside bidirectional 5m MFA window)
            event_id="AUTH-NEAR",
            username="t.garcia",
            event_type="mfa_denied",
            source_ip="198.51.100.45",
            target_system="workstation-08",
            auth_method="push",
            notes="near event",
        )
        distant_event = AuthEvent(
            timestamp_utc="2026-10-19T14:00:00Z",  # +5h 28m (outside 5m window)
            event_id="AUTH-DISTANT",
            username="t.garcia",
            event_type="mfa_denied",
            source_ip="198.51.100.45",
            target_system="workstation-08",
            auth_method="push",
            notes="distant unrelated event hours later",
        )

        matched, notes = explain_alert_correlations(
            mfa_alert, [near_event, distant_event]
        )
        self.assertEqual([e.event_id for e in matched], ["AUTH-NEAR"])
        self.assertTrue(any("Matched AUTH-NEAR" in n for n in notes))
        self.assertTrue(any("Excluded candidate AUTH-DISTANT" in n for n in notes))

        # Verify pre-alert-only directionality for privilege_granted (post-alert privilege events are excluded)
        priv_alert = AlertRecord(
            alert_id="EDR-1004",
            timestamp_utc="2026-10-19T10:07:02Z",
            host="ADMIN-CONSOLE",
            user="m.patel",
            severity="high",
            rule="Privilege granted without change reference",
            process="admin-api",
            action="logged",
        )
        pre_priv = AuthEvent(
            timestamp_utc="2026-10-19T10:06:12Z",  # 50s prior to alert
            event_id="AUTH-PRE-PRIV",
            username="m.patel",
            event_type="privilege_granted",
            source_ip="198.51.100.22",
            target_system="admin-console",
            auth_method="MFA",
            notes="no change ticket",
        )
        post_priv = AuthEvent(
            timestamp_utc="2026-10-19T10:10:00Z",  # +2m 58s after alert (excluded by pre-alert lookback)
            event_id="AUTH-POST-PRIV",
            username="m.patel",
            event_type="privilege_granted",
            source_ip="198.51.100.22",
            target_system="admin-console",
            auth_method="MFA",
            notes="later event after alert fired",
        )
        matched_priv, priv_notes = explain_alert_correlations(
            priv_alert, [pre_priv, post_priv]
        )
        self.assertEqual([e.event_id for e in matched_priv], ["AUTH-PRE-PRIV"])
        self.assertTrue(
            any("Excluded candidate AUTH-POST-PRIV" in n and "pre-alert" in n for n in priv_notes)
        )

    def test_09_correlation_avoids_matching_unrelated_host_or_user_events(self) -> None:
        """Verify events on a different host or for a different user do not falsely correlate."""
        alert = AlertRecord(
            alert_id="EDR-1004",
            timestamp_utc="2026-10-19T10:07:02Z",
            host="ADMIN-CONSOLE",
            user="m.patel",
            severity="high",
            rule="Privilege granted without change reference",
            process="admin-api",
            action="logged",
        )
        wrong_host_event = AuthEvent(
            timestamp_utc="2026-10-19T10:06:12Z",
            event_id="AUTH-WRONG-HOST",
            username="m.patel",
            event_type="privilege_granted",
            source_ip="198.51.100.22",
            target_system="workstation-03",
            auth_method="MFA",
            notes="different system",
        )
        wrong_user_event = AuthEvent(
            timestamp_utc="2026-10-19T10:06:12Z",
            event_id="AUTH-WRONG-USER",
            username="j.lee",
            event_type="privilege_granted",
            source_ip="198.51.100.21",
            target_system="admin-console",
            auth_method="MFA",
            notes="different user",
        )

        self.assertTrue(hosts_match("WKSTN-008", "workstation-08"))
        self.assertTrue(hosts_match("VPN-GW-01", "vpn-gateway"))
        self.assertFalse(hosts_match("ADMIN-CONSOLE", "workstation-03"))

        matched = correlate_alert_with_auth_events(
            alert, [wrong_host_event, wrong_user_event]
        )
        self.assertEqual(matched, [])

    def test_10_missing_or_invalid_timestamps_handled_safely_in_correlation_and_timeline(self) -> None:
        """Ensure invalid or empty timestamps do not crash correlation or timeline generation."""
        bad_alert = AlertRecord(
            alert_id="EDR-BAD-TS",
            timestamp_utc="invalid-timestamp",
            host="WKSTN-008",
            user="t.garcia",
            severity="medium",
            rule="Repeated MFA denial",
            process="browser.exe",
            action="allowed",
        )
        valid_alert = AlertRecord(
            alert_id="EDR-OK-TS",
            timestamp_utc="2026-10-19T08:31:47Z",
            host="WKSTN-008",
            user="t.garcia",
            severity="medium",
            rule="Repeated MFA denial",
            process="browser.exe",
            action="allowed",
        )
        bad_auth = AuthEvent(
            timestamp_utc="",
            event_id="AUTH-BAD-TS",
            username="t.garcia",
            event_type="mfa_denied",
            source_ip="198.51.100.45",
            target_system="workstation-08",
            auth_method="push",
            notes="missing timestamp",
        )
        valid_auth = AuthEvent(
            timestamp_utc="2026-10-19T08:35:29Z",
            event_id="AUTH-OK-TS",
            username="t.garcia",
            event_type="mfa_denied",
            source_ip="198.51.100.45",
            target_system="workstation-08",
            auth_method="push",
            notes="valid timestamp",
        )

        self.assertEqual(
            correlate_alert_with_auth_events(bad_alert, [valid_auth]), []
        )
        matched = correlate_alert_with_auth_events(
            valid_alert, [bad_auth, valid_auth]
        )
        self.assertEqual([e.event_id for e in matched], ["AUTH-OK-TS"])

        ranked = rank_alerts([bad_alert, valid_alert], auth_events=[bad_auth, valid_auth])
        timeline = generate_incident_timeline(ranked, [bad_auth, valid_auth])
        timeline_ids = [item["id"] for item in timeline]
        self.assertEqual(timeline_ids, ["EDR-OK-TS", "AUTH-OK-TS"])

    def test_11_soc_t04_mode_a_full_dataset_vs_mode_b_strict_incident_window(self) -> None:
        """Verify Mode A includes AUTH-0020 with discrepancy note and Mode B excludes AUTH-0020 returning insufficient_evidence."""
        auth_events, _ = load_auth_events_file(AUTH_CSV_PATH)
        soc_cases = load_soc_test_cases_file(SOC_TESTS_CSV_PATH)
        t04_case = [c for c in soc_cases if c["case_id"] == "SOC-T04"]

        # Mode A (Full-dataset evaluation): includes AUTH-0019 (10:22:16Z) and AUTH-0020 (11:51:08Z)
        mode_a_res = evaluate_soc_test_cases(
            t04_case, auth_events, evaluation_mode="full_dataset"
        )[0]
        self.assertTrue(mode_a_res.passed)
        self.assertEqual(mode_a_res.expected_class, "likely_benign")
        self.assertEqual(mode_a_res.actual_class, "likely_benign")
        self.assertEqual(mode_a_res.matched_events, ["AUTH-0019", "AUTH-0020"])
        self.assertIn("88m 52s", mode_a_res.evidence_summary)
        self.assertIn("outside the official INC-2026-104", mode_a_res.evidence_summary)
        self.assertIn("not proof that the overall incident was benign", mode_a_res.evidence_summary)

        # Mode B (Strict incident-window 08:00:00Z-10:30:00Z): excludes AUTH-0020 and returns insufficient_evidence
        mode_b_res = evaluate_soc_test_cases(
            t04_case, auth_events, evaluation_mode="strict_incident_window"
        )[0]
        self.assertFalse(mode_b_res.passed)
        self.assertEqual(mode_b_res.expected_class, "likely_benign")
        self.assertEqual(mode_b_res.actual_class, "insufficient_evidence")
        self.assertEqual(mode_b_res.matched_events, ["AUTH-0019"])
        self.assertNotIn("AUTH-0020", mode_b_res.matched_events)
        self.assertIn("NOT observed within the 08:00–10:30 UTC incident window", mode_b_res.evidence_summary)

    def test_12_strict_vs_full_timeline_separation_and_classification(self) -> None:
        """Verify strict incident timeline excludes AUTH-0020 (23 events) while full timeline includes all 24 events."""
        _, alerts, _ = load_alerts_file(ALERTS_JSON_PATH)
        auth_events, _ = load_auth_events_file(AUTH_CSV_PATH)
        ranked = rank_alerts(alerts, auth_events=auth_events)

        strict_timeline = generate_strict_incident_timeline(ranked, auth_events)
        full_timeline = generate_incident_timeline(ranked, auth_events, strict_window=False)

        self.assertEqual(len(strict_timeline), 23)  # 4 alerts + 19 in-window auth events
        self.assertEqual(len(full_timeline), 24)    # 4 alerts + 20 total auth events

        strict_by_id = {item["id"]: item for item in strict_timeline}
        full_by_id = {item["id"]: item for item in full_timeline}

        # AUTH-0020 (11:51:08Z) must NOT appear in strict incident-window timeline
        self.assertNotIn("AUTH-0020", strict_by_id)
        self.assertIn("AUTH-0020", full_by_id)
        self.assertIn(
            "OUTSIDE OFFICIAL INCIDENT WINDOW", full_by_id["AUTH-0020"]["summary"]
        )

        # In strict window, AUTH-0019 has no follow-up login_success -> INSUFFICIENT_EVIDENCE
        self.assertEqual(
            strict_by_id["AUTH-0019"]["classification"], "INSUFFICIENT_EVIDENCE"
        )
        # In full dataset, AUTH-0019 is paired with AUTH-0020 -> LIKELY_BENIGN
        self.assertEqual(full_by_id["AUTH-0019"]["classification"], "LIKELY_BENIGN")
        self.assertEqual(full_by_id["AUTH-0020"]["classification"], "LIKELY_BENIGN")

        # Other classifications remain consistent across both timelines
        for ev_id in ["AUTH-0003", "AUTH-0004", "AUTH-0005", "AUTH-0006", "AUTH-0012", "AUTH-0013", "AUTH-0014"]:
            self.assertEqual(strict_by_id[ev_id]["classification"], "SUSPICIOUS")
        for ev_id in ["AUTH-0007", "AUTH-0009", "AUTH-0010"]:
            self.assertEqual(strict_by_id[ev_id]["classification"], "REVIEW")
        self.assertEqual(strict_by_id["AUTH-0017"]["classification"], "HIGH_REVIEW")
        self.assertEqual(strict_by_id["AUTH-0016"]["classification"], "LIKELY_BENIGN")
        self.assertEqual(strict_by_id["AUTH-0008"]["classification"], "LIKELY_BENIGN")
        self.assertEqual(strict_by_id["AUTH-0018"]["classification"], "LIKELY_BENIGN")

    def test_13_recommendations_and_heuristic_cmdb_assumptions_documented(self) -> None:
        """Verify recommendations and assumptions clarify heuristic confidence and CMDB asset criticality."""
        _, alerts, _ = load_alerts_file(ALERTS_JSON_PATH)
        auth_events, _ = load_auth_events_file(AUTH_CSV_PATH)
        ranked = rank_alerts(alerts, auth_events=auth_events)

        top_alert = ranked[0]  # EDR-1004
        assumptions_text = " ".join(top_alert.assumptions)
        self.assertIn("CMDB", assumptions_text)
        self.assertIn("not a statistically calibrated probability", assumptions_text)
        self.assertIn("not confirmed compromise", top_alert.recommended_action)

        cred_alert = AlertRecord(
            alert_id="EDR-2001",
            timestamp_utc="2026-10-19T11:00:00Z",
            host="WKSTN-099",
            user="c.admin",
            severity="critical",
            rule="Credential dumping detected",
            process="lsass.exe",
            action="allowed",
            asset_criticality="critical",
            confidence=0.95,
        )
        rec_cred = build_recommendation(
            cred_alert,
            "P1 (Critical)",
            correlated_ids=[],
            criticality_level="critical",
            confidence_score=95.0,
        )
        self.assertIn("lsass.exe", rec_cred)
        self.assertNotIn("change records", rec_cred)

    def test_14_reusable_pattern_evaluation_independent_of_case_id_labels(self) -> None:
        """Verify evaluate_soc_test_cases works with custom case_id values."""
        auth_events, _ = load_auth_events_file(AUTH_CSV_PATH)
        custom_cases = [
            {
                "case_id": "CUSTOM-001",
                "input_pattern": "4+ login_failure events for same username and source IP within 2 minutes",
                "expected_class": "suspicious",
                "reason": "Custom ID test for brute-force pattern.",
            },
            {
                "case_id": "CUSTOM-002",
                "input_pattern": "privilege_granted event without change ticket",
                "expected_class": "high_review",
                "reason": "Custom ID test for unapproved privilege grant.",
            },
        ]
        results = evaluate_soc_test_cases(custom_cases, auth_events)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].passed)
        self.assertTrue(results[1].passed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
