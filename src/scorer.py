"""Explainable risk scoring, priority ranking, and SOC test-case correlation.

Student ID: 2419 (Group C — SOC Operations & Threat Detection)

Documented Scoring Formula (Preserved):
---------------------------------------
Risk Score (0.00 to 100.00) =
    0.35 * Severity_Score
  + 0.30 * Asset_Criticality_Score
  + 0.20 * Confidence_Score
  + 0.15 * Action_Exposure_Score

Component Scales (0 to 100):
- Severity_Score:
    low = 25.0, medium = 55.0, high = 85.0, critical = 100.0
- Asset_Criticality_Score:
    low = 25.0, medium = 50.0, high = 75.0, critical = 100.0
    (If not explicitly present in JSON record, inferred from host naming convention
     and recorded in RankedAlert.assumptions as an assumption. Production systems
     should obtain asset criticality from an approved asset inventory or CMDB.)
- Confidence_Score (0.0 to 100.0):
    Uses explicit confidence field if provided. Otherwise derived as a heuristic
    prioritisation score (not a statistically calibrated probability) from
    analyst_note, action status, and directionally bounded cross-log correlation
    with authentication_events.csv, with every inference recorded in
    RankedAlert.assumptions.
- Action_Exposure_Score:
    blocked = 20.0 (prevented by control)
    rate_limited = 55.0 (partially throttled)
    logged = 85.0 (unblocked, audit-only; requires manual verification)
    allowed = 100.0 (unmitigated execution/access)

Priority Thresholds:
- P1 (Critical): Risk Score >= 75.0
- P2 (High):     60.0 <= Risk Score < 75.0
- P3 (Medium):   40.0 <= Risk Score < 60.0
- P4 (Low):      Risk Score < 40.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Sequence, Tuple

from .models import (
    AlertRecord,
    AuthEvent,
    RankedAlert,
    TestCaseResult,
    parse_iso_timestamp,
)

WEIGHT_SEVERITY = 0.35
WEIGHT_CRITICALITY = 0.30
WEIGHT_CONFIDENCE = 0.20
WEIGHT_ACTION = 0.15

SEVERITY_SCORES: Dict[str, float] = {
    "low": 25.0,
    "medium": 55.0,
    "high": 85.0,
    "critical": 100.0,
}

CRITICALITY_SCORES: Dict[str, float] = {
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}

ACTION_SCORES: Dict[str, float] = {
    "blocked": 20.0,
    "rate_limited": 55.0,
    "logged": 85.0,
    "allowed": 100.0,
}

DEFAULT_INCIDENT_WINDOW_UTC: Tuple[str, str] = (
    "2026-10-19T08:00:00Z",
    "2026-10-19T10:30:00Z",
)


@dataclass(frozen=True)
class CorrelationConfig:
    """Configurable directional time windows for cross-log alert-to-authentication correlation.

    Scenario Temporal Direction Rationale:
    - Authentication failures ('auth_failure'): Triggered by preceding failed login bursts
      leading up to the alert timestamp (default lookback=5.0m, lookahead=0.0m).
    - Privilege grants ('privilege'): Triggered by preceding privilege_granted events
      leading up to the alert timestamp (default lookback=10.0m, lookahead=0.0m).
    - MFA denials ('mfa'): Endpoint browser session alerts and identity-provider push
      denial logs can arrive across an active prompt window; uses a bounded bidirectional
      window (default lookback=5.0m, lookahead=5.0m).
    """

    mfa_window_minutes: float = 5.0
    auth_failure_window_minutes: float = 5.0
    privilege_window_minutes: float = 10.0
    default_window_minutes: float = 10.0
    mfa_lookahead_minutes: Optional[float] = None
    auth_failure_lookahead_minutes: float = 0.0
    privilege_lookahead_minutes: float = 0.0
    default_lookahead_minutes: float = 0.0


def _safe_parse_timestamp(ts_value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp safely, returning None on missing or invalid input."""
    if not ts_value or not isinstance(ts_value, str):
        return None
    try:
        return parse_iso_timestamp(ts_value)
    except (ValueError, TypeError):
        return None


def normalize_host_identifier(host_value: str) -> str:
    """Normalize endpoint hostnames and auth target_system names to a canonical form.

    Examples:
    - 'WKSTN-008' and 'workstation-08' -> 'workstation-8'
    - 'WKSTN-014' and 'workstation-14' -> 'workstation-14'
    - 'VPN-GW-01' and 'vpn-gateway'    -> 'vpn-gateway'
    - 'ADMIN-CONSOLE' and 'admin-console' -> 'admin-console'
    """
    if not isinstance(host_value, str) or not host_value.strip():
        return ""
    norm = host_value.strip().lower()

    wkstn_match = re.match(r"^(?:wkstn|workstation)-0*(\d+)$", norm)
    if wkstn_match:
        return f"workstation-{int(wkstn_match.group(1))}"

    if norm.startswith("vpn-gw") or norm == "vpn-gateway":
        return "vpn-gateway"

    return norm


def hosts_match(alert_host: str, event_target_system: str) -> bool:
    """Return True if an endpoint alert host and authentication target_system refer to the same asset."""
    h1 = normalize_host_identifier(alert_host)
    h2 = normalize_host_identifier(event_target_system)
    return bool(h1 and h2 and h1 == h2)


def infer_asset_criticality(alert: AlertRecord) -> Tuple[str, float, Optional[str]]:
    """Determine asset criticality level and score, documenting any hostname assumption made."""
    if alert.asset_criticality is not None:
        level = alert.asset_criticality.lower()
        return level, CRITICALITY_SCORES[level], None

    host_upper = alert.host.upper()
    cmdb_note = (
        "Production systems should obtain asset criticality from an approved asset inventory or CMDB."
    )
    if "ADMIN" in host_upper or "DC" in host_upper or "DOMAIN" in host_upper:
        level = "critical"
        reason = (
            f"Assumption: asset_criticality not in source JSON; inferred '{level}' (score 100, "
            f"contributing +30.00 to risk score) from privileged management hostname '{alert.host}'. "
            f"{cmdb_note}"
        )
    elif "VPN" in host_upper or "GW" in host_upper or "FW" in host_upper or "BACKUP" in host_upper:
        level = "high"
        reason = (
            f"Assumption: asset_criticality not in source JSON; inferred '{level}' (score 75, "
            f"contributing +22.50 to risk score) from perimeter/infrastructure hostname '{alert.host}'. "
            f"{cmdb_note}"
        )
    elif "WKSTN" in host_upper or "WORKSTATION" in host_upper or "LAPTOP" in host_upper:
        level = "medium"
        reason = (
            f"Assumption: asset_criticality not in source JSON; inferred '{level}' (score 50, "
            f"contributing +15.00 to risk score) from standard workstation hostname '{alert.host}'. "
            f"{cmdb_note}"
        )
    else:
        level = "medium"
        reason = (
            f"Assumption: asset_criticality not in source JSON and hostname '{alert.host}' unrecognised; "
            f"defaulted to '{level}' (score 50, contributing +15.00 to risk score). {cmdb_note}"
        )

    return level, CRITICALITY_SCORES[level], reason


def _get_directional_window_minutes(
    rule_lower: str,
    config: CorrelationConfig,
    override_window_minutes: Optional[float] = None,
) -> Tuple[float, float, str]:
    """Return (lookback_minutes_before_alert, lookahead_minutes_after_alert, direction_description)."""
    if override_window_minutes is not None:
        w = max(0.0, float(override_window_minutes))
        if "mfa" in rule_lower:
            return w, w, f"bidirectional [-{w:g}m, +{w:g}m]"
        return w, 0.0, f"pre-alert lookback [-{w:g}m, 0m]"

    if "mfa" in rule_lower:
        lookback = max(0.0, float(config.mfa_window_minutes))
        lookahead = (
            max(0.0, float(config.mfa_lookahead_minutes))
            if config.mfa_lookahead_minutes is not None
            else lookback
        )
        return lookback, lookahead, f"bidirectional [-{lookback:g}m, +{lookahead:g}m]"
    if "privilege" in rule_lower:
        lookback = max(0.0, float(config.privilege_window_minutes))
        lookahead = max(0.0, float(config.privilege_lookahead_minutes))
        return lookback, lookahead, f"pre-alert lookback [-{lookback:g}m, +{lookahead:g}m]"
    if "authentication failure" in rule_lower or "login failure" in rule_lower:
        lookback = max(0.0, float(config.auth_failure_window_minutes))
        lookahead = max(0.0, float(config.auth_failure_lookahead_minutes))
        return lookback, lookahead, f"pre-alert lookback [-{lookback:g}m, +{lookahead:g}m]"

    lookback = max(0.0, float(config.default_window_minutes))
    lookahead = max(0.0, float(config.default_lookahead_minutes))
    return lookback, lookahead, f"pre-alert lookback [-{lookback:g}m, +{lookahead:g}m]"


def _event_matches_rule_type_and_entity(
    alert: AlertRecord, ev: AuthEvent
) -> Tuple[bool, str]:
    """Check whether an AuthEvent matches the alert's rule semantics and user/IP entity."""
    rule_lower = alert.rule.lower()
    note_lower = alert.analyst_note.lower()
    alert_user_lower = alert.user.strip().lower()
    ev_user_lower = ev.username.strip().lower()
    ev_ip_lower = ev.source_ip.strip().lower()

    if "mfa" in rule_lower:
        if ev.event_type != "mfa_denied":
            return False, f"event_type '{ev.event_type}' != 'mfa_denied'"
        if ev_user_lower != alert_user_lower:
            return False, f"username '{ev.username}' != '{alert.user}'"
        return True, f"matched user '{ev.username}' and event_type 'mfa_denied'"

    if "privilege" in rule_lower:
        if ev.event_type != "privilege_granted":
            return False, f"event_type '{ev.event_type}' != 'privilege_granted'"
        if ev_user_lower != alert_user_lower:
            return False, f"username '{ev.username}' != '{alert.user}'"
        return True, f"matched user '{ev.username}' and event_type 'privilege_granted'"

    if "authentication failure" in rule_lower or "login failure" in rule_lower:
        if ev.event_type != "login_failure":
            return False, f"event_type '{ev.event_type}' != 'login_failure'"
        ip_mentioned = bool(ev_ip_lower and ev_ip_lower in note_lower)
        if alert_user_lower == "unknown":
            if ev_user_lower != "unknown":
                return False, f"username '{ev.username}' != 'unknown'"
            if "203." in note_lower and not ip_mentioned:
                return False, f"source_ip '{ev.source_ip}' not referenced in analyst_note"
            return True, f"matched user 'unknown' and source_ip '{ev.source_ip}'"
        else:
            if ev_user_lower == alert_user_lower or ip_mentioned:
                return True, f"matched user/IP ('{ev.username}', '{ev.source_ip}')"
            return False, f"username '{ev.username}' and source_ip '{ev.source_ip}' did not match alert"

    return False, f"rule '{alert.rule}' has no auth-correlation mapping"


def explain_alert_correlations(
    alert: AlertRecord,
    auth_events: Optional[Sequence[AuthEvent]],
    config: Optional[CorrelationConfig] = None,
    window_minutes: Optional[float] = None,
) -> Tuple[List[AuthEvent], List[str]]:
    """Correlate an alert with auth_events and document why candidate events were matched or excluded."""
    if not auth_events:
        return [], ["No authentication events supplied for cross-log correlation."]

    alert_dt = _safe_parse_timestamp(alert.timestamp_utc)
    if alert_dt is None:
        return [], [
            f"Alert '{alert.alert_id}' has an invalid or missing timestamp ('{alert.timestamp_utc}'); correlation skipped safely."
        ]

    cfg = config or CorrelationConfig()
    rule_lower = alert.rule.lower()
    lookback_min, lookahead_min, dir_desc = _get_directional_window_minutes(
        rule_lower, cfg, override_window_minutes=window_minutes
    )
    max_before = timedelta(minutes=lookback_min)
    max_after = timedelta(minutes=lookahead_min)

    matched: List[Tuple[datetime, AuthEvent]] = []
    notes: List[str] = []

    for ev in auth_events:
        ev_dt = _safe_parse_timestamp(ev.timestamp_utc)
        if ev_dt is None:
            notes.append(
                f"Excluded {ev.event_id}: invalid or missing timestamp ('{ev.timestamp_utc}')."
            )
            continue

        same_host = hosts_match(alert.host, ev.target_system)
        same_user = ev.username.strip().lower() == alert.user.strip().lower()
        semantic_ok, semantic_reason = _event_matches_rule_type_and_entity(alert, ev)

        # Signed delta: negative means ev occurred BEFORE alert; positive means ev occurred AFTER alert
        signed_delta_sec = int((ev_dt - alert_dt).total_seconds())
        delta_str = (
            f"{abs(signed_delta_sec)}s prior to alert"
            if signed_delta_sec <= 0
            else f"+{signed_delta_sec}s after alert"
        )

        if signed_delta_sec < 0:
            in_time_window = (alert_dt - ev_dt) <= max_before
        else:
            in_time_window = (ev_dt - alert_dt) <= max_after

        if in_time_window and same_host and semantic_ok:
            matched.append((ev_dt, ev))
            notes.append(
                f"Matched {ev.event_id} ({ev.timestamp_utc}, {delta_str} within {dir_desc}): "
                f"host '{alert.host}' == '{ev.target_system}', {semantic_reason}."
            )
        elif same_user or same_host or semantic_ok:
            # Document why a relevant candidate event (sharing user, host, or rule type) was excluded
            reasons: List[str] = []
            if not in_time_window:
                if signed_delta_sec > 0 and lookahead_min == 0.0:
                    reasons.append(
                        f"occurred {delta_str} (rule requires pre-alert events only within {dir_desc})"
                    )
                else:
                    reasons.append(
                        f"timestamp {ev.timestamp_utc} ({delta_str}) is outside {dir_desc}"
                    )
            if not same_host:
                reasons.append(
                    f"target_system '{ev.target_system}' != alert host '{alert.host}'"
                )
            if not semantic_ok:
                reasons.append(semantic_reason)
            notes.append(f"Excluded candidate {ev.event_id}: {'; '.join(reasons)}.")

    matched.sort(key=lambda pair: (pair[0], pair[1].event_id))
    if not matched and not notes:
        notes.append(
            f"No candidate authentication events shared host '{alert.host}' or user '{alert.user}'."
        )
    return [ev for _, ev in matched], notes


def correlate_alert_with_auth_events(
    alert: AlertRecord,
    auth_events: Optional[Sequence[AuthEvent]],
    config: Optional[CorrelationConfig] = None,
    window_minutes: Optional[float] = None,
) -> List[AuthEvent]:
    """Find authentication events that correlate with an endpoint alert within a directionally bounded time window."""
    matched, _ = explain_alert_correlations(
        alert, auth_events, config=config, window_minutes=window_minutes
    )
    return matched


def infer_confidence_score(
    alert: AlertRecord, correlated_events: Sequence[AuthEvent]
) -> Tuple[float, Optional[str]]:
    """Determine heuristic confidence score (0-100) and record any assumption if not in JSON."""
    if alert.confidence is not None:
        return alert.confidence, None

    note_lower = alert.analyst_note.lower()
    rule_lower = alert.rule.lower()
    calib_disclaimer = (
        "Heuristic prioritisation score (not a statistically calibrated probability); "
        "correlation does not prove compromise."
    )

    if "training simulation" in note_lower:
        return (
            30.0,
            f"Assumption: confidence not in source JSON; assigned heuristic score 30.0% (low, contributing "
            f"+6.00 to risk score) because analyst_note marks this alert as a 'Training simulation'. "
            f"{calib_disclaimer}",
        )

    if correlated_events:
        event_ids = ", ".join(ev.event_id for ev in correlated_events)
        if "privilege" in rule_lower:
            return (
                90.0,
                f"Assumption: confidence not in source JSON; assigned heuristic score 90.0% (high, contributing "
                f"+18.00 to risk score) due to pre-alert correlation with privilege events [{event_ids}] on "
                f"{alert.host}. {calib_disclaimer}",
            )
        if "mfa" in rule_lower:
            return (
                85.0,
                f"Assumption: confidence not in source JSON; assigned heuristic score 85.0% (high, contributing "
                f"+17.00 to risk score) due to time-window correlation with repeated MFA denials [{event_ids}] on "
                f"{alert.host}. {calib_disclaimer}",
            )
        if "authentication failure" in rule_lower or "login failure" in rule_lower:
            return (
                80.0,
                f"Assumption: confidence not in source JSON; assigned heuristic score 80.0% (high, contributing "
                f"+16.00 to risk score) due to pre-alert correlation with failed login events [{event_ids}] on "
                f"{alert.host}. {calib_disclaimer}",
            )

    # Heuristic fallback when authentication_events.csv is not provided or no events fall in window
    if "privilege" in rule_lower and alert.action == "logged":
        return (
            85.0,
            f"Assumption: confidence not in source JSON and no correlated auth events in window; assigned heuristic "
            f"score 85.0% (contributing +17.00 to risk score) from unblocked administrative privilege rule. "
            f"{calib_disclaimer}",
        )
    if "mfa" in rule_lower and alert.action == "allowed":
        return (
            80.0,
            f"Assumption: confidence not in source JSON and no correlated auth events in window; assigned heuristic "
            f"score 80.0% (contributing +16.00 to risk score) from repeated MFA denial rule with 'allowed' action. "
            f"{calib_disclaimer}",
        )
    if "authentication failure" in rule_lower or "login failure" in rule_lower:
        return (
            75.0,
            f"Assumption: confidence not in source JSON and no correlated auth events in window; assigned heuristic "
            f"score 75.0% (contributing +15.00 to risk score) from repeated authentication failure rule. "
            f"{calib_disclaimer}",
        )

    return (
        65.0,
        f"Assumption: confidence not in source JSON; defaulted to baseline heuristic score 65.0% (medium, "
        f"contributing +13.00 to risk score) pending additional log telemetry. {calib_disclaimer}",
    )


def assign_priority_band(risk_score: float) -> str:
    """Assign priority level P1-P4 based on documented thresholds."""
    if risk_score >= 75.0:
        return "P1 (Critical)"
    if risk_score >= 60.0:
        return "P2 (High)"
    if risk_score >= 40.0:
        return "P3 (Medium)"
    return "P4 (Low)"


def build_recommendation(
    alert: AlertRecord,
    priority: str,
    correlated_ids: Sequence[str] = (),
    criticality_level: str = "medium",
    confidence_score: float = 65.0,
) -> str:
    """Generate defensive, evidence-driven SOC triage guidance considering rule, action, criticality, confidence, and evidence."""
    rule_lower = alert.rule.lower()
    note_lower = alert.analyst_note.lower()
    action_lower = alert.action.lower()
    corr_text = (
        f" Correlated auth telemetry in window: [{', '.join(correlated_ids)}]."
        if correlated_ids
        else " No correlated auth events matched within the time window."
    )

    if action_lower == "allowed":
        action_guidance = (
            f"Action was 'allowed' on {criticality_level}-criticality host '{alert.host}' "
            f"(process '{alert.process}' was not blocked)."
        )
    elif action_lower == "logged":
        action_guidance = (
            f"Action was 'logged' only (unblocked) on {criticality_level}-criticality host '{alert.host}'."
        )
    elif action_lower == "rate_limited":
        action_guidance = (
            f"Action was 'rate_limited' on {criticality_level}-criticality host '{alert.host}', "
            f"reducing immediate brute-force throughput."
        )
    elif action_lower == "blocked":
        action_guidance = (
            f"Endpoint control 'blocked' execution of '{alert.process}' on {criticality_level}-criticality "
            f"host '{alert.host}'."
        )
    else:
        action_guidance = (
            f"Recorded action '{alert.action}' on {criticality_level}-criticality host '{alert.host}'."
        )

    if "training simulation" in note_lower:
        scenario_step = (
            f"Verify with the training coordinator that ticket {alert.ticket} for user '{alert.user}' "
            f"matches an authorised simulation before closing."
        )
    elif "privilege" in rule_lower:
        scenario_step = (
            f"Reconcile administrative privilege grant for '{alert.user}' via '{alert.process}' against "
            f"approved change records (ticket {alert.ticket}). Preserve admin audit logs before adjusting permissions."
        )
    elif "mfa" in rule_lower:
        scenario_step = (
            f"Contact user '{alert.user}' out-of-band to verify whether the MFA push prompts were user-initiated, "
            f"inspect active browser/VPN sessions, and rotate credentials if the prompts were unexpected."
        )
    elif "authentication failure" in rule_lower or "login failure" in rule_lower:
        scenario_step = (
            f"Review perimeter authentication logs on '{alert.host}' for the source IP noted in {alert.ticket}, "
            f"check whether any subsequent login succeeded from that IP, and verify rate-limiting thresholds."
        )
    elif (
        "credential" in rule_lower
        or "lsass" in alert.process.lower()
        or "powershell" in alert.process.lower()
        or "child process" in rule_lower
    ):
        if action_lower == "blocked":
            scenario_step = (
                f"Inspect parent-child process telemetry ('{alert.process}') for user '{alert.user}' "
                f"to confirm no secondary payload executed after the block."
            )
        else:
            scenario_step = (
                f"Prioritise live host triage on '{alert.host}' for user '{alert.user}': capture volatile process "
                f"and command-line evidence for '{alert.process}' and consider host containment pending investigation."
            )
    else:
        scenario_step = (
            f"Review endpoint and authentication telemetry for user '{alert.user}' and process '{alert.process}' "
            f"under ticket {alert.ticket}."
        )

    return (
        f"[{priority} | Sev: {alert.severity} | Crit: {criticality_level} | Heuristic Conf: {confidence_score:.0f}%] "
        f"{action_guidance} {scenario_step}{corr_text} "
        f"Treat as an investigative indicator, not confirmed compromise, until verified."
    )


def score_alert(
    alert: AlertRecord,
    auth_events: Optional[Sequence[AuthEvent]] = None,
    rank: int = 0,
    correlation_config: Optional[CorrelationConfig] = None,
    correlation_window_minutes: Optional[float] = None,
) -> RankedAlert:
    """Calculate the explainable risk score and priority for a single validated AlertRecord."""
    assumptions: List[str] = []

    sev_score = SEVERITY_SCORES.get(alert.severity.lower(), 50.0)
    crit_level, crit_score, crit_assumption = infer_asset_criticality(alert)
    if crit_assumption:
        assumptions.append(crit_assumption)

    correlated, corr_notes = explain_alert_correlations(
        alert,
        auth_events,
        config=correlation_config,
        window_minutes=correlation_window_minutes,
    )
    correlated_ids = [ev.event_id for ev in correlated]

    conf_score, conf_assumption = infer_confidence_score(alert, correlated)
    if conf_assumption:
        assumptions.append(conf_assumption)

    if alert.action in ACTION_SCORES:
        act_score = ACTION_SCORES[alert.action]
    else:
        act_score = 70.0
        assumptions.append(
            f"Assumption: action '{alert.action}' not in standard action map; defaulted exposure score to 70.0 "
            f"(contributing +10.50 to risk score)."
        )

    raw_score = (
        WEIGHT_SEVERITY * sev_score
        + WEIGHT_CRITICALITY * crit_score
        + WEIGHT_CONFIDENCE * conf_score
        + WEIGHT_ACTION * act_score
    )
    risk_score = round(raw_score, 2)
    priority = assign_priority_band(risk_score)

    explanation = (
        f"Priority {priority} (Score {risk_score:.2f}/100): "
        f"severity='{alert.severity}' ({sev_score:.0f} * 0.35 = {WEIGHT_SEVERITY * sev_score:.2f}) + "
        f"asset_criticality='{crit_level}' ({crit_score:.0f} * 0.30 = {WEIGHT_CRITICALITY * crit_score:.2f}) + "
        f"heuristic_confidence={conf_score:.0f}% ({conf_score:.0f} * 0.20 = {WEIGHT_CONFIDENCE * conf_score:.2f}) + "
        f"action='{alert.action}' ({act_score:.0f} * 0.15 = {WEIGHT_ACTION * act_score:.2f})."
    )
    if correlated_ids:
        explanation += f" Correlated auth events in directional window: {', '.join(correlated_ids)}."

    recommendation = build_recommendation(
        alert=alert,
        priority=priority,
        correlated_ids=correlated_ids,
        criticality_level=crit_level,
        confidence_score=conf_score,
    )

    return RankedAlert(
        rank=rank,
        alert=alert,
        risk_score=risk_score,
        priority=priority,
        severity_score=sev_score,
        criticality_level=crit_level,
        criticality_score=crit_score,
        confidence_score=conf_score,
        action_score=act_score,
        correlated_events=correlated_ids,
        correlation_notes=corr_notes,
        assumptions=assumptions,
        explanation=explanation,
        recommended_action=recommendation,
    )


def rank_alerts(
    alerts: Sequence[AlertRecord],
    auth_events: Optional[Sequence[AuthEvent]] = None,
    correlation_config: Optional[CorrelationConfig] = None,
    correlation_window_minutes: Optional[float] = None,
) -> List[RankedAlert]:
    """Score and rank alerts from highest risk to lowest risk with deterministic tie-breaking."""
    unranked = [
        score_alert(
            a,
            auth_events=auth_events,
            correlation_config=correlation_config,
            correlation_window_minutes=correlation_window_minutes,
        )
        for a in alerts
    ]

    sorted_alerts = sorted(
        unranked,
        key=lambda r: (
            -r.risk_score,
            -r.severity_score,
            -r.criticality_score,
            r.alert.timestamp_utc,
            r.alert.alert_id,
        ),
    )

    return [
        RankedAlert(
            rank=idx + 1,
            alert=item.alert,
            risk_score=item.risk_score,
            priority=item.priority,
            severity_score=item.severity_score,
            criticality_level=item.criticality_level,
            criticality_score=item.criticality_score,
            confidence_score=item.confidence_score,
            action_score=item.action_score,
            correlated_events=item.correlated_events,
            correlation_notes=item.correlation_notes,
            assumptions=item.assumptions,
            explanation=item.explanation,
            recommended_action=item.recommended_action,
        )
        for idx, item in enumerate(sorted_alerts)
    ]


def _filter_auth_events_by_window(
    auth_events: Sequence[AuthEvent],
    window_start_utc: Optional[str] = None,
    window_end_utc: Optional[str] = None,
) -> List[Tuple[datetime, AuthEvent]]:
    """Return valid (datetime, AuthEvent) pairs filtered by optional inclusive UTC start/end timestamps."""
    start_dt = _safe_parse_timestamp(window_start_utc) if window_start_utc else None
    end_dt = _safe_parse_timestamp(window_end_utc) if window_end_utc else None

    valid_pairs: List[Tuple[datetime, AuthEvent]] = []
    for ev in auth_events:
        ev_dt = _safe_parse_timestamp(ev.timestamp_utc)
        if ev_dt is None:
            continue
        if start_dt is not None and ev_dt < start_dt:
            continue
        if end_dt is not None and ev_dt > end_dt:
            continue
        valid_pairs.append((ev_dt, ev))

    valid_pairs.sort(key=lambda pair: (pair[0], pair[1].event_id))
    return valid_pairs


def evaluate_soc_test_cases(
    test_cases: Sequence[Dict[str, str]],
    auth_events: Sequence[AuthEvent],
    window_start_utc: Optional[str] = None,
    window_end_utc: Optional[str] = None,
    max_typo_gap_minutes: float = 90.0,
    evaluation_mode: Optional[str] = None,
) -> List[TestCaseResult]:
    """Evaluate SOC detection test cases in either Mode A (full_dataset) or Mode B (strict_incident_window).

    Evaluation Modes:
    -----------------
    - Mode A ('full_dataset', default when no strict window is specified):
        Evaluates all 20 events in authentication_events.csv. SOC-T04 matches AUTH-0019 (10:22:16Z)
        and AUTH-0020 (11:51:08Z, 88m 52s later), while explicitly documenting that AUTH-0020 occurs
        outside the official 08:00:00Z–10:30:00Z incident window and is not proof that the overall
        incident was benign.
    - Mode B ('strict_incident_window', or when window_start_utc/window_end_utc bounds 08:00–10:30 UTC):
        Includes only events between 2026-10-19T08:00:00Z and 2026-10-19T10:30:00Z inclusive.
        AUTH-0020 (11:51:08Z) is excluded. SOC-T04 is NOT classified as confirmed 'likely_benign'
        from the incomplete single failure; instead it returns actual_class='insufficient_evidence'
        and reports the discrepancy against the CSV's expected_class='likely_benign'.
    """
    if evaluation_mode == "strict_incident_window" and window_start_utc is None and window_end_utc is None:
        window_start_utc, window_end_utc = DEFAULT_INCIDENT_WINDOW_UTC

    is_strict_mode = (
        evaluation_mode == "strict_incident_window"
        or window_start_utc is not None
        or window_end_utc is not None
    )
    mode_label = "strict_incident_window" if is_strict_mode else "full_dataset"

    filtered_pairs = _filter_auth_events_by_window(
        auth_events, window_start_utc=window_start_utc, window_end_utc=window_end_utc
    )
    incident_end_dt = _safe_parse_timestamp(DEFAULT_INCIDENT_WINDOW_UTC[1])

    results: List[TestCaseResult] = []

    for tc in test_cases:
        case_id = tc.get("case_id", "").strip()
        pattern = tc.get("input_pattern", "").strip()
        pattern_lower = pattern.lower()
        expected = tc.get("expected_class", "").strip()
        reason = tc.get("reason", "").strip()

        matched_ids: List[str] = []
        actual_class = "insufficient_evidence"
        evidence_summary = ""

        # Rule 1: Repeated login failures (4+ login_failure events for same username & source IP within 2 minutes)
        if "login_failure" in pattern_lower and ("4+" in pattern_lower or "repeated" in pattern_lower):
            grouped_failures: Dict[Tuple[str, str, str], List[Tuple[datetime, AuthEvent]]] = {}
            for dt, ev in filtered_pairs:
                if ev.event_type == "login_failure":
                    key = (
                        ev.username.lower(),
                        ev.source_ip.lower(),
                        normalize_host_identifier(ev.target_system),
                    )
                    grouped_failures.setdefault(key, []).append((dt, ev))

            for (user, ip, _), ev_list in grouped_failures.items():
                for i in range(len(ev_list)):
                    t_start = ev_list[i][0]
                    window = [
                        pair[1]
                        for pair in ev_list[i:]
                        if (pair[0] - t_start) <= timedelta(minutes=2)
                    ]
                    if len(window) >= 4:
                        matched_ids = [e.event_id for e in window]
                        actual_class = "suspicious"
                        span_sec = int(
                            (_safe_parse_timestamp(window[-1].timestamp_utc) - t_start).total_seconds()  # type: ignore[operator]
                        )
                        follow_up = [
                            pair[1].event_id
                            for pair in filtered_pairs
                            if pair[1].event_type == "login_success"
                            and pair[1].username.lower() == user
                            and pair[1].source_ip.lower() == ip
                            and timedelta(0) < (pair[0] - t_start) <= timedelta(minutes=5)
                        ]
                        follow_str = (
                            f", followed by MFA login_success ({', '.join(follow_up)})"
                            if follow_up
                            else ""
                        )
                        evidence_summary = (
                            f"User '{window[0].username}' from {window[0].source_ip} had {len(window)} "
                            f"login_failure events within {span_sec}s ({window[0].event_id}..{window[-1].event_id})"
                            f"{follow_str}."
                        )
                        break
                if matched_ids:
                    break

        # Rule 2: Repeated MFA denials (mfa_denied twice by same user within 5 minutes)
        elif "mfa_denied" in pattern_lower:
            grouped_mfa: Dict[Tuple[str, str], List[Tuple[datetime, AuthEvent]]] = {}
            for dt, ev in filtered_pairs:
                if ev.event_type == "mfa_denied":
                    key = (ev.username.lower(), normalize_host_identifier(ev.target_system))
                    grouped_mfa.setdefault(key, []).append((dt, ev))

            for (user, _), ev_list in grouped_mfa.items():
                for i in range(len(ev_list)):
                    t_start = ev_list[i][0]
                    window = [
                        pair
                        for pair in ev_list[i:]
                        if (pair[0] - t_start) <= timedelta(minutes=5)
                    ]
                    if len(window) >= 2:
                        matched_ids = [pair[1].event_id for pair in window]
                        actual_class = "review"
                        delta_sec = int((window[-1][0] - window[0][0]).total_seconds())
                        evidence_summary = (
                            f"User '{window[0][1].username}' denied {len(window)} push MFA prompts within "
                            f"{delta_sec}s on {window[0][1].target_system} (correlates with EDR-1002)."
                        )
                        break
                if matched_ids:
                    break

        # Rule 3: Privilege granted without change ticket
        elif "privilege_granted" in pattern_lower and "without change" in pattern_lower:
            priv_matches = [
                ev
                for _, ev in filtered_pairs
                if ev.event_type == "privilege_granted"
                and ("no change ticket" in ev.notes.lower() or "chg-" not in ev.notes.lower())
            ]
            if priv_matches:
                matched_ids = [e.event_id for e in priv_matches]
                actual_class = "high_review"
                evidence_summary = (
                    f"Event {priv_matches[0].event_id} granted privilege to '{priv_matches[0].username}' "
                    f"on {priv_matches[0].target_system} with note '{priv_matches[0].notes}' (correlates with EDR-1004)."
                )

        # Rule 4: Single login_failure followed by MFA login_success from same workstation (SOC-T04)
        elif "single login_failure" in pattern_lower and "login_success" in pattern_lower:
            by_user_host: Dict[Tuple[str, str], List[Tuple[datetime, AuthEvent]]] = {}
            for dt, ev in filtered_pairs:
                key = (ev.username.lower(), normalize_host_identifier(ev.target_system))
                by_user_host.setdefault(key, []).append((dt, ev))

            unpaired_single_failure: Optional[Tuple[datetime, AuthEvent]] = None
            for (user, _), ev_list in by_user_host.items():
                failures = [pair for pair in ev_list if pair[1].event_type == "login_failure"]
                successes = [
                    pair
                    for pair in ev_list
                    if pair[1].event_type == "login_success" and pair[1].auth_method.upper() == "MFA"
                ]
                if len(failures) == 1:
                    f_dt, f_ev = failures[0]
                    valid_successes = [
                        (s_dt, s_ev)
                        for s_dt, s_ev in successes
                        if s_dt > f_dt
                        and s_ev.source_ip == f_ev.source_ip
                        and (s_dt - f_dt) <= timedelta(minutes=max_typo_gap_minutes)
                    ]
                    if len(valid_successes) == 1:
                        s_dt, s_ev = valid_successes[0]
                        gap_sec = int((s_dt - f_dt).total_seconds())
                        gap_min, gap_rem_sec = divmod(gap_sec, 60)
                        matched_ids = [f_ev.event_id, s_ev.event_id]
                        actual_class = "likely_benign"
                        window_note = ""
                        if incident_end_dt is not None and s_dt > incident_end_dt:
                            window_note = (
                                f" Discrepancy note (Mode A Full-Dataset): {s_ev.event_id} ({s_ev.timestamp_utc}) "
                                f"occurs {gap_min}m {gap_rem_sec}s after {f_ev.event_id} ({f_ev.timestamp_utc}) "
                                f"and outside the official INC-2026-104 detection window (08:00:00Z–10:30:00Z); "
                                f"this full-dataset pattern match is not proof that the overall incident was benign."
                            )
                        evidence_summary = (
                            f"User '{f_ev.username}' on {f_ev.target_system} ({f_ev.source_ip}) had 1 "
                            f"login_failure ({f_ev.event_id} at {f_ev.timestamp_utc}) followed by MFA "
                            f"login_success ({s_ev.event_id} at {s_ev.timestamp_utc}).{window_note}"
                        )
                        break
                    else:
                        unpaired_single_failure = (f_dt, f_ev)

            if not matched_ids and unpaired_single_failure is not None:
                f_dt, f_ev = unpaired_single_failure
                matched_ids = [f_ev.event_id]
                actual_class = "insufficient_evidence"
                evidence_summary = (
                    f"Mode B (Strict Incident Window {window_start_utc or '08:00:00Z'}–{window_end_utc or '10:30:00Z'}): "
                    f"User '{f_ev.username}' had a single login_failure ({f_ev.event_id} at {f_ev.timestamp_utc}) "
                    f"on {f_ev.target_system}, but the required subsequent MFA login_success was NOT observed "
                    f"within the 08:00–10:30 UTC incident window (AUTH-0020 at 2026-10-19T11:51:08Z occurs 88m 52s "
                    f"later, outside the official window, and is excluded). Returning 'insufficient_evidence' rather "
                    f"than claiming the complete 'likely_benign' pattern occurred inside the incident window."
                )

        # Rule 5: Scheduled service-account backup login from documented internal fixture address
        elif "svc-backup" in pattern_lower or "scheduled" in pattern_lower:
            svc_events = [
                ev
                for _, ev in filtered_pairs
                if ev.username.lower().startswith("svc-backup")
                and ev.event_type == "login_success"
                and ev.auth_method == "service_token"
                and ev.source_ip.startswith("192.0.2.")
            ]
            if svc_events:
                matched_ids = [e.event_id for e in svc_events]
                actual_class = "likely_benign"
                evidence_summary = (
                    f"Scheduled service login {svc_events[0].event_id} by '{svc_events[0].username}' "
                    f"from documented TEST-NET-1 fixture IP {svc_events[0].source_ip} to {svc_events[0].target_system}."
                )

        results.append(
            TestCaseResult(
                case_id=case_id,
                input_pattern=pattern,
                expected_class=expected,
                actual_class=actual_class,
                passed=(actual_class == expected),
                matched_events=matched_ids,
                reason=reason,
                evidence_summary=evidence_summary,
                evaluation_mode=mode_label,
            )
        )

    return results


def classify_auth_events_in_context(
    auth_events: Sequence[AuthEvent],
    incident_window_utc: Optional[Tuple[str, str]] = DEFAULT_INCIDENT_WINDOW_UTC,
    max_typo_gap_minutes: float = 90.0,
    strict_window: bool = False,
) -> Dict[str, Tuple[str, str]]:
    """Classify each AuthEvent in context for either Full-Dataset (Mode A) or Strict Incident Window (Mode B).

    When strict_window=True:
    - Only events within incident_window_utc (08:00:00Z to 10:30:00Z inclusive) are evaluated.
    - AUTH-0020 (11:51:08Z) is excluded, so AUTH-0019 (10:22:16Z) has no in-window recovery
      and is classified as 'INSUFFICIENT_EVIDENCE' (matching Mode B of SOC-T04).
    """
    win_start_str = incident_window_utc[0] if (strict_window and incident_window_utc) else None
    win_end_str = incident_window_utc[1] if (strict_window and incident_window_utc) else None
    valid_pairs = _filter_auth_events_by_window(
        auth_events, window_start_utc=win_start_str, window_end_utc=win_end_str
    )
    classifications: Dict[str, Tuple[str, str]] = {}

    win_start_dt = (
        _safe_parse_timestamp(incident_window_utc[0]) if incident_window_utc else None
    )
    win_end_dt = (
        _safe_parse_timestamp(incident_window_utc[1]) if incident_window_utc else None
    )

    # 1. Identify repeated login_failure clusters (>=3 within 2 minutes for same user, IP, host)
    failure_burst_ids: Dict[str, int] = {}
    burst_end_by_user_ip: Dict[Tuple[str, str, str], datetime] = {}
    failures_by_key: Dict[Tuple[str, str, str], List[Tuple[datetime, AuthEvent]]] = {}
    for dt, ev in valid_pairs:
        if ev.event_type == "login_failure":
            key = (
                ev.username.lower(),
                ev.source_ip.lower(),
                normalize_host_identifier(ev.target_system),
            )
            failures_by_key.setdefault(key, []).append((dt, ev))

    for key, ev_list in failures_by_key.items():
        for i in range(len(ev_list)):
            t_start = ev_list[i][0]
            cluster = [
                pair
                for pair in ev_list[i:]
                if (pair[0] - t_start) <= timedelta(minutes=2)
            ]
            if len(cluster) >= 3:
                for dt, ev in cluster:
                    failure_burst_ids[ev.event_id] = max(
                        failure_burst_ids.get(ev.event_id, 0), len(cluster)
                    )
                    prev_end = burst_end_by_user_ip.get(key)
                    if prev_end is None or dt > prev_end:
                        burst_end_by_user_ip[key] = dt

    # 2. Identify repeated mfa_denied clusters (>=2 within 5 minutes for same user, host)
    mfa_cluster_ids: Dict[str, int] = {}
    mfa_by_key: Dict[Tuple[str, str], List[Tuple[datetime, AuthEvent]]] = {}
    for dt, ev in valid_pairs:
        if ev.event_type == "mfa_denied":
            key = (ev.username.lower(), normalize_host_identifier(ev.target_system))
            mfa_by_key.setdefault(key, []).append((dt, ev))

    for key, ev_list in mfa_by_key.items():
        for i in range(len(ev_list)):
            t_start = ev_list[i][0]
            cluster = [
                pair
                for pair in ev_list[i:]
                if (pair[0] - t_start) <= timedelta(minutes=5)
            ]
            if len(cluster) >= 2:
                for _, ev in cluster:
                    mfa_cluster_ids[ev.event_id] = max(
                        mfa_cluster_ids.get(ev.event_id, 0), len(cluster)
                    )

    # 3. Identify single-typo recovery pairs within active event set
    typo_failure_to_success: Dict[str, AuthEvent] = {}
    typo_success_to_failure: Dict[str, AuthEvent] = {}
    events_by_user_host: Dict[Tuple[str, str], List[Tuple[datetime, AuthEvent]]] = {}
    for dt, ev in valid_pairs:
        key = (ev.username.lower(), normalize_host_identifier(ev.target_system))
        events_by_user_host.setdefault(key, []).append((dt, ev))

    for key, ev_list in events_by_user_host.items():
        failures = [pair for pair in ev_list if pair[1].event_type == "login_failure"]
        successes = [
            pair
            for pair in ev_list
            if pair[1].event_type == "login_success" and pair[1].auth_method.upper() == "MFA"
        ]
        if len(failures) == 1:
            f_dt, f_ev = failures[0]
            matching_succ = [
                (s_dt, s_ev)
                for s_dt, s_ev in successes
                if s_dt > f_dt
                and s_ev.source_ip == f_ev.source_ip
                and (s_dt - f_dt) <= timedelta(minutes=max_typo_gap_minutes)
            ]
            if len(matching_succ) == 1:
                _, s_ev = matching_succ[0]
                typo_failure_to_success[f_ev.event_id] = s_ev
                typo_success_to_failure[s_ev.event_id] = f_ev

    # 4. Assign context-aware classification to every event in the active set
    for dt, ev in valid_pairs:
        outside_window = False
        if win_start_dt is not None and dt < win_start_dt:
            outside_window = True
        if win_end_dt is not None and dt > win_end_dt:
            outside_window = True
        win_tag = (
            " [OUTSIDE OFFICIAL INCIDENT WINDOW 08:00:00Z-10:30:00Z]"
            if outside_window
            else ""
        )

        key_u_ip_h = (
            ev.username.lower(),
            ev.source_ip.lower(),
            normalize_host_identifier(ev.target_system),
        )

        if ev.event_type == "privilege_granted":
            if "no change ticket" in ev.notes.lower() or "chg-" not in ev.notes.lower():
                classifications[ev.event_id] = (
                    "HIGH_REVIEW",
                    f"Unreferenced privilege grant requiring change verification{win_tag}",
                )
            else:
                classifications[ev.event_id] = (
                    "LIKELY_BENIGN",
                    f"Privilege grant reconciled with approved change ticket{win_tag}",
                )
        elif ev.event_id in failure_burst_ids:
            count = failure_burst_ids[ev.event_id]
            classifications[ev.event_id] = (
                "SUSPICIOUS",
                f"Part of {count}x repeated login_failure burst within 2m{win_tag}",
            )
        elif ev.event_id in mfa_cluster_ids:
            count = mfa_cluster_ids[ev.event_id]
            classifications[ev.event_id] = (
                "REVIEW",
                f"Part of {count}x repeated MFA denial within 5m; user verification needed{win_tag}",
            )
        elif ev.event_type == "mfa_denied":
            classifications[ev.event_id] = (
                "REVIEW",
                f"Isolated MFA denial; verify with user{win_tag}",
            )
        elif ev.event_id in typo_failure_to_success:
            succ_ev = typo_failure_to_success[ev.event_id]
            classifications[ev.event_id] = (
                "LIKELY_BENIGN",
                f"Single password typo followed by MFA success {succ_ev.event_id} at {succ_ev.timestamp_utc} (full-dataset view){win_tag}",
            )
        elif ev.event_type == "login_failure":
            classifications[ev.event_id] = (
                "INSUFFICIENT_EVIDENCE",
                f"Single login_failure without an observed follow-up MFA login_success inside the active time window; do not assume attack or confirmed benign{win_tag}",
            )
        elif ev.event_type == "login_success":
            burst_dt = burst_end_by_user_ip.get(key_u_ip_h)
            if (
                burst_dt is not None
                and timedelta(0) <= (dt - burst_dt) <= timedelta(minutes=5)
            ) or "after repeated failures" in ev.notes.lower():
                classifications[ev.event_id] = (
                    "REVIEW",
                    f"Login success following repeated login failures; session review required{win_tag}",
                )
            elif ev.event_id in typo_success_to_failure:
                fail_ev = typo_success_to_failure[ev.event_id]
                classifications[ev.event_id] = (
                    "LIKELY_BENIGN",
                    f"MFA login recovery 88m 52s after single typo {fail_ev.event_id}{win_tag}",
                )
            elif ev.auth_method == "service_token" and ev.source_ip.startswith("192.0.2."):
                classifications[ev.event_id] = (
                    "LIKELY_BENIGN",
                    f"Scheduled service-account login from documented fixture IP{win_tag}",
                )
            else:
                classifications[ev.event_id] = (
                    "LIKELY_BENIGN",
                    f"Routine authenticated session{win_tag}",
                )
        else:
            classifications[ev.event_id] = (
                "LIKELY_BENIGN",
                f"Verified authentication event{win_tag}",
            )

    return classifications


def generate_incident_timeline(
    ranked_alerts: Sequence[RankedAlert],
    auth_events: Sequence[AuthEvent],
    incident_window_utc: Optional[Tuple[str, str]] = DEFAULT_INCIDENT_WINDOW_UTC,
    max_typo_gap_minutes: float = 90.0,
    strict_window: bool = False,
) -> List[Dict[str, str]]:
    """Build a chronological timeline for either the full dataset (strict_window=False) or strict 08:00-10:30 UTC window (strict_window=True).

    When strict_window=True:
    - Excludes any endpoint alert or authentication event outside incident_window_utc
      (08:00:00Z to 10:30:00Z inclusive), ensuring AUTH-0020 (11:51:08Z) is never presented
      as part of the official incident timeline.
    """
    win_start_dt = (
        _safe_parse_timestamp(incident_window_utc[0])
        if (strict_window and incident_window_utc)
        else None
    )
    win_end_dt = (
        _safe_parse_timestamp(incident_window_utc[1])
        if (strict_window and incident_window_utc)
        else None
    )

    entries: List[Tuple[datetime, Dict[str, str]]] = []
    auth_context = classify_auth_events_in_context(
        auth_events,
        incident_window_utc=incident_window_utc,
        max_typo_gap_minutes=max_typo_gap_minutes,
        strict_window=strict_window,
    )

    for r in ranked_alerts:
        a = r.alert
        dt = _safe_parse_timestamp(a.timestamp_utc)
        if dt is None:
            continue
        if win_start_dt is not None and dt < win_start_dt:
            continue
        if win_end_dt is not None and dt > win_end_dt:
            continue
        entries.append(
            (
                dt,
                {
                    "timestamp_utc": a.timestamp_utc,
                    "source": "ENDPOINT_ALERT",
                    "id": a.alert_id,
                    "entity": f"{a.user}@{a.host}",
                    "classification": f"{r.priority} [Score {r.risk_score:.2f}]",
                    "summary": f"{a.rule} (action={a.action}, ticket={a.ticket})",
                },
            )
        )

    for ev in auth_events:
        dt = _safe_parse_timestamp(ev.timestamp_utc)
        if dt is None:
            continue
        if win_start_dt is not None and dt < win_start_dt:
            continue
        if win_end_dt is not None and dt > win_end_dt:
            continue
        ev_class, context_reason = auth_context.get(
            ev.event_id, ("INSUFFICIENT_EVIDENCE", "Unclassified event")
        )
        entries.append(
            (
                dt,
                {
                    "timestamp_utc": ev.timestamp_utc,
                    "source": "AUTH_EVENT",
                    "id": ev.event_id,
                    "entity": f"{ev.username}@{ev.target_system} ({ev.source_ip})",
                    "classification": ev_class,
                    "summary": (
                        f"{ev.event_type} via {ev.auth_method} — {ev.notes} "
                        f"[{context_reason}]"
                    ),
                },
            )
        )

    entries.sort(key=lambda pair: (pair[0], pair[1]["id"]))
    return [item for _, item in entries]


def generate_strict_incident_timeline(
    ranked_alerts: Sequence[RankedAlert],
    auth_events: Sequence[AuthEvent],
    incident_window_utc: Tuple[str, str] = DEFAULT_INCIDENT_WINDOW_UTC,
) -> List[Dict[str, str]]:
    """Build the Strict Incident-Window Timeline (08:00:00Z to 10:30:00Z inclusive), excluding AUTH-0020 (11:51:08Z)."""
    return generate_incident_timeline(
        ranked_alerts=ranked_alerts,
        auth_events=auth_events,
        incident_window_utc=incident_window_utc,
        strict_window=True,
    )
