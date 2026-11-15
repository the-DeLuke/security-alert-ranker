
# Security Alert Risk-Ranking & Incident Triage Prototype

A Python-based Security Operations Center (SOC) prototype for explainable alert prioritisation, cross-log correlation, detection scenario evaluation, and incident timeline reconstruction.

---

## Project Overview

Security Operations Center analysts handle multiple security alerts from different sources. Prioritising these alerts based only on severity may overlook asset criticality, detection confidence, and action exposure.

This project demonstrates a structured SOC alert-triage workflow using synthetic endpoint and authentication data.

### Key Objectives

- Process and validate endpoint security alerts.
- Calculate explainable risk scores.
- Classify alerts based on risk priority.
- Correlate endpoint alerts with authentication events.
- Evaluate predefined SOC detection scenarios.
- Generate strict and full-dataset incident timelines.
- Validate functionality through automated unit and regression tests.

---

## Key Features

### 1. Risk Scoring Model

The prototype calculates a risk score using four weighted components.

| Component | Weight |
|---|---:|
| Severity | 35% |
| Asset Criticality | 30% |
| Heuristic Confidence | 20% |
| Action Exposure | 15% |

**Risk Score Formula**

```text
Risk Score =
(0.35 × Severity) +
(0.30 × Asset Criticality) +
(0.20 × Confidence) +
(0.15 × Action Exposure)
```

### Priority Classification

| Priority | Classification | Score Range |
|---|---|---:|
| P1 | Critical | 75 and above |
| P2 | High | 60–74.99 |
| P3 | Medium | 40–59.99 |
| P4 | Low | Below 40 |

### 2. Ranked Alert Results

The prototype processes four synthetic endpoint alerts.

| Rank | Alert ID | Risk Score | Priority |
|---|---|---:|---|
| 1 | EDR-1004 | 90.50 | P1 Critical |
| 2 | EDR-1002 | 66.25 | P2 High |
| 3 | EDR-1003 | 66.00 | P2 High |
| 4 | EDR-1001 | 32.75 | P4 Low |

### 3. Cross-Log Correlation

The correlation engine analyses endpoint alerts alongside authentication events using:

- Host-aware event matching.
- User and IP address matching where applicable.
- Scenario-specific temporal correlation windows.
- Directional event correlation.
- Matched and excluded event explanations.

**Example correlated events:**

| Endpoint Alert | Authentication Events |
|---|---|
| EDR-1004 | AUTH-0016, AUTH-0017 |
| EDR-1002 | AUTH-0009, AUTH-0010 |
| EDR-1003 | AUTH-0012, AUTH-0013, AUTH-0014 |

### 4. SOC Detection Scenario Evaluation

The prototype evaluates five detection scenarios:

| Test Case | Detection Scenario |
|---|---|
| SOC-T01 | Repeated login failures |
| SOC-T02 | Repeated MFA denials |
| SOC-T03 | Privilege grant without a change ticket |
| SOC-T04 | Login failure followed by MFA success |
| SOC-T05 | Scheduled service-account login |

Two evaluation modes are supported.

**Mode A: Full-Dataset Evaluation**

- Evaluates all 20 authentication events.
- Includes events outside the official incident window.
- Generates a 24-event timeline.

**Mode B: Strict Incident-Window Evaluation**

- Evaluates events only within the official incident window.
- Incident window: 19 October 2026, 08:00–10:30 UTC.
- Generates a 23-event timeline.
- Excludes AUTH-0020 because it occurs after the incident window.

### SOC-T04 Timing Discrepancy

| Event | Timestamp (UTC) | Description |
|---|---|---|
| AUTH-0019 | 10:22:16 | Login failure |
| AUTH-0020 | 11:51:08 | MFA login success |

Time difference: **88 minutes and 52 seconds**.

Mode A identifies the full-dataset pattern as `likely_benign`, with a post-window warning.

Mode B returns `insufficient_evidence` because AUTH-0020 is outside the official incident window.

This distinction prevents post-window activity from being incorrectly treated as evidence within the incident window.

---

## Technology Stack

- Python 3.12
- JSON
- CSV
- Python Dataclasses
- Python unittest
- Command-Line Interface (CLI)

The prototype uses Python's standard library and does not require third-party packages.

---

## Project Structure

```text
security-alert-ranker/
│
├── 03_SOC_LOGS/
│   ├── endpoint_alerts.json
│   ├── authentication_events.csv
│   ├── soc_detection_test_cases.csv
│   └── incident_triage_brief.txt
│
├── src/
│   └── alert_ranker/
│       ├── __init__.py
│       ├── cli.py
│       ├── loader.py
│       ├── models.py
│       └── scorer.py
│
├── tests/
│   └── test_alert_ranker.py
│
├── evidence/
│   ├── 01_cli_execution.png
│   ├── 02_ranked_alerts.png
│   ├── 03_mode_a_evaluation.png
│   ├── 04_mode_b_evaluation.png
│   ├── 05_strict_timeline.png
│   └── 06_automated_tests.png
│
├── docs/
│   └── Technical_Report.pdf
│
├── README.md
├── .gitignore
├── TECHNICAL_REPORT.md
├── learning_journal.md
├── ranked_alerts_output.json
├── sample_triage_report.txt
└── test_evidence.txt
```

---

## Installation and Setup

### Requirements

- Python 3.12 or compatible version.
- Git.
- Visual Studio Code or another Python-compatible editor.

### Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd security-alert-ranker
```

No external Python packages are required.

---

## Running the Prototype

### Windows PowerShell

Set the Python module path:

```powershell
$env:PYTHONPATH="src"
```

Execute the alert-ranking prototype:

```powershell
py -3.12 -m alert_ranker.cli --alerts 03_SOC_LOGS/endpoint_alerts.json --auth-events 03_SOC_LOGS/authentication_events.csv --test-cases 03_SOC_LOGS/soc_detection_test_cases.csv --include-timeline --json-out ranked_alerts_output.json
```

The CLI performs the following operations:

1. Loads endpoint alerts and authentication events.
2. Validates input records.
3. Calculates risk scores.
4. Ranks endpoint alerts.
5. Evaluates SOC detection scenarios.
6. Generates incident timelines.
7. Exports ranked results to JSON.

---

## Running Automated Tests

Execute the following command in Windows PowerShell:

```powershell
cmd /c "set PYTHONPATH=src&& py -3.12 -X utf8 -m unittest discover -s tests -v"
```

**Expected test summary:**

```text
Ran 14 tests

OK
```

### Test Coverage

The 14 automated tests cover:

- Alert validation and ingestion.
- Risk-score calculation.
- Priority classification.
- Asset criticality and confidence assumptions.
- Malformed input handling.
- Correlation logic.
- Directional temporal windows.
- Host and user matching.
- Invalid timestamp handling.
- SOC detection scenario evaluation.
- SOC-T04 Mode A and Mode B behaviour.
- Strict and full timeline separation.
- Recommendations and assumptions.
- Reusable detection-pattern evaluation.

**Result: 14 automated tests passed.**

---

## Sample CLI Output

```text
SECURITY ALERT RISK-RANKING PROTOTYPE

Summary: 4 valid alert(s) ranked
         0 malformed record(s) skipped

Rank   Alert ID   Priority       Score

#1     EDR-1004   P1 Critical     90.50
#2     EDR-1002   P2 High         66.25
#3     EDR-1003   P2 High         66.00
#4     EDR-1001   P4 Low          32.75
```

---

## Limitations and Assumptions

- All supplied telemetry is synthetic training data.
- Confidence values are heuristic prioritisation scores, not calibrated probabilities.
- Asset criticality may be inferred from hostname conventions when explicit values are unavailable.
- Production deployments should retrieve asset criticality from an approved asset inventory or CMDB.
- Correlation results are investigative indicators and do not independently establish compromise.
- This prototype is an educational demonstration, not a production SOC platform.

---

## Project Documentation

| File | Description |
|---|---|
| `TECHNICAL_REPORT.md` | Technical methodology, architecture, scoring, correlation and test results |
| `learning_journal.md` | Learning notes and technical reflections |
| `test_evidence.txt` | Automated test execution evidence |
| `ranked_alerts_output.json` | Generated ranked alert output |
| `sample_triage_report.txt` | Sample SOC triage report |

---

## Disclaimer

This project was developed for cybersecurity learning and internship purposes using synthetic security data. It does not contain real endpoint telemetry or represent a production incident investigation.

---

## Author

**Dany Geo Johnson**

Cybersecurity | SOC Operations | Threat Detection | Vulnerability Assessment
