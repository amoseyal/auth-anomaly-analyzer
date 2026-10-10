# Authentication Anomaly Analyzer

A Python-based security analytics tool for detecting suspicious authentication activity through time-window analysis and event correlation.

The analyzer processes structured authentication logs and identifies brute-force activity, password spraying, and successful logins following repeated authentication failures. Detection results are presented as structured security alerts in the terminal, with optional CSV export and a self-contained HTML security analysis report.

The HTML report provides an executive summary, detection overview, investigation findings, supporting event evidence, and chronological authentication timelines.

Built with **Python, pandas, and pytest**, with **39 automated tests** covering detection logic, input validation, reporting, command-line integration, and end-to-end processing.

## Overview

The analyzer applies explicit, rule-based detection logic to authentication events using defined thresholds, correlation criteria, and time windows.

The project currently detects three authentication patterns:

- **Brute-force activity** — repeated failed authentication attempts against the same user account from the same source IP address.
- **Password spraying** — failed authentication attempts against multiple user accounts from a common source IP address.
- **Successful login after repeated failures** — a successful authentication following multiple failed attempts against the same account from the same source IP address.

Authentication data is loaded from CSV files, validated before analysis, and evaluated using defined thresholds and time windows. Detected anomalies are presented in the terminal and can optionally be exported to CSV for further analysis.

## Detection Rules

### 1. Brute Force

Identifies repeated failed authentication attempts against the same user account from the same source IP address.

**Detection criteria:**
- At least **5 failed login attempts**
- Same **username**
- Same **source IP address**
- Occurring within a **10-minute window**

The alert records the affected username, source IP address, failure count, and the timestamps of the first and last failures in the qualifying window.

### 2. Password Spraying

Identifies a source IP address attempting authentication against multiple distinct user accounts within a short period.

**Detection criteria:**
- At least **5 distinct usernames**
- Same **source IP address**
- Failed authentication attempts
- Occurring within a **10-minute window**

The alert records the source IP address, number of unique accounts targeted, usernames involved, and the timestamps of the first and last failures.

### 3. Successful Login After Repeated Failures

Identifies a successful authentication that occurs after repeated failed attempts against the same account from the same source IP address.

**Detection criteria:**
- At least **5 failed login attempts**
- Same **username**
- Same **source IP address**
- Failures occurring within the **10 minutes preceding a successful login**

The successful authentication acts as the triggering event. The alert records the username, source IP address, number of preceding failures, failure time range, and successful login timestamp.

## Features

- Rule-based detection of brute-force activity, password spraying, and successful logins following repeated failures
- Time-window analysis and event correlation by username and source IP address
- Structured security alerts containing detection type, severity, affected entities, event counts, and relevant timestamps
- CSV authentication log ingestion and validation using pandas
- Validation of required fields and timestamp data before analysis
- Human-readable terminal reporting for detected anomalies
- Optional CSV export for downstream analysis and reporting
- Self-contained HTML security analysis reports with an executive summary and detection overview
- Detailed investigation findings with supporting authentication event evidence
- Chronological event timelines and documented detection methodology
- Command-line interface with configurable input, CSV output, and HTML report paths
- Support for generating CSV and HTML reports simultaneously
- Modular detection and reporting functions designed for extension
- Automated unit and integration testing with pytest

## Project Structure

```text
auth-anomaly-analyzer/
├── data/
│   └── auth_logs.csv
├── output/
│   └── (generated CSV and HTML reports)
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   └── reporting.py
├── tests/
│   ├── test_analyzer.py
│   ├── test_cli.py
│   └── test_reporting.py
├── .gitignore
├── README.md
└── requirements.txt
```

- `data/` contains the synthetic authentication log used to demonstrate the analyzer.
- `src/analyzer.py` contains data ingestion, validation, detection logic, terminal reporting, CSV export, and CLI functionality.
- `src/reporting.py` generates self-contained HTML security analysis reports with investigation findings, supporting evidence, and event timelines.
- `src/__init__.py` defines `src` as a Python package.
- `tests/test_analyzer.py` validates detection logic, input handling, and CSV reporting.
- `tests/test_reporting.py` validates HTML report generation, content, and formatting.
- `tests/test_cli.py` contains CLI integration tests covering HTML generation, simultaneous exports, and backward compatibility.
- `requirements.txt` defines the project's direct third-party dependencies.
- `output/` stores generated CSV and HTML reports and is excluded from version control.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/amoseyal/auth-anomaly-analyzer.git
cd auth-anomaly-analyzer
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

On macOS or Linux:

```bash
source .venv/bin/activate
```

On Windows:

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

### Analyze the default sample data

The analyzer uses `data/auth_logs.csv` as the default input file:

```bash
python -m src.analyzer
```

### Specify an input file

Use `--input` to analyze a different authentication log:

```bash
python -m src.analyzer --input path/to/auth_logs.csv
```

### Export detected alerts

Use `--output` to export the detected anomalies to a CSV file:

```bash
python -m src.analyzer --output output/alerts.csv
```

### Specify both input and output files

```bash
python -m src.analyzer \
    --input data/auth_logs.csv \
    --output output/alerts.csv
```

The output directory is created automatically if it does not already exist.

### Generate an HTML security report

Use `--html` to generate a self-contained HTML report containing an executive summary, detection overview, investigation findings, supporting evidence, and chronological authentication event timelines.

```bash
python -m src.analyzer --html output/security_report.html
```

The report can be opened in any modern web browser without requiring a web server or additional dependencies.

### Generate CSV and HTML reports simultaneously

Use `--output` and `--html` together to generate both report formats during a single analysis:

```bash
python -m src.analyzer \
    --input data/auth_logs.csv \
    --output output/alerts.csv \
    --html output/security_report.html
```

Both reports contain findings from the same authentication analysis. The CSV provides structured alert data for downstream processing, while the HTML report provides a more detailed, human-readable investigation summary.

The analyzer continues to display detected alerts in the terminal regardless of whether either export option is specified.

### View command-line help

```bash
python -m src.analyzer --help
```

## Example Output

Running the analyzer against the included synthetic authentication log produces three security alerts, demonstrating each implemented detection rule:

```text
Detected 3 authentication anomaly(s):

Detection: brute_force
Severity: high
Source IP: 185.72.14.91
Window: 10min
First failure: 2026-09-20 22:14:03
Last failure: 2026-09-20 22:15:02
Username: jdoe
Failure count: 5
--------------------------------------------------

Detection: password_spraying
Severity: high
Source IP: 203.0.113.77
Window: 10min
First failure: 2026-09-21 02:31:04
Last failure: 2026-09-21 02:34:11
Unique users targeted: 5
Usernames: rpatel, mchen, sgarcia, bsmith, aeyal
--------------------------------------------------

Detection: success_after_failures
Severity: high
Source IP: 185.72.14.91
Window: 10min
First failure: 2026-09-20 22:14:03
Last failure: 2026-09-20 22:15:17
Username: jdoe
Failure count: 6
Successful login: 2026-09-20 22:15:36
--------------------------------------------------
```

When `--output` is specified, the same findings are also exported as structured CSV data for further analysis or reporting.

### HTML Security Report

When `--html` is specified, the analyzer generates a self-contained HTML security report designed to support authentication security investigations.

The report includes:

- **Executive summary** — An overview of the authentication analysis and detected security findings.
- **Detection overview** — A breakdown of findings by detection type.
- **Investigation findings** — Detailed information about individual alerts, including affected accounts, source IP addresses, severity, and relevant timestamps.
- **Supporting evidence** — Authentication events associated with each finding.
- **Event timelines** — Chronological views of authentication activity relevant to detected anomalies.
- **Detection methodology** — Explanations of the rules and criteria used to identify suspicious activity.

To generate the report using the included sample data:

```bash
python -m src.analyzer --html output/security_report.html
```

Open `output/security_report.html` in a web browser to review the findings.

The HTML report is intended for human-readable security analysis, while the CSV export provides structured alert data suitable for additional processing.

## Input Format

The analyzer expects authentication data in CSV format with the following required columns:

| Column | Description |
| --- | --- |
| `timestamp` | Date and time of the authentication event |
| `username` | User account involved in the authentication attempt |
| `source_ip` | Source IP address of the authentication attempt |
| `status` | Authentication result: `success` or `failure` |

Example:

```csv
timestamp,username,source_ip,status
2026-09-20 22:14:03,jdoe,185.72.14.91,failure
2026-09-20 22:14:18,jdoe,185.72.14.91,failure
2026-09-20 22:14:32,jdoe,185.72.14.91,failure
2026-09-20 22:15:36,jdoe,185.72.14.91,success
```

During ingestion, the analyzer validates that all required columns are present and converts the `timestamp` field to datetime values. Missing required columns or invalid timestamp data cause the analysis to stop with a descriptive error message.

The authentication data included in this repository is synthetic and does not contain real user or production authentication information.

## Testing

The project includes **39 automated tests** using pytest, covering authentication anomaly detection, input validation, CSV export, HTML security reporting, and command-line integration.

The test suite is organized into three modules:

- **`tests/test_analyzer.py`** — 14 tests covering detection thresholds, time-window enforcement, event correlation, input validation, terminal output, and CSV export.
- **`tests/test_reporting.py`** — 22 tests covering HTML report generation, report content, investigation evidence, event timelines, formatting, and output safety.
- **`tests/test_cli.py`** — 3 integration tests covering HTML report generation, simultaneous CSV and HTML exports, and execution without optional export arguments.

### Run the complete test suite

From the project root:

```bash
python -m pytest -v
```

Expected result:

```text
39 passed
```

### Run individual test modules

Detection and CSV reporting:

```bash
python -m pytest tests/test_analyzer.py -v
```

HTML security reporting:

```bash
python -m pytest tests/test_reporting.py -v
```

Command-line integration:

```bash
python -m pytest tests/test_cli.py -v
```

The tests use synthetic authentication events to validate expected detection behavior, including threshold boundaries, time-window constraints, and correlation criteria.

Reporting tests verify that detected anomalies are represented accurately in generated reports. CLI integration tests exercise the complete workflow from command-line argument processing through authentication analysis and report generation.

Temporary files and directories are managed through pytest fixtures to keep test execution isolated and reproducible.

## Limitations

This project is a rule-based authentication log analyzer intended for learning, demonstration, and security analytics practice. The current implementation has several limitations:

- **Static detection thresholds** — Detection rules currently use fixed thresholds and 10-minute time windows. Production environments would typically require thresholds tuned to normal authentication behavior and organizational risk.
- **Limited event context** — Analysis is based on timestamp, username, source IP address, and authentication status. It does not currently incorporate device identity, geolocation, user agent, authentication method, identity provider, or other contextual signals.
- **Potential false positives** — Repeated failures can result from forgotten passwords, stale credentials, automated services, shared network addresses, or legitimate user behavior.
- **Potential false negatives** — Slow or distributed attacks may remain below the configured thresholds. Attackers using multiple source IP addresses may also avoid rules that correlate events by a single source IP.
- **IP addresses do not uniquely identify users or devices** — NAT, proxies, VPNs, and shared infrastructure can cause multiple systems or users to appear under the same source IP address.
- **Successful authentication does not prove compromise** — A successful login following repeated failures is treated as a higher-interest event for investigation, not confirmation that an account was compromised.
- **CSV-based analysis** — The current version processes static CSV files rather than ingesting authentication events continuously from an identity provider, SIEM, API, or log pipeline.
- **No threat-intelligence enrichment** — Source IP addresses are not currently evaluated against reputation services, known malicious infrastructure, or other external intelligence.

Detected anomalies should therefore be treated as **investigative signals that require additional context and validation**.

## Potential Extensions

The current implementation is intentionally scoped as a rule-based authentication analytics project. Potential extensions for a production-oriented implementation could include:

- **Configurable detection thresholds** — Move detection thresholds and time windows from constants to command-line arguments or a configuration file.
- **Additional authentication detections** — Add rules for unusual login times, distributed authentication attacks, repeated account lockouts, and other suspicious authentication patterns.
- **Contextual enrichment** — Incorporate additional fields such as device identifiers, geographic information, authentication methods, and user agents to improve detection context.
- **IP reputation enrichment** — Optionally evaluate source IP addresses using external threat-intelligence or reputation data.
- **Structured logging and alert formats** — Support formats such as JSON for easier integration with security tooling and downstream analysis.
- **Larger-scale log processing** — Adapt the analyzer to process larger datasets or ingest events from APIs, identity platforms, or centralized logging systems.
- **Detection configuration and severity tuning** — Allow detection rules, thresholds, and severity levels to be adjusted for different environments and risk profiles.

## Technologies

- **Python 3**
- **pandas** — CSV ingestion, datetime processing, filtering, grouping, and structured alert export
- **pytest** — Unit and integration testing
- **argparse** — Command-line interface and argument handling
- **pathlib** — Platform-independent filesystem path handling

## Project Purpose

The Authentication Anomaly Analyzer demonstrates how authentication security concepts can be translated into explicit, testable detection logic using Python and structured log data.

The project focuses on correlating authentication events across users, source IP addresses, and time windows; distinguishing suspicious patterns from normal activity; validating security telemetry before analysis; and producing structured findings that can support further investigation.

The implementation emphasizes readable and modular code, clearly documented detection criteria, input validation, positive and negative test cases, and reproducible security analysis.