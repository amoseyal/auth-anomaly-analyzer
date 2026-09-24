# Authentication Anomaly Analyzer

A Python-based security analytics tool for detecting suspicious authentication activity in structured login data.

## Overview

The Authentication Anomaly Analyzer processes authentication logs and applies rule-based detection logic to identify potentially suspicious login behavior.

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

- Rule-based detection of common authentication anomalies
- Time-window analysis of authentication events
- Detection based on username and source IP correlation
- CSV authentication log ingestion using pandas
- Input validation for required fields and timestamp data
- Command-line interface with configurable input and output paths
- Human-readable terminal reporting
- Optional CSV export of structured detection results
- Automated unit and integration testing with pytest
- Modular detection functions designed for extension with additional rules

## Project Structure

```text
auth-anomaly-analyzer/
├── data/
│   └── auth_logs.csv
├── output/
│   └── (generated alert reports)
├── src/
│   ├── __init__.py
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── .gitignore
├── README.md
└── requirements.txt
```

- `data/` contains the synthetic authentication log used to demonstrate the analyzer.
- `src/analyzer.py` contains data ingestion, validation, detection, reporting, export, and CLI logic.
- `src/__init__.py` defines `src` as a Python package.
- `tests/` contains the pytest unit and integration test suite.
- `requirements.txt` defines the project's direct third-party dependencies.
- `output/` is created automatically when CSV output is requested and is excluded from version control.

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

### View command-line help

```bash
python -m src.analyzer --help
```

## Example Output

Running the analyzer against the included sample authentication log produces three detections:

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

The project includes automated unit and integration tests using pytest.

Run the complete test suite from the project root:

```bash
python -m pytest
```

The current test suite contains **14 tests** covering:

- Brute-force detection at the configured threshold
- Prevention of brute-force false positives below the threshold
- Time-window enforcement for brute-force detection
- Separation of authentication activity by username and source IP
- Password-spraying detection across multiple user accounts
- Prevention of password-spraying detection against a single account
- Successful-login-after-failures detection
- Required-column validation during CSV ingestion
- Invalid timestamp handling
- CSV alert creation and exported field validation
- Human-readable formatting of password-spraying usernames
- Terminal output for detected anomalies
- End-to-end processing from CSV ingestion through detection and CSV export

The integration test creates synthetic authentication data, processes it through all three detection rules, exports the resulting alerts, and verifies that all expected detection types are present in the exported report.

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

## Future Improvements

Potential extensions for future versions include:

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

This project was developed as part of a cybersecurity portfolio to apply Python programming and data-analysis techniques to a practical security use case.

The project focuses on translating authentication security concepts into explicit detection logic, validating structured log data, correlating events across users and source IP addresses, producing actionable findings, and testing detection behavior against both positive and negative cases.

The implementation emphasizes readable code, modular detection functions, documented detection criteria, input validation, and automated testing.