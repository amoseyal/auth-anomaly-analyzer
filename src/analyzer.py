import argparse
from pathlib import Path
from ipaddress import ip_address

import pandas as pd


# Define the path to the authentication log data file.
# Path is used to handle filesystem paths
# in a platform-independent way.
DATA_FILE = Path('data/auth_logs.csv')

# Define the columns required to exist in the data file.
REQUIRED_COLUMNS = {
    'timestamp',
    'username',
    'source_ip',
    'status'
}

# Define detection thresholds for potential brute-force activity.
# These values can be adjusted without changing the detection logic.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = '10min'

# Define detection thersholds for potential password_spraying activity.
PASSWORD_SPRAY_THRESHOLD = 5
PASSWORD_SPRAY_WINDOW = '10min'

# Define detection thresholds for successful login attempt after multiple failures.
SUCCESS_AFTER_FAILURES_THRESHOLD = 5
SUCCESS_AFTER_FAILURES_WINDOW = '10min'


def parse_arguments():
    '''Parse command-line arguments.'''

    parser = argparse.ArgumentParser(
        description='Analyze authentication logs for suspicious activity.'
    )

    parser.add_argument(
        '--input',
        type = Path,
        default = DATA_FILE,
        help = 'path to the authentication log CSV file'
    )

    parser.add_argument(
        '--output',
        type = Path,
        help = 'optional path for exporting detected alerts as a CSV file'
    )

    parser.add_argument(
        '--html',
        type=Path,
        help='optional path for generating an HTML security analysis report'
    )

    # Configure the minimum number of failed authentication attempts
    # required to trigger brute-force detection.
    parser.add_argument(
        '--brute-force-threshold',
        type=int,
        default=BRUTE_FORCE_THRESHOLD,
        help='minimum failed attempts required for brute-force detection'
    )

    # Configure the rolling time window used for brute-force detectiong.
    parser.add_argument(
        '--brute-force-window',
        type=str,
        default=BRUTE_FORCE_WINDOW,
        help='brute-force detection window (e.g., 10min, 30min, 1h)'
    )

    # Configure the minimum number of distinct accounts targeted
    # from one source IP required to trigger password-spraying detection.
    parser.add_argument(
        '--password-spray-threshold',
        type=int,
        default=PASSWORD_SPRAY_THRESHOLD,
        help='minimum distinct accounts required for password-spraying detection'
    )

    # Configure the minimum time window used for password-spraying detection.
    parser.add_argument(
        '--password-spray-window',
        type=str,
        default=PASSWORD_SPRAY_WINDOW,
        help='password-spraying detection window (e.g., 10min, 30min, 1h)'
    )

    # Configure the minimum number os preceding failed attempts
    # required to flag a subsequent successful login.
    parser.add_argument(
        '--success-after-failures-threshold',
        type=int,
        default=SUCCESS_AFTER_FAILURES_THRESHOLD,
        help='minimum preceding failures required to flag a successful login'
    )

    # Configure how far back to examine failed attempts
    # before a successful authentication event.
    parser.add_argument(
        '--success-after-failures-window',
        type=str,
        default=SUCCESS_AFTER_FAILURES_WINDOW,
        help='detection window before a successful login (e.g., 10min, 30min, 1h)'
    )

    return parser.parse_args()


def load_auth_logs(filepath):
    '''
    Load and validate authentication event data from a CSV file.

    The input file must contain the columns required by the
    authentication anomaly detection rules.
    '''

    df = pd.read_csv(filepath)

    missing_columns = REQUIRED_COLUMNS - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {', '.join(sorted(missing_columns))}"
        )

    # Reject records containing missing or blank usernames.
    # Invalid usernames prevent reliable account-based detection.
    invalid_usernames = (
        df['username'].isna()
        | df['username'].astype('string').str.strip().eq('').fillna(False)
    )

    if invalid_usernames.any():
        raise ValueError(
            'Authentication log contains missing or blank usernames.'
        )

    # Validate source IP addresses using Python's standard library.
    # Reject missing, blank, or malformed IPv4 and IPv6 addresses.
    for source_ip in df['source_ip']:

        if pd.isna(source_ip):
            raise ValueError(
                'Authentication log contains missing or invalid source IP addresses.'
            )

        try:
            ip_address(str(source_ip).strip())

        except ValueError as error:
            raise ValueError(
                'Authentication log contains missing or invalid source IP addresses.'
            ) from error

    # Define the authentication statuses supported by the detection rules.
    valid_statuses = {'success', 'failure'}

    # Identify missing or unsupported authentication status values.
    invalid_statuses = ~df['status'].isin(valid_statuses)

    if invalid_statuses.any():
        raise ValueError(
            'Authentication log contains missing or invalid status values.'
        )

    try:
        df['timestamp'] = pd.to_datetime(
            df['timestamp'],
            errors='raise'
        )

    except ValueError as error:
        raise ValueError(
            'Invalid timestamp data in authentication log.'
        ) from error

    # Reject missing timestamps that cannot be used for time-window analysis.
    # Pandas represents missing datetime values as NaT (Not a Time).
    if df['timestamp'].isna().any():
        raise ValueError(
            'Authentication log contains missing timestamp values.'
        )

    return df


def validate_detection_parameters(threshold, window):
    '''
    Validate the threshold and time window used by a detection rule.

    Thresholds must be positive integers, and time windows must
    represent positive durations.
    '''

    # Reject booleans because bool is a subclass of int in Python.
    if type(threshold) is not int or threshold < 1:
        raise ValueError(
            'Detection threshold must be a positive integer.'
        )

    # Convert the supplied window into a pandas duration.
    try:
        duration = pd.Timedelta(window)
    except (ValueError, TypeError) as error:
        raise ValueError(
            'Detection window must be a valid time duration.'
        ) from error

    # A zero or negative duration is not meaningful for detection.
    if pd.isna(duration) or duration <= pd.Timedelta(0):
        raise ValueError(
            'Detection window must be greater than zero.'
        )

    return duration


def detect_brute_force(
        auth_logs,
        threshold=BRUTE_FORCE_THRESHOLD,
        window=BRUTE_FORCE_WINDOW
        ):
    '''
    Identify potential brute-force authentication attempts.

    A brute-force attempt is evaluated by grouping failed logins by
    username and source IP so repeated attempts against the same
    account from the same source can be analyzed together.
    '''

    # Validate configuration before processing authentication events.
    validate_detection_parameters(threshold, window)

    alerts = []

    # Isolate failed authentication attempts from the full dataset.
    failed_logins = auth_logs[auth_logs['status'] == 'failure']

    # Group failures by both username and source IP.
    failure_groups = failed_logins.groupby(['username', 'source_ip'])

    for (username, source_ip), group in failure_groups:

        # Sort events chronologically before applying
        # time-based detection logic.
        group = group.sort_values('timestamp')

        # Use the timestamp as the index so pandas can calculate
        # the number of failures occurring within a rolling time window.
        timed_group = group.set_index('timestamp')

        rolling_failures = (
            timed_group['status']
            .rolling(window)
            .count()
        )

        # Identify points where the configured failure threshold
        # is reached within the rolling time window.
        threshold_reached = rolling_failures >= threshold

        if threshold_reached.any():

            # Identify the first timestamp at which the detection
            # threshold is reached.
            detection_time = threshold_reached[
                threshold_reached
            ].index[0]

            # Calculate the beginning of the rolling detection window.
            window_start = detection_time - pd.Timedelta(
                window
            )

            # Isolate only the failures that contributed to the
            # window that caused the alert to trigger.
            detected_window = group[
                (group['timestamp'] > window_start)
                & (group['timestamp'] <= detection_time)
            ]

            alert = {
                'detection': 'brute_force',
                'severity': 'high',
                'username': username,
                'source_ip': source_ip,
                'failure_count': len(detected_window),
                'window': window,
                'first_failure': detected_window['timestamp'].min(),
                'last_failure': detected_window['timestamp'].max(),
            }

            alerts.append(alert)

    return alerts


def detect_password_spraying(
        auth_logs,
        threshold=PASSWORD_SPRAY_THRESHOLD,
        window=PASSWORD_SPRAY_WINDOW
        ):
    '''
    Identify potential password-spraying attempts.
    
    Failed authentication attempts are grouped by source IP so
    activity against multipole accounts from the same source
    can be analyzed together.
    '''

    # Validate configuration before analyzing authentication events.
    validate_detection_parameters(threshold, window)

    alerts = []

    # Isolate failed authentication attemps from the full dataset.
    failed_logins = auth_logs[auth_logs['status'] == 'failure']

    # gourp failures by source IP.
    failure_groups = failed_logins.groupby('source_ip')

    for source_ip, group in failure_groups:

        # Sort events chronologically before applying
        # time-based detection logic.
        group = group.sort_values('timestamp')

                # Evaluate each failure as the potential end of a
        # password-spraying detection window.
        for _, event in group.iterrows():

            detection_time = event['timestamp']

            # Calculate the beginning of the detection window.
            window_start = detection_time - pd.Timedelta(
                window
            )

            # Select failures from this source IP that occurred
            # within the current detection window.
            detected_window = group[
                (group['timestamp'] > window_start)
                & (group['timestamp'] <= detection_time)
            ]

            # Count the number of distinct accounts targeted
            # within the detection window.
            unique_user_count = detected_window['username'].nunique()

                        # Trigger an alert when the number of distinct targeted
            # accounts reaches the configured threshold.
            if unique_user_count >= threshold:

                alert = {
                    'detection': 'password_spraying',
                    'severity': 'high',
                    'source_ip': source_ip,
                    'unique_user_count': unique_user_count,
                    'usernames': detected_window['username'].unique().tolist(),
                    'window': window,
                    'first_failure': detected_window['timestamp'].min(),
                    'last_failure': detected_window['timestamp'].max()
                }

                alerts.append(alert)

                # Stop evaluating this source IP after its first
                # qualifying detection window is identified.
                break

    return alerts


def detect_success_after_failures(
        auth_logs,
        threshold=SUCCESS_AFTER_FAILURES_THRESHOLD,
        window=SUCCESS_AFTER_FAILURES_WINDOW
        ):
    '''
    Identify successful logins following repeated authentication failures.

    Authentication events are grouped by username and source IP so
    successful logins can be evaluated against preceding failures
    from the same source targeting the same account.
    '''

    # Validate configuration before processing authentication events.
    validate_detection_parameters(threshold, window)

    alerts = []

    # Group authentication events by username and source IP.
    auth_groups = auth_logs.groupby(['username', 'source_ip'])

    for (username, source_ip), group in auth_groups:

        # Sort events chronologically before applying
        # time-based detection logic.
        group = group.sort_values('timestamp')

        # Isolate successful authentication events.
        successful_logins = group[group['status'] == 'success']

        # Evaluate each successful login against failures that occurred
        # within the preceding detection window.
        for _, success_event in successful_logins.iterrows():

            success_time = success_event['timestamp']

            # Calculate the beginning of the detection window.
            window_start = success_time - pd.Timedelta(
                window
            )

            # Select failed authentication attempts that occurred
            # before the success and within the detection window.
            preceding_failures = group[
                (group['status'] == 'failure')
                & (group['timestamp'] > window_start)
                & (group['timestamp'] < success_time)
            ]

            failure_count = len(preceding_failures)

            # Trigger an alert when the number of preceding failures
            # reaches the configured threshold.
            if failure_count >= threshold:

                alert = {
                    'detection': 'success_after_failures',
                    'severity': 'high',
                    'username': username,
                    'source_ip': source_ip,
                    'failure_count': failure_count,
                    'window': window,
                    'first_failure': preceding_failures['timestamp'].min(),
                    'last_failure': preceding_failures['timestamp'].max(),
                    'success_time': success_time
                }

                alerts.append(alert)

                # Stop evaluating this username/source-IP combination
                # after the first qualifying successful login.
                break

    return alerts


def display_alerts(alerts):
    '''Display detected authentication anomalies in a readable format.'''

    if not alerts:
        print('No authentication anomalies detected.')
        return

    print(f'\nDetected {len(alerts)} authentication anomaly(s):\n')

    for alert in alerts:
        print(f"Detection: {alert['detection']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Window: {alert['window']}")
        print(f"First failure: {alert['first_failure']}")
        print(f"Last failure: {alert['last_failure']}")

        if alert['detection'] == 'brute_force':
            print(f"Username: {alert['username']}")
            print(f"Failure count: {alert['failure_count']}")

        elif alert['detection'] == 'password_spraying':
            print(f"Unique users targeted: {alert['unique_user_count']}")
            print(f"Usernames: {', '.join(alert['usernames'])}")

        elif alert['detection'] == 'success_after_failures':
            print(f"Username: {alert['username']}")
            print(f"Failure count: {alert['failure_count']}")
            print(f"Successful login: {alert['success_time']}")

        print('-' * 50)


def export_alerts(alerts, output_path):
    '''Export detected authentication anomalies to a CSV file.'''

    # Convert the structured alert records into a DataFrame.
    alerts_df = pd.DataFrame(alerts)

    # Format lists for human-readable CSV output.
    if 'usernames' in alerts_df.columns:
        alerts_df['usernames'] = alerts_df['usernames'].apply(
            lambda usernames: (
                '; '.join(usernames)
                if isinstance(usernames, list)
                else usernames
            )
        )

    # Preserve integer formatting for numeric count fields
    # that may contain missing values across detection types.
    count_columns = [
        'failure_count',
        'unique_user_count'
    ]

    for column in count_columns:
        if column in alerts_df.columns:
            alerts_df[column] = alerts_df[column].astype('Int64')

    # Create the output directory if it does not already exist.
    output_path.parent.mkdir(parents = True, exist_ok = True)

    # Export the alerts without including the DataFrame index.
    alerts_df.to_csv(output_path, index = False)

    print(f"Alerts exported to '{output_path}'.")


def main():
    '''Run the authentication log analysis.'''

    args = parse_arguments()

    try:
        auth_logs = load_auth_logs(args.input)

    except FileNotFoundError:
        print(f"Error: input file '{args.input}' was not found.")
        return 1
    except ValueError as error:
        print(f'Error: {error}')
        return 1

    # Run each detection rule against the authentication logs:
    try:
        brute_force_alerts = detect_brute_force(
            auth_logs,
            threshold=args.brute_force_threshold,
            window=args.brute_force_window
        )

        password_spray_alerts = detect_password_spraying(
            auth_logs,
            threshold=args.password_spray_threshold,
            window=args.password_spray_window
        )

        success_after_failure_alerts = detect_success_after_failures(
            auth_logs,
            threshold=args.success_after_failures_threshold,
            window=args.success_after_failures_window
        )

    except ValueError as error:
        print(f'Error: {error}')
        return 1

    # Combine findings from all detection rules.
    alerts = (
        brute_force_alerts
        + password_spray_alerts
        + success_after_failure_alerts
    )

    display_alerts(alerts)

    if args.output:
        export_alerts(alerts, args.output)

    # Generate an HTML security report when an output path is provided.
    if args.html:
        from src.reporting import generate_html_report

        # Record the detection parameters used during this analysis.
        # This allows the report to document the actual configuration.
        detection_config = {
            'brute_force': {
                'threshold': args.brute_force_threshold,
                'window': args.brute_force_window
            },
            'password_spraying': {
                'threshold': args.password_spray_threshold,
                'window': args.password_spray_window
            },
            'success_after_failures': {
                'threshold': args.success_after_failures_threshold,
                'window': args.success_after_failures_window
            }
        }

        # Pass the authentication data, alerts, and detection settings
        # to the HTML report generator.
        generate_html_report(
            auth_logs,
            alerts,
            args.html,
            source_path=args.input,
            detection_config=detection_config
        )

        print(f'HTML security report generated: {args.html}')

    # Indicate that the authentication analysis completed successfully.
    return 0

if __name__ == '__main__':
    raise SystemExit(main())