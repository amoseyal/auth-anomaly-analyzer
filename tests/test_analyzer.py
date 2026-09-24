import pandas as pd
import pytest

from src.analyzer import (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
    display_alerts,
    export_alerts,
    load_auth_logs
)


# Brute-force detection tests

def test_brute_force_detected():
    '''Five failures within ten minutes should trigger an alert.'''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:14:47',
                    '2026-09-20 22:15:02'
                ]
            ),
            'username': ['jdoe'] * 5,
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    alerts = detect_brute_force(test_data)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert['detection'] == 'brute_force'
    assert alert['severity'] == 'high'
    assert alert['username'] == 'jdoe'
    assert alert['source_ip'] == '185.72.14.91'
    assert alert['failure_count'] == 5
    assert alert['window'] == '10min'
    assert alert['first_failure'] == pd.Timestamp(
        '2026-09-20 22:14:03'
    )
    assert alert['last_failure'] == pd.Timestamp(
        '2026-09-20 22:15:02'
    )


def test_brute_force_not_detected_below_threshold():
    '''Four failures within ten minutes should not trigger an alert.'''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:14:47'
                ]
            ),
            'username': ['jdoe'] * 4,
            'source_ip': ['185.72.14.91'] * 4,
            'status': ['failure'] * 4
        }
    )

    alerts = detect_brute_force(test_data)

    assert len(alerts) == 0


def test_brute_force_not_detected_outside_time_window():
    '''Five failures spread beyond ten minutes should not trigger an alert.'''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 20:00:00',
                    '2026-09-20 20:15:00',
                    '2026-09-20 20:30:00',
                    '2026-09-20 20:45:00',
                    '2026-09-20 21:00:00'
                ]
            ),
            'username': ['jdoe'] * 5,
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    alerts = detect_brute_force(test_data)

    assert len(alerts) == 0


def test_brute_force_does_not_combine_source_ips():
    '''Failures from different source IPs should not be combined.'''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:14:47',
                    '2026-09-20 22:15:02'
                ]
            ),
            'username': ['jdoe'] * 5,
            'source_ip': [
                '185.72.14.91',
                '185.72.14.92',
                '185.72.14.93',
                '185.72.14.94',
                '185.72.14.95'
            ],
            'status': ['failure'] * 5
        }
    )

    alerts = detect_brute_force(test_data)

    assert len(alerts) == 0


def test_brute_force_does_not_combine_usernames():
    '''Failures against different usernames should not be combined.'''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:14:47',
                    '2026-09-20 22:15:02'
                ]
            ),
            'username': [
                'jdoe',
                'aeyal',
                'mchen',
                'sgarcia',
                'bsmith'
            ],
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    alerts = detect_brute_force(test_data)

    assert len(alerts) == 0


# Password-spraying detection tests

def test_password_spraying_detected():
    '''Five distinct usernames from one source IP should trigger an alert.'''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:14:47',
                    '2026-09-20 22:15:02'
                ]
            ),
            'username': [
                'jdoe',
                'aeyal',
                'mchen',
                'sgarcia',
                'bsmith'
            ],
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    alerts = detect_password_spraying(test_data)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert['detection'] == 'password_spraying'
    assert alert['severity'] == 'high'
    assert alert['source_ip'] == '185.72.14.91'
    assert alert['unique_user_count'] == 5
    assert alert['usernames'] == [
        'jdoe',
        'aeyal',
        'mchen',
        'sgarcia',
        'bsmith'
    ]
    assert alert['window'] == '10min'
    assert alert['first_failure'] == pd.Timestamp(
        '2026-09-20 22:14:03'
    )
    assert alert['last_failure'] == pd.Timestamp(
        '2026-09-20 22:15:02'
    )


def test_password_spraying_not_detected_same_username():
    '''Repeated failures against one username should not trigger password spraying.'''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:14:47',
                    '2026-09-20 22:15:02'
                ]
            ),
            'username': ['jdoe'] * 5,
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    alerts = detect_password_spraying(test_data)

    assert len(alerts) == 0


# Successful-login-after-failures detection tests

def test_success_after_failures_detected():
    '''A success after repeated failures should generate an alert.'''

    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:14:47',
                    '2026-09-20 22:15:02',
                    '2026-09-20 22:15:36'
                ]
            ),
            'username': ['jdoe'] * 6,
            'source_ip': ['185.72.14.91'] * 6,
            'status': [
                'failure',
                'failure',
                'failure',
                'failure',
                'failure',
                'success'
            ]
        }
    )

    alerts = detect_success_after_failures(auth_logs)

    assert len(alerts) == 1
    assert alerts[0]['detection'] == 'success_after_failures'
    assert alerts[0]['severity'] == 'high'
    assert alerts[0]['username'] == 'jdoe'
    assert alerts[0]['source_ip'] == '185.72.14.91'
    assert alerts[0]['failure_count'] == 5
    assert alerts[0]['success_time'] == pd.Timestamp(
        '2026-09-20 22:15:36'
    )


# Authentication log validation tests

def test_load_auth_logs_rejects_missing_columns(tmp_path):
    '''Authentication logs missing required columns should be rejected.'''

    test_file = tmp_path / 'invalid_auth_logs.csv'

    test_file.write_text(
        'timestamp,username,status\n'
        '2026-09-20 22:14:03,jdoe,failure\n'
    )

    with pytest.raises(ValueError, match='source_ip'):
        load_auth_logs(test_file)


def test_load_auth_logs_rejects_invalid_timestamp(tmp_path):
    '''Authentication logs with invalid timestamps should be rejected.'''

    test_file = tmp_path / 'invalid_timestamp.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        'not-a-date,jdoe,192.168.1.25,failure\n'
    )

    with pytest.raises(
        ValueError,
        match='Invalid timestamp data'
    ):
        load_auth_logs(test_file)


# Alert export tests

def test_export_alerts_creates_csv(tmp_path):
    '''Detected alerts should be exported to the requested CSV file.'''

    output_file = tmp_path / 'alerts.csv'

    alerts = [
        {
            'detection': 'brute_force',
            'severity': 'high',
            'username': 'jdoe',
            'source_ip': '185.72.14.91',
            'failure_count': 5,
            'window': '10min',
            'first_failure': pd.Timestamp('2026-09-20 22:14:03'),
            'last_failure': pd.Timestamp('2026-09-20 22:15:02')
        }
    ]

    export_alerts(alerts, output_file)

    assert output_file.exists()

    exported_data = pd.read_csv(output_file)

    assert len(exported_data) == 1
    assert exported_data.loc[0, 'detection'] == 'brute_force'
    assert exported_data.loc[0, 'severity'] == 'high'
    assert exported_data.loc[0, 'username'] == 'jdoe'
    assert exported_data.loc[0, 'source_ip'] == '185.72.14.91'
    assert exported_data.loc[0, 'failure_count'] == 5


def test_export_alerts_formats_usernames(tmp_path):
    '''Password-spraying usernames should be exported as readable text.'''

    output_file = tmp_path / 'alerts.csv'

    alerts = [
        {
            'detection': 'password_spraying',
            'severity': 'high',
            'source_ip': '203.0.113.77',
            'unique_user_count': 5,
            'usernames': [
                'rpatel',
                'mchen',
                'sgarcia',
                'bsmith',
                'aeyal'
            ],
            'window': '10min',
            'first_failure': pd.Timestamp('2026-09-21 02:31:04'),
            'last_failure': pd.Timestamp('2026-09-21 02:34:11')
        }
    ]

    export_alerts(alerts, output_file)

    exported_data = pd.read_csv(output_file)

    assert exported_data.loc[0, 'usernames'] == (
        'rpatel; mchen; sgarcia; bsmith; aeyal'
    )


# Alert display tests

def test_display_success_after_failures(capsys):
    '''Success-after-failures alerts should display correctly.'''

    alerts = [
        {
            'detection': 'success_after_failures',
            'severity': 'high',
            'username': 'jdoe',
            'source_ip': '185.72.14.91',
            'failure_count': 5,
            'window': '10min',
            'first_failure': pd.Timestamp('2026-09-20 22:14:03'),
            'last_failure': pd.Timestamp('2026-09-20 22:15:02'),
            'success_time': pd.Timestamp('2026-09-20 22:15:36')
        }
    ]

    display_alerts(alerts)

    captured = capsys.readouterr()

    assert 'Detection: success_after_failures' in captured.out
    assert 'Username: jdoe' in captured.out
    assert 'Failure count: 5' in captured.out
    assert 'Successful login: 2026-09-20 22:15:36' in captured.out


# Integration tests

def test_authentication_analysis_pipeline(tmp_path):
    """Authentication logs should be analyzed and exported end to end."""

    input_file = tmp_path / 'auth_logs.csv'
    output_file = tmp_path / 'alerts.csv'

    # Create authentication data containing all three
    # supported anomaly patterns.
    input_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,jdoe,185.72.14.91,failure\n'
        '2026-09-20 22:14:18,jdoe,185.72.14.91,failure\n'
        '2026-09-20 22:14:32,jdoe,185.72.14.91,failure\n'
        '2026-09-20 22:14:47,jdoe,185.72.14.91,failure\n'
        '2026-09-20 22:15:02,jdoe,185.72.14.91,failure\n'
        '2026-09-20 22:15:36,jdoe,185.72.14.91,success\n'
        '2026-09-21 02:31:04,rpatel,203.0.113.77,failure\n'
        '2026-09-21 02:31:39,mchen,203.0.113.77,failure\n'
        '2026-09-21 02:32:15,sgarcia,203.0.113.77,failure\n'
        '2026-09-21 02:33:02,bsmith,203.0.113.77,failure\n'
        '2026-09-21 02:34:11,aeyal,203.0.113.77,failure\n'
    )

    # Load and validate the authentication log.
    auth_logs = load_auth_logs(input_file)

    # Run all supported detection rules.
    alerts = (
        detect_brute_force(auth_logs)
        + detect_password_spraying(auth_logs)
        + detect_success_after_failures(auth_logs)
    )

    # Export the combined findings.
    export_alerts(alerts, output_file)

    # Read the exported report back into the test.
    exported_data = pd.read_csv(output_file)

    # Verify that the complete pipeline produced all three
    # expected detection types.
    assert len(exported_data) == 3

    assert set(exported_data['detection']) == {
        'brute_force',
        'password_spraying',
        'success_after_failures'
    }