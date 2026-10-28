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

def test_brute_force_custom_threshold():
    '''
    A custom threshold of three failures should trigger an alert
    even though the default threshold requires five.
    '''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32'
                ]
            ),
            'username': ['jdoe'] * 3,
            'source_ip': ['185.72.14.91'] * 3,
            'status': ['failure'] * 3
        }
    )

    # Three failures should not meet the default threshold of five.
    default_alerts = detect_brute_force(test_data)

    assert len(default_alerts) == 0

    # Lowering the threshold to three should trigger an alert.
    custom_alerts = detect_brute_force(
        test_data,
        threshold=3
    )

    assert len(custom_alerts) == 1
    assert custom_alerts[0]['detection'] == 'brute_force'
    assert custom_alerts[0]['failure_count'] == 3
    assert custom_alerts[0]['window'] == '10min'

def test_brute_force_custom_time_window():
    '''
    Five failures spread over twenty minutes should trigger an
    alert with a thirty-minute window, but not the default
    ten-minute window.
    '''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 20:00:00',
                    '2026-09-20 20:05:00',
                    '2026-09-20 20:10:00',
                    '2026-09-20 20:15:00',
                    '2026-09-20 20:20:00'
                ]
            ),
            'username': ['jdoe'] * 5,
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    # The default ten-minute window should not trigger an alert.
    default_alerts = detect_brute_force(test_data)

    assert len(default_alerts) == 0

    # A thirty-minute window should include all five failures.
    custom_alerts = detect_brute_force(
        test_data,
        window='30min'
    )

    assert len(custom_alerts) == 1

    alert = custom_alerts[0]

    assert alert['detection'] == 'brute_force'
    assert alert['failure_count'] == 5
    assert alert['window'] == '30min'
    assert alert['first_failure'] == pd.Timestamp(
        '2026-09-20 20:00:00'
    )
    assert alert['last_failure'] == pd.Timestamp(
        '2026-09-20 20:20:00'
    )

@pytest.mark.parametrize(
    'invalid_threshold',
    [0, -1, 2.5, '5', True, None]
)
def test_brute_force_rejects_invalid_threshold(invalid_threshold):
    '''
    Reject thresholds that are not positive integers.
    '''

    # An empty DataFrame is sufficient because parameter validation
    # must happen before authentication events are processed.
    test_data = pd.DataFrame()

    with pytest.raises(
        ValueError,
        match='Detection threshold must be a positive integer'
    ):
        detect_brute_force(
            test_data,
            threshold=invalid_threshold
        )

@pytest.mark.parametrize(
    'invalid_window',
    ['abc', '0min', '-5min', '', None]
)
def test_brute_force_rejects_invalid_window(invalid_window):
    '''
    Reject time windows that are invalid or not positive.
    '''

    # Validation should occur before authentication events
    # are processed, so no event data is necessary.
    test_data = pd.DataFrame()

    with pytest.raises(
        ValueError,
        match='Detection window must'
    ):
        detect_brute_force(
            test_data,
            window=invalid_window
        )

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

def test_password_spraying_custom_threshold():
    '''
    Three distinct accounts targeted from one source IP should
    trigger an alert when the threshold is reduced to three.
    '''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32'
                ]
            ),
            'username': ['jdoe', 'asmith', 'mchen'],
            'source_ip': ['185.72.14.91'] * 3,
            'status': ['failure'] * 3
        }
    )

    # Three distinct usernames do not meet the default threshold.
    default_alerts = detect_password_spraying(test_data)

    assert len(default_alerts) == 0

    # A custom threshold of three should trigger detection.
    custom_alerts = detect_password_spraying(
        test_data,
        threshold=3
    )

    assert len(custom_alerts) == 1

    alert = custom_alerts[0]

    assert alert['detection'] == 'password_spraying'
    assert alert['source_ip'] == '185.72.14.91'
    assert alert['unique_user_count'] == 3
    assert set(alert['usernames']) == {'jdoe', 'asmith', 'mchen'}
    assert alert['window'] == '10min'

def test_password_spraying_custom_time_window():
    '''
    Five distinct accounts targeted over twenty minutes should
    trigger an alert with a thirty-minute detection window,
    but not with the default ten-minute window.
    '''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 20:00:00',
                    '2026-09-20 20:05:00',
                    '2026-09-20 20:10:00',
                    '2026-09-20 20:15:00',
                    '2026-09-20 20:20:00'
                ]
            ),
            'username': [
                'jdoe',
                'asmith',
                'mchen',
                'sgarcia',
                'bsmith'
            ],
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    # The default ten-minute window should not trigger an alert.
    default_alerts = detect_password_spraying(test_data)

    assert len(default_alerts) == 0

    # A thirty-minute window includes all five targeted accounts.
    custom_alerts = detect_password_spraying(
        test_data,
        window='30min'
    )

    assert len(custom_alerts) == 1

    alert = custom_alerts[0]

    assert alert['detection'] == 'password_spraying'
    assert alert['source_ip'] == '185.72.14.91'
    assert alert['unique_user_count'] == 5
    assert set(alert['usernames']) == {
        'jdoe',
        'asmith',
        'mchen',
        'sgarcia',
        'bsmith'
    }
    assert alert['window'] == '30min'
    assert alert['first_failure'] == pd.Timestamp(
        '2026-09-20 20:00:00'
    )
    assert alert['last_failure'] == pd.Timestamp(
        '2026-09-20 20:20:00'
    )

@pytest.mark.parametrize(
    'invalid_threshold',
    [0, -1, 2.5, '5', True, None]
)
def test_password_spraying_rejects_invalid_threshold(invalid_threshold):
    '''
    Reject password-spraying thresholds that are not
    positive integers.
    '''

    # Parameter validation should occur before processing events.
    test_data = pd.DataFrame()

    with pytest.raises(
        ValueError,
        match='Detection threshold must be a positive integer'
    ):
        detect_password_spraying(
            test_data,
            threshold=invalid_threshold
        )

@pytest.mark.parametrize(
    'invalid_window',
    ['abc', '0min', '-5min', '', None]
)
def test_password_spraying_rejects_invalid_window(invalid_window):
    '''
    Reject password-spraying detection windows that are
    invalid, zero-length, or negative.
    '''

    # Validation must occur before authentication events
    # are processed, so an empty DataFrame is sufficient.
    test_data = pd.DataFrame()

    with pytest.raises(
        ValueError,
        match='Detection window must'
    ):
        detect_password_spraying(
            test_data,
            window=invalid_window
        )

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


def test_success_after_failures_custom_threshold():
    '''
    Three failures followed by a successful login should trigger
    an alert when the threshold is reduced to three.
    '''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:32',
                    '2026-09-20 22:15:00'
                ]
            ),
            'username': ['jdoe'] * 4,
            'source_ip': ['185.72.14.91'] * 4,
            'status': [
                'failure',
                'failure',
                'failure',
                'success'
            ]
        }
    )

    # Three failures do not meet the default threshold of five.
    default_alerts = detect_success_after_failures(test_data)

    assert len(default_alerts) == 0

    # A threshold of three should identify the suspicious login.
    custom_alerts = detect_success_after_failures(
        test_data,
        threshold=3
    )

    assert len(custom_alerts) == 1

    alert = custom_alerts[0]

    assert alert['detection'] == 'success_after_failures'
    assert alert['severity'] == 'high'
    assert alert['username'] == 'jdoe'
    assert alert['source_ip'] == '185.72.14.91'
    assert alert['failure_count'] == 3
    assert alert['window'] == '10min'
    assert alert['success_time'] == pd.Timestamp(
        '2026-09-20 22:15:00'
    )


def test_success_after_failures_custom_time_window():
    '''
    Five failures followed by a successful login should trigger
    an alert with a thirty-minute window, but not the default
    ten-minute window.
    '''

    test_data = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 20:00:00',
                    '2026-09-20 20:05:00',
                    '2026-09-20 20:10:00',
                    '2026-09-20 20:15:00',
                    '2026-09-20 20:20:00',
                    '2026-09-20 20:25:00'
                ]
            ),
            'username': ['jdoe'] * 6,
            'source_ip': ['185.72.14.91'] * 6,
            'status': ['failure'] * 5 + ['success']
        }
    )

    # The default ten-minute window should not trigger an alert.
    default_alerts = detect_success_after_failures(test_data)

    assert len(default_alerts) == 0

    # A thirty-minute window includes all five preceding failures.
    custom_alerts = detect_success_after_failures(
        test_data,
        window='30min'
    )

    assert len(custom_alerts) == 1

    alert = custom_alerts[0]

    assert alert['detection'] == 'success_after_failures'
    assert alert['failure_count'] == 5
    assert alert['window'] == '30min'
    assert alert['first_failure'] == pd.Timestamp(
        '2026-09-20 20:00:00'
    )
    assert alert['last_failure'] == pd.Timestamp(
        '2026-09-20 20:20:00'
    )
    assert alert['success_time'] == pd.Timestamp(
        '2026-09-20 20:25:00'
    )


@pytest.mark.parametrize(
    'invalid_threshold',
    [0, -1, 2.5, '5', True, None]
)
def test_success_after_failures_rejects_invalid_threshold(invalid_threshold):
    '''
    Reject successful-login detection thresholds that are
    not positive integers.
    '''

    # Validation must occur before authentication events
    # are processed, so an empty DataFrame is sufficient.
    test_data = pd.DataFrame()

    with pytest.raises(
        ValueError,
        match='Detection threshold must be a positive integer'
    ):
        detect_success_after_failures(
            test_data,
            threshold=invalid_threshold
        )


@pytest.mark.parametrize(
    'invalid_window',
    ['abc', '0min', '-5min', '', None]
)
def test_success_after_failures_rejects_invalid_window(invalid_window):
    '''
    Reject successful-login detection windows that are
    invalid, zero-length, or negative.
    '''

    # Validation must occur before authentication events
    # are processed, so an empty DataFrame is sufficient.
    test_data = pd.DataFrame()

    with pytest.raises(
        ValueError,
        match='Detection window must'
    ):
        detect_success_after_failures(
            test_data,
            window=invalid_window
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
    '''
    Authentication logs with invalid timestamps should be rejected.
    '''

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


def test_load_auth_logs_rejects_missing_username(tmp_path):
    '''
    Authentication logs with missing usernames should be rejected.
    '''

    test_file = tmp_path / 'missing_username.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,,192.168.1.25,failure\n'
    )

    with pytest.raises(
        ValueError,
        match='missing or blank usernames'
    ):
        load_auth_logs(test_file)


def test_load_auth_logs_rejects_blank_username(tmp_path):
    '''
    Authentication logs with whitespace-only usernames should be rejected.
    '''

    test_file = tmp_path / 'blank_username.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,   ,192.168.1.25,failure\n'
    )

    with pytest.raises(
        ValueError,
        match='missing or blank usernames'
    ):
        load_auth_logs(test_file)


def test_load_auth_logs_rejects_invalid_source_ip(tmp_path):
    '''
    Authentication logs with malformed IP addresses should be rejected.
    '''

    test_file = tmp_path / 'invalid_source_ip.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,jdoe,999.168.1.25,failure\n'
    )

    with pytest.raises(
        ValueError,
        match='missing or invalid source IP addresses'
    ):
        load_auth_logs(test_file)


def test_load_auth_logs_rejects_missing_source_ip(tmp_path):
    '''Authentication logs with missing source IP addresses should be rejected.'''

    test_file = tmp_path / 'missing_source_ip.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,jdoe,,failure\n'
    )

    with pytest.raises(
        ValueError,
        match='missing or invalid source IP addresses'
    ):
        load_auth_logs(test_file)


def test_load_auth_logs_accepts_ipv6_source_ip(tmp_path):
    '''
    Valid IPv6 source addresses should be accepted.
    '''

    test_file = tmp_path / 'valid_ipv6.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,jdoe,2001:db8::1,failure\n'
    )

    auth_logs = load_auth_logs(test_file)

    assert len(auth_logs) == 1
    assert auth_logs.loc[0, 'source_ip'] == '2001:db8::1'

def test_laod_auth_logs_reject_invalid_status(tmp_path):
    '''
    Unsupported authentication statuses should be rejected.
    '''

    test_file = tmp_path / 'invalid_status.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,jdoe,192.168.1.25,unknown\n'
    )

    with pytest.raises(
        ValueError,
        match='missing or invalid status values'
    ):
        load_auth_logs(test_file)

def test_load_auth_logs_rejects_missing_status(tmp_path):
    '''
    Missing authentication statuses should be rejected.
    '''

    test_file = tmp_path / 'missing_status.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,jdoe,192.168.1.25,\n'
    )

    with pytest.raises(
        ValueError,
        match='missing or invalid status values'
    ):
        load_auth_logs(test_file)

def test_load_auth_logs_accepts_valid_statuses(tmp_path):
    '''
    Both supported authentication statuses should be accepted.
    '''

    test_file = tmp_path / 'valid_statuses.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        '2026-09-20 22:14:03,jdoe,192.168.1.25,failure\n'
        '2026-09-20 22:15:03,jdoe,192.168.1.25,success\n'
    )

    auth_logs = load_auth_logs(test_file)

    assert len(auth_logs) ==2
    assert auth_logs['status'].tolist() == [
        'failure',
        'success'
    ]

def test_load_auth_logs_rejects_missing_timestamp(tmp_path):
    '''
    Authentication logs with missing timestamps should be rejected.
    '''

    test_file = tmp_path / 'missing_timestamp.csv'

    test_file.write_text(
        'timestamp,username,source_ip,status\n'
        ',jdoe,192.168.1.25,failure\n'
    )

    with pytest.raises(
        ValueError,
        match='missing timestamp values'
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