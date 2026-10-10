import pandas as pd

from src.reporting import (
    build_analysis_summary,
    build_authentication_timeline,
    build_detection_evidence,
    generate_html_report,
    escape_html_value,
    get_authentication_status_class,
    get_detection_methodology,
    get_analyst_interpretation
)


def test_build_analysis_summary_counts_events_and_alerts():
    '''
    Verify that the analysis summary correctly counts authentication
    events and generated security alerts.
    '''

    # Create a small authentication dataset representing three
    # events processed by the analyzer.
    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:15:36'
                ]
            ),
            'username': [
                'jdoe',
                'jdoe',
                'jdoe'
            ],
            'source_ip': [
                '185.72.14.91',
                '185.72.14.91',
                '185.72.14.91'
            ],
            'status': [
                'failure',
                'failure',
                'success'
            ]
        }
    )

    # Use representative structured alerts rather than rerunning
    # detection logic. Reporting tests should validate reporting
    # behavior independently of the detection engine.
    alerts = [
        {
            'detection': 'brute_force'
        },
        {
            'detection': 'success_after_failures'
        }
    ]

    summary = build_analysis_summary(
        auth_logs,
        alerts
    )

    assert summary['total_events'] == 3
    assert summary['total_alerts'] == 2


def test_build_analysis_summary_counts_detection_types():
    '''
    Verify that the summary reports alert counts for every
    implemented authentication detection rule.
    '''

    # The detection-count test does not depend on event contents,
    # so an empty DataFrame is sufficient here.
    auth_logs = pd.DataFrame()

    alerts = [
        {
            'detection': 'brute_force'
        },
        {
            'detection': 'brute_force'
        },
        {
            'detection': 'password_spraying'
        }
    ]

    summary = build_analysis_summary(
        auth_logs,
        alerts
    )

    assert summary['detection_counts'] == {
        'brute_force': 2,
        'password_spraying': 1,
        'success_after_failures': 0
    }


def test_build_analysis_summary_counts_affected_entities():
    '''
    Verify that the summary counts unique affected accounts and
    source IP addresses represented across different alert types.
    '''

    # Event contents are not needed because these metrics are
    # calculated from the structured alerts.
    auth_logs = pd.DataFrame()

    alerts = [
        {
            'detection': 'brute_force',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        },
        {
            'detection': 'password_spraying',
            'usernames': [
                'rpatel',
                'mchen',
                'sgarcia',
                'bsmith',
                'aeyal'
            ],
            'source_ip': '203.0.113.77'
        },
        {
            'detection': 'success_after_failures',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        }
    ]

    summary = build_analysis_summary(
        auth_logs,
        alerts
    )

    # jdoe appears in two alerts but should only be counted once.
    # The password-spraying alert contributes five additional
    # distinct affected accounts.
    assert summary['affected_accounts'] == 6

    # Two unique source IP addresses appear across the three alerts.
    assert summary['unique_source_ips'] == 2


def test_build_authentication_timeline_filters_sorts_and_labels_events():
    '''
    Verify that the authentication timeline includes only events
    associated with generated alerts, sorts them chronologically,
    and assigns readable event labels.
    '''

    # Include both alert-related and unrelated authentication
    # activity so the test can verify timeline filtering.
    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:15:36',
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:14:30'
                ]
            ),
            'username': [
                'jdoe',
                'jdoe',
                'jdoe',
                'unrelated_user'
            ],
            'source_ip': [
                '185.72.14.91',
                '185.72.14.91',
                '185.72.14.91',
                '192.0.2.50'
            ],
            'status': [
                'success',
                'failure',
                'failure',
                'success'
            ]
        }
    )

    # The alert identifies the username/source-IP combination
    # relevant to the investigation timeline.
    alerts = [
        {
            'detection': 'success_after_failures',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        }
    ]

    # Build the timeline for one specific security alert.
    # Each alert will eventually have its own visualization.
    timeline = build_authentication_timeline(
        auth_logs,
        alerts[0]
    )

    # The unrelated authentication event should be excluded.
    assert len(timeline) == 3
    assert 'unrelated_user' not in timeline['username'].tolist()

    # Relevant events should remain in chronological order.
    assert timeline['timestamp'].tolist() == list(
        pd.to_datetime(
            [
                '2026-09-20 22:14:03',
                '2026-09-20 22:14:18',
                '2026-09-20 22:15:36'
            ]
        )
    )

    # Labels should remain suitable for report presentation.
    assert timeline['event_label'].tolist() == [
        'jdoe — failure',
        'jdoe — failure',
        'jdoe — success'
    ]


def test_generate_html_report_creates_report_with_summary(tmp_path):
    '''
    Verify that the HTML report is created and contains the
    expected executive-summary metrics.
    '''

    # Create a small authentication dataset for the report.
    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime(
                [
                    '2026-09-20 22:14:03',
                    '2026-09-20 22:14:18',
                    '2026-09-20 22:15:36'
                ]
            ),
            'username': [
                'jdoe',
                'jdoe',
                'jdoe'
            ],
            'source_ip': [
                '185.72.14.91',
                '185.72.14.91',
                '185.72.14.91'
            ],
            'status': [
                'failure',
                'failure',
                'success'
            ]
        }
    )

    # Use two representative alerts that affect the same account
    # and source IP.
    alerts = [
        {
            'detection': 'brute_force',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        },
        {
            'detection': 'success_after_failures',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        }
    ]

    output_path = tmp_path / 'security_report.html'

    generate_html_report(
        auth_logs,
        alerts,
        output_path
    )

    # Verify that the report file was actually created.
    assert output_path.exists()

    # Read the generated report so its visible contents can
    # be validated.
    report_html = output_path.read_text(
        encoding='utf-8'
    )

    assert '<title>Authentication Security Analysis Report</title>' in report_html
    assert '<h1>Authentication Security Analysis Report</h1>' in report_html

    # Verify the executive-summary values generated from the
    # supplied authentication data and alerts.
    assert '<p>3</p>' in report_html
    assert '<p>2</p>' in report_html
    assert '<p>1</p>' in report_html

    assert 'Events Analyzed' in report_html
    assert 'Alerts Generated' in report_html
    assert 'Affected Accounts' in report_html
    assert 'Source IPs' in report_html


def test_generate_html_report_creates_separate_alert_timelines(tmp_path):
    '''
    Verify that the HTML report generates a separate investigation
    timeline for each detected authentication anomaly.
    '''

    # Create authentication events representing two distinct
    # suspicious activity patterns.
    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime([
                '2026-09-20 22:14:03',
                '2026-09-20 22:14:18',
                '2026-09-21 02:31:04',
                '2026-09-21 02:31:20'
            ]),
            'username': [
                'jdoe',
                'jdoe',
                'rpatel',
                'mchen'
            ],
            'source_ip': [
                '185.72.14.91',
                '185.72.14.91',
                '203.0.113.77',
                '203.0.113.77'
            ],
            'status': [
                'failure',
                'failure',
                'failure',
                'failure'
            ]
        }
    )

    # Supply two alerts representing different detection types.
    alerts = [
        {
            'detection': 'brute_force',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        },
        {
            'detection': 'password_spraying',
            'usernames': ['rpatel', 'mchen'],
            'source_ip': '203.0.113.77'
        }
    ]

    output_path = tmp_path / 'security_report.html'

    generate_html_report(
        auth_logs,
        alerts,
        output_path
    )

    report_html = output_path.read_text(
        encoding='utf-8'
    )

    # Each alert should generate its own investigation container.
    assert report_html.count('class="alert-timeline"') == 2

    # Verify that each investigation uses the standardized,
    # human-readable detection labels.
    assert '<h3>Brute-Force Activity</h3>' in report_html
    assert '<h3>Password-Spraying Activity</h3>' in report_html

    # Verify that each investigation identifies its source IP.
    assert '185.72.14.91' in report_html
    assert '203.0.113.77' in report_html


def test_build_authentication_timeline_respects_detection_window():
    '''
    Verify that the investigation timeline includes only events
    occurring within the alert's detection time boundaries.
    '''

    # Include authentication events before, during, and after
    # the detection window for the same account and source IP.
    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime([
                '2026-09-20 22:00:00',
                '2026-09-20 22:14:03',
                '2026-09-20 22:14:18',
                '2026-09-20 22:15:02',
                '2026-09-20 23:00:00'
            ]),
            'username': ['jdoe'] * 5,
            'source_ip': ['185.72.14.91'] * 5,
            'status': ['failure'] * 5
        }
    )

    # Define the actual detection boundaries.
    # Events outside this interval should not appear.
    alert = {
        'detection': 'brute_force',
        'username': 'jdoe',
        'source_ip': '185.72.14.91',
        'first_failure': pd.Timestamp('2026-09-20 22:14:03'),
        'last_failure': pd.Timestamp('2026-09-20 22:15:02')
    }

    timeline = build_authentication_timeline(
        auth_logs,
        alert
    )

    # Only the three events within the detection window remain.
    assert len(timeline) == 3

    # Both detection boundaries are inclusive.
    assert timeline['timestamp'].min() == alert['first_failure']
    assert timeline['timestamp'].max() == alert['last_failure']

    # Confirm that unrelated historical activity was excluded.
    assert pd.Timestamp(
        '2026-09-20 22:00:00'
    ) not in timeline['timestamp'].tolist()

    assert pd.Timestamp(
        '2026-09-20 23:00:00'
    ) not in timeline['timestamp'].tolist()


def test_build_authentication_timeline_includes_successful_login():
    '''
    Verify that a success-after-failures timeline includes the
    successful authentication following the repeated failures.
    '''

    # Create authentication events surrounding the detection.
    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime([
                '2026-09-20 22:00:00',
                '2026-09-20 22:14:03',
                '2026-09-20 22:14:18',
                '2026-09-20 22:15:17',
                '2026-09-20 22:15:36',
                '2026-09-20 22:30:00'
            ]),
            'username': ['jdoe'] * 6,
            'source_ip': ['185.72.14.91'] * 6,
            'status': [
                'failure',
                'failure',
                'failure',
                'failure',
                'success',
                'success'
            ]
        }
    )

    # The successful login occurs after the final failure.
    # It must remain inside the investigation timeline.
    alert = {
        'detection': 'success_after_failures',
        'username': 'jdoe',
        'source_ip': '185.72.14.91',
        'first_failure': pd.Timestamp('2026-09-20 22:14:03'),
        'last_failure': pd.Timestamp('2026-09-20 22:15:17'),
        'success_time': pd.Timestamp('2026-09-20 22:15:36')
    }

    timeline = build_authentication_timeline(
        auth_logs,
        alert
    )

    # The timeline should contain three failures followed
    # by the successful authentication.
    assert len(timeline) == 4

    assert timeline['status'].tolist() == [
        'failure',
        'failure',
        'failure',
        'success'
    ]

    # Verify that the timeline ends at the successful login,
    # rather than at the final failed authentication.
    assert timeline['timestamp'].max() == alert['success_time']

    # Authentication activity after the successful login
    # must not appear in this investigation timeline.
    assert pd.Timestamp(
        '2026-09-20 22:30:00'
    ) not in timeline['timestamp'].tolist()


def test_build_detection_evidence_brute_force():
    '''
    Verify that brute-force evidence includes the targeted account,
    failed attempt count, and relevant detection information.
    '''

    # Create a representative brute-force alert.
    alert = {
        'detection': 'brute_force',
        'severity': 'high',
        'username': 'jdoe',
        'source_ip': '185.72.14.91',
        'failure_count': 5,
        'window': '10min',
        'first_failure': pd.Timestamp('2026-09-20 22:14:03'),
        'last_failure': pd.Timestamp('2026-09-20 22:15:02')
    }

    evidence = build_detection_evidence(alert)

    # Verify that the detection-specific evidence is preserved.
    assert evidence['Severity'] == 'High'
    assert evidence['Source IP'] == '185.72.14.91'
    assert evidence['Detection Window'] == '10min'
    assert evidence['Target Account'] == 'jdoe'
    assert evidence['Failed Attempts'] == 5

    # Verify that the evidence retains its original timestamps.
    assert evidence['First Failure'] == alert['first_failure']
    assert evidence['Last Failure'] == alert['last_failure']


def test_build_detection_evidence_password_spraying():
    '''
    Verify that password-spraying evidence includes the number
    and identities of accounts targeted by the source IP.
    '''

    # Create a representative password-spraying alert.
    alert = {
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

    evidence = build_detection_evidence(alert)

    # Verify that all five targeted accounts are represented.
    assert evidence['Accounts Targeted'] == 5

    assert evidence['Targeted Usernames'] == (
        'rpatel, mchen, sgarcia, bsmith, aeyal'
    )

    assert evidence['Source IP'] == '203.0.113.77'
    assert evidence['Detection Window'] == '10min'


def test_build_detection_evidence_success_after_failures():
    '''
    Verify that successful-login evidence includes the preceding
    failure count and the successful authentication timestamp.
    '''

    # Create a representative success-after-failures alert.
    alert = {
        'detection': 'success_after_failures',
        'severity': 'high',
        'username': 'jdoe',
        'source_ip': '185.72.14.91',
        'failure_count': 6,
        'window': '10min',
        'first_failure': pd.Timestamp('2026-09-20 22:14:03'),
        'last_failure': pd.Timestamp('2026-09-20 22:15:17'),
        'success_time': pd.Timestamp('2026-09-20 22:15:36')
    }

    evidence = build_detection_evidence(alert)

    # Verify the account and preceding authentication failures.
    assert evidence['Target Account'] == 'jdoe'
    assert evidence['Preceding Failures'] == 6

    # The successful login must be represented separately from
    # the last failed authentication.
    assert evidence['Successful Login'] == alert['success_time']
    assert evidence['Last Failure'] == alert['last_failure']


def test_generate_html_report_includes_detection_evidence(tmp_path):
    '''
    Verify that the generated HTML includes the evidence fields
    associated with a detected authentication anomaly.
    '''

    # Create authentication events for a single account.
    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime([
                '2026-09-20 22:14:03',
                '2026-09-20 22:14:18'
            ]),
            'username': ['jdoe', 'jdoe'],
            'source_ip': ['185.72.14.91'] * 2,
            'status': ['failure', 'failure']
        }
    )

    # Supply an alert containing detection evidence.
    alert = {
        'detection': 'brute_force',
        'severity': 'high',
        'username': 'jdoe',
        'source_ip': '185.72.14.91',
        'failure_count': 5,
        'window': '10min',
        'first_failure': pd.Timestamp('2026-09-20 22:14:03'),
        'last_failure': pd.Timestamp('2026-09-20 22:14:18')
    }

    output_path = tmp_path / 'security_report.html'

    # Generate the report using the reporting pipeline.
    generate_html_report(
        auth_logs,
        [alert],
        output_path
    )

    report_html = output_path.read_text(
        encoding='utf-8'
    )

    # Confirm that the evidence panel was generated.
    assert 'class="evidence-grid"' in report_html

    # Verify that detection-specific evidence is displayed.
    assert 'Target Account' in report_html
    assert 'Failed Attempts' in report_html
    assert 'Detection Window' in report_html

    # Verify that the corresponding evidence values appear.
    assert 'jdoe' in report_html
    assert '185.72.14.91' in report_html
    assert '10min' in report_html

    # Check the rendered failure count, not merely the raw
    # authentication events supplied to the report.
    assert '<span class="evidence-value">5</span>' in report_html


def test_escape_html_value_prevents_html_injection():
    '''
    Verify that untrusted authentication data is escaped
    before being inserted into the HTML report.
    '''

    # Simulate a malicious username containing HTML markup.
    malicious_username = '<script>alert("test")</script>'

    escaped_value = escape_html_value(malicious_username)

    # HTML tags must be converted into harmless text.
    assert '<script>' not in escaped_value
    assert '&lt;script&gt;' in escaped_value

    # Quotation marks must also be escaped.
    assert '&quot;test&quot;' in escaped_value

    # Non-string values must remain representable.
    assert escape_html_value(5) == '5'


def test_generate_html_report_escapes_evidence_values(tmp_path):
    '''
    Verify that malicious HTML in authentication evidence
    is escaped before being written into the report.
    '''

    # Simulate a username containing potentially executable HTML.
    malicious_username = '<script>alert("test")</script>'

    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime([
                '2026-09-20 22:14:03'
            ]),
            'username': [malicious_username],
            'source_ip': ['185.72.14.91'],
            'status': ['failure']
        }
    )

    alert = {
        'detection': 'brute_force',
        'severity': 'high',
        'username': malicious_username,
        'source_ip': '185.72.14.91',
        'failure_count': 5,
        'window': '10min'
    }

    output_path = tmp_path / 'security_report.html'

    # Generate the report containing untrusted evidence.
    generate_html_report(
        auth_logs,
        [alert],
        output_path
    )

    report_html = output_path.read_text(
        encoding='utf-8'
    )

    # Verify that the evidence panel contains escaped markup.
    assert (
        '&lt;script&gt;alert(&quot;test&quot;)&lt;/script&gt;'
        in report_html
    )

    # Raw script elements must never appear in the report.
    assert '<script>' not in report_html


def test_generate_html_report_escapes_timeline_events(tmp_path):
    '''
    Verify that untrusted authentication event fields are escaped
    when rendered in the HTML investigation timeline.
    '''

    # Simulate malicious values in authentication log fields.
    malicious_username = '<img src=x onerror=alert(1)>'
    malicious_source_ip = '192.0.2.10"><script>alert(1)</script>'
    malicious_status = 'failure" onclick="alert(1)'

    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime([
                '2026-09-20 22:14:03'
            ]),
            'username': [malicious_username],
            'source_ip': [malicious_source_ip],
            'status': [malicious_status]
        }
    )

    alert = {
        'detection': 'brute_force',
        'severity': 'high',
        'username': malicious_username,
        'source_ip': malicious_source_ip,
        'failure_count': 5,
        'window': '10min'
    }

    output_path = tmp_path / 'security_report.html'

    # Generate the report using potentially malicious input.
    generate_html_report(
        auth_logs,
        [alert],
        output_path
    )

    report_html = output_path.read_text(
        encoding='utf-8'
    )

    # Verify that the timeline contains escaped authentication data.
    assert '&lt;img src=x onerror=alert(1)&gt;' in report_html
    assert '192.0.2.10&quot;&gt;' in report_html

    # Verify that HTML attribute injection is escaped.
    assert 'failure&quot; onclick=&quot;alert(1)' in report_html

    # No executable HTML elements should originate from the input.
    assert '<img src=x onerror=alert(1)>' not in report_html
    assert '<script>alert(1)</script>' not in report_html


def test_generate_html_report_uses_correct_detection_percentages(tmp_path):
    '''
    Verify that each detection bar is scaled according to its
    own alert count relative to the largest detection count.
    '''

    # Create an empty authentication dataset with the required columns.
    # Timeline events are unnecessary for testing chart percentages.
    auth_logs = pd.DataFrame(
        columns=['timestamp', 'username', 'source_ip', 'status']
    )

    # Generate three password-spraying alerts and one brute-force
    # alert to produce deliberately different chart percentages.
    alerts = [
        {
            'detection': 'password_spraying',
            'source_ip': f'192.0.2.{i}',
            'usernames': ['jdoe']
        }
        for i in range(1, 4)
    ]

    alerts.append(
        {
            'detection': 'brute_force',
            'source_ip': '198.51.100.10',
            'username': 'jdoe'
        }
    )

    output_path = tmp_path / 'security_report.html'

    # Generate the report using the unequal detection counts.
    generate_html_report(
        auth_logs,
        alerts,
        output_path
    )

    report_html = output_path.read_text(encoding='utf-8')

    # Isolate the Password Spraying chart row so its percentage
    # cannot be confused with another detection's percentage.
    password_spraying_row = report_html.split(
        'Password Spraying'
    )[1].split('class="detection-count"')[0]

    # Three alerts represent 100% of the maximum detection count.
    assert 'width: 100.0%' in password_spraying_row

    # One brute-force alert represents approximately 33.33%.
    brute_force_row = report_html.split(
        'Brute Force'
    )[1].split('class="detection-count"')[0]

    assert 'width: 33.33333333333333%' in brute_force_row


def test_get_authentication_status_class():
    '''
    Verify that only recognized authentication statuses
    are permitted as status-specific CSS classes.
    '''

    # Recognized authentication outcomes retain their classes.
    assert get_authentication_status_class('success') == 'success'
    assert get_authentication_status_class('failure') == 'failure'

    # Unexpected statuses receive a neutral fallback class.
    assert get_authentication_status_class('unknown') == 'unknown'

    # Malicious attribute content must never become a CSS class.
    assert get_authentication_status_class(
        'failure" onclick="alert(1)'
    ) == 'unknown'


def test_generate_html_report_restricts_status_classes(tmp_path):
    '''
    Verify that the HTML report uses only approved authentication
    status classes while preserving unexpected values as text.
    '''

    # Simulate an authentication event with an unexpected status.
    malicious_status = 'failure" onclick="alert(1)'

    auth_logs = pd.DataFrame(
        {
            'timestamp': pd.to_datetime([
                '2026-09-20 22:14:03'
            ]),
            'username': ['jdoe'],
            'source_ip': ['185.72.14.91'],
            'status': [malicious_status]
        }
    )

    # Associate the event with a brute-force investigation.
    alert = {
        'detection': 'brute_force',
        'severity': 'high',
        'username': 'jdoe',
        'source_ip': '185.72.14.91',
        'failure_count': 5,
        'window': '10min'
    }

    output_path = tmp_path / 'security_report.html'

    # Generate the report using the unexpected authentication status.
    generate_html_report(
        auth_logs,
        [alert],
        output_path
    )

    report_html = output_path.read_text(
        encoding='utf-8'
    )

    # The event must receive the neutral CSS class.
    assert 'class="timeline-event unknown"' in report_html

    # The original status must remain visible as escaped text.
    assert 'failure&quot; onclick=&quot;alert(1)' in report_html

    # The untrusted status must not create an HTML event handler.
    assert 'class="timeline-event failure" onclick=' not in report_html


def test_get_detection_methodology():
    '''
    Verify that methodology descriptions accurately document
    the existing authentication anomaly detection rules.
    '''

    # Brute-force detection requires five failed attempts
    # against the same account from the same source IP.
    brute_force = get_detection_methodology('brute_force')

    assert 'five failures' in brute_force
    assert 'ten-minute window' in brute_force
    assert 'same account' in brute_force

    # Password spraying requires failed attempts against
    # five distinct accounts from the same source IP.
    password_spraying = get_detection_methodology(
        'password_spraying'
    )

    assert 'five unique accounts' in password_spraying
    assert 'ten-minute window' in password_spraying

    # Success-after-failures requires a successful login
    # following at least five failed attempts.
    success_after_failures = get_detection_methodology(
        'success_after_failures'
    )

    assert 'successful login' in success_after_failures
    assert 'five failures' in success_after_failures
    assert 'preceding ten minutes' in success_after_failures

    # Unknown detection types must receive a neutral fallback.
    unknown = get_detection_methodology('unknown_detection')

    assert unknown == (
        'No methodology description is available for this detection.'
    )


def test_generate_html_report_includes_detection_methodology(tmp_path):
    '''
    Verify that the HTML report includes the correct methodology
    description for each authentication anomaly detection.
    '''

    # Create an empty authentication dataset with the required columns.
    # Timeline events are not necessary for this test.
    auth_logs = pd.DataFrame(
        columns=['timestamp', 'username', 'source_ip', 'status']
    )

    # Supply one alert for each supported detection rule.
    alerts = [
        {
            'detection': 'brute_force',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        },
        {
            'detection': 'password_spraying',
            'usernames': ['rpatel', 'mchen'],
            'source_ip': '203.0.113.77'
        },
        {
            'detection': 'success_after_failures',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        }
    ]

    output_path = tmp_path / 'security_report.html'

    # Generate the HTML report.
    generate_html_report(
        auth_logs,
        alerts,
        output_path
    )

    report_html = output_path.read_text(
        encoding='utf-8'
    )

    # Each investigation must contain its own methodology panel.
    assert report_html.count('class="methodology-panel"') == 3

    # Verify that the correct rule descriptions appear.
    assert (
        'five failures occur within a ten-minute window'
        in report_html
    )

    assert (
        'five unique accounts are targeted within '
        'a ten-minute window'
        in report_html
    )

    assert (
        'five failures within the preceding ten minutes'
        in report_html
    )


def test_get_analyst_interpretation():
    '''
    Verify that analyst interpretations describe potential threats,
    acknowledge uncertainty, and recommend investigative follow-up.
    '''

    # Brute-force activity may indicate credential guessing,
    # but legitimate authentication errors are also possible.
    brute_force = get_analyst_interpretation('brute_force')

    assert 'password guessing' in brute_force
    assert 'legitimate user errors' in brute_force
    assert 'Review the source IP' in brute_force

    # Password spraying involves attempts against multiple accounts,
    # but similar patterns can result from legitimate processes.
    password_spraying = get_analyst_interpretation(
        'password_spraying'
    )

    assert 'password spraying' in password_spraying
    assert 'Shared infrastructure' in password_spraying
    assert 'targeted accounts' in password_spraying

    # A successful login after repeated failures warrants closer
    # investigation but does not establish account compromise.
    success_after_failures = get_analyst_interpretation(
        'success_after_failures'
    )

    assert 'credential-guessing attempt succeeded' in success_after_failures
    assert 'MFA results' in success_after_failures
    assert 'does not establish account compromise' in success_after_failures

    # Unknown detection types receive a neutral fallback.
    unknown = get_analyst_interpretation('unknown_detection')

    assert unknown == (
        'No analyst interpretation is available for this detection.'
    )


def test_generate_html_report_includes_analyst_interpretations(tmp_path):
    '''
    Verify that each detection includes its corresponding
    analyst interpretation in the generated HTML report.
    '''

    # Create an empty authentication dataset.
    auth_logs = pd.DataFrame(
        columns=['timestamp', 'username', 'source_ip', 'status']
    )

    # Create one alert for each supported detection type.
    alerts = [
        {
            'detection': 'brute_force',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        },
        {
            'detection': 'password_spraying',
            'usernames': ['rpatel', 'mchen'],
            'source_ip': '203.0.113.77'
        },
        {
            'detection': 'success_after_failures',
            'username': 'jdoe',
            'source_ip': '185.72.14.91'
        }
    ]

    output_path = tmp_path / 'security_report.html'

    # Generate the HTML report.
    generate_html_report(
        auth_logs,
        alerts,
        output_path
    )

    report_html = output_path.read_text(
        encoding='utf-8'
    )

    # Each investigation must include an interpretation panel.
    assert report_html.count('class="interpretation-panel"') == 3

    # Verify that each detection's interpretation is included.
    assert 'password guessing' in report_html
    assert 'Shared infrastructure' in report_html
    assert 'MFA results' in report_html

    # Verify that the report preserves appropriate uncertainty.
    assert 'does not establish account compromise' in report_html


def test_generate_html_report_includes_analysis_metadata(tmp_path):
    '''
    Verify that the HTML report includes the analysis metadata
    and correctly identifies the source authentication log.
    '''

    # Create an empty authentication dataset.
    auth_logs = pd.DataFrame(
        columns=['timestamp', 'username', 'source_ip', 'status']
    )

    alerts = []
    output_path = tmp_path / 'security_report.html'

    # Generate the report with a specified source file.
    generate_html_report(
        auth_logs,
        alerts,
        output_path,
        source_path='data/auth_logs.csv'
    )

    # Read the generated HTML.
    html = output_path.read_text(encoding='utf-8')

    # Verify that the metadata section and fields are present.
    assert '<h2>Analysis Information</h2>' in html
    assert 'Analysis Date' in html
    assert 'Analysis Scope' in html
    assert 'Authentication anomaly detection' in html
    assert 'Data Source' in html
    assert 'auth_logs.csv' in html
    assert 'Observation Period' in html
    assert 'No authentication events available' in html
    assert 'Detection Methodology' in html
    assert 'Rule-based correlation of authentication events' in html


def test_generate_html_report_observation_period(tmp_path):
    '''
    Verify that the observation period reflects the earliest and
    latest authentication events, regardless of their original order.
    '''

    # Create authentication events in nonchronological order.
    auth_logs = pd.DataFrame({
        'timestamp': pd.to_datetime([
            '2026-10-10 14:30:00',
            '2026-10-08 09:15:00',
            '2026-10-09 18:45:00'
        ]),
        'username': ['jdoe', 'mchen', 'rpatel'],
        'source_ip': [
            '192.0.2.10',
            '192.0.2.20',
            '192.0.2.30'
        ],
        'status': ['success', 'failure', 'success']
    })

    alerts = []
    output_path = tmp_path / 'security_report.html'

    # Generate the HTML report.
    generate_html_report(
        auth_logs,
        alerts,
        output_path,
        source_path='data/auth_logs.csv'
    )

    # Read the generated HTML.
    html = output_path.read_text(encoding='utf-8')

    # Verify the observation period uses the earliest and latest events.
    assert (
        'October 08, 2026 09:15:00 - '
        'October 10, 2026 14:30:00'
    ) in html


def test_generate_html_report_escapes_source_filename(tmp_path):
    '''
    Verify that potentially unsafe characters in the source
    filename are escaped before insertion into the HTML report.
    '''

    # Create an empty authentication dataset.
    auth_logs = pd.DataFrame(
        columns=['timestamp', 'username', 'source_ip', 'status']
    )

    alerts = []
    output_path = tmp_path / 'security_report.html'

    # Use a filename containing HTML markup.
    source_path = 'data/<script>alert(1).csv'

    # Generate the HTML report.
    generate_html_report(
        auth_logs,
        alerts,
        output_path,
        source_path=source_path
    )

    # Read the generated HTML.
    html = output_path.read_text(encoding='utf-8')

    # Verify that the HTML markup is escaped.
    assert '&lt;script&gt;alert(1).csv' in html
    assert '<script>' not in html