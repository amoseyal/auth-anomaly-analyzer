import sys

import pandas as pd

from src.analyzer import main


def test_main_generates_html_report(monkeypatch, tmp_path):
    '''
    Verify that the CLI generates an HTML security report
    when the --html argument is provided.
    '''

    # Define a temporary destination for the generated report.
    html_path = tmp_path / 'security_report.html'

    # Simulate running the CLI with an HTML output argument.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv',
            '--html',
            str(html_path)
        ]
    )

    # Execute the command-line interface.
    # A successful analysis should return exit code zero.
    exit_code = main()

    assert exit_code == 0

    # Verify that the HTML report was created.
    assert html_path.exists()

    # Verify that the generated file contains the report title.
    html_content = html_path.read_text(encoding='utf-8')

    assert 'Authentication Security Analysis Report' in html_content


def test_main_generates_csv_and_html_reports(monkeypatch, tmp_path):
    '''
    Verify that the CLI can generate CSV and HTML reports
    during the same authentication analysis.
    '''

    # Define temporary destinations for both output files.
    csv_path = tmp_path / 'alerts.csv'
    html_path = tmp_path / 'security_report.html'

    # Simulate running the CLI with both export arguments.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv',
            '--output',
            str(csv_path),
            '--html',
            str(html_path)
        ]
    )

    # Execute the command-line interface.
    main()

    # Verify that both reports were generated.
    assert csv_path.exists()
    assert html_path.exists()

    # Verify that the CSV contains the expected alert data.
    alerts_df = pd.read_csv(csv_path)

    assert not alerts_df.empty
    assert 'detection' in alerts_df.columns

    # Verify that the HTML contains the report title.
    html_content = html_path.read_text(encoding='utf-8')

    assert 'Authentication Security Analysis Report' in html_content


def test_main_without_export_arguments(monkeypatch, tmp_path, capsys):
    '''
    Verify that the CLI runs successfully without optional
    CSV or HTML export arguments.
    '''

    # Simulate running the CLI with only an input file.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv'
        ]
    )

    # Execute the command-line interface.
    # An invalid threshold should cause the analysis to fail.
    exit_code = main()

    assert exit_code == 0

    # Capture the terminal output.
    captured = capsys.readouterr()

    # Verify that the analysis produced terminal output.
    assert captured.out.strip()

    # Verify that no reports were generated.
    assert list(tmp_path.iterdir()) == []


def test_main_custom_brute_force_parameters(monkeypatch, capsys):
    '''
    Verify that custom brute-force CLI parameters are applied
    during authentication analysis.
    '''

    # Simulate running the analyzer with a custom threshold
    # and detection window.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv',
            '--brute-force-threshold',
            '3',
            '--brute-force-window',
            '30min'
        ]
    )

    # Execute the CLI using the simulated arguments.
    main()

    # Capture the analyzer's terminal output.
    captured = capsys.readouterr()

    # Extract the brute-force alert from the terminal output.
    brute_force_output = captured.out.split(
        'Detection: brute_force'
    )[1].split(
        '--------------------------------------------------'
    )[0]

    # Verify that the custom time window is reported.
    assert 'Window: 30min' in brute_force_output

    # Verify that detection occurred after three failures.
    assert 'Failure count: 3' in brute_force_output


def test_main_custom_password_spray_parameters(monkeypatch, capsys):
    '''
    Verify that custom password-spraying CLI parameters
    are applied during authentication analysis.
    '''

    # Simulate running the analyzer with custom password-spraying
    # detection parameters.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv',
            '--password-spray-threshold',
            '3',
            '--password-spray-window',
            '30min'
        ]
    )

    # Execute the CLI using the simulated arguments.
    main()

    # Capture the analyzer's terminal output.
    captured = capsys.readouterr()

    # Isolate the password-spraying alert.
    password_spray_output = captured.out.split(
        'Detection: password_spraying'
    )[1].split(
        '--------------------------------------------------'
    )[0]

    # Verify that the custom detection window is reported.
    assert 'Window: 30min' in password_spray_output

    # Verify that detection occurred after targeting three accounts.
    assert 'Unique users targeted: 3' in password_spray_output

    # Verify that the alert identifies the targeted accounts.
    assert 'Usernames: rpatel, mchen, sgarcia' in password_spray_output


def test_main_custom_success_after_failures_parameters(monkeypatch, capsys):
    '''
    Verify that custom successful-login detection parameters
    are applied during authentication analysis.
    '''

    # Simulate running the analyzer with custom threshold
    # and time-window settings.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv',
            '--success-after-failures-threshold',
            '3',
            '--success-after-failures-window',
            '30min'
        ]
    )

    # Execute the CLI using the simulated arguments.
    main()

    # Capture the analyzer's terminal output.
    captured = capsys.readouterr()

    # Isolate the successful-login-after-failures alert.
    success_output = captured.out.split(
        'Detection: success_after_failures'
    )[1].split(
        '--------------------------------------------------'
    )[0]

    # Verify that the custom time window is reported.
    assert 'Window: 30min' in success_output

    # Verify that the alert identifies the preceding failures.
    assert 'Failure count: 6' in success_output

    # Verify that the successful authentication is recorded.
    assert 'Successful login: 2026-09-20 22:15:36' in success_output


def test_main_rejects_invalid_threshold(monkeypatch, capsys):
    '''
    Verify that the CLI displays a clear error message
    when a detection threshold is invalid.
    '''

    # Simulate an invalid brute-force threshold.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv',
            '--brute-force-threshold',
            '0'
        ]
    )

    # Execute the CLI with the invalid configuration.
    # An invalid threshold should cause the analysis to fail.
    exit_code = main()

    assert exit_code == 1

    # Capture the terminal output.
    captured = capsys.readouterr()

    # Verify that the user receives a meaningful error message.
    assert (
        'Error: Detection threshold must be a positive integer.'
        in captured.out
    )

    # Verify that analysis did not proceed.
    assert 'Detected' not in captured.out


def test_main_rejects_invalid_window(monkeypatch, capsys):
    '''
    Verify that the CLI displays a clear error message
    when a detection time window is invalid.
    '''

    # Simulate an invalid password-spraying detection window.
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'analyzer.py',
            '--input',
            'data/auth_logs.csv',
            '--password-spray-window',
            'abc'
        ]
    )

    # Execute the CLI with the invalid configuration.
    # An invalid time window should cause the analysis to fail.
    exit_code = main()

    assert exit_code == 1

    # Capture the terminal output.
    captured = capsys.readouterr()

    # Verify that the CLI displays a meaningful error message.
    assert (
        'Error: Detection window must be a valid time duration.'
        in captured.out
    )

    # Verify that analysis did not proceed.
    assert 'Detected' not in captured.out


def test_main_rejects_missing_input_file(monkeypatch, tmp_path, capsys):
    '''
    Verify that the CLI returns an error when the specified
    authentication log file does not exist.
    '''

    # Construct a path to a file that has not been created.
    missing_file = tmp_path / 'missing_auth_logs.csv'

    # Simulate running the analyzer with a nonexistent input file.
    monkeypatch.setattr(
        sys, 'argv',
        [
            'analyzer.py',
            '--input',
            str(missing_file)
        ]
    )

    # Execute the CLI and capture its return code.
    exit_code = main()

    # Verify that the analysis failed.
    assert exit_code == 1

    # Verify that a meaningful error message was displayed.
    captured = capsys.readouterr()

    assert 'was not found' in captured.out
    assert str(missing_file) in captured.out

    # Verify that the analyzer did not proceed with detection.
    assert 'Detected' not in captured.out