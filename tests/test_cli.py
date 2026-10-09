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
    main()

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
    main()

    # Capture the terminal output.
    captured = capsys.readouterr()

    # Verify that the analysis produced terminal output.
    assert captured.out.strip()

    # Verify that no reports were generated.
    assert list(tmp_path.iterdir()) == []