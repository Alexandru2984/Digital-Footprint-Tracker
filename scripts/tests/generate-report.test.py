#!/usr/bin/env python3
"""The PDF report renders whatever a scan found, in any script, and states the
application's own risk score. Every non-Latin-1 character (a Romanian name, an
emoji in a bio) used to fail the whole export.

Needs fpdf2 (the production Python has it); without it the case is skipped
loudly rather than passed quietly."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
try:
    import generate_report as report
except ModuleNotFoundError as missing:
    print(f'generate-report: SKIPPED, {missing.name} is not installed for {sys.executable}')
    sys.exit(0)

document = {
    'scanID': 'x', 'input': 'ștefan@example.ro', 'status': 'completed',
    'riskScore': 74, 'riskLevel': 'High',
    'riskFactors': [{'category': 'breach', 'label': 'Breaches and leaks', 'points': 28, 'findings': 1}],
    'dossier': {'headline': 'Ștefan Țăranu — 1 confirmed account', 'confirmed': [{'label': 'github: ștefan', 'score': 98}],
                'probable': [], 'unconfirmedCount': 0, 'sites': [], 'emails': ['ștefan@example.ro'], 'phones': [],
                'locations': ['Cluj-Napoca, România'], 'organizations': [], 'breachCount': 0, 'sensitiveData': []},
    'unavailableSources': ['GreyNoise'],
    'results': [{'source': 'GitHub', 'type': 'account_presence', 'confidenceScore': 0.9,
                 'rawData': 'Name: Ștefan Țăranu 🚀 — bio ✓ 日本語'}],
}

pdf = report.make_report(document)
assert pdf.startswith(b'%PDF-'), pdf[:20]

# Without a Unicode font on the host, text is reduced to the core fonts'
# encoding instead of failing.
font = report.UNICODE_FONT
report.UNICODE_FONT = '/nonexistent/font.ttf'
try:
    assert report.make_report(document).startswith(b'%PDF-')
finally:
    report.UNICODE_FONT = font

# The score is the application's, not the script's own estimate.
assert report.report_risk(document, document['results'])[:2] == (74, 'High')
assert report.report_risk({'results': []}, [])[:2] == (0, 'Low'), 'no score in the document: the local estimate'

print('generate-report contract tests passed')
