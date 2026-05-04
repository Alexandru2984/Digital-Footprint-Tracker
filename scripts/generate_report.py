#!/usr/bin/env python3
"""
generate_report.py — reads scan JSON from stdin, writes PDF bytes to stdout.
Usage: python3 generate_report.py < scan.json > report.pdf
"""
import sys, json
from fpdf import FPDF
from datetime import datetime, timezone


def compute_risk(results: list) -> tuple:
    """Returns (score 0-100, level str, colour RGB tuple)."""
    if not results:
        return (0, 'Low', (100, 160, 100))
    total = 0.0
    for r in results:
        t = (r.get('type') or '').lower()
        if any(k in t for k in ('breach', 'credential', 'leak', 'password')):
            w = 3.0
        elif any(k in t for k in ('email', 'phone', 'location')):
            w = 2.0
        else:
            w = 1.0
        total += r.get('confidenceScore', 0) * w
    score = int(min(100, round(total / 20.0 * 100)))
    if score < 25:
        return (score, 'Low',      (100, 160, 100))
    elif score < 50:
        return (score, 'Medium',   (200, 160,  50))
    elif score < 75:
        return (score, 'High',     (210, 100,  30))
    else:
        return (score, 'Critical', (200,  40,  40))


def make_report(data: dict) -> bytes:
    scan_id = str(data.get('scanID', ''))
    target = data.get('input', 'UNKNOWN')
    status = data.get('status', 'unknown')
    results = data.get('results', [])
    completed_ts = data.get('completedAt')

    completed_str = ''
    if completed_ts:
        completed_str = datetime.fromtimestamp(completed_ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    high = [r for r in results if r.get('confidenceScore', 0) >= 0.8]
    med  = [r for r in results if 0.5 <= r.get('confidenceScore', 0) < 0.8]
    low  = [r for r in results if r.get('confidenceScore', 0) < 0.5]

    risk_score, risk_level, risk_colour = compute_risk(results)

    pdf = FPDF(orientation='L', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font('Helvetica', 'B', 18)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 10, 'OSINT Report  -  Digital Footprint Tracker', ln=True)
    pdf.set_draw_color(80, 120, 200)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 287, pdf.get_y())
    pdf.ln(4)

    # Risk Score banner (right-aligned block)
    banner_x = 210
    pdf.set_xy(banner_x, 14)
    pdf.set_fill_color(*risk_colour)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(70, 7, f'Risk Score: {risk_score}/100  [{risk_level}]', border=0, fill=True, align='C', ln=True)
    pdf.set_text_color(20, 20, 20)
    pdf.set_xy(10, pdf.get_y())

    # Meta
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(60, 60, 60)
    meta_rows = [
        ('Target', target),
        ('Scan ID', scan_id),
        ('Generated', datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')),
        ('Status', status.upper()),
    ]
    if completed_str:
        meta_rows.insert(3, ('Completed', completed_str))
    for label, value in meta_rows:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(35, 5, label + ':', ln=False)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(0, 5, value, ln=True)
    pdf.ln(4)

    # Summary
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 7, 'Summary', ln=True)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(60, 60, 60)
    for label in [
        f'Total findings: {len(results)}',
        f'High confidence (>=80%): {len(high)}',
        f'Medium confidence (50-79%): {len(med)}',
        f'Low confidence (<50%): {len(low)}',
    ]:
        pdf.cell(70, 5, label, ln=False)
    pdf.ln()
    pdf.ln(4)

    if not results:
        pdf.set_font('Helvetica', 'I', 10)
        pdf.cell(0, 8, 'No findings recorded for this scan.', ln=True)
    else:
        # Results table
        pdf.set_font('Helvetica', 'B', 12)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(0, 7, f'Findings ({len(results)} total, sorted by confidence)', ln=True)
        pdf.ln(1)

        # A4 landscape = 297mm, margins 10+10 = 277mm
        col_w = [55, 40, 22, 160]
        hdrs  = ['Source', 'Type', 'Confidence', 'Details']

        pdf.set_fill_color(30, 50, 100)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 8)
        for w, h in zip(col_w, hdrs):
            pdf.cell(w, 7, h, border=1, fill=True, align='C')
        pdf.ln()

        sorted_results = sorted(results, key=lambda x: x.get('confidenceScore', 0), reverse=True)
        pdf.set_font('Helvetica', '', 7)

        for i, r in enumerate(sorted_results):
            if i % 2 == 0:
                pdf.set_fill_color(240, 244, 255)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(20, 20, 20)

            conf     = r.get('confidenceScore', 0)
            conf_pct = f'{conf * 100:.0f}%'
            source   = (r.get('source') or '')[:52]
            rtype    = (r.get('type')   or '')[:38]
            raw      = (r.get('rawData') or '').replace('\n', ' ').replace('\r', '')[:155]

            row_h = 6
            pdf.cell(col_w[0], row_h, source, border=1, fill=True)
            pdf.cell(col_w[1], row_h, rtype,  border=1, fill=True)

            if conf >= 0.8:
                pdf.set_text_color(180, 30, 30)
            elif conf >= 0.5:
                pdf.set_text_color(180, 100, 0)
            else:
                pdf.set_text_color(100, 100, 100)
            pdf.cell(col_w[2], row_h, conf_pct, border=1, fill=True, align='C')
            pdf.set_text_color(20, 20, 20)
            pdf.cell(col_w[3], row_h, raw, border=1, fill=True)
            pdf.ln()

    # Footer
    pdf.ln(5)
    pdf.set_font('Helvetica', 'I', 7)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 4, 'Digital Footprint Tracker  -  swift.micutu.com  -  Authorised use only.', align='C', ln=True)

    return bytes(pdf.output())


if __name__ == '__main__':
    data = json.loads(sys.stdin.buffer.read())
    sys.stdout.buffer.write(make_report(data))
