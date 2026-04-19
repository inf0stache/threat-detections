#!/usr/bin/env python3
"""
Extract mailto: addresses from Firebase phishing .eml samples.

Splits recipients by CTA button:
  - "Report the user" mailtos  -> report_the_user.csv
  - "Yes, me" / "This was me" mailtos -> yes_me.csv

Usage:
    python3 extract_mailtos.py /path/to/eml/folder
"""

import csv
import email
import email.policy
import re
import sys
import urllib.parse
from pathlib import Path


# Match <a href="mailto:...">LABEL</a> — tolerates attrs, whitespace, newlines.
ANCHOR_RE = re.compile(
    r'<a\b[^>]*?href\s*=\s*"(mailto:[^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

# Zero-width and directional marks that get stuffed into the visible label.
INVISIBLE_CHARS_RE = re.compile(r'[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]')

# Buckets — match on normalized label text.
REPORT_PATTERNS      = ('report the user',)
YESME_PATTERNS       = ('yes, me', 'yes me', 'this was me', 'it was me')
UNSUBSCRIBE_PATTERNS = ('unsubscribe',)


def strip_html(fragment: str) -> str:
    """Collapse an anchor's inner HTML to plain text for label matching."""
    text = re.sub(r'<[^>]+>', ' ', fragment)
    text = INVISIBLE_CHARS_RE.sub('', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text.lower()


def classify(label: str) -> str | None:
    if any(p in label for p in REPORT_PATTERNS):
        return 'report'
    if any(p in label for p in YESME_PATTERNS):
        return 'yesme'
    if any(p in label for p in UNSUBSCRIBE_PATTERNS):
        return 'unsubscribe'
    return None


def parse_mailto(mailto_uri: str) -> tuple[list[str], str, str]:
    """Return (recipients, subject, body) from a mailto: URI."""
    parsed = urllib.parse.urlparse(mailto_uri)
    # mailto: allows both ',' and ';' as address separators in the wild.
    raw_recipients = re.split(r'[;,]', parsed.path)
    recipients = [r.strip() for r in raw_recipients if r.strip()]
    params = urllib.parse.parse_qs(parsed.query)
    subject = params.get('subject', [''])[0]
    body    = params.get('body', [''])[0]
    return recipients, subject, body


def get_html_body(msg: email.message.EmailMessage) -> str:
    """Pull the text/html part out of a parsed email, decoded."""
    html_part = msg.get_body(preferencelist=('html',))
    if html_part is None:
        return ''
    return html_part.get_content()


def extract_from_eml(path: Path) -> list[dict]:
    """Return rows of {file, bucket, recipient, subject, body, raw_label}."""
    with path.open('rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    html = get_html_body(msg)
    rows = []

    for mailto_uri, inner_html in ANCHOR_RE.findall(html):
        label = strip_html(inner_html)
        bucket = classify(label)
        if bucket is None:
            continue

        recipients, subject, body = parse_mailto(mailto_uri)
        for recipient in recipients:
            rows.append({
                'source_file': path.name,
                'bucket': bucket,
                'recipient': recipient,
                'subject': subject,
                'body': body,
                'label': label,
            })

    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = ['source_file', 'recipient', 'subject', 'body', 'label']
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in fields})


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} /path/to/eml/folder', file=sys.stderr)
        sys.exit(1)

    folder = Path(sys.argv[1])
    eml_files = sorted(folder.glob('*.eml'))
    if not eml_files:
        print(f'No .eml files found in {folder}', file=sys.stderr)
        sys.exit(1)

    all_rows = []
    for eml in eml_files:
        rows = extract_from_eml(eml)
        print(f'{eml.name}: {len(rows)} mailto recipients extracted')
        all_rows.extend(rows)

    report_rows      = [r for r in all_rows if r['bucket'] == 'report']
    yesme_rows       = [r for r in all_rows if r['bucket'] == 'yesme']
    unsubscribe_rows = [r for r in all_rows if r['bucket'] == 'unsubscribe']

    out_dir = folder
    write_csv(out_dir / 'report_the_user.csv', report_rows)
    write_csv(out_dir / 'yes_me.csv', yesme_rows)
    write_csv(out_dir / 'unsubscribe.csv', unsubscribe_rows)

    print()
    print(f'[+] report_the_user.csv: {len(report_rows)} rows')
    print(f'[+] yes_me.csv:          {len(yesme_rows)} rows')
    print(f'[+] unsubscribe.csv:     {len(unsubscribe_rows)} rows')
    print(f'[+] unique recipients across all: '
          f'{len({r["recipient"] for r in all_rows})}')


if __name__ == '__main__':
    main()