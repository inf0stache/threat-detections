#!/usr/bin/env python3
"""
Enrich the 410 reply-sink domains with infrastructure data to prove
operator linkage.

For each unique domain across the phishing recipient list, pull:
  - Registrar
  - Creation date
  - Updated date
  - Nameservers
  - MX records

Output:
  - domain_enrichment.csv       (per-domain rows)
  - infra_summary.txt           (registrar/NS/MX counts, date histogram)

Usage:
    python3 enrich_domains.py yes_me.csv

Dependencies:
    pip install python-whois dnspython
"""

import csv
import re
import sys
import time
from collections import Counter
from pathlib import Path

try:
    import whois
except ImportError:
    print('[-] missing: pip install python-whois', file=sys.stderr)
    sys.exit(1)

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print('[-] missing: pip install dnspython', file=sys.stderr)
    sys.exit(1)


# Use public resolvers to avoid local DNS cache pollution / ISP rewriting.
RESOLVER = dns.resolver.Resolver(configure=False)
RESOLVER.nameservers = ['1.1.1.1', '8.8.8.8']
RESOLVER.lifetime = 5.0
RESOLVER.timeout = 5.0


def domain_from_address(addr: str) -> str:
    """Pull the registrable domain from an email address.

    'info@info.agepirade.com' -> 'agepirade.com'
    'contact@contact.teddfod.cn.com' -> 'teddfod.cn.com'
    """
    addr = addr.strip().lower()
    if '@' not in addr:
        return addr
    host = addr.split('@', 1)[1]
    # The attacker uses subdomains like info.X.com, contact.contact.X.com.
    # We want the registrable domain. Multi-part TLDs (.co.uk, .cn.com,
    # .com.mx, .org.uk) complicate this — handle the common ones.
    parts = host.split('.')
    multi_tlds = {
        ('co', 'uk'), ('org', 'uk'), ('me', 'uk'), ('ac', 'uk'),
        ('cn', 'com'), ('us', 'org'), ('us', 'com'), ('br', 'com'),
        ('de', 'com'), ('uk', 'com'), ('com', 'mx'), ('web', 'id'),
    }
    if len(parts) >= 3 and tuple(parts[-2:]) in multi_tlds:
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def load_domains(csv_path: Path) -> list[str]:
    domains: set[str] = set()
    with csv_path.open(encoding='utf-8') as f:
        for row in csv.DictReader(f):
            d = domain_from_address(row['recipient'])
            if d:
                domains.add(d)
    return sorted(domains)


def fmt_date(d) -> str:
    if d is None:
        return ''
    if isinstance(d, list):
        d = d[0] if d else None
    if d is None:
        return ''
    try:
        return d.strftime('%Y-%m-%d')
    except Exception:
        return str(d)


def lookup_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        return {
            'registrar': (w.registrar or '').strip() if w.registrar else '',
            'created':   fmt_date(w.creation_date),
            'updated':   fmt_date(w.updated_date),
            'whois_err': '',
        }
    except Exception as e:
        return {'registrar': '', 'created': '', 'updated': '',
                'whois_err': str(e)[:80]}


def lookup_dns(domain: str, rtype: str) -> list[str]:
    try:
        ans = RESOLVER.resolve(domain, rtype)
        return sorted({str(r).rstrip('.').lower() for r in ans})
    except dns.exception.DNSException:
        return []


def enrich(domain: str) -> dict:
    row = {'domain': domain}
    row.update(lookup_whois(domain))
    row['nameservers'] = ';'.join(lookup_dns(domain, 'NS'))
    # MX records look like "10 mx.example.com" — keep the host only.
    mx_raw = lookup_dns(domain, 'MX')
    row['mx'] = ';'.join(m.split()[-1] if ' ' in m else m for m in mx_raw)
    return row


def summarize(rows: list[dict], out_path: Path) -> None:
    registrars = Counter(r['registrar'] for r in rows if r['registrar'])
    ns_hosts = Counter()
    for r in rows:
        for ns in r['nameservers'].split(';'):
            if ns:
                ns_hosts[ns] += 1
    mx_hosts = Counter()
    for r in rows:
        for m in r['mx'].split(';'):
            if m:
                mx_hosts[m] += 1

    # Creation-date histogram by year-month.
    month_bucket = Counter()
    for r in rows:
        if re.match(r'\d{4}-\d{2}', r['created']):
            month_bucket[r['created'][:7]] += 1

    lines = []
    lines.append(f'Total domains enriched: {len(rows)}')
    lines.append(f'WHOIS failures:         '
                 f'{sum(1 for r in rows if r["whois_err"])}')
    lines.append(f'Domains with MX:        '
                 f'{sum(1 for r in rows if r["mx"])}')
    lines.append('')
    lines.append('=== REGISTRARS ===')
    for name, n in registrars.most_common():
        lines.append(f'  {n:4d}  {name}')
    lines.append('')
    lines.append('=== NAMESERVERS (top 20) ===')
    for ns, n in ns_hosts.most_common(20):
        lines.append(f'  {n:4d}  {ns}')
    lines.append('')
    lines.append('=== MX HOSTS (top 20) ===')
    for mx, n in mx_hosts.most_common(20):
        lines.append(f'  {n:4d}  {mx}')
    lines.append('')
    lines.append('=== CREATION DATES (by month) ===')
    for month in sorted(month_bucket):
        lines.append(f'  {month}  {month_bucket[month]:4d}')

    out_path.write_text('\n'.join(lines), encoding='utf-8')
    print('\n'.join(lines))


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <recipients.csv>', file=sys.stderr)
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    domains = load_domains(csv_path)
    print(f'[+] {len(domains)} unique domains extracted from {csv_path.name}')

    rows = []
    for i, d in enumerate(domains, 1):
        print(f'  [{i:3d}/{len(domains)}] {d}')
        rows.append(enrich(d))
        # Be polite to WHOIS servers — rate-limited / blocklisted otherwise.
        time.sleep(1.5)

    out_csv = csv_path.parent / 'domain_enrichment.csv'
    fields = ['domain', 'registrar', 'created', 'updated',
              'nameservers', 'mx', 'whois_err']
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f'\n[+] wrote {out_csv}')

    summary_path = csv_path.parent / 'infra_summary.txt'
    print()
    summarize(rows, summary_path)
    print(f'\n[+] wrote {summary_path}')


if __name__ == '__main__':
    main()