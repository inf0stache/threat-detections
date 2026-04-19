#!/usr/bin/env python3
"""
Passive-only infrastructure expansion on the enriched domain set.

Two pivots:
  1. crt.sh — pull certificate history for each domain.
     Any domain with issued certs has (or had) a web server, meaning
     stage-two hosting beyond the mail-only reply sinks.

  2. HackerTarget reverse NS — find every domain using the same nameserver
     as the okinawazones.net cluster. This expands the campaign map
     beyond the 138 that happened to land in your inbox.

Both are passive — no packets sent to attacker infrastructure.

Usage:
    python3 expand_infra.py domain_enrichment.csv

Outputs:
    cert_hits.csv          — domains that have issued TLS certs
    reverse_ns_expansion.csv — every domain on the shared nameservers

No pip dependencies beyond stdlib + requests.
"""

import csv
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

try:
    import requests
except ImportError:
    print('[-] missing: pip install requests', file=sys.stderr)
    sys.exit(1)


CRTSH_URL = 'https://crt.sh/?q=%25.{domain}&output=json'
HACKERTARGET_REVERSE_NS = 'https://api.hackertarget.com/findshareddns/?q={ns}'
HEADERS = {'User-Agent': 'infra-research/1.0'}


def load_enrichment(path: Path) -> list[dict]:
    with path.open(encoding='utf-8') as f:
        return list(csv.DictReader(f))


def query_crtsh(domain: str) -> list[dict]:
    """Return list of {cert_id, name_value, issuer, not_before} for a domain."""
    url = CRTSH_URL.format(domain=domain)
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        if r.status_code != 200:
            return []
        # crt.sh sometimes returns concatenated JSON objects — handle that.
        text = r.text.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Occasionally returns lines of JSON objects instead of an array.
            data = [json.loads(line) for line in text.splitlines() if line]
        return data if isinstance(data, list) else []
    except requests.RequestException:
        return []


def query_reverse_ns(nameserver: str) -> list[str]:
    """Return list of domains sharing this nameserver, via HackerTarget."""
    url = HACKERTARGET_REVERSE_NS.format(ns=nameserver)
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        if r.status_code != 200:
            return []
        body = r.text.strip()
        if not body or 'error' in body.lower() or 'API count' in body:
            return []
        return [line.strip().lower() for line in body.splitlines() if line.strip()]
    except requests.RequestException:
        return []


def collect_unique_nameservers(rows: list[dict]) -> Counter:
    ns_counter: Counter = Counter()
    for r in rows:
        for ns in r['nameservers'].split(';'):
            ns = ns.strip().lower()
            if ns:
                ns_counter[ns] += 1
    return ns_counter


def run_crtsh_pivot(rows: list[dict], out_path: Path) -> None:
    print('=' * 60)
    print('CRT.SH CERTIFICATE PIVOT')
    print('=' * 60)
    hits: list[dict] = []

    for i, row in enumerate(rows, 1):
        domain = row['domain']
        print(f'  [{i:3d}/{len(rows)}] {domain}', end=' ')
        certs = query_crtsh(domain)
        print(f'→ {len(certs)} cert entries')
        for c in certs:
            hits.append({
                'domain':       domain,
                'name_value':   c.get('name_value', '').replace('\n', ','),
                'issuer':       c.get('issuer_name', ''),
                'not_before':   c.get('not_before', ''),
                'not_after':    c.get('not_after', ''),
                'cert_id':      c.get('id', ''),
            })
        # crt.sh is free but back off to stay a good citizen.
        time.sleep(1.0)

    fields = ['domain', 'name_value', 'issuer',
              'not_before', 'not_after', 'cert_id']
    with out_path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(hits)

    # Summary: which domains had certs, which did not.
    with_certs = sorted({h['domain'] for h in hits})
    without_certs = sorted({r['domain'] for r in rows} - set(with_certs))
    print()
    print(f'[+] {len(with_certs)}/{len(rows)} domains have certs '
          f'(= web server somewhere in lifecycle)')
    print(f'[+] {len(without_certs)}/{len(rows)} domains mail-only')
    print(f'[+] wrote {out_path}')
    return with_certs, without_certs


def run_reverse_ns_pivot(ns_counter: Counter, known_domains: set[str],
                         out_path: Path) -> None:
    print()
    print('=' * 60)
    print('REVERSE NAMESERVER PIVOT')
    print('=' * 60)
    print('Targeting nameservers that are NOT shared Namecheap defaults '
          '(self-hosted or custom).')

    # Skip the generic shared hosts — reverse lookups against those return
    # millions of unrelated domains.
    skip = {
        'dns1.registrar-servers.com', 'dns2.registrar-servers.com',
        'adele.ns.cloudflare.com', 'sterling.ns.cloudflare.com',
    }
    targets = [ns for ns in ns_counter
               if ns not in skip
               and not ns.endswith('.cloudflare.com')]
    print(f'Candidate nameservers to reverse-lookup: {len(targets)}')
    for ns in targets:
        print(f'  - {ns} ({ns_counter[ns]} domains in your set)')

    all_expansion: dict[str, list[str]] = defaultdict(list)
    for ns in targets:
        print(f'\n[+] reverse lookup: {ns}')
        domains = query_reverse_ns(ns)
        # HackerTarget limits free queries to ~50/day/IP. Pause politely.
        time.sleep(2.5)
        if not domains:
            print('    (no results / rate limited / needs paid tier)')
            continue
        new_domains = [d for d in domains if d not in known_domains]
        print(f'    {len(domains)} domains on this NS, '
              f'{len(new_domains)} NOT in your known set')
        for d in domains:
            all_expansion[ns].append(d)

    # Write expansion results.
    rows = []
    for ns, domains in all_expansion.items():
        for d in domains:
            rows.append({
                'nameserver': ns,
                'domain':     d,
                'was_known':  d in known_domains,
            })

    fields = ['nameserver', 'domain', 'was_known']
    with out_path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f'\n[+] wrote {out_path} ({len(rows)} rows)')
    unknown = {r['domain'] for r in rows if not r['was_known']}
    print(f'[+] {len(unknown)} NEW domains discovered not in your 138')


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} domain_enrichment.csv', file=sys.stderr)
        sys.exit(1)

    in_path = Path(sys.argv[1])
    rows = load_enrichment(in_path)
    known_domains = {r['domain'] for r in rows}
    print(f'[+] loaded {len(rows)} domains')

    ns_counter = collect_unique_nameservers(rows)
    out_dir = in_path.parent

    run_crtsh_pivot(rows, out_dir / 'cert_hits.csv')
    run_reverse_ns_pivot(ns_counter, known_domains,
                         out_dir / 'reverse_ns_expansion.csv')


if __name__ == '__main__':
    main()