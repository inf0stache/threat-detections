# threat-detections

Detection and scoping artifacts organized by hunting use case.

## What's In Here

- `kql/phishing`: Email and phishing scoping queries (subject/sender, URL clicks, attachment pivots).
- `kql/identity`: Identity/authentication hunting queries.
- `kql/infra`: Infrastructure pivots (IP, domain, ASN, TLS/cert context).
- `kql/templates`: Reusable KQL snippets and helper patterns.
- `scripts`: Utility scripts that support detection workflows.
- `sigma`: Portable detection rules.

## Notes

- This repo is organized by use case, not by platform.
- Keep queries short, editable, and practical for real investigations.
