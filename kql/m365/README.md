These queries are scoped for rapid phishing triage in Microsoft 365 Defender.
Each query starts from one concrete artifact and expands to blast radius.
`scope_phishing_messageid_expansion.kql` pivots from a MessageId to recipients, delivery outcomes, and related URLs/attachments.
`scope_phishing_url_clicks.kql` pivots from a suspicious URL to who received it and who clicked it.
`scope_phishing_attachment_hashes.kql` pivots from an attachment hash to impacted mailboxes and endpoint execution/download context.
The design goal is reusable scoping, not one-off hunting logic.
Use optional filters to tighten time range, sender scope, and domains as needed.
How to use: start with MessageId if available; if not, start from Subject/Sender/URL and then pivot into the matching scope query.
Case writeups for this repo live on heyosj.com.
