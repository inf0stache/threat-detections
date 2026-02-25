# M365 hunting scopes

Small KQL scopes I actually use during phishing triage.
They are short, readable, and easy to tweak.
Each query defaults to `ago(7d)` through `now()` using `TimeGenerated`.
Start with sender/subject scope, then pivot to click and attachment context.
Use `contains` first; tighten only if needed.
No heavy frameworks here, just practical filters and summaries.
Run order: 1) subject/sender scope 2) url clicks 3) attachment hashes.
Writeups live on heyosj.com; this repo is just the reusable artifacts.
