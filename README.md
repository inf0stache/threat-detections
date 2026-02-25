# threat-detections

Translating operational threat intelligence into reusable detection artifacts.

## What's In Here

- Detection content focused on turning real-world incidents into repeatable coverage.
- Queries and rules intended for both immediate scoping and durable detection.
- Supporting scripts for data handling and operational workflows.

## kql

`/kql` contains KQL detections and investigation queries organized by platform:

- `m365`: Microsoft 365-focused detection and scoping queries.
- `sentinel`: Microsoft Sentinel detections, hunts, and triage queries.
- `cloudflare`: Cloudflare telemetry queries for detection and incident scoping.

Primary use: take a single phishing or malware event and expand it to organizational scope (users, hosts, inboxes, identities, infrastructure, and related activity).

## sigma

`/sigma` contains portable detection rules that can be adapted across SIEM/XDR tooling.

Primary use: codify attacker behavior observed during incidents into reusable logic that improves future detection and scoping.

## scripts

`/scripts` contains helper tooling to support detection engineering workflows (for example: conversion, enrichment, validation, and packaging tasks).

Primary use: reduce manual work and keep detection artifacts consistent.

## What This Repo Is (and Isn't)

This repo is for detection and scoping artifacts.

This repo is not a case management system and not a narrative incident journal. Case writeups, timelines, and post-incident reporting live elsewhere.

## Philosophy

- Start from concrete adversary activity, not hypothetical coverage.
- Build detections that support both alerting and scope expansion.
- Prefer clear, maintainable logic over opaque complexity.
- Treat each incident as an opportunity to improve future response speed.

## Status

Initial scaffold. Content will be added iteratively as incidents are translated into production-usable detection artifacts.
