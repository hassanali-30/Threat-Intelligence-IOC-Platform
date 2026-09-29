# Security Policy

This is local-first defensive threat-intelligence software.

## Safety boundaries

The platform:

- ingests authorized local CSV, JSON, or STIX-style files
- stores indicators in a local SQLite database
- does not scan or connect to indicator infrastructure
- does not execute samples or block hosts
- does not automatically publish intelligence
- binds its optional API to localhost only

IOC databases and reports may contain sensitive threat data, internal addresses, or investigative context. Protect them appropriately.

## Reporting

Use a private security report when possible. Do not publish credentials, private intelligence, or live malware samples.