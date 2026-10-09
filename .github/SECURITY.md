# Security policy

Customs is a security tool, so a flaw in it can let malware through. Reports are welcome.

## Supported versions

Only the latest release gets fixes.

## Reporting a vulnerability

Use [private vulnerability reporting](https://github.com/yib7/customs/security/advisories/new)
on this repository. Please do not open a public issue for a vulnerability.

Include the version (`customs --version`), what you did, what you expected, and what
happened. Expect a first reply within a week.

## What counts

- A way to get a package past the proxy without a verdict: a route, encoding or
  redirect that skips the scan.
- A way to make the hook allow a command that installs a package it should have checked.
- A crash, hang or unbounded memory use caused by an archive, lockfile or HTTP request
  (the scanner reads attacker-controlled bytes).
- Anything that runs package code: Customs must never execute, import or install what it
  scans.
- Policy changes that skip the admin token, and secrets that leak into logs, verdicts or
  webhook messages.

A malicious package that the model scores as safe is a detection gap, not a
vulnerability. Those are still useful: open an ordinary issue with the package name,
version and registry. Do not attach the archive, since registries remove malware and a
name and version are enough to find it in public datasets.
