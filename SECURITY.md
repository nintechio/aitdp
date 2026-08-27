# Security Policy

## Reporting a vulnerability

AITDP is a security tool; we take bugs in it seriously.

**Please do not open public issues for security vulnerabilities.** Instead, use
GitHub's private vulnerability reporting ("Report a vulnerability" under the
Security tab) or email **admin@nintech.io**.

We aim to acknowledge reports within 3 business days.

## What counts

- Bypasses of a rule that is documented as covering a technique are **rule accuracy
  issues**, not vulnerabilities — please open a normal issue with the
  *False positive / false negative* template. Detection is best-effort by design.
- ReDoS in a shipped rule, code execution via crafted rule files, or the SDK
  crashing an application on untrusted input **are** vulnerabilities.

## Supported versions

Only the latest minor release receives security fixes.
