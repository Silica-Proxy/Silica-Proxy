# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |

Older releases are not actively patched. Please upgrade to the latest version before reporting a vulnerability.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via one of the following channels:

- **GitHub Private Security Advisory** (preferred): open a [draft security advisory](../../security/advisories/new) in this repository — it is visible only to maintainers.
- **Email**: send details to `silicaproxy@gmail.com` with the subject line `[SECURITY] <short description>`.

### What to include

- A clear description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code or HTTP traces if applicable)
- Affected component and version
- Your suggested fix or mitigation, if any

### Response timeline

| Event | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Initial assessment | 7 business days |
| Fix or workaround | 30 days (critical), 90 days (others) |
| Public disclosure | Coordinated with the reporter after fix is released |

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure): please allow us to release a fix before making the vulnerability public.

## Scope

In scope:

- Proxy bypass (a vulnerable or blocked package is allowed through)
- Authentication/authorization flaws in the admin API
- Remote code execution or SSRF via crafted package metadata
- SQL injection or path traversal in package URL parsing
- Sensitive data exposure (credentials, tokens) in logs or API responses

Out of scope:

- Vulnerabilities in dependencies not yet fixed upstream (report to the upstream project first)
- Denial-of-service attacks without a practical exploit path
- Issues requiring physical access to the host

## Security Hardening

Refer to the [README](README.md) for recommended JVM flags, PostgreSQL configuration, and network isolation guidelines to run SilicaProxy securely in production.
