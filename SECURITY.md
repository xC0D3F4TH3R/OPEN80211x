# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Reporting a vulnerability

open80211 is a security testing tool and is itself security-sensitive.
Please report issues privately:

* Open a **private vulnerability report** via GitHub's "Security" tab
  (preferred), or
* Email the maintainers (address listed on the repository).

Do **not** open a public issue for a vulnerability before it is addressed.

When reporting, include:
* Affected module(s) and version,
* A minimal reproduction (no live network targets / victim data),
* Impact assessment and proposed fix, if any.

## Scope

We take reports affecting the integrity of the tool seriously, e.g.:
* Code execution or privilege escalation via crafted captures/files,
* Injection or privilege misuse in the MITM / Evil AP modules,
* Mishandling of captured credentials, keys, or CA material,
* Unsafe default behavior that could harm third parties.

## Response

You can expect an acknowledgement within 3 business days and a fix
recommendation shortly after triage.

## Responsible use

This tool performs intrusive actions by design. It is intended solely for
authorized assessments. Misuse reports are out of scope; the project does not
assist with unauthorized use.