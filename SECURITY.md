# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub: open the Security tab of
this repository and choose "Report a vulnerability". Do not open a public issue for
a security problem.

Useful details: the version or commit, the SQL input that triggers the problem, and
what you expected to happen.

You can expect a first reply within 7 days. Fixed issues are listed in CHANGELOG.md.

## What counts as a security issue here

rls-open-check reads SQL files and prints findings. It makes no network calls and
never connects to a database. Security issues include:

- the tool reading or writing files outside the paths you pass to it,
- the tool executing code from the files it scans,
- crafted SQL that makes the tool hang or use unbounded memory.

A missed finding (a false negative) or a wrong finding (a false positive) is a bug,
not a vulnerability. Please report those as normal issues, with the SQL that shows it.

## Supported versions

Only the latest commit on main is supported until the first tagged release.
