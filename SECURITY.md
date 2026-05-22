# Security Policy

## Reporting a Vulnerability

If you find a security issue in TinyLoad (not in a file packed with it, but in the packer itself), please report it privately.

**Do not open a public issue.**

Email me at ugaafelix@gmail.com or open a private vulnerability report through GitHub.

I'll respond within 48 hours and work with you on a fix. Please don't disclose the issue publicly until it's patched.

## What Counts as a Vulnerability

Bugs in the packer that could be exploited (buffer overflows, arbitrary code execution during packing, etc).

## What Doesn't Count

The fact that a packed file can be reverse engineered. TinyLoad is obfuscation, not "unbreakable" encryption
