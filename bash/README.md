# PHP2Shell Bash and curl scanner

This folder contains a standalone Linux shell scanner for potential exposure to
CVE-2026-109618 and CVE-2026-109619.

## Requirements

- Bash 3.2 or newer
- curl
- awk

No Nmap, Nuclei, Python, jq, or project files are required.

## Run

    ./php2shell-exposure.sh https://TARGET/index.php

Optional controls:

    ./php2shell-exposure.sh \
      --connect-timeout 5 \
      --max-time 15 \
      https://TARGET/index.php

Use --insecure only for an explicitly approved target whose TLS certificate
cannot be verified.

The script sends one GET, does not follow redirects, and inspects the final
response header block for duplicate X-Powered-By and Server fields.

## Exit codes

- 0: no affected PHP version was disclosed
- 1: at least one likely affected PHP version was disclosed
- 2: usage, dependency, request, or response error

## Interpretation

The script prints every PHP version it observes and its assessment. LIKELY
VULNERABLE is a banner-based result and is not proof of exploitability. A clean
result does not prove remediation when banners are hidden, stale, supplied by a
proxy, or unchanged after a vendor backport.
