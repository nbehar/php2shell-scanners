# PHP2Shell Nmap NSE scanner

This folder contains a standalone, banner-based Nmap check for potential
exposure to CVE-2026-109618 and CVE-2026-109619.

## Requirements

- Nmap with its standard NSE libraries
- Network permission to make one HTTP GET request to each target

The script uses only the http, shortport, stdnse, and vulns libraries bundled
with Nmap. It does not require any file outside this folder.

## Run

    nmap -sV -p 80,443 \
      --script ./http-vuln-php2shell.nse \
      --script-args 'http-vuln-php2shell.path=/index.php' \
      TARGET

On a nonstandard port that Nmap labels unknown, force the script with a leading
plus sign:

    nmap -Pn -p 8080 \
      --script +./http-vuln-php2shell.nse \
      --script-args 'http-vuln-php2shell.path=/index.php' \
      TARGET

The path must start with one slash. Redirects are not followed.

## Interpret the result

LIKELY VULNERABLE means a response disclosed a PHP version below the first
upstream fixed release. No script output means no affected version was
disclosed.

This is not an exploit test. Hidden, stale, spoofed, proxy-supplied, or
backported version banners can produce incomplete or misleading results.
Confirm the serving runtime and package provenance before remediation or
closure.
