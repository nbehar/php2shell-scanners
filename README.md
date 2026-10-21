# PHP2Shell scanners

Banner-based checks for potential exposure to CVE-2026-109618 and
CVE-2026-109619. The repository provides the same low-impact check in two
formats:

| Scanner | File | Runtime |
| --- | --- | --- |
| Nmap NSE | [`nmap/php2shell-exposure.nse`](nmap/php2shell-exposure.nse) | Nmap |
| Bash | [`bash/php2shell-exposure.sh`](bash/php2shell-exposure.sh) | Bash, curl, and awk |

The scanners send one HTTP GET request and inspect `X-Powered-By` and `Server`
response headers for a disclosed PHP version. They do not send an exploit
payload.

## Important limitation

A reported version is evidence of potential exposure, not proof that the host
is vulnerable. Headers can be hidden, stale, spoofed, or supplied by a proxy.
Linux distributions and other vendors may also backport fixes without changing
the advertised upstream version. Verify the serving PHP binary and its package
provenance before deciding that a host is vulnerable or remediated.

## Quick start

Use the Nmap script:

```sh
nmap -sV -p 80,443 \
  --script ./nmap/php2shell-exposure.nse \
  --script-args 'php2shell.path=/index.php' \
  TARGET
```

Use the Bash scanner:

```sh
./bash/php2shell-exposure.sh https://TARGET/index.php
```

Each scanner has a more detailed README in its directory.

## Validate locally

```sh
nmap --script-help ./nmap/php2shell-exposure.nse
luac -p ./nmap/php2shell-exposure.nse
shellcheck ./bash/php2shell-exposure.sh
bash -n ./bash/php2shell-exposure.sh
```

## Submit the NSE script to Nmap

Nmap accepts GitHub pull requests even though GitHub is a mirror of its
authoritative Subversion repository.

1. Fork [`nmap/nmap`](https://github.com/nmap/nmap) on GitHub and clone the
   fork.
2. Create a branch from the latest `master` branch.
3. Copy `nmap/php2shell-exposure.nse` into the fork's `scripts/` directory.
   Ask the maintainers in the pull request whether they prefer the current
   name or an `http-vuln-*` name; renaming changes the script-argument prefix.
4. Run the checks above with the script in the Nmap source tree. Test against
   controlled endpoints that return an affected version, a fixed version, no
   PHP version, duplicate headers, and a vendor-suffixed version.
5. Commit the new `.nse` file and open a pull request against
   `nmap/nmap:master`. Do not edit `scripts/script.db`; Nmap generates it.
6. In the pull request, explain that the result is banner-based, list the two
   CVEs and fixed releases, include representative output, and record the Nmap
   version and targets used for testing.
7. Email `dev@nmap.org` with the pull request link and a short description.
   Nmap's contribution guide recommends this because not every committer
   watches GitHub daily.

Useful upstream references:

- [Nmap contribution guide](https://github.com/nmap/nmap/blob/master/CONTRIBUTING.md)
- [Nmap NSE script format](https://nmap.org/book/nse-script-format.html)
- [Nmap code standards](https://secwiki.org/w/Nmap/Code_Standards)
- [PHP security announcement](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

Only scan systems you own or are authorized to assess.
