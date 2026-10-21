# PHP2Shell Nuclei template

This folder contains a banner-based Nuclei template for potential exposure to
CVE-2026-109618 and CVE-2026-109619.

## Requirements

- Nuclei v3
- Tested with Nuclei 3.11.1
- Network permission to make one HTTP GET request to each target

## Validate

    nuclei -validate \
      -t ./php2shell-exposure.yaml \
      -disable-update-check

## Run one target

    nuclei \
      -u https://TARGET/index.php \
      -t ./php2shell-exposure.yaml \
      -disable-update-check

## Run a target list

    nuclei \
      -l targets.txt \
      -t ./php2shell-exposure.yaml \
      -disable-update-check

The template does not follow redirects and does not retain cookies. A finding
includes the affected version token extracted from X-Powered-By or Server.

A finding means an affected upstream version was disclosed. No finding means no
affected version was disclosed; it does not prove the runtime is patched.
Vendor backports, hidden banners, proxies, and stale headers require manual
verification.
