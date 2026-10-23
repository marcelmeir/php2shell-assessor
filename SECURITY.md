# Security Policy

## Reporting a vulnerability

Do not disclose security-sensitive defects, scope escapes, or unsafe network
behavior in a public issue.

Use GitHub's private vulnerability-reporting feature when it is available for
this repository. If it is not available, open a minimal public issue asking the
maintainers for a private contact channel without including technical details,
target information, credentials, or proof-of-concept material.

Include the affected version, platform, impact, and a minimal sanitized
reproduction. Do not test a suspected defect against systems you do not own or
have explicit permission to assess.

## Authorized use

Active scans must only target explicitly approved address ranges. Domain lists
never expand the configured IP scope. The TOML launcher therefore requires
`authorization_confirmed = true`.

DNS resolution may disclose internal names to the configured resolver. Set
`resolve_domains = false` when this is not permitted and supply explicit
IP/hostname mappings instead.

## Network behavior

The tool performs:

- TCP connection attempts on the configured ports
- bounded HTTP `GET` requests to a small, explicit path list
- at most 256 KiB of response-body processing per request
- no automatic redirect following
- no exploitation, authentication, write methods, access-control bypasses,
  parameter fuzzing, or denial-of-service tests

## Result interpretation

`CRITICAL` means that a publicly visible PHP version string is below the
configured upstream baseline. It is a prioritized verification finding, not
proof of exploitability. Linux distributions may backport security fixes without
changing the visible upstream version.

`PATCH_LEVEL_DETECTED` is also not a verified patch status. Verification requires
a trusted inventory source or an authenticated administrative check.

Missing PHP indicators do not prove that PHP is absent. Reverse proxies, load
balancers, disabled headers, stale headers, and intentionally misleading headers
can all affect detection.
