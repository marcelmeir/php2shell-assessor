# Contributing

Contributions that improve safe discovery, reporting, portability, tests, or
documentation are welcome.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
```

Windows activation: `.venv\Scripts\activate`.

## Pull requests

- Keep network behavior non-invasive and bounded.
- Do not add exploits, authentication attempts, access-control bypasses,
  brute-force discovery, denial-of-service behavior, or write methods.
- Preserve strict target-scope enforcement for DNS and redirects.
- Add or update tests for behavior changes.
- Do not include real scan results, internal hostnames, credentials, tokens, or
  organization-specific inventories.
- Explain user-visible behavior and security tradeoffs in the pull request.

Run the complete test suite before submitting a pull request.

## Security reports

Do not disclose security-sensitive defects in a public issue. Use the
repository's private GitHub security-advisory reporting channel as described in
`SECURITY.md`.
