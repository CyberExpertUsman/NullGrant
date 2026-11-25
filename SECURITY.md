# Security policy

## This is a security tool — read this first

NullGrant sends live HTTP requests to whatever target you name, including deliberately
malformed and off-site `redirect_uri` values. Only run it against a server you own, or one
you hold written permission to test.

The tool enforces this with a gate rather than trusting you to read the docs: nothing is
sent unless you pass `--i-authorize-target`, or complete the interactive prompt by typing
the target hostname exactly.

## What the tool deliberately does not do

- No brute forcing, credential stuffing, or rate-limit testing
- No enumeration of clients, users, tenants or accounts beyond the single `client_id` you
  supply (one probe uses an obviously-fake nonexistent client id, to see whether the error
  response leaks a stack trace)
- No exploitation of anything it finds — it reports conditions, not working attacks
- No writes, no state changes, no token revocation
- No connections to any host other than the endpoints you supply

The only external-looking hostname in the source is `evil-audit.invalid`. `.invalid` is
reserved by RFC 2606 specifically for tests that must fail, and is guaranteed never to
resolve. It is used only as a string value inside a `redirect_uri` parameter sent to your
own server; the tool never connects to it. **Do not replace it with an unreserved name.**

## Handling output

Reports can contain details about your infrastructure: endpoint URLs, advertised
capabilities, error message text, and truncated credential values. `.gitignore` excludes
`report*/` for this reason. Review a report before sharing or committing it.

Credential-like parameters (`access_token`, `id_token`, `refresh_token`, `code`,
`client_secret`, `code_verifier`, `password`) are truncated in console output, JSON and
HTML. `state` is deliberately not redacted, because verifying that it is echoed verbatim is
the point of the check.

## Destructive checks

`--refresh-token` with `--allow-refresh-replay` consumes the token you supply, and a
correctly configured server will revoke the entire token family when it sees the replay.
Use a throwaway lab session. This is why the check requires two separate flags.

## Reporting a vulnerability in this tool

If you find a defect in NullGrant itself — particularly one that could cause it to send
traffic somewhere the operator did not intend, or to leak a credential into a report —
please open a private security advisory rather than a public issue:

GitHub → this repository → **Security** → **Advisories** → **Report a vulnerability**

Please include the version (`nullgrant --version`), the command line used with
credentials removed, and what you expected to happen.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Disclaimer

A PASS finding means "no weakness was observed from this position", not "this server is
secure". Several controls — refresh-token rotation, sender-constrained tokens, token
lifetimes, consent behaviour — cannot be verified by external probing and are reported as
advisories. Nothing this tool produces is a substitute for a full security review.
