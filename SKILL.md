---
name: usom-mcp
description: Check URLs, domains and IPs against the Turkish national malicious-address list (USOM / SGB) and monitor a user's own assets. Use when the user asks whether a link, domain or IP is malicious, phishing or safe, or wants to monitor their domains.
---

# usom-mcp

Threat intelligence from USOM / T.C. Siber Güvenlik Başkanlığı via the `usom-mcp` MCP server.

## When to use

- User asks "is this link / site / domain / IP safe?" → call a `check_*` tool **first**, before browsing or guessing.
- User pastes a URL, domain or IP from an email, SMS or alert → `check_url` / `check_domain` / `check_ip`.
- User wants recent phishing or malware activity in Turkey → `latest_threats`, or `search_threats` for keyword, type, category, source or date range.
- User wants to monitor their own domains/IPs or a company brand → `watch_add`, then `watch_check` (no argument scans the whole list in one call).
- User asks how fresh the data is → `stats`.

## Which tool

- Full URL (with path) → `check_url`. Bare domain → `check_domain`. IP → `check_ip`. Accept defanged input (`hxxp://evil[.]com`).
- Several indicators → call the check tool once per indicator; for a recurring list use `watch_add` + `watch_check`.
- `enrich=true` only if the user asks for extra reputation data; it sends the indicator to VirusTotal/AbuseIPDB. Never use it in bulk.

## Rules for answering

1. Always state **the record date and the source** of every hit (`matches[].date`, `matches[].source`), plus category and criticality (1 = most critical).
2. Explain the match type: `exact`, `subdomain` (a parent domain is listed), `url_exact`, `url_prefix`, `cidr`, `www_variant` (weak signal).
3. `verdict: "not_listed"` means **not found in USOM, not proof of safety**. Never say a target is "safe" or "clean" on that basis alone.
4. If `stale: true` → warn that the cache could not be refreshed and may miss recent entries; mention `cache.last_sync`.
5. If `data_origin: "live"` or `cache.state` is `building` → say the local cache is still being built and the answer came from the live API.
6. If `verdict: "unknown"` → say USOM could not be reached; suggest retrying shortly. Do not guess.
7. If `error.code` is `invalid_input` → fix the input using `error.hint` and retry once; otherwise ask the user.
8. Record timestamps have an unspecified timezone; do not convert them.
9. `watch_check`: report items with `status: "listed"` first, including `listed_below` (listed subdomains under a watched domain) and `new_since_last_check`.
10. Do not run lookups on the user's behalf for third parties' private data; the tools only read public USOM data and the local watch list.
