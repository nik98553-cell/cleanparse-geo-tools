# 2026 Public Documentation AI Search Visibility Benchmark

Snapshot captured at `2026-11-21T05:57:57Z` using [`scripts/check_llms_and_robots.py`](../scripts/check_llms_and_robots.py) (`v0.2.5`).

> Live web page counterpart: <https://cleanparse.com/ai-crawler-visibility-benchmark>

## Summary of Observed Snapshot

- **Targets tested**: 12 public developer documentation & tool homepages
- **HTTP 2xx pages**: 12 / 12
- **HTML pages parsed (excluding 204 / 206)**: 12 / 12
- **All 3 AI search crawlers allowed (`OAI-SearchBot`, `Claude-SearchBot`, `PerplexityBot`)**: 12 / 12
- **At least one AI training crawler blocked (`GPTBot` / `ClaudeBot`)**: 0 / 12
- **Split policy (allow search, block training)**: 0 / 12
- **`/llms.txt` HTTP 2xx / strict structural valid**: 7 / 7
- **Static HTML `server_rendered` (among 2xx)**: 12 / 12

## Results Table

| Site | HTTP | OAI-SearchBot | Claude-SearchBot | PerplexityBot | GPTBot | ClaudeBot | /llms.txt | Non-JS Words | HTML Verdict |
|---|---|---|---|---|---|---|---|---|---|
| [CleanParse Studio](https://cleanparse.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (12 links, valid) | 609 | `server_rendered` |
| [Next.js Docs](https://nextjs.org/docs) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (10 links, valid) | 605 | `server_rendered` |
| [React Docs](https://react.dev/learn) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (181 links, valid) | 2021 | `server_rendered` |
| [Astro](https://astro.build/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 926 | `server_rendered` |
| [Vite Guide](https://vite.dev/guide/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (43 links, valid) | 1469 | `server_rendered` |
| [Vue.js Guide](https://vuejs.org/guide/introduction.html) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (94 links, valid) | 1698 | `server_rendered` |
| [Svelte Docs](https://svelte.dev/docs) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (7 links, valid) | 212 | `server_rendered` |
| [Nuxt Docs](https://nuxt.com/docs) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (436 links, valid) | 1024 | `server_rendered` |
| [Docusaurus Docs](https://docusaurus.io/docs) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 1874 | `server_rendered` |
| [Tailwind CSS Docs](https://tailwindcss.com/docs) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 798 | `server_rendered` |
| [Python 3 Docs](https://docs.python.org/3/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 526 | `server_rendered` |
| [MDN Web Docs](https://developer.mozilla.org/en-US/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 909 | `server_rendered` |

## Methodology & Caveats

- **Read-only single-pass GETs**: Each target is audited once via RFC 9309 `robots.txt` evaluation, `/llms.txt` structure checks, and raw HTML visible-text extraction without executing JavaScript.
- **No anti-bot or firewall bypass**: HTTP status codes are recorded verbatim without retries, spoofed headers, or workarounds. 403/429 or non-2xx statuses yield `fetch_failed`; HTTP 200 challenge pages enter static word counting without JS execution or WAF bypass.
- **HTTP 204 / 206**: an HTTP 204 page counts as 2xx with verdict `no_content` (no HTML body, not parsed); an HTTP 206 partial page counts as 2xx but is not parsed (`fetch_failed`); a `/llms.txt` HTTP 204 (empty body) is not a valid `llms.txt`.
- **`robots.txt` fetch failure**: if `robots.txt` fails after the page was fetched, the observed page HTTP status and HTML fields are kept, `robots_policy` becomes `error` (crawler cells show `ERROR`) and the message is recorded in `error`.
- **`/llms.txt` fetch failure**: if `/llms.txt` fails, the robots policy and crawler verdicts are kept, `llms_http_status` is `null` (table cell `ERR`) and the message is recorded in `error`.
- **No `*` group**: when a `robots.txt` has no group matching any AI crawler and no `*` wildcard group, the row notes that RFC 9309 defaults to allow all.
- **Point-in-time snapshot**: Crawler policies, `robots.txt`, and server rendering change over time. Verify any site's current status live via:

```bash
python3 scripts/check_llms_and_robots.py --url https://cleanparse.com/
```

## Reproduce

```bash
python3 -B benchmarks/run_public_docs_benchmark.py
```

Add `--use-system-proxy` (routes through local OS proxy; proxy egress DNS is outside local SSRF IP pinning). It requires an explicit `http://host:port` OS proxy, exits with code 2 before touching any output file when none is configured, and never falls back to unpinned direct TCP.

```bash
python3 -B benchmarks/run_public_docs_benchmark.py --use-system-proxy
```

MIT Licensed dataset (`public_docs_geo_2026.json` & `public_docs_geo_2026.csv`). The other 11 measured sites are not affiliated with and do not endorse this benchmark (CleanParse Studio is our own site).
