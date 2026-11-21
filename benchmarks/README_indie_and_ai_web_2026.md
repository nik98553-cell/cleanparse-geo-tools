# 2026 Indie SaaS & AI Web Apps AI Search Visibility Benchmark

Snapshot captured at `2026-11-21T12:00:10Z` using [`scripts/check_llms_and_robots.py`](../scripts/check_llms_and_robots.py) (`v0.2.5`).

## Summary of Observed Snapshot

- **Targets tested**: 60 public indie SaaS, AI web app & developer tool homepages
- **HTTP 2xx pages**: 57 / 60
- **HTML pages parsed (excluding 204 / 206)**: 57 / 60
- **All 3 AI search crawlers allowed (`OAI-SearchBot`, `Claude-SearchBot`, `PerplexityBot`)**: 57 / 57 (robots.txt checked on 57 of 59 completed requests; 2 hit stop-on-block or a robots.txt fetch error)
- **At least one AI training crawler blocked (`GPTBot` / `ClaudeBot`)**: 0 / 57 (robots.txt checked on 57 of 59 completed requests; 2 hit stop-on-block or a robots.txt fetch error)
- **Split policy (allow search, block training)**: 0 / 57 (robots.txt checked on 57 of 59 completed requests; 2 hit stop-on-block or a robots.txt fetch error)
- **`/llms.txt` HTTP 2xx / strict structural valid**: 46 / 38
- **Static HTML `server_rendered` (among 2xx)**: 54 / 57

## Results Table

| Site | HTTP | OAI-SearchBot | Claude-SearchBot | PerplexityBot | GPTBot | ClaudeBot | /llms.txt | Non-JS Words | HTML Verdict |
|---|---|---|---|---|---|---|---|---|---|
| [Cursor](https://cursor.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (0 links, non-standard) | 1422 | `server_rendered` |
| [Replit](https://replit.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (229 links, valid) | 1417 | `server_rendered` |
| [Bolt.new](https://bolt.new/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (0 links, non-standard) | 504 | `server_rendered` |
| [Lovable](https://lovable.dev/) | 403 | ERROR | ERROR | ERROR | ERROR | ERROR | ERR | 0 | `fetch_failed` |
| [v0](https://v0.dev/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (0 links, non-standard) | 293 | `server_rendered` |
| [Windsurf](https://windsurf.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (0 links, non-standard) | 901 | `server_rendered` |
| [Jina AI](https://jina.ai/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 1688 | `server_rendered` |
| [Firecrawl](https://firecrawl.dev/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (188 links, valid) | 3413 | `server_rendered` |
| [Exa](https://exa.ai/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (122 links, valid) | 312 | `server_rendered` |
| [Tavily](https://tavily.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (122 links, valid) | 846 | `server_rendered` |
| [Ollama](https://ollama.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (10 links, valid) | 78 | `thin_content` |
| [OpenRouter](https://openrouter.ai/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (51 links, valid) | 610 | `server_rendered` |
| [Hugging Face](https://huggingface.co/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 714 | `server_rendered` |
| [Together AI](https://together.ai/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (91 links, valid) | 3518 | `server_rendered` |
| [Groq](https://groq.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 140 | `thin_content` |
| [Replicate](https://replicate.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (0 links, valid) | 2202 | `server_rendered` |
| [Perplexity](https://perplexity.ai/) | 403 | ERROR | ERROR | ERROR | ERROR | ERROR | ERR | 0 | `fetch_failed` |
| [Anthropic](https://anthropic.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 186 | `server_rendered` |
| [Linear](https://linear.app/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (186 links, valid) | 1545 | `server_rendered` |
| [Cal.com](https://cal.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (52 links, valid) | 3290 | `server_rendered` |
| [Dub](https://dub.co/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (5 links, valid) | 2106 | `server_rendered` |
| [Resend](https://resend.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (57 links, valid) | 2332 | `server_rendered` |
| [Railway](https://railway.app/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (41 links, valid) | 1258 | `server_rendered` |
| [Fly.io](https://fly.io/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (32 links, valid) | 796 | `server_rendered` |
| [Render](https://render.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (414 links, valid) | 312 | `server_rendered` |
| [Neon](https://neon.tech/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (177 links, non-standard) | 900 | `server_rendered` |
| [Turso](https://turso.tech/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (0 links, non-standard) | 1178 | `server_rendered` |
| [Upstash](https://upstash.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (27 links, valid) | 1383 | `server_rendered` |
| [Convex](https://convex.dev/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (39 links, non-standard) | 1208 | `server_rendered` |
| [Clerk](https://clerk.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (49 links, valid) | 1546 | `server_rendered` |
| [PostHog](https://posthog.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (4910 links, valid) | 1271 | `server_rendered` |
| [Plausible](https://plausible.io/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 1145 | `server_rendered` |
| [Umami](https://umami.is/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (111 links, valid) | 0 | `likely_csr_shell` |
| [Twenty](https://twenty.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (6 links, valid) | 1624 | `server_rendered` |
| [Documenso](https://documenso.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 1969 | `server_rendered` |
| [Formbricks](https://formbricks.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (73 links, valid) | 2074 | `server_rendered` |
| [Trigger.dev](https://trigger.dev/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (37 links, valid) | 2114 | `server_rendered` |
| [Inngest](https://inngest.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (325 links, valid) | 1550 | `server_rendered` |
| [Supabase](https://supabase.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (44 links, valid) | 1378 | `server_rendered` |
| [Vercel](https://vercel.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (87 links, valid) | 485 | `server_rendered` |
| [Netlify](https://netlify.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (27 links, valid) | 772 | `server_rendered` |
| [Cloudflare](https://cloudflare.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (90 links, valid) | 1149 | `server_rendered` |
| [Mintlify](https://mintlify.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (42 links, valid) | 1556 | `server_rendered` |
| [Fern](https://fern.build/) | ERR | ERROR | ERROR | ERROR | ERROR | ERROR | ERR | - | `fetch_error` |
| [ReadMe](https://readme.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (197 links, valid) | 2151 | `server_rendered` |
| [GitBook](https://gitbook.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (100 links, valid) | 1652 | `server_rendered` |
| [Framer](https://framer.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (61 links, valid) | 1859 | `server_rendered` |
| [Webflow](https://webflow.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (75 links, valid) | 2928 | `server_rendered` |
| [Carrd](https://carrd.co/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 316 | `server_rendered` |
| [Tally](https://tally.so/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (27 links, valid) | 1424 | `server_rendered` |
| [Typeform](https://typeform.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (23 links, valid) | 1050 | `server_rendered` |
| [Lemon Squeezy](https://lemonsqueezy.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 1135 | `server_rendered` |
| [Polar](https://polar.sh/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (133 links, valid) | 1536 | `server_rendered` |
| [Creem](https://creem.io/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (0 links, non-standard) | 1924 | `server_rendered` |
| [Stripe](https://stripe.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (304 links, valid) | 6107 | `server_rendered` |
| [Gumroad](https://gumroad.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (7 links, valid) | 682 | `server_rendered` |
| [Paddle](https://paddle.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 789 | `server_rendered` |
| [shadcn/ui](https://shadcn.com/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 172 | `server_rendered` |
| [Lucide](https://lucide.dev/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | 200 (255 links, valid) | 204 | `server_rendered` |
| [htmx](https://htmx.org/) | 200 | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW | HTTP 404 | 354 | `server_rendered` |

## Methodology & Caveats

- **Read-only single-pass GETs**: Each target is audited once via RFC 9309 `robots.txt` evaluation, `/llms.txt` structure checks, and raw HTML visible-text extraction without executing JavaScript.
- **No anti-bot or firewall bypass**: HTTP status codes are recorded verbatim without retries, spoofed headers, or workarounds. 403/429 or non-2xx statuses yield `fetch_failed`; HTTP 200 challenge pages enter static word counting without JS execution or WAF bypass.
- **HTTP 204 / 206**: an HTTP 204 page counts as 2xx with verdict `no_content` (no HTML body, not parsed); an HTTP 206 partial page counts as 2xx but is not parsed (`fetch_failed`); a `/llms.txt` HTTP 204 (empty body) is not a valid `llms.txt`.
- **`robots.txt` fetch failure**: if `robots.txt` fails after the page was fetched, the observed page HTTP status and HTML fields are kept, `robots_policy` becomes `error` (crawler cells show `ERROR`) and the message is recorded in `error`.
- **`/llms.txt` fetch failure**: if `/llms.txt` fails, the robots policy and crawler verdicts are kept, `llms_http_status` is `null` (table cell `ERR`) and the message is recorded in `error`.
- **Stop-on-block**: redirects are followed and every hop is checked against its own host's `robots.txt`; a `robots.txt` HTTP 404 means allow all (RFC 9309). If the page itself returns HTTP 403 or 429, no `robots.txt` or `/llms.txt` request is sent to that site (`robots_policy` `error`, `llms_http_status` `null`); if a `robots.txt` returns HTTP 429, `/llms.txt` on that origin is skipped.
- **No `*` group**: when a `robots.txt` has no group matching any AI crawler and no `*` wildcard group, the row notes that RFC 9309 defaults to allow all.
- **Point-in-time snapshot**: Crawler policies, `robots.txt`, and server rendering change over time. Verify any site's current status live via:

```bash
python3 scripts/check_llms_and_robots.py --url https://cleanparse.com/
```

## Reproduce

```bash
python3 -B benchmarks/run_public_docs_benchmark.py --targets-json benchmarks/targets_indie_and_ai_web_2026.json --benchmark-name indie_and_ai_web_2026
```

Add `--use-system-proxy` (routes through local OS proxy; proxy egress DNS is outside local SSRF IP pinning). It requires an explicit `http://host:port` OS proxy, exits with code 2 before touching any output file when none is configured, and never falls back to unpinned direct TCP.

```bash
python3 -B benchmarks/run_public_docs_benchmark.py --use-system-proxy --targets-json benchmarks/targets_indie_and_ai_web_2026.json --benchmark-name indie_and_ai_web_2026
```

MIT Licensed dataset (`indie_and_ai_web_2026.json` & `indie_and_ai_web_2026.csv`). All 60 measured sites are third-party public sites and are not affiliated with or endorse this benchmark.
