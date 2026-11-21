# CleanParse GEO & Format Starter CLI (`cleanparse-geo-tools`)

A small, zero-dependency toolkit for developers and site owners who want their pages to be
**found and cited by AI search engines** without handing content to model-training crawlers.

- `scripts/check_llms_and_robots.py` - one Python 3.12 file, standard library only:
  - audits `robots.txt` for **AI search crawlers** (`OAI-SearchBot`, `Claude-SearchBot`, `PerplexityBot`)
    separately from **AI training crawlers** (`GPTBot`, `ClaudeBot`), using RFC 9309 group selection
    and longest-match rules;
  - lints `llms.txt` structure (`# Title`, `> summary`, `##` sections of `- [name](url)` links);
  - flags empty client-side-rendered (CSR) HTML shells that crawlers without JavaScript see as blank pages.
- `examples/` - clean fixtures for robots/llms checks plus messy sample data for CSV normalization,
  BibTeX deduplication and SSR-vs-CSR comparisons.
- `benchmarks/` - a reproducible public docs benchmark (runner plus the MIT-licensed JSON / CSV dataset).
- `tests/` - an offline `unittest` suite (no network calls).

MIT licensed. No install step, no `pip`, no API keys.

## Use it online (free browser tools)

Prefer not to run anything locally? The same checks run in the browser:

| Tool / guide | Link |
|---|---|
| Live web workbench | <https://cleanparse.com/> |
| AI search visibility checker | <https://cleanparse.com/ai-search-visibility-checker> |
| CSV cleaner | <https://cleanparse.com/csv-cleaner> |
| BibTeX sanitizer | <https://cleanparse.com/bibtex-sanitizer> |
| HTML to Markdown | <https://cleanparse.com/html-to-markdown> |
| Guide: AI crawlers in robots.txt | <https://cleanparse.com/ai-crawler-robots-txt-guide> |
| Guide: SPA / JS rendering and GEO | <https://cleanparse.com/spa-js-rendering-geo-guide> |
| 2026 AI crawler visibility benchmark | <https://cleanparse.com/ai-crawler-visibility-benchmark> |

### Official tools

- **Chrome extension** - CleanParse Web to Markdown:
  <https://chromewebstore.google.com/detail/cleanparse-web-to-markdow/iccjfnefgcplkknmgnkkgphafkcaiaii>
- **Offline Pro Pack** - one-time purchase, local workbench ZIP: <https://cleanparse.com/#pricing>

This repository is the free, open companion; it does not contain the Pro Pack.

## Quick start

Requires Python 3.12+ (use `python` instead of `python3` on Windows).

```bash
git clone https://github.com/nik98553-cell/cleanparse-geo-tools.git
cd cleanparse-geo-tools

# Live mode: fetches /robots.txt, /llms.txt and the page itself
python3 scripts/check_llms_and_robots.py --url https://cleanparse.com/

# Offline mode: audit local files (nothing leaves your machine)
python3 scripts/check_llms_and_robots.py \
  --robots-file examples/sample_robots.txt \
  --llms-file examples/sample_llms.txt \
  --html-file examples/csr_vs_ssr_sample.html

# Machine-readable output, and a specific path to test robots rules against
python3 scripts/check_llms_and_robots.py --robots-file examples/sample_robots.txt --path /account/ --json
```

Abridged example output (offline mode with the bundled fixtures):

```text
[robots.txt] examples/sample_robots.txt  (path /, 4 groups)
  AI search    OAI-SearchBot     ALLOW    group=OAI-SearchBot     Allow: /
  AI search    Claude-SearchBot  ALLOW    group=Claude-SearchBot  Allow: /
  AI search    PerplexityBot     ALLOW    group=PerplexityBot     Allow: /
  AI training  GPTBot            BLOCK    group=GPTBot            Disallow: /
  AI training  ClaudeBot         BLOCK    group=ClaudeBot         Disallow: /
  policy: search_allowed_training_blocked

[llms.txt] examples/sample_llms.txt  -> VALID
  title: Example Docs | sections: 3 | links: 6

[html] examples/csr_vs_ssr_sample.html  -> likely_csr_shell
  visible words: 0 | script tags: 3 | inline script ratio: 0.219 | empty mounts: root
```

Exit codes: `0` report printed, `1` network or file error, `2` URL refused by the safety guard.

## What the checks mean

### robots.txt: search vs training

AI vendors run different crawlers for different jobs. Blocking one does not block the other:

| Vendor | Search / citation crawler | Training crawler |
|---|---|---|
| OpenAI | `OAI-SearchBot` | `GPTBot` |
| Anthropic | `Claude-SearchBot` | `ClaudeBot` |
| Perplexity | `PerplexityBot` | - |

The script resolves each bot the way RFC 9309 specifies:

1. All groups whose `User-agent` matches the bot's product token (case-insensitive) are merged.
2. If none match, the `User-agent: *` group applies; if there is none, everything is allowed.
3. Among matching `Allow` / `Disallow` patterns, the **longest** wins; on a tie, `Allow` wins.
   `*` and a trailing `$` are supported.

A common mistake is `User-agent: * / Disallow: /` with an exception for Googlebot only - that silently
removes the site from every AI answer engine. `examples/sample_robots.txt` shows the
"allow search, block training" pattern.

Note: robots.txt is a voluntary convention. Vendors document their own bot names and may change them;
check their current documentation before relying on any policy.

### llms.txt

`llms.txt` is a proposed convention: a markdown file at the site root that points language models to the
most useful pages. The linter checks for one H1 title, a `>` summary line, `##` sections, and list items in
the form `- [name](url): optional notes`. Errors make the file invalid; warnings are style hints.

### SSR vs CSR shells

Many AI crawlers fetch raw HTML and do not execute JavaScript. A single-page app that ships
`<div id="root"></div>` plus a bundle looks empty to them. The script counts visible words outside
`<script>`, `<style>`, `<noscript>` and `<template>`, measures the inline-script byte ratio and detects
empty mount nodes (`root`, `app`, `__next`, `__nuxt`, ...). Verdicts: `server_rendered`, `thin_content`,
`likely_csr_shell`. These are heuristics, not a crawler simulation.

## Sample data for format cleanup

| File | Problems it contains | Try it with |
|---|---|---|
| `examples/dirty_orders.csv` | padded headers, duplicate row, blank row, mixed date formats, `$`/`€`/thousand separators, inconsistent status and country values | [CSV cleaner](https://cleanparse.com/csv-cleaner) |
| `examples/messy_refs.bib` | duplicate citation keys, the same DOI under three keys, mixed field casing and quoting | [BibTeX sanitizer](https://cleanparse.com/bibtex-sanitizer) |
| `examples/csr_vs_ssr_sample.html` | an SPA shell with no server-rendered text | this script, `--html-file` |

## Public Docs Benchmark (`benchmarks/`)

A dated, point-in-time snapshot of how 12 public documentation and tool homepages (Next.js, React, Astro,
Vite, Vue.js, Svelte, Nuxt, Docusaurus, Tailwind CSS, Python 3, MDN and our own site) treat AI crawlers.

| File | What it is |
|---|---|
| `benchmarks/run_public_docs_benchmark.py` | Runner: one read-only GET per page, robots.txt and `/llms.txt`, evaluated with the same functions as `scripts/check_llms_and_robots.py` |
| `benchmarks/public_docs_geo_2026.json` | Full dataset: summary counts plus one record per site (crawler verdicts, matched groups, llms.txt stats, HTML verdict) |
| `benchmarks/public_docs_geo_2026.csv` | The same per-site rows as a flat CSV for spreadsheets |
| `benchmarks/README.md` | Generated summary and results table for the latest snapshot |
| `benchmarks/README_indie_and_ai_web_2026.md` | Expanded 60-site cohort (indie SaaS, AI web apps and dev tools), observed `2026-11-21T12:00:10Z`: summary, results table and methodology |
| `benchmarks/indie_and_ai_web_2026.csv` | The 60-site cohort as a flat CSV, one row per site |
| `benchmarks/indie_and_ai_web_2026.json` | The 60-site cohort as JSON: summary counts plus one record per site |
| `benchmarks/targets_indie_and_ai_web_2026.json` | The 60 target URLs used for the expanded cohort (input to the runner's `--targets-json`) |

```bash
python3 -B benchmarks/run_public_docs_benchmark.py
# Opt-in: route through the OS proxy (for fake-IP DNS networks); every redirect hop is still validated
python3 -B benchmarks/run_public_docs_benchmark.py --use-system-proxy
# 60-site cohort
python3 -B benchmarks/run_public_docs_benchmark.py --targets-json benchmarks/targets_indie_and_ai_web_2026.json --benchmark-name indie_and_ai_web_2026 --use-system-proxy
```

Rerunning overwrites the JSON, CSV and `benchmarks/README.md` with a new snapshot. Blocks (HTTP 403 / 429 /
challenge pages) are recorded as-is, with no retries or workarounds. Read the write-up at
<https://cleanparse.com/ai-crawler-visibility-benchmark>. The other 11 measured sites are not affiliated with
and do not endorse this benchmark (CleanParse Studio is our own site).

## Safety of live mode

`--url` only fetches public `http(s)` targets. It refuses other schemes, credentials in the URL, non-web
ports, `localhost` / `.local` / single-label hosts, numeric host tricks, and any IP literal or DNS result that
is loopback, private, link-local, CGNAT or otherwise non-global - on the first request and on every redirect.
Responses are capped at 2 MB with a single 10 s monotonic deadline spanning redirects and body reads, and each hop opens a direct pinned-IP connection (with SNI and certificate hostname verification on HTTPS) so DNS is resolved once per hop and environment proxies are ignored.

If you are behind a proxy or VPN that uses "fake-IP" DNS (answers in `198.18.0.0/15`), live mode will refuse every
host because those answers are not public addresses. Run it on a normal network, or use offline mode with files
you downloaded yourself.

## Run the tests

```bash
python3 -B -m unittest discover -s tests -v
```

The suite is fully offline: socket lookups are patched to fail if any test tries to use the network.
It also checks that the committed benchmark JSON and CSV agree with each other and that the benchmark's
proxy transport refuses unsafe URLs before opening any connection.

## Contributing

Issues and pull requests are welcome - especially new crawler tokens with a link to the vendor's
documentation, and real-world robots.txt edge cases (anonymized). Please keep the script standard-library only.

## License

MIT - see [LICENSE](LICENSE). Copyright (c) 2026 CleanParse Studio <support@cleanparse.com>.
