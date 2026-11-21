#!/usr/bin/env python3
"""check_llms_and_robots.py - zero-dependency GEO audit helper (Python 3.12 stdlib only).

Part of cleanparse-geo-tools (MIT License, CleanParse Studio).
Online version: https://cleanparse.com/ai-search-visibility-checker

What it checks
--------------
1. robots.txt   - evaluates AI *search* crawlers (OAI-SearchBot, Claude-SearchBot,
                  PerplexityBot) separately from AI *training* crawlers (GPTBot,
                  ClaudeBot) using RFC 9309 group selection and longest-match rules.
                  Records are split ONLY on CR, LF and CRLF (RFC 9309 2.2); keys and
                  values are trimmed of ASCII space / tab only, so U+2028, U+2029,
                  \\v, \\f or NBSP inside a comment or value never create a directive.
                  Literal '*' / '$' in URIs match '%2A' / '%24' in rules, and the exact
                  URI "/robots.txt" (no query string) is always allowed (RFC 9309
                  2.2.2 / 2.2.3 / 2.3); "/robots.txt?..." is evaluated like any path.
                  URIs, --path values and rule literals share ONE normalization, so
                  "/catalog?tag[]=blue" and "/catalog?tag%5B%5D=blue" are identical.
                  An explicit empty query ("/catalog?") is preserved (RFC 3986 6.2.3)
                  in live --url mode, on every redirect hop and on the wire, so it
                  evaluates exactly like the offline "--path /catalog?". Redirects are
                  resolved with RFC 3986 5.2 (empty path segments such as "//" are
                  kept). A fetched robots.txt is a policy only for 2xx; 4xx means
                  "allow all" and every other status means "disallow all".
2. llms.txt     - lints the markdown structure: "# Title", "> summary", "##" sections
                  with "- [name](url)" link items.
3. HTML (SSR)   - estimates whether a page ships real server-rendered text or an empty
                  client-side (CSR) JavaScript shell: visible word count (text inside
                  `hidden` subtrees, closed <dialog> elements, inline styles whose
                  cascaded display is "none" or visibility "hidden" / "collapse", and
                  inert <template> contents is excluded, honouring HTML implied end tags
                  such as "<p hidden>a<p>b"; declarative shadow roots
                  (<template shadowrootmode="open|closed">) are rendered content;
                  visible <body> <noscript> fallback text counts, <head> <noscript> is
                  ignored; CJK characters count as one word each), executable <script>
                  byte ratio (JSON-LD, JSON and importmap data blocks are not
                  JavaScript) and empty SPA mount nodes. In --url mode a 2xx page with
                  an explicit non-HTML Content-Type is reported as
                  "unsupported_content" instead of being parsed as HTML.

Modes
-----
Offline:  --robots-file FILE  --llms-file FILE  --html-file FILE
Live:     --url https://example.com/   (fetches /robots.txt, /llms.txt and the page)

Live mode only fetches public http(s) URLs. It rejects other schemes, credentials in
the URL, localhost, and loopback / private / site-local / link-local / reserved /
multicast / unspecified IP addresses (both IP literals and DNS results, including on
every redirect hop). Internationalized host names are converted once to ASCII IDNA
before every check, the DNS lookup, TLS SNI and the HTTP Host header. Each hop is
resolved exactly once and the TCP connection is pinned to a validated IP (no second
DNS lookup, no environment proxies); if a validated IP refuses the connection the
next validated IP is tried. One monotonic wall-clock deadline covers DNS, every
TCP connect attempt, TLS handshake, request, interim 1xx responses (e.g. 103 Early
Hints, consumed on the same connection), response headers and every body read;
a watchdog armed before the first TCP connect shuts the socket down when the
deadline expires. 101 Switching Protocols is a fetch error. A body that ends before
its declared length is a fetch error.
A gzip / x-gzip / deflate Content-Encoding is decoded incrementally with
MAX_FETCH_BYTES enforced on the DECOMPRESSED output (decompression-bomb safe);
invalid compressed data, oversized output and every other content coding (br, zstd,
layered codings ...) are fetch errors, never parsed as plain text.
In --url mode every redirect hop is evaluated against its own origin's robots.txt
(a crawler is allowed only if allowed at every hop) and the HTML audit reports the
final URL.
"""
from __future__ import annotations

import argparse
import codecs
import functools
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import zlib
from html.parser import HTMLParser

__version__ = "0.2.5"

SEARCH_CRAWLERS = ("OAI-SearchBot", "Claude-SearchBot", "PerplexityBot")
TRAINING_CRAWLERS = ("GPTBot", "ClaudeBot")

USER_AGENT = "cleanparse-geo-tools/%s (+https://github.com/nik98553-cell/cleanparse-geo-tools)" % __version__
MAX_FETCH_BYTES = 2 * 1024 * 1024
FETCH_TIMEOUT = 10
FETCH_CHUNK = 64 * 1024
MAX_REDIRECTS = 5
# Interim (1xx) responses accepted before the final response of one request.
MAX_INTERIM_RESPONSES = 10
# Paths longer than this are rejected with ValueError instead of being silently
# truncated (truncation could make a rule that differs late in the string match).
MAX_MATCH_CHARS = 64 * 1024
MAX_PATH_CHARS = MAX_MATCH_CHARS  # backward-compatible alias

_now = time.monotonic


# --------------------------------------------------------------------------- robots.txt

# RFC 9309 2.2: records end with CR, LF or CRLF only (NOT U+2028, U+2029, \v, \f ...).
_ROBOTS_EOL_RE = re.compile(r"\r\n|\r|\n")
_ROBOTS_WS = " \t"


def parse_robots(text: str) -> list[dict]:
    """Parse robots.txt into groups: [{"agents": [...], "rules": [(allow, path), ...]}].

    Consecutive user-agent lines share one group; a user-agent line that follows
    rules starts a new group (RFC 9309 section 2.1). Sitemap and unknown lines are
    ignored for grouping purposes. A leading UTF-8 BOM is ignored. Records are split
    on CR / LF / CRLF only and trimmed of ASCII space and tab only (RFC 9309 2.2).
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    groups: list[dict] = []
    current: dict | None = None
    last_was_agent = False
    for raw in _ROBOTS_EOL_RE.split(text):
        line = raw.split("#", 1)[0].strip(_ROBOTS_WS)
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip(_ROBOTS_WS).lower()
        value = value.strip(_ROBOTS_WS)
        if key == "user-agent":
            if current is None or not last_was_agent:
                current = {"agents": [], "rules": []}
                groups.append(current)
            current["agents"].append(value)
            last_was_agent = True
        elif key in ("allow", "disallow"):
            last_was_agent = False
            if current is None:
                continue  # rule before any user-agent line: ignored
            if value == "":
                continue  # empty "Disallow:" means nothing is disallowed
            current["rules"].append((key == "allow", value))
        else:
            # sitemap / crawl-delay / unknown keys do not end the agent run in
            # most parsers, but they never carry rules either.
            continue
    return groups


def _product_token(agent_value: str) -> str:
    return agent_value.split("/", 1)[0].strip(_ROBOTS_WS).lower()


def select_rules(groups: list[dict], crawler: str) -> tuple[list[tuple[bool, str]], str]:
    """Return (rules, matched_group_label) for a crawler per RFC 9309 section 2.2.1.

    All groups naming the crawler's product token (case-insensitive) are merged.
    If none match, all "*" groups are merged. If neither exists, no rules apply.
    """
    token = crawler.lower()
    specific = [g for g in groups if any(_product_token(a) == token for a in g["agents"])]
    if specific:
        return [r for g in specific for r in g["rules"]], crawler
    wildcard = [g for g in groups if any(a.strip(_ROBOTS_WS) == "*" for a in g["agents"])]
    if wildcard:
        return [r for g in wildcard for r in g["rules"]], "*"
    return [], "(none)"


_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEXDIGITS = frozenset(b"0123456789abcdefABCDEF")
_RULE_OPS = frozenset(b"*$")
# ASCII characters that are neither unreserved nor RFC 3986 delimiters: always
# percent-encoded, exactly as they are on the wire. URI delimiters such as
# '/', '?', '&', '=', ':', '@', '!', "'", '(', ')', '+', ',', ';' are preserved.
_ALWAYS_ENCODE = frozenset(b'"#<>[\\]^`{|}')


def normalize_path(value: str, encode_rule_ops: bool = True) -> str:
    """Canonical percent-encoding for robots matching (RFC 9309 2.2.2 / RFC 3986 6.2.2).

    One component-aware normalization shared by --url request targets, --path values
    and robots rule literals:
    - %XX escapes of unreserved characters are decoded ("/%64ocs" -> "/docs");
    - remaining escapes get upper-case hex ("%2f" -> "%2F", "%5b" -> "%5B");
    - non-ASCII characters are UTF-8 percent-encoded ("/café" -> "/caf%C3%A9");
    - spaces/control bytes, stray '%' and non-delimiter ASCII characters
      ('[' ']' '{' '}' '|' '^' '<' '>' '"' '\\' '`' '#') are percent-encoded, so
      "/catalog?tag[]=blue" -> "/catalog?tag%5B%5D=blue";
    - URI delimiters ('/', '?', '&', '=', ...) are preserved, and so are empty path
      segments ("/a//b" stays "/a//b");
    - with encode_rule_ops=True (default) literal '*' -> "%2A" and '$' -> "%24", so a
      URI "/foo*bar" compares equal to a rule literal "/foo%2Abar" (RFC 9309 2.2.3).
      Rule patterns must be split on their '*' / trailing '$' operators *before*
      their literal segments are passed here (see _pattern_parts).
    The result is pure ASCII, so len() equals its length in UTF-8 octets. Linear time.
    """
    raw = value.encode("utf-8", errors="replace")
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0x25 and i + 2 < n and raw[i + 1] in _HEXDIGITS and raw[i + 2] in _HEXDIGITS:
            v = int(raw[i + 1:i + 3], 16)
            out.append(chr(v) if v in _UNRESERVED else "%%%02X" % v)
            i += 3
            continue
        if (b == 0x25 or b <= 0x20 or b >= 0x7F or b in _ALWAYS_ENCODE
                or (encode_rule_ops and b in _RULE_OPS)):
            out.append("%%%02X" % b)
        else:
            out.append(chr(b))
        i += 1
    return "".join(out)


def _pattern_parts(pattern: str) -> tuple[list[str], bool, int]:
    """Split a robots path pattern on its operators, then normalize each literal.

    A trailing literal '$' anchors the match; every literal '*' is a wildcard; any
    other '$' is an ordinary character (encoded as %24). '%2A' / '%24' escapes stay
    literal. Returns (segments, end_anchored, length_in_utf8_octets_after_normalization).
    """
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    segments = [normalize_path(seg, encode_rule_ops=True) for seg in body.split("*")]
    length = sum(len(s) for s in segments) + (len(segments) - 1) + (1 if anchored else 0)
    return segments, anchored, length


def wildcard_match(segments: list[str], anchored: bool, path: str) -> bool:
    """Match a normalized path against '*'-split pattern segments without regex.

    Greedy leftmost search of each literal segment with str.find: no backtracking,
    so cost stays bounded by len(path) * number_of_segments (no ReDoS).
    """
    first = segments[0]
    if not path.startswith(first):
        return False
    if len(segments) == 1:
        return path == first if anchored else True
    pos = len(first)
    last = segments[-1]
    for seg in segments[1:-1]:
        if not seg:
            continue
        idx = path.find(seg, pos)
        if idx < 0:
            return False
        pos = idx + len(seg)
    if anchored:
        return len(path) - len(last) >= pos and path.endswith(last)
    return not last or path.find(last, pos) >= 0


ROBOTS_TXT_PATH = "/robots.txt"


def is_allowed(rules: list[tuple[bool, str]], path: str) -> tuple[bool, str | None]:
    """Longest-match evaluation. On equal length, allow wins (RFC 9309 2.2.2).

    Pattern and path are both percent-encoding-normalized first (RFC 9309 2.2.2).
    Length is measured in UTF-8 octets of the normalized pattern. The complete path
    and complete patterns are evaluated (no truncation); a path longer than
    MAX_MATCH_CHARS raises ValueError.

    Only the exact normalized URI "/robots.txt" (no query string) is implicitly
    allowed (RFC 9309 2.2.2 / 2.3). "/robots.txt?foo=1" is a different URI and is
    evaluated against the rules like any other path.
    """
    if len(path) > MAX_MATCH_CHARS:
        raise ValueError("Path is too long to evaluate (%d characters; limit %d)."
                         % (len(path), MAX_MATCH_CHARS))
    if not path.startswith("/"):
        path = "/" + path
    path = normalize_path(path, encode_rule_ops=True)
    if path == ROBOTS_TXT_PATH:
        return True, None
    best: tuple[int, bool, str] | None = None
    for allow, pattern in rules:
        segments, anchored, length = _pattern_parts(pattern)
        if not wildcard_match(segments, anchored, path):
            continue
        if best is None or length > best[0] or (length == best[0] and allow and not best[1]):
            best = (length, allow, pattern)
    if best is None:
        return True, None
    return best[1], ("Allow: " if best[1] else "Disallow: ") + best[2][:200]


def _robots_policy(search: dict, training: dict) -> str:
    search_ok = all(v["allowed"] for v in search.values())
    training_blocked = all(not v["allowed"] for v in training.values())
    if search_ok and training_blocked:
        return "search_allowed_training_blocked"
    if search_ok:
        return "search_allowed_training_allowed_or_mixed"
    if training_blocked:
        return "all_ai_blocked_or_search_partially_blocked"
    return "search_blocked_training_allowed_or_mixed"


def audit_robots(text: str, path: str = "/", source: str = "robots.txt") -> dict:
    groups = parse_robots(text)

    def evaluate(names: tuple[str, ...]) -> dict:
        out = {}
        for name in names:
            rules, group = select_rules(groups, name)
            allowed, matched = is_allowed(rules, path)
            out[name] = {"allowed": allowed, "group": group, "matched_rule": matched}
        return out

    search = evaluate(SEARCH_CRAWLERS)
    training = evaluate(TRAINING_CRAWLERS)
    notes = []
    if not all(v["allowed"] for v in search.values()):
        blocked = [k for k, v in search.items() if not v["allowed"]]
        notes.append("AI search crawlers blocked at %s: %s - pages cannot be cited in AI search answers."
                     % (path[:200], ", ".join(blocked)))
    if not any(v["group"] != "*" and v["group"] != "(none)" for v in {**search, **training}.values()):
        notes.append("No AI-crawler-specific groups found; every bot falls back to the '*' group.")
    return {
        "source": source,
        "path": path,
        "groups_found": len(groups),
        "search_crawlers": search,
        "training_crawlers": training,
        "policy": _robots_policy(search, training),
        "notes": notes,
    }


def _robots_report_for_status(status: int, body: str, path: str, robots_url: str) -> dict:
    """robots audit for one fetched robots.txt, honouring RFC 9309 2.3.1 status rules.

    Only complete 2xx (204 -> empty body -> allow all; 206 Partial Content excluded) is a
    valid policy. 4xx means the file is unavailable (allow all). Every other final status
    (206, 5xx, 1xx, a 3xx that could not be followed, ...) is treated as unreachable:
    disallow all.
    """
    if 200 <= status < 300 and status != 206:
        report = audit_robots(body, path, robots_url)
    elif 400 <= status < 500:
        report = audit_robots("", path, robots_url)
        report["notes"].append(
            "robots.txt returned HTTP %d; RFC 9309 lets crawlers treat an unavailable (4xx) "
            "robots.txt as 'allow all'." % status)
    else:
        report = audit_robots("User-agent: *\nDisallow: /", path, robots_url)
        if status >= 500:
            reason = "while the server error persists"
        else:
            reason = "because the status is neither a complete success (2xx, not 206) nor 'unavailable' (4xx)"
        report["notes"].append(
            "robots.txt returned HTTP %d; RFC 9309 says crawlers must assume 'disallow all' %s."
            % (status, reason))
    report["http_status"] = status
    return report


def combine_robots_hops(hops: list[tuple[str, dict]]) -> dict:
    """Combine per-hop robots reports [(hop_url, report), ...] of one redirect chain.

    A crawler is allowed only if it is allowed at EVERY hop. A single hop returns its
    report unchanged (backward-compatible schema). For several hops the first hop's
    keys are kept, crawler verdicts are AND-combined (each entry gains "blocked_at":
    the first hop URL that blocks it, or None), policy and notes are recomputed, and
    "final_url" / "redirect_chain" are added.
    """
    _first_url, first = hops[0]
    if len(hops) == 1:
        return first
    merged: dict[str, dict] = {}
    for key in ("search_crawlers", "training_crawlers"):
        merged[key] = {}
        for name, base in first[key].items():
            entry = dict(base, blocked_at=None)
            for hop_url, hop in hops:
                verdict = hop[key][name]
                if not verdict["allowed"]:
                    entry = dict(verdict, blocked_at=hop_url)
                    break
            merged[key][name] = entry
    notes: list[str] = []
    for _hop_url, hop in hops:
        for note in hop["notes"]:
            if note not in notes:
                notes.append(note)
    notes.append("Followed a redirect chain of %d URLs; a crawler counts as allowed only if every "
                 "hop is allowed by that hop's own robots.txt." % len(hops))
    combined = dict(first)
    combined.update(
        search_crawlers=merged["search_crawlers"],
        training_crawlers=merged["training_crawlers"],
        policy=_robots_policy(merged["search_crawlers"], merged["training_crawlers"]),
        notes=notes,
        final_url=hops[-1][0],
        redirect_chain=[{
            "url": hop_url,
            "robots_source": hop["source"],
            "path": hop["path"],
            "http_status": hop.get("http_status"),
            "groups_found": hop["groups_found"],
            "policy": hop["policy"],
            "search_crawlers": hop["search_crawlers"],
            "training_crawlers": hop["training_crawlers"],
        } for hop_url, hop in hops],
    )
    return combined


# --------------------------------------------------------------------------- llms.txt

_LINK_ITEM = re.compile(r"^[-*]\s+\[([^\]]+)\]\(([^)\s]+)\)(?:\s*:\s*(.*))?$")
_SHOW_CHARS = 80
_MAX_LISTED = 3


def _short(value: str) -> str:
    """Truncate user-controlled text shown in warnings."""
    return value if len(value) <= _SHOW_CHARS else value[:_SHOW_CHARS] + "..."


def _emit_limited(warnings: list[str], items: list, render, more: str) -> None:
    """Emit at most _MAX_LISTED per-item warnings plus one aggregated remainder line."""
    for item in items[:_MAX_LISTED]:
        warnings.append(render(item))
    if len(items) > _MAX_LISTED:
        warnings.append(more % (len(items) - _MAX_LISTED))


def audit_llms(text: str, source: str = "llms.txt") -> dict:
    if text.startswith("\ufeff"):
        text = text[1:]
    errors: list[str] = []
    warnings: list[str] = []
    lines = [ln.rstrip() for ln in text.splitlines()]
    non_empty = [ln for ln in lines if ln.strip()]
    title = None
    summary = None
    sections: list[dict] = []
    bad_urls: list[list] = []  # parallel to sections: [count, first_bad_url]

    if not non_empty:
        errors.append("File is empty.")
    else:
        first = non_empty[0]
        if first.startswith("# ") and not first.startswith("## "):
            title = first[2:].strip()
        else:
            errors.append("First non-empty line must be an H1 title: '# Project Name'.")
        h1_count = sum(1 for ln in non_empty if ln.startswith("# "))
        if h1_count > 1:
            errors.append("Only one H1 ('# ') heading is allowed; found %d." % h1_count)
        if len(non_empty) > 1 and non_empty[1].startswith(">"):
            summary = non_empty[1].lstrip(">").strip()
        else:
            warnings.append("Missing '> summary' blockquote directly after the title.")

    current: dict | None = None
    current_bad: list | None = None
    deep_count = 0
    first_deep = ""
    for ln in lines:
        s = ln.strip()
        if s.startswith("## "):
            current = {"name": s[3:].strip(), "links": 0, "bad_items": 0}
            current_bad = [0, ""]
            sections.append(current)
            bad_urls.append(current_bad)
        elif s.startswith("#") and not s.startswith("# ") and not s.startswith("## "):
            if not deep_count:
                first_deep = s
            deep_count += 1
        elif current is not None and s[:2] in ("- ", "* "):
            m = _LINK_ITEM.match(s)
            if m:
                current["links"] += 1
                url = m.group(2)
                if not (url.startswith("https://") or url.startswith("http://") or url.startswith("/")):
                    if not current_bad[0]:
                        current_bad[1] = url
                    current_bad[0] += 1
            else:
                current["bad_items"] += 1

    if deep_count:
        warnings.append("%d heading(s) deeper than H2 found, e.g. %r (spec uses H2 sections)."
                        % (deep_count, _short(first_deep)))
    if non_empty and not sections:
        errors.append("No '## Section' headings with link lists found.")

    relative = [(sec, bad) for sec, bad in zip(sections, bad_urls) if bad[0]]
    _emit_limited(
        warnings, relative,
        lambda e: "Section %r has %d link(s) that are not an absolute or root-relative URL, e.g. %r."
                  % (_short(e[0]["name"]), e[1][0], _short(e[1][1])),
        "%d more section(s) have links that are not an absolute or root-relative URL.")
    _emit_limited(
        warnings, [s for s in sections if s["links"] == 0],
        lambda s: "Section %r has no '- [name](url)' link items." % _short(s["name"]),
        "%d more section(s) have no '- [name](url)' link items.")
    _emit_limited(
        warnings, [s for s in sections if s["bad_items"]],
        lambda s: "Section %r has %d list items that are not '- [name](url): notes'."
                  % (_short(s["name"]), s["bad_items"]),
        "%d more section(s) have list items that are not '- [name](url): notes'.")
    return {
        "source": source,
        "valid": not errors,
        "title": title,
        "summary": summary,
        "sections": sections,
        "total_links": sum(s["links"] for s in sections),
        "errors": errors,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- HTML SSR/CSR

_MOUNT_IDS = {"root", "app", "__next", "__nuxt", "svelte", "___gatsby", "q-app"}
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
              "param", "source", "track", "wbr"}
# <template> is handled separately: a plain <template> subtree is inert, a declarative
# shadow root (<template shadowrootmode="open|closed">) is an isolated rendered frame.
# <noscript> is handled separately too: ignored inside <head>, normal content in <body>.
_SKIP_TAGS = ("script", "style")
# Start tags that may appear inside <head>; any other start tag implicitly closes it.
_HEAD_CONTENT_TAGS = frozenset((
    "html", "head", "base", "basefont", "bgsound", "link", "meta", "noframes", "noscript",
    "script", "style", "template", "title"))
# Media types audited as HTML in --url mode (an absent Content-Type is audited too).
_HTML_MEDIA_TYPES = frozenset(("text/html", "application/xhtml+xml"))

# JavaScript MIME type essences (WHATWG MIME Sniffing) plus the "module" script type.
_JS_MIME_ESSENCES = frozenset((
    "application/ecmascript", "application/javascript", "application/x-ecmascript",
    "application/x-javascript", "text/ecmascript", "text/javascript", "text/javascript1.0",
    "text/javascript1.1", "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
    "text/javascript1.5", "text/jscript", "text/livescript", "text/x-ecmascript",
    "text/x-javascript", "module"))

# ---- inline style cascade (display / visibility)
_CSS_WS = " \t\n\r\f"
_IMPORTANT_RE = re.compile(r"!\s*important\s*$", re.I)
_CSS_WIDE_KEYWORDS = frozenset(("inherit", "initial", "unset", "revert", "revert-layer"))
_DISPLAY_KEYWORDS = frozenset((
    "none", "contents", "block", "inline", "inline-block", "run-in", "flow", "flow-root",
    "table", "inline-table", "table-row-group", "table-header-group", "table-footer-group",
    "table-row", "table-cell", "table-column-group", "table-column", "table-caption",
    "flex", "inline-flex", "grid", "inline-grid", "list-item", "ruby", "ruby-base",
    "ruby-text", "ruby-base-container", "ruby-text-container", "math", "-webkit-box",
    "-webkit-inline-box", "-moz-box", "-moz-inline-box", "-ms-flexbox", "-ms-inline-flexbox",
    "-ms-grid", "-ms-inline-grid")) | _CSS_WIDE_KEYWORDS
# Keywords allowed in the multi-keyword display syntax ("inline flex", "block flow-root").
_DISPLAY_MULTI_KEYWORDS = frozenset((
    "block", "inline", "run-in", "flow", "flow-root", "table", "flex", "grid", "ruby",
    "list-item", "math"))
_VISIBILITY_VALUES = frozenset(("visible", "hidden", "collapse")) | _CSS_WIDE_KEYWORDS
_CASCADED_PROPERTIES = ("display", "visibility")


def _split_css_declarations(style: str) -> list[str]:
    """Split an inline style on top-level ';' (strings, escapes, parentheses respected).

    CSS comments are removed (replaced by one space). Linear time.
    """
    decls: list[str] = []
    buf: list[str] = []
    quote = ""
    depth = 0
    i, n = 0, len(style)
    while i < n:
        ch = style[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(style[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "/" and style.startswith("/*", i):
            end = style.find("*/", i + 2)
            i = n if end < 0 else end + 2
            buf.append(" ")
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(style[i + 1])
            i += 2
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            decls.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    decls.append("".join(buf))
    return decls


def _valid_display(value: str) -> bool:
    tokens = value.split(" ")
    if len(tokens) == 1:
        return tokens[0] in _DISPLAY_KEYWORDS
    return (len(tokens) <= 3 and len(set(tokens)) == len(tokens)
            and all(t in _DISPLAY_MULTI_KEYWORDS for t in tokens))


def _resolve_inline_style(style: str) -> dict[str, tuple[str, bool]]:
    """Cascade the inline display / visibility declarations: {prop: (value, important)}.

    Property names and values are case-insensitive; a trailing "!important" is
    honoured. A later !important declaration overrides anything earlier; a later
    normal declaration overrides an earlier normal one but never an earlier
    !important one. Invalid values are dropped (they never override), like CSS does.
    """
    winners: dict[str, tuple[str, bool]] = {}
    for decl in _split_css_declarations(style):
        if ":" not in decl:
            continue
        name, value = decl.split(":", 1)
        prop = name.strip(_CSS_WS).lower()
        if prop not in _CASCADED_PROPERTIES:
            continue
        value = value.strip(_CSS_WS)
        match = _IMPORTANT_RE.search(value)
        important = match is not None
        if important:
            value = value[:match.start()]
        value = " ".join(value.lower().split())
        if not value:
            continue
        if prop == "display" and not _valid_display(value):
            continue
        if prop == "visibility" and value not in _VISIBILITY_VALUES:
            continue
        previous = winners.get(prop)
        if previous is None or important or not previous[1]:
            winners[prop] = (value, important)
    return winners


def _style_hides(style: str) -> bool:
    """True if the cascaded inline display is "none" or visibility "hidden" / "collapse"."""
    winners = _resolve_inline_style(style)
    display = winners.get("display", ("", False))[0]
    visibility = winners.get("visibility", ("", False))[0]
    return display == "none" or visibility in ("hidden", "collapse")


def _element_visibility(attrs, tag: str, parent_details_closed: bool) -> tuple[bool, bool | None, bool]:
    """Return (box_hidden, visibility_override, details_closed) for an HTML element.

    - box_hidden hides an entire subtree unconditionally (`hidden`, `display:none`,
      closed `<dialog>`, or non-`<summary>` child directly inside a closed `<details>`).
    - visibility_override is `True` for `visibility:hidden|collapse`, `False` for
      `visibility:visible` (which CSS allows inside a `visibility:hidden` ancestor),
      and `None` when inherited.
    - details_closed marks `<details>` without `open` so direct text and non-`<summary>`
      children stay concealed.
    """
    has_hidden_attr = False
    has_open_attr = False
    style_val: str | None = None
    seen_style = False
    for name, value in attrs:
        if name == "hidden":
            has_hidden_attr = True
        elif name == "open":
            has_open_attr = True
        elif name == "style" and not seen_style:
            seen_style = True
            style_val = value

    display_none = False
    vis_override: bool | None = None
    if style_val:
        winners = _resolve_inline_style(style_val)
        display_none = winners.get("display", ("", False))[0] == "none"
        vis = winners.get("visibility", ("", False))[0]
        if vis in ("hidden", "collapse"):
            vis_override = True
        elif vis == "visible":
            vis_override = False

    box_hidden = (
        has_hidden_attr
        or display_none
        or (tag == "dialog" and not has_open_attr)
        or parent_details_closed
    )
    details_closed = tag == "details" and not has_open_attr
    return box_hidden, vis_override, details_closed


def _hides_subtree(attrs, tag: str = "") -> bool:
    """Compatibility helper: True when element itself is box-hidden or visibility-hidden."""
    box_hidden, vis_override, _ = _element_visibility(attrs, tag, False)
    return box_hidden or (vis_override is True)


def _is_declarative_shadow_root(attrs) -> bool:
    """<template shadowrootmode="open|closed"> (first attribute wins, ASCII case-insensitive)."""
    for name, value in attrs:
        if name == "shadowrootmode":
            return (value or "").lower() in ("open", "closed")
    return False


def _is_executable_script(attrs) -> bool:
    """HTML script type classification: classic/module JavaScript vs. data blocks.

    No `type` (and no `language`), an empty `type` or a JavaScript MIME type essence
    (MIME parameters such as "; charset=utf-8" ignored, case-insensitive) or "module"
    is executable. application/ld+json, application/json, importmap,
    speculationrules, text/x-template ... are data blocks, not JavaScript.
    """
    values: dict[str, str | None] = {}
    for name, value in attrs:
        values.setdefault(name, value)  # the first duplicate attribute wins
    if "type" in values:
        script_type = values["type"] or ""
    elif values.get("language"):
        script_type = "text/" + values["language"]
    else:
        return True
    essence = script_type.split(";", 1)[0].strip().lower()
    return not essence or essence in _JS_MIME_ESSENCES


_HEADINGS = ("h1", "h2", "h3", "h4", "h5", "h6")
# Start tags that close an open <p> in button scope (WHATWG HTML "in body" rules).
_P_CLOSERS = frozenset((
    "address", "article", "aside", "blockquote", "center", "details", "dialog", "dir",
    "div", "dl", "dd", "dt", "fieldset", "figcaption", "figure", "footer", "form",
    "header", "hgroup", "hr", "li", "main", "menu", "nav", "ol", "p", "pre", "section",
    "summary", "table", "ul") + _HEADINGS)
_BUTTON_SCOPE = frozenset(("applet", "button", "caption", "html", "marquee", "object",
                           "table", "td", "th", "template"))
_TABLE_SCOPE = frozenset(("html", "table", "template"))
_TABLE_SECTIONS = frozenset(("thead", "tbody", "tfoot"))

# (start tags that trigger the rule, open tags it implicitly closes, scope boundaries).
# Rules run in order; each closes the nearest closable element above the nearest
# boundary, popping every unclosed element above it as well.
_IMPLIED_END_RULES: tuple[tuple[frozenset, frozenset, frozenset], ...] = (
    (frozenset(("td", "th", "tr")) | _TABLE_SECTIONS, frozenset(("td", "th")), _TABLE_SCOPE),
    (frozenset(("tr",)) | _TABLE_SECTIONS, frozenset(("tr",)), _TABLE_SCOPE),
    (_TABLE_SECTIONS | {"caption", "colgroup"}, _TABLE_SECTIONS, _TABLE_SCOPE),
    (frozenset(("li",)), frozenset(("li",)), _BUTTON_SCOPE | {"ul", "ol"}),
    (frozenset(("dt", "dd")), frozenset(("dt", "dd")), _BUTTON_SCOPE | {"dl"}),
    (_P_CLOSERS, frozenset(("p",)), _BUTTON_SCOPE),
)


class _VisibleTextParser(HTMLParser):
    """Collect visible text, script stats and SPA mount-node emptiness.

    Open elements are tracked on a stack. An end tag closes the nearest matching
    open element and every unclosed element above it. Start tags first apply HTML
    implied end tags ("<p hidden>a<p>b" closes the hidden <p> before the second one
    opens; likewise li/li, dt/dd, td/th/tr and table sections) *before* the new
    element's own hidden state is evaluated. Text inside any subtree carrying the
    HTML `hidden` attribute, a closed <dialog> (no `open` attribute) or an inline
    style whose cascaded display is "none" / visibility "hidden" or "collapse"
    counts neither as visible words nor as mount-node content.

    <noscript> inside an open <head> is ignored; inside the body it is an ordinary
    element whose (non-hidden) fallback text counts as visible text. Any start tag
    that cannot live in <head> (e.g. <body>, <div>) implicitly closes <head>.

    Only executable <script> elements (see _is_executable_script) count toward
    script_count / external_script_count / script_bytes; JSON-LD, JSON and importmap
    and other data blocks are counted in data_script_count only. Script and style
    contents are never visible text.

    A plain <template>'s contents are an inert, separate document fragment: while
    template_depth > 0 no outer element is pushed or popped, no implied end tag is
    applied, hidden / mount state is never touched and no text or script is counted.
    A declarative shadow root (<template shadowrootmode="open|closed"> outside any
    inert template) is rendered: it is pushed as an isolated "template" frame, which
    is a scope boundary for implied end tags, end tags inside it never close outer
    elements, and the host's hidden / mount state still applies.
    Per-tag stack positions keep every lookup O(1), so parsing stays linear.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.script_bytes = 0
        self.script_count = 0
        self.external_script_count = 0
        self.data_script_count = 0
        self.template_depth = 0
        self._skip_depth = 0
        self._head_noscript_depth = 0
        self._in_script = False
        self._script_executable = False
        # (tag, is_hidden, mount_ident_or_None) -- keep exact 3-tuples
        self._stack: list[tuple[str, bool, str | None]] = []
        # Parallel per-element stacks for CSS visibility inheritance and closed <details>
        self._vis_stack: list[bool] = []
        # "none" | "ready" (closed <details> before 1st <summary>) | "done" (1st <summary> seen)
        self._details_closed_stack: list[str] = []
        # tag -> ascending stack indices of currently open elements with that tag
        self._positions: dict[str, list[int]] = {}
        self._hidden_depth = 0
        self._vis_hidden = False
        self._skip_textarea = False
        self._open_mounts: list[str] = []
        self._mount_has_content: dict[str, bool] = {}
        self.title = ""
        self._in_title = False

    def unknown_decl(self, data: str) -> None:
        # CPython's HTMLParser/ParserBase can raise AssertionError on malformed
        # <![...]> marked-section declarations; treat unknown declarations as no-op.
        return

    def parse_marked_section(self, i: int, report: int = 1) -> int:
        try:
            return super().parse_marked_section(i, report)
        except AssertionError:
            gt = self.rawdata.find(">", i + 3)
            return -1 if gt < 0 else gt + 1

    def _top_index(self, tags) -> int:
        best = -1
        for t in tags:
            pos = self._positions.get(t)
            if pos and pos[-1] > best:
                best = pos[-1]
        return best

    def _frame_floor(self) -> int:
        """Stack index of the innermost open declarative shadow root, or -1."""
        frames = self._positions.get("template")
        return frames[-1] if frames else -1

    def _open_head_index(self) -> int:
        """Stack index of an open <head> in the current frame, or -1."""
        head = self._positions.get("head")
        if head and head[0] > self._frame_floor():
            return head[0]
        return -1

    def _pop_to(self, index: int) -> None:
        """Pop every open element at stack position >= index."""
        while len(self._stack) > index:
            open_tag, box_hidden, mount = self._stack.pop()
            self._vis_hidden = self._vis_stack.pop()
            self._details_closed_stack.pop()
            self._positions[open_tag].pop()
            if box_hidden:
                self._hidden_depth -= 1
            if mount is not None:
                self._open_mounts.pop()

    def _close_implied(self, tag: str) -> None:
        for closers, closable, scope in _IMPLIED_END_RULES:
            if tag not in closers:
                continue
            target = self._top_index(closable)
            if target >= 0 and target > self._top_index(scope):
                self._pop_to(target)

    def handle_starttag(self, tag, attrs):
        if tag == "template":
            if self.template_depth or not _is_declarative_shadow_root(attrs):
                self.template_depth += 1  # inert template content
                return
            # Declarative shadow root: rendered, isolated frame (scope boundary).
            self._positions.setdefault("template", []).append(len(self._stack))
            self._vis_stack.append(self._vis_hidden)
            self._details_closed_stack.append("none")
            self._stack.append(("template", False, None))
            return
        if self.template_depth:
            return  # inert template content: never touches the outer document
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
            if tag == "script":
                self._in_script = True
                self._script_executable = _is_executable_script(attrs)
                if self._script_executable:
                    self.script_count += 1
                    if any(name == "src" for name, _value in attrs):
                        self.external_script_count += 1
                else:
                    self.data_script_count += 1
            return
        if tag == "noscript" and self._open_head_index() >= 0:
            # <head><noscript>: never visible page text.
            self._head_noscript_depth += 1
            self._skip_depth += 1
            return
        if tag not in _HEAD_CONTENT_TAGS:
            head = self._open_head_index()
            if head >= 0:
                self._pop_to(head)  # body content implicitly ends <head>
        # Implied end tags first (also for void tags such as <hr>), so a hidden
        # element closed implicitly no longer hides the new element's content.
        self._close_implied(tag)
        details_state = self._details_closed_stack[-1] if self._details_closed_stack else "none"
        if tag == "summary" and details_state == "ready":
            self._details_closed_stack[-1] = "done"
            parent_details_closed = False
        else:
            parent_details_closed = details_state != "none"
        if tag == "title":
            self._in_title = True
            self.set_cdata_mode(tag)
        elif tag == "textarea":
            # HTML RCDATA element: ignore literal tags such as <script> inside <textarea>
            # until </textarea>, and honour hidden/display:none/visibility on textarea itself.
            t_box_hidden, t_vis_override, _ = _element_visibility(attrs, tag, parent_details_closed)
            t_vis = self._vis_hidden if t_vis_override is None else t_vis_override
            self._skip_textarea = bool(self._hidden_depth or t_box_hidden or t_vis or parent_details_closed)
            self.set_cdata_mode(tag)
            return
        if tag in _VOID_TAGS:
            return
        box_hidden, vis_override, details_closed = _element_visibility(attrs, tag, parent_details_closed)
        ident = dict(attrs).get("id")
        mount = None
        if ident and ident.lower() in _MOUNT_IDS and ident not in self._mount_has_content:
            # A mount node counts as "empty" unless visible text appears inside it.
            self._mount_has_content[ident] = False
            self._open_mounts.append(ident)
            mount = ident
        self._vis_stack.append(self._vis_hidden)
        if vis_override is not None:
            self._vis_hidden = vis_override
        if box_hidden:
            self._hidden_depth += 1
        self._details_closed_stack.append("ready" if details_closed else "none")
        self._positions.setdefault(tag, []).append(len(self._stack))
        self._stack.append((tag, box_hidden, mount))

    def handle_endtag(self, tag):
        if tag == "template":
            if self.template_depth > 0:
                self.template_depth -= 1
                return
            frames = self._positions.get("template")
            if frames:
                self._pop_to(frames[-1])  # closes the innermost declarative shadow root
            return  # a stray </template> closes nothing in the outer document
        if self.template_depth:
            return
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            if tag == "script":
                self._in_script = False
                self._script_executable = False
            return
        if tag == "noscript" and self._head_noscript_depth:
            self._head_noscript_depth -= 1
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "title":
            self._in_title = False
        elif tag == "textarea":
            self._skip_textarea = False
            return
        positions = self._positions.get(tag)
        if not positions or positions[-1] < self._frame_floor():
            return  # stray end tag (or outside the current shadow root): O(1), ignored
        self._pop_to(positions[-1])

    def handle_data(self, data):
        if self.template_depth:
            return
        if self._in_script:
            if self._script_executable:
                self.script_bytes += len(data.encode("utf-8"))
            return
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
            return
        if self._hidden_depth or self._vis_hidden or self._skip_textarea or (self._details_closed_stack and self._details_closed_stack[-1] != "none"):
            return
        if data.strip():
            self.text_parts.append(data)
            for ident in self._open_mounts:
                self._mount_has_content[ident] = True


# Han (incl. extensions and compatibility ideographs, 々〆〇), Hiragana, Katakana
# (incl. half-width) and Hangul: scripts written without spaces between words.
# Each such character counts as one word.
_CJK_CLASS = ("\u1100-\u11ff\u3005-\u3007\u3041-\u3096\u309d-\u309f\u30a1-\u30fa"
              "\u30fc-\u30ff\u3131-\u318e\u31f0-\u31ff\u3400-\u4dbf\u4e00-\u9fff"
              "\uac00-\ud7a3\uf900-\ufaff\uff66-\uff9f\U00020000-\U0003134f")
_CJK_CHAR_RE = re.compile("[" + _CJK_CLASS + "]")
_NON_CJK_WORD_RE = re.compile(r"[^\W" + _CJK_CLASS + "]+")


def count_words(text: str) -> int:
    """Count words: every CJK/Han/Kana/Hangul character plus every other \\w+ run."""
    return len(_CJK_CHAR_RE.findall(text)) + len(_NON_CJK_WORD_RE.findall(text))


def audit_html(html: str, source: str = "page.html") -> dict:
    parser = _VisibleTextParser()
    parser.feed(html)
    parser.close()
    text = " ".join(" ".join(parser.text_parts).split())
    words = count_words(text)
    total_bytes = max(1, len(html.encode("utf-8")))
    script_ratio = round(parser.script_bytes / total_bytes, 3)
    empty_mounts = sorted(k for k, v in parser._mount_has_content.items() if not v)
    external_scripts = parser.external_script_count

    if words < 50 and (empty_mounts or script_ratio >= 0.3 or external_scripts >= 1):
        verdict = "likely_csr_shell"
        advice = ("AI search crawlers generally do not execute JavaScript; they would see almost no "
                  "text here. Pre-render or server-render the main content.")
    elif words < 150:
        verdict = "thin_content"
        advice = "Server HTML contains little visible text; check that key content is in the initial HTML."
    else:
        verdict = "server_rendered"
        advice = "Main content is present in the initial HTML."
    return {
        "source": source,
        "title": parser.title.strip(),
        "visible_words": words,
        "script_tags": parser.script_count,
        "external_scripts": external_scripts,
        "data_script_tags": parser.data_script_count,
        "inline_script_byte_ratio": script_ratio,
        "empty_mount_nodes": empty_mounts,
        "verdict": verdict,
        "advice": advice,
        "text_preview": text[:160],
    }


def html_fetch_failed(source: str, status: int) -> dict:
    """HTML report for a page that did not return 2xx (all audit_html keys present)."""
    return {
        "source": source,
        "http_status": status,
        "verdict": "fetch_failed",
        "advice": "Page returned HTTP %d; fix the HTTP status before auditing rendered content." % status,
        "visible_words": 0,
        "script_tags": 0,
        "external_scripts": 0,
        "data_script_tags": 0,
        "inline_script_byte_ratio": 0.0,
        "empty_mount_nodes": [],
        "title": "",
        "text_preview": "",
    }


def html_unsupported_content(source: str, status: int, media_type: str) -> dict:
    """HTML report for a 2xx response with an explicit non-HTML Content-Type."""
    return {
        "source": source,
        "http_status": status,
        "content_type": media_type,
        "verdict": "unsupported_content",
        "advice": "Response has non-HTML Content-Type (%s); skipping HTML shell check." % media_type,
        "visible_words": 0,
        "script_tags": 0,
        "external_scripts": 0,
        "data_script_tags": 0,
        "inline_script_byte_ratio": 0.0,
        "empty_mount_nodes": [],
        "title": "",
        "text_preview": "",
    }


# --------------------------------------------------------------------------- SSRF-guarded fetch

class UnsafeURLError(ValueError):
    """Raised when a URL is not a safe public http(s) target."""


class FetchError(OSError):
    """Raised for fetch failures such as too many redirects or a truncated body."""


_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$", re.I)
_ASCII_LABEL_RE = re.compile(r"^[a-z0-9_-]{1,63}$")


def _idna_host(host: str) -> str:
    """Return an ASCII host name, converting non-ASCII DNS names to IDNA once.

    ASCII hosts (including IPv6 literals) are returned unchanged. Non-ASCII names are
    encoded with the stdlib "idna" codec (nameprep + punycode); invalid names, empty
    or oversized labels and non-ASCII IP literals raise UnsafeURLError. Full-width
    digits / dots ("１２７。０。０。１") come out as plain ASCII ("127.0.0.1"), so the
    caller's IP-literal and numeric-host checks still see the real address.
    """
    if host.isascii():
        return host
    if ":" in host or "%" in host:
        raise UnsafeURLError("Non-ASCII characters are not allowed in IP literal hosts.")
    try:
        converted = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeURLError("Invalid internationalized host name %r: %s" % (host[:200], exc)) from None
    converted = converted.rstrip(".").lower()
    if not converted or not all(_ASCII_LABEL_RE.match(label) for label in converted.split(".")):
        raise UnsafeURLError("Invalid internationalized host name %r." % host[:200])
    return converted


def _check_ip(ip: ipaddress._BaseAddress, label: str) -> None:
    """Reject every non-public address class explicitly.

    Note: Python 3.12 reports fec0::/10 (deprecated IPv6 site-local) as is_global=True,
    so is_site_local must be checked on its own.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (getattr(ip, "is_site_local", False) or ip.is_private or ip.is_loopback
            or ip.is_link_local or ip.is_reserved or ip.is_multicast
            or ip.is_unspecified or not ip.is_global):
        raise UnsafeURLError("%s resolves to a non-public address (%s)." % (label, ip))


def _resolve_host(host: str, port: int, timeout: float) -> list:
    """socket.getaddrinfo with a hard wall-clock timeout.

    The lookup runs in a daemon thread; if it has not finished within `timeout`
    seconds, TimeoutError is raised immediately (the stuck thread cannot block exit).
    """
    result: dict = {}
    done = threading.Event()

    def worker() -> None:
        try:
            result["infos"] = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except BaseException as exc:  # re-raised in the calling thread
            result["error"] = exc
        finally:
            done.set()

    threading.Thread(target=worker, name="cleanparse-dns", daemon=True).start()
    if not done.wait(timeout=max(0.0, timeout)):
        raise TimeoutError("DNS lookup for %s exceeded %.1fs." % (host[:200], max(0.0, timeout)))
    exc = result.get("error")
    if exc is not None:
        if isinstance(exc, (socket.gaierror, UnicodeError)):
            raise UnsafeURLError("DNS lookup failed for %s: %s" % (host[:200], exc)) from None
        raise exc
    return result["infos"]


def _validate_url(url: str, resolve: bool, timeout: float | None = None
                  ) -> tuple[str, urllib.parse.SplitResult, str, int, list[str]]:
    """Validate a URL once. Returns (cleaned_url, parts, ascii_host, port, validated_ips).

    The returned host is always ASCII: non-ASCII DNS names are converted to IDNA
    BEFORE the local-name, IP-literal and numeric-host checks and the DNS lookup.
    validated_ips is empty only when resolve=False and the host is a DNS name.
    `timeout` bounds the DNS lookup (defaults to FETCH_TIMEOUT). cleaned_url is the
    stripped input string itself, so an explicit empty query ("/catalog?") and empty
    path segments ("/a//b") survive.
    """
    cleaned = url.strip()
    try:
        parts = urllib.parse.urlsplit(cleaned)
    except ValueError as exc:
        raise UnsafeURLError("Malformed URL: %s" % exc) from None
    if parts.scheme.lower() not in ("http", "https"):
        raise UnsafeURLError("Only http:// and https:// URLs are allowed.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UnsafeURLError("Credentials in URLs are not allowed.")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeURLError("URL has no host.")
    host = _idna_host(host)
    if ":" not in host and any(not label for label in host.split(".")):
        raise UnsafeURLError("Host name %r has an empty label." % host[:200])
    try:
        port = parts.port
    except ValueError:
        raise UnsafeURLError("Invalid port.") from None
    if port is not None and port not in (80, 443, 8080, 8443):
        raise UnsafeURLError("Port %d is not allowed (use 80/443/8080/8443)." % port)
    if port is None:
        port = 443 if parts.scheme.lower() == "https" else 80
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") \
            or host.endswith(".internal") or "." not in host and ":" not in host:
        raise UnsafeURLError("Local or single-label host names are not allowed.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    ips: list[str] = []
    if ip is not None:
        _check_ip(ip, host)
        ips.append(str(ip))
    elif _NUMERIC_HOST.match(host):
        raise UnsafeURLError("Ambiguous numeric host %r is not allowed." % host)
    elif resolve:
        infos = _resolve_host(host, port, FETCH_TIMEOUT if timeout is None else timeout)
        for info in infos:
            addr = info[4][0].split("%", 1)[0]
            _check_ip(ipaddress.ip_address(addr), host)
            if addr not in ips:
                ips.append(addr)
        if not ips:
            raise UnsafeURLError("DNS lookup returned no addresses for %s." % host)
    return cleaned, parts, host, port, ips


def validate_public_url(url: str, resolve: bool = True) -> str:
    """Return the URL if it is a safe public http(s) URL, else raise UnsafeURLError.

    resolve=False skips DNS (used by offline unit tests); IP literals and obvious
    local names are still rejected.
    """
    return _validate_url(url, resolve)[0]


def resolve_public_url(url: str) -> tuple[str, list[str]]:
    """Validate and resolve once. Returns (normalized_url, validated_ips)."""
    cleaned, _parts, _host, _port, ips = _validate_url(url, resolve=True)
    return cleaned, ips


def _connect_budget(deadline: float | None, fallback: float, host: str) -> float:
    """Seconds left before `deadline` (monotonic); `fallback` when no deadline is set."""
    if deadline is None:
        return fallback
    left = deadline - _now()
    if left <= 0:
        raise TimeoutError("Connection to %s exceeded the fetch deadline." % host[:200])
    return left


def _close_quietly(sock) -> None:
    try:
        sock.close()
    except Exception:
        pass


class _FinalResponse(http.client.HTTPResponse):
    """HTTPResponse that consumes interim 1xx responses on the SAME connection.

    http.client only skips "100 Continue"; any other interim status (102, 103 Early
    Hints, ...) would otherwise be returned as the response. Every interim status
    line and its header block are read from the same buffered stream and skipped,
    up to MAX_INTERIM_RESPONSES. `on_interim()` runs after each interim response (the
    fetcher uses it to re-apply the remaining deadline to the socket and to check the
    watchdog). "101 Switching Protocols" is not a fetchable response: FetchError.
    """

    def __init__(self, sock, debuglevel=0, method=None, url=None, on_interim=None):
        super().__init__(sock, debuglevel, method, url)
        self.on_interim = on_interim
        self.interim_statuses: list[int] = []

    def _read_status(self):
        while True:
            version, status, reason = super()._read_status()
            if status == 101:
                raise FetchError("HTTP 101 Switching Protocols response: protocol upgrades are "
                                 "not fetchable.")
            if not 100 <= status < 200:
                return version, status, reason
            if len(self.interim_statuses) >= MAX_INTERIM_RESPONSES:
                raise FetchError("More than %d interim (1xx) HTTP responses."
                                 % MAX_INTERIM_RESPONSES)
            self.interim_statuses.append(status)
            http.client.parse_headers(self.fp)  # skip the interim header block
            if self.on_interim is not None:
                self.on_interim()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP connection that dials a pre-validated IP (no second DNS lookup).

    `deadline` (a time.monotonic() value) bounds the TCP connect; without it the
    classic per-operation `timeout` is used. `on_socket(sock)` is called as soon as
    the socket exists (used to hand it to the fetch watchdog). The host is converted
    to ASCII IDNA. Interim 1xx responses are consumed (see _FinalResponse).
    """

    response_class = _FinalResponse

    def __init__(self, host: str, port: int, ip: str, timeout: float,
                 deadline: float | None = None, on_socket=None) -> None:
        super().__init__(_idna_host(host), port, timeout=timeout)
        self.pinned_ip = ip
        self.deadline = deadline
        self.on_socket = on_socket

    def connect(self) -> None:
        sock = socket.create_connection(
            (self.pinned_ip, self.port), _connect_budget(self.deadline, self.timeout, self.host))
        if self.on_socket is not None:
            try:
                self.on_socket(sock)
            except BaseException:
                _close_quietly(sock)
                raise
        self.sock = sock


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection to a pre-validated IP; SNI + certificate checks use the URL host.

    The host is converted to ASCII IDNA once, so TLS server_hostname is punycode.
    TCP connect and TLS handshake share ONE clock: with `deadline` set, the time
    left is recomputed after the TCP connect and applied to the raw socket before
    wrap_socket and to the TLS socket before the explicit handshake. `on_socket`
    receives the raw socket and then the TLS socket, so a watchdog can abort a
    stalled handshake. Interim 1xx responses are consumed (see _FinalResponse).
    """

    response_class = _FinalResponse

    def __init__(self, host: str, port: int, ip: str, timeout: float,
                 context: ssl.SSLContext | None = None,
                 deadline: float | None = None, on_socket=None) -> None:
        super().__init__(_idna_host(host), port, timeout=timeout,
                         context=context if context is not None else ssl.create_default_context())
        self.pinned_ip = ip
        self.deadline = deadline
        self.on_socket = on_socket

    def _budget(self) -> float:
        return _connect_budget(self.deadline, self.timeout, self.host)

    def _notify(self, sock) -> None:
        if self.on_socket is not None:
            self.on_socket(sock)

    def connect(self) -> None:
        raw = socket.create_connection((self.pinned_ip, self.port), self._budget())
        tls = None
        try:
            self._notify(raw)
            raw.settimeout(self._budget())
            tls = self._context.wrap_socket(raw, server_hostname=self.host,
                                            do_handshake_on_connect=False)
            self._notify(tls)
            tls.settimeout(self._budget())
            handshake = getattr(tls, "do_handshake", None)
            if handshake is not None:
                handshake()
        except BaseException:
            if tls is not None:
                _close_quietly(tls)
            _close_quietly(raw)
            raise
        self.sock = tls


_REDIRECT_CODES = frozenset((301, 302, 303, 307, 308))


def _has_query_marker(url: str) -> bool:
    """True if the URL has a '?' before any '#fragment' (explicit, possibly empty query)."""
    return "?" in url.split("#", 1)[0]


def _request_target(parts, query_marker: bool | None = None) -> str:
    """Request target sent on the wire, using the same normalization as robots matching.

    `parts` is a urllib.parse.SplitResult or a URL string. urlsplit() drops an empty
    query ("https://e.com/catalog?" -> query ""), so for a string the explicit '?'
    marker is detected from the raw URL; for a SplitResult pass query_marker=True to
    keep it. "/catalog?" and "/catalog" are different URIs (RFC 3986 6.2.3). Empty
    path segments ("/a//b") are kept exactly.

    normalize_path(encode_rule_ops=False) keeps '*' / '$' literal on the wire; robots
    matching encodes them afterwards, so --url, --path and rules all compare equal.
    """
    if isinstance(parts, str):
        url = parts
        parts = urllib.parse.urlsplit(url)
        if query_marker is None:
            query_marker = _has_query_marker(url)
    target = normalize_path(parts.path or "/", encode_rule_ops=False)
    if not target.startswith("/"):
        target = "/" + target
    if parts.query or query_marker:
        target += "?" + normalize_path(parts.query, encode_rule_ops=False)
    return target


_URI_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def _split_uri(uri: str) -> tuple[str | None, str | None, str, str | None]:
    """RFC 3986 appendix B split of a fragment-free URI reference.

    Returns (scheme, authority, path, query); absent components are None, so an
    empty query ("?") is "" and an empty authority ("//") is "".
    """
    scheme = None
    rest = uri
    match = _URI_SCHEME_RE.match(uri)
    if match:
        scheme = uri[:match.end() - 1]
        rest = uri[match.end():]
    authority = None
    if rest.startswith("//"):
        end = len(rest)
        for ch in "/?":
            k = rest.find(ch, 2)
            if 0 <= k < end:
                end = k
        authority = rest[2:end]
        rest = rest[end:]
    path, sep, query = rest.partition("?")
    return scheme, authority, path, (query if sep else None)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 5.2.4 remove_dot_segments. Empty segments ("//") are preserved."""
    out: list[str] = []
    i, n = 0, len(path)
    while i < n:
        if path.startswith("../", i):
            i += 3
        elif path.startswith("./", i):
            i += 2
        elif path.startswith("/./", i):
            i += 2
        elif path.startswith("/.", i) and i + 2 == n:
            out.append("/")
            break
        elif path.startswith("/../", i):
            i += 3
            if out:
                out.pop()
        elif path.startswith("/..", i) and i + 3 == n:
            if out:
                out.pop()
            out.append("/")
            break
        elif n - i <= 2 and path[i:] in (".", ".."):
            break
        else:
            start = i + 1 if path[i] == "/" else i
            j = path.find("/", start)
            if j < 0:
                j = n
            out.append(path[i:j])
            i = j
    return "".join(out)


def _merge_paths(base_authority: str | None, base_path: str, ref_path: str) -> str:
    """RFC 3986 5.2.3 merge."""
    if base_authority is not None and not base_path:
        return "/" + ref_path
    return base_path[:base_path.rfind("/") + 1] + ref_path


def _resolve_redirect(base: str, location: str) -> str:
    """Resolve a Location header against the hop URL (RFC 3986 5.2), dropping the fragment.

    Unlike urllib.parse.urljoin, empty path segments are never collapsed
    ("/news/start" + "reports//daily" -> "/news/reports//daily") and an explicit
    (possibly empty) query in the reference is preserved: "/catalog?" ->
    ".../catalog?", and a bare "?" replaces the base query with an empty one. An
    empty reference (e.g. "#frag") yields the base URL without its fragment, '?'
    marker included. A same-scheme reference without authority ("http:g") is
    resolved as relative (RFC 3986 5.2.2 backward-compatible mode).
    """
    ref = location.strip().split("#", 1)[0]
    base = base.split("#", 1)[0]
    if not ref:
        return base
    b_scheme, b_auth, b_path, b_query = _split_uri(base)
    r_scheme, r_auth, r_path, r_query = _split_uri(ref)
    if (r_scheme is not None and r_auth is None and b_scheme is not None
            and r_scheme.lower() == b_scheme.lower()):
        r_scheme = None
    if r_scheme is not None:
        scheme, auth, path, query = r_scheme, r_auth, _remove_dot_segments(r_path), r_query
    else:
        scheme = b_scheme
        if r_auth is not None:
            auth, path, query = r_auth, _remove_dot_segments(r_path), r_query
        else:
            auth = b_auth
            if not r_path:
                path = b_path
                query = r_query if r_query is not None else b_query
            else:
                if r_path.startswith("/"):
                    path = _remove_dot_segments(r_path)
                else:
                    path = _remove_dot_segments(_merge_paths(b_auth, b_path, r_path))
                query = r_query
    return ((scheme + ":" if scheme is not None else "")
            + ("//" + auth if auth is not None else "")
            + path
            + ("?" + query if query is not None else ""))


def _host_header(host: str, port: int, scheme: str) -> str:
    host = _idna_host(host)
    shown = "[%s]" % host if ":" in host else host
    return shown if port == (443 if scheme == "https" else 80) else "%s:%d" % (shown, port)


def _abort_socket(sock, fired: threading.Event) -> None:
    """Watchdog callback: mark the deadline as expired and unblock any pending I/O."""
    fired.set()
    shutdown = getattr(sock, "shutdown", None)
    if shutdown is None:
        return
    try:
        shutdown(socket.SHUT_RDWR)
    except Exception:
        pass


class _Watchdog:
    """Per-hop deadline timer, armed BEFORE the first TCP connect attempt.

    Sockets are attached as they come into existence (raw TCP socket, then TLS
    socket, for every IP attempt). When the timer fires, the most recently attached
    socket is shut down; a socket attached after expiry is shut down immediately.
    """

    def __init__(self, seconds: float) -> None:
        self.fired = threading.Event()
        self._lock = threading.Lock()
        self._sock = None
        self._timer = threading.Timer(max(0.0, seconds), self._expire)
        self._timer.daemon = True

    def start(self) -> None:
        self._timer.start()

    def cancel(self) -> None:
        self._timer.cancel()

    def attach(self, sock) -> None:
        with self._lock:
            self._sock = sock
            expired = self.fired.is_set()
        if expired:
            _abort_socket(sock, self.fired)

    def _expire(self) -> None:
        with self._lock:
            self.fired.set()
            sock = self._sock
        if sock is not None:
            _abort_socket(sock, self.fired)


_ALLOWED_CHARSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$")
_REJECTED_CODECS = frozenset(("idna", "punycode", "undefined", "unicode_escape", "raw_unicode_escape"))


def _decode_body(raw: bytes, charset: str | None, force_utf8: bool = False) -> str:
    """Decode body bytes per RFC 9309 (robots.txt UTF-8) or WHATWG BOM + charset sniffing.

    Transform / binary codecs (hex, base64, bz2, quopri, rot-13 ...), idna/punycode,
    malformed names and unknown charsets all fall back to UTF-8 with replacement.
    """
    if force_utf8:
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        return raw.decode("utf-8", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    name = (charset or "").strip().strip("\"'")
    if name and _ALLOWED_CHARSET_RE.match(name):
        try:
            info = codecs.lookup(name)
            if getattr(info, "_is_text_encoding", True) and info.name.replace("-", "_") not in _REJECTED_CODECS:
                return raw.decode(info.name, errors="replace")
        except (LookupError, UnicodeError, TypeError, ValueError):
            pass
    return raw.decode("utf-8", errors="replace")


def _media_type_essence(value: str | None) -> str | None:
    """Lower-case MIME essence of a Content-Type value ("Text/HTML; charset=x" -> "text/html").

    None when the header is absent or empty.
    """
    if not value:
        return None
    essence = value.split(";", 1)[0].strip(" \t").lower()
    return essence or None


def _content_coding(header: str | None, length: int | None) -> str | None:
    """Return "gzip", "deflate" or None for a Content-Encoding header value.

    Empty values and "identity" mean no coding. gzip / x-gzip / deflate (a single
    coding) are supported; anything else (br, zstd, compress, layered codings such
    as "gzip, br") raises FetchError, unless the body is known to be empty.
    """
    codings = [c.strip().lower() for c in (header or "").split(",")]
    codings = [c for c in codings if c and c != "identity"]
    if not codings:
        return None
    if codings in (["gzip"], ["x-gzip"]):
        return "gzip"
    if codings == ["deflate"]:
        return "deflate"
    if length == 0:
        return None  # nothing to decode
    raise FetchError("Unsupported Content-Encoding: %s" % (header or "").strip()[:100])


class _CompressedBody:
    """Incremental gzip / deflate decoder with a hard limit on DECOMPRESSED output.

    Every decompress() call is bounded with max_length, so at most limit + 1 output
    bytes are ever produced (decompression-bomb safe); exceeding the limit raises
    FetchError. gzip accepts multiple members. HTTP "deflate" is tried as a zlib
    (RFC 1950) stream first; if that fails before any output, the buffered input is
    retried as raw deflate (RFC 1951, -zlib.MAX_WBITS). Invalid data, trailing
    garbage after a deflate stream and a stream that ends early raise FetchError.
    """

    def __init__(self, coding: str, limit: int, source: str = "") -> None:
        self.coding = coding
        self.limit = limit
        self.source = source
        self.size = 0
        self._parts: list[bytes] = []
        self._fed = False
        if coding == "gzip":
            self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            self._probe: bytes | None = None
        else:
            self._d = zlib.decompressobj()
            self._probe = b""  # input kept until the zlib wrapper produced output

    @property
    def complete(self) -> bool:
        return self._fed and self._d.eof

    def _error(self, detail: str) -> FetchError:
        return FetchError("Invalid %s-compressed response body from %s: %s"
                          % (self.coding, self.source[:200], detail))

    def feed(self, data: bytes) -> None:
        if not data:
            return
        self._fed = True
        if self._probe is not None:
            self._probe += data
        self._inflate(data)

    def _inflate(self, data: bytes) -> None:
        while data:
            if self._d.eof:
                if self.coding != "gzip":
                    raise self._error("trailing data after the end of the deflate stream")
                self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)  # next gzip member
            room = self.limit - self.size
            try:
                out = self._d.decompress(data, room + 1)
            except zlib.error as exc:
                if self._probe is not None:
                    # Not a zlib-wrapped stream: retry everything as raw deflate.
                    data, self._probe = self._probe, None
                    self._d = zlib.decompressobj(-zlib.MAX_WBITS)
                    continue
                raise self._error(str(exc)) from None
            if out:
                self._probe = None
                self.size += len(out)
                if self.size > self.limit:
                    raise FetchError("Decompressed response body from %s exceeds the %d-byte limit "
                                     "(possible decompression bomb)." % (self.source[:200], self.limit))
                self._parts.append(out)
            if self._d.eof:
                self._probe = None
                data = self._d.unused_data
            else:
                data = self._d.unconsumed_tail

    def finish(self) -> bytes:
        if not self._fed:
            return b""
        if not self._d.eof:
            raise self._error("compressed stream ended early (truncated body)")
        return b"".join(self._parts)


def _check_transfer_encoding(header: str | None, resp_chunked: bool) -> None:
    """Reject unsupported or undecoded Transfer-Encoding codings (RFC 9112 section 6.1)."""
    if not header:
        return
    codings = [c.strip().lower() for c in header.split(",") if c.strip()]
    for c in codings:
        if c not in ("chunked", "identity"):
            raise FetchError("Unsupported Transfer-Encoding: %s" % header.strip()[:100])
    if codings.count("chunked") > 1 or ("chunked" in codings and codings[-1] != "chunked"):
        raise FetchError("Ambiguous Transfer-Encoding: %s" % header.strip()[:100])
    if "chunked" in codings and not resp_chunked:
        raise FetchError("Chunked Transfer-Encoding was not decoded by HTTP client.")


def _check_content_length(headers, resp_length: int | None, resp_chunked: bool) -> None:
    """Reject conflicting, invalid, or unenforced Content-Length headers."""
    if headers is None or not hasattr(headers, "get_all"):
        return
    raw_vals = headers.get_all("Content-Length") or []
    if not raw_vals:
        return
    parsed: set[int] = set()
    for hdr in raw_vals:
        for part in str(hdr).split(","):
            tok = part.strip(" \t")
            if not tok or not tok.isdigit():
                raise FetchError("Invalid Content-Length header.")
            parsed.add(int(tok))
    if len(parsed) > 1:
        raise FetchError("Conflicting Content-Length headers.")
    expected = next(iter(parsed))
    if not resp_chunked and resp_length != expected:
        raise FetchError("Content-Length was not enforced by HTTP client.")


def _fetch_url_details(url: str, force_utf8: bool = False) -> dict:
    """Fetch a public URL (SSRF-guarded).

    Returns {"status", "text", "visited", "content_type"}: visited lists every hop
    URL of the redirect chain in order (the start URL first, fragments removed,
    explicit empty queries and empty path segments kept), so visited[-1] is the
    final URL; content_type is the lower-case MIME essence of the final response's
    Content-Type (e.g. "application/json") or None if the header is absent.

    Every hop is validated and resolved exactly once. The connection is pinned to a
    validated IP; when connecting or sending the request to one validated IP fails
    with OSError (e.g. ConnectionRefusedError), the next validated IP is tried while
    time remains. Once a response is received the IP loop ends. One monotonic
    deadline (FETCH_TIMEOUT) and one watchdog per hop cover DNS, every connect
    attempt, TLS, request, interim 1xx responses (consumed on the same connection,
    the remaining time re-applied after each one), headers and body. 101 Switching
    Protocols raises FetchError. A body that ends before its declared
    Content-Length (or a truncated chunked body) raises FetchError; stopping an
    uncompressed body at the MAX_FETCH_BYTES cap is intentional and not an error.
    gzip / deflate bodies are decoded incrementally with MAX_FETCH_BYTES enforced on
    the decompressed output (overflow, invalid or truncated streams raise
    FetchError); unsupported content codings raise FetchError.
    """
    deadline = _now() + FETCH_TIMEOUT
    timeout_msg = "Fetch of %s exceeded the %ss deadline." % (url[:200], FETCH_TIMEOUT)

    def remaining() -> float:
        left = deadline - _now()
        if left <= 0:
            raise TimeoutError(timeout_msg)
        return left

    visited: list[str] = []

    def result(status: int, text: str, content_type: str | None) -> dict:
        return {"status": status, "text": text, "visited": visited, "content_type": content_type}

    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        cleaned, parts, host, port, ips = _validate_url(current, resolve=True, timeout=remaining())
        visited.append(cleaned)
        scheme = parts.scheme.lower()
        conn_cls = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
        target = _request_target(parts, query_marker=_has_query_marker(cleaned))
        headers = {
            "Host": _host_header(host, port, scheme),
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        watchdog = _Watchdog(remaining())
        conn = None
        resp = None
        try:
            watchdog.start()
            for idx, ip in enumerate(ips):
                attempt = conn_cls(host, port, ip, remaining(), deadline=deadline,
                                   on_socket=watchdog.attach)
                try:
                    attempt.connect()
                    if watchdog.fired.is_set():
                        raise TimeoutError(timeout_msg)
                    attempt.sock.settimeout(remaining())
                    attempt.request("GET", target, headers=headers)
                except OSError:
                    attempt.close()
                    if watchdog.fired.is_set() or idx == len(ips) - 1:
                        raise
                    remaining()  # same deadline: no time left -> TimeoutError
                    continue
                except BaseException:
                    attempt.close()
                    raise
                conn = attempt
                break
            if conn is None:
                raise FetchError("No validated address could be reached for %s." % host[:200])
            sock = conn.sock
            sock.settimeout(remaining())

            def on_interim(sock=sock, watchdog=watchdog) -> None:
                # After each interim 1xx response: same deadline, same watchdog.
                if watchdog.fired.is_set():
                    raise TimeoutError(timeout_msg)
                sock.settimeout(remaining())

            conn.response_class = functools.partial(_FinalResponse, on_interim=on_interim)
            resp = conn.getresponse()
            if watchdog.fired.is_set():
                raise TimeoutError(timeout_msg)
            status = resp.status
            media_type = _media_type_essence(resp.getheader("Content-Type"))
            if status in _REDIRECT_CODES:
                location = resp.getheader("Location")
                if not location:
                    return result(status, "", media_type)
                current = _resolve_redirect(cleaned, location)
                continue
            if status >= 400:
                return result(status, "", media_type)
            _check_transfer_encoding(resp.getheader("Transfer-Encoding"), bool(resp.chunked))
            _check_content_length(resp.headers, resp.length, bool(resp.chunked))
            coding = _content_coding(resp.getheader("Content-Encoding"), resp.length)
            decoder = _CompressedBody(coding, MAX_FETCH_BYTES, cleaned) if coding else None
            chunks: list[bytes] = []
            total = 0  # raw (on-the-wire) body bytes read
            # Once the last body byte has been read (Content-Length / final chunk),
            # http.client closes the response and the underlying socket; touching
            # sock.settimeout() after that raises OSError (WinError 10038 / EBADF).
            # The isclosed() check runs right before every settimeout() call.
            while total < MAX_FETCH_BYTES and not resp.isclosed():
                sock.settimeout(remaining())
                try:
                    chunk = resp.read1(min(FETCH_CHUNK, MAX_FETCH_BYTES - total))
                except http.client.IncompleteRead:
                    if watchdog.fired.is_set():
                        raise TimeoutError(timeout_msg) from None
                    raise FetchError("Incomplete HTTP response body from %s: connection closed "
                                     "after %d bytes (truncated chunked body)."
                                     % (cleaned[:200], total)) from None
                if not chunk:
                    if resp.length is not None and resp.length > 0:
                        if watchdog.fired.is_set():
                            raise TimeoutError(timeout_msg)
                        raise FetchError("Incomplete HTTP response body from %s: connection closed "
                                         "after %d bytes, %d more declared by Content-Length."
                                         % (cleaned[:200], total, resp.length))
                    break
                total += len(chunk)
                if decoder is None:
                    chunks.append(chunk)
                else:
                    decoder.feed(chunk)
            if watchdog.fired.is_set():
                raise TimeoutError(timeout_msg)  # EOF caused by the watchdog, not the server
            if total >= MAX_FETCH_BYTES and not resp.isclosed():
                sock.settimeout(remaining())
                try:
                    more = resp.read1(1)
                except http.client.IncompleteRead:
                    if watchdog.fired.is_set():
                        raise TimeoutError(timeout_msg) from None
                    raise FetchError("Incomplete HTTP response body from %s at %d bytes." % (cleaned[:200], total)) from None
                if watchdog.fired.is_set():
                    raise TimeoutError(timeout_msg)
                if not more and resp.length is not None and resp.length > 0:
                    raise FetchError("Incomplete HTTP response body from %s: connection closed "
                                     "after %d bytes, %d more declared by Content-Length."
                                     % (cleaned[:200], total, resp.length))
                has_more = bool(more)
            else:
                has_more = False
            if decoder is None:
                body = b"".join(chunks)
                if force_utf8 and has_more:
                    # Drop any incomplete trailing line (CR, LF or CRLF) so a 2 MiB cutoff
                    # inside e.g. "Disallow: /account/" never fabricates "Disallow: /".
                    cut = max(body.rfind(b"\n"), body.rfind(b"\r"))
                    body = body[:cut + 1] if cut >= 0 else b""
            else:
                if has_more or (not resp.isclosed() and not decoder.complete):
                    raise FetchError("Compressed response body from %s exceeds the %d-byte limit."
                                     % (cleaned[:200], MAX_FETCH_BYTES))
                body = decoder.finish()
            try:
                charset = resp.msg.get_content_charset()
            except Exception:
                charset = None
            return result(status, _decode_body(body, charset, force_utf8=force_utf8), media_type)
        except Exception:
            if watchdog.fired.is_set():
                raise TimeoutError(timeout_msg) from None
            raise
        finally:
            watchdog.cancel()
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
            if conn is not None:
                conn.close()
    raise FetchError("Too many redirects (more than %d) for %s" % (MAX_REDIRECTS, url[:200]))


def _fetch_with_chain(url: str, force_utf8: bool = False) -> tuple[int, str, list[str]]:
    """Fetch a public URL (SSRF-guarded). Returns (status, text, visited_urls).

    Backward-compatible wrapper around _fetch_url_details (same guarantees).
    """
    details = _fetch_url_details(url, force_utf8=force_utf8)
    return details["status"], details["text"], details["visited"]


def fetch_text(url: str) -> tuple[int, str]:
    """Fetch a public URL (SSRF-guarded). Returns (status, text); 4xx/5xx return (status, "").

    See _fetch_url_details for the full guarantees (pinned validated IPs with
    failover, one monotonic deadline + watchdog, interim 1xx handling, redirect
    validation, truncation detection, bounded gzip / deflate decoding).
    """
    status, text, _visited = _fetch_with_chain(url)
    return status, text


_ORIG_FETCH_TEXT = fetch_text


def _fetch_robots_text(url: str) -> tuple[int, str]:
    """Fetch robots.txt as UTF-8 with mid-line 2 MiB cutoff protection, preserving mock hooks."""
    if fetch_text is not _ORIG_FETCH_TEXT:
        return fetch_text(url)
    details = _fetch_url_details(url, force_utf8=True)
    return details["status"], details["text"]


# --------------------------------------------------------------------------- CLI

def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _read_html_file(path: str) -> str:
    with open(path, "rb") as fh:
        return _decode_body(fh.read(), None)


def _robots_origin(url: str) -> tuple[tuple[str, str, int], str]:
    """(origin_key, origin_url) for a hop URL; the key uses the ASCII host + real port."""
    _cleaned, parts, host, port, _ips = _validate_url(url, resolve=False)
    return (parts.scheme.lower(), host, port), "%s://%s" % (parts.scheme, parts.netloc)


def run(args: argparse.Namespace) -> dict:
    report: dict = {"tool": "cleanparse-geo-tools", "version": __version__}
    if args.url:
        # Syntax/IP-literal check only; the fetchers resolve + pin every hop themselves.
        page_url = validate_public_url(args.url, resolve=False)
        parts = urllib.parse.urlsplit(page_url)
        origin = "%s://%s" % (parts.scheme, parts.netloc)
        report["url"] = page_url

        details = _fetch_url_details(page_url)
        page_status = details["status"]
        page_body = details["text"]
        media_type = details.get("content_type")
        visited = list(details["visited"]) or [page_url]

        # Evaluate EVERY hop against its own origin's robots.txt (fetched once per origin).
        robots_cache: dict[tuple[str, str, int], tuple[str, int, str]] = {}
        hops: list[tuple[str, dict]] = []
        for idx, hop_url in enumerate(visited):
            key, hop_origin = _robots_origin(hop_url)
            if key not in robots_cache:
                robots_url = hop_origin + "/robots.txt"
                r_status, r_body = _fetch_robots_text(robots_url)
                robots_cache[key] = (robots_url, r_status, r_body)
            robots_url, r_status, r_body = robots_cache[key]
            if idx == 0 and args.path is not None:
                hop_path = args.path
            else:
                # Exactly the request target sent on the wire
                # (e.g. "/catalog?tag[]=blue" -> "/catalog?tag%5B%5D=blue",
                # "/catalog?" keeps its explicit empty query, "/a//b" keeps "//").
                hop_path = _request_target(hop_url)
            hops.append((hop_url, _robots_report_for_status(r_status, r_body, hop_path, robots_url)))
        report["robots"] = combine_robots_hops(hops)

        status, body = fetch_text(origin + "/llms.txt")
        report["llms"] = audit_llms(body, origin + "/llms.txt") if 200 <= status < 300 and status != 206 else {
            "source": origin + "/llms.txt", "valid": False, "http_status": status,
            "errors": ["llms.txt not found (HTTP %d)." % status], "warnings": []}

        final_url = visited[-1]
        if not 200 <= page_status < 300 or page_status == 206:
            report["html"] = html_fetch_failed(final_url, page_status)
        elif media_type is not None and media_type not in _HTML_MEDIA_TYPES:
            report["html"] = html_unsupported_content(final_url, page_status, media_type)
        else:
            report["html"] = audit_html(page_body, final_url)
        report["html"]["http_status"] = page_status
        if len(visited) > 1:
            report["final_url"] = final_url
    if args.robots_file:
        offline_path = args.path if args.path is not None else "/"
        report["robots"] = audit_robots(_read_file(args.robots_file), offline_path, args.robots_file)
    if args.llms_file:
        report["llms"] = audit_llms(_read_file(args.llms_file), args.llms_file)
    if args.html_file:
        report["html"] = audit_html(_read_html_file(args.html_file), args.html_file)
    report["more"] = "https://cleanparse.com/ai-search-visibility-checker"
    return report


def format_human(report: dict) -> str:
    out = ["CleanParse GEO check v%s" % report["version"]]
    if "url" in report:
        out.append("URL: %s" % report["url"])
    if "final_url" in report:
        out.append("Final URL: %s" % report["final_url"])
    rb = report.get("robots")
    if rb:
        out.append("")
        out.append("[robots.txt] %s  (path %s, %d groups)" % (rb["source"], rb["path"][:200], rb["groups_found"]))
        for label, key in (("AI search", "search_crawlers"), ("AI training", "training_crawlers")):
            for name, v in rb[key].items():
                out.append("  %-12s %-17s %-8s group=%-17s %s" % (
                    label, name, "ALLOW" if v["allowed"] else "BLOCK", v["group"], v["matched_rule"] or ""))
        out.append("  policy: %s" % rb["policy"])
        for hop in rb.get("redirect_chain", []):
            out.append("  hop: %s  (robots %s, path %s)"
                       % (hop["url"][:200], hop["robots_source"][:200], hop["path"][:200]))
        out.extend("  note: " + n for n in rb["notes"])
    ll = report.get("llms")
    if ll:
        out.append("")
        out.append("[llms.txt] %s  -> %s" % (ll["source"], "VALID" if ll["valid"] else "INVALID"))
        if ll.get("title"):
            out.append("  title: %s | sections: %d | links: %d"
                       % (ll["title"], len(ll.get("sections", [])), ll.get("total_links", 0)))
        out.extend("  error: " + e for e in ll["errors"])
        out.extend("  warn:  " + w for w in ll["warnings"])
    ht = report.get("html")
    if ht:
        out.append("")
        out.append("[html] %s  -> %s" % (ht["source"], ht["verdict"]))
        out.append("  visible words: %d | script tags: %d | inline script ratio: %.3f | empty mounts: %s"
                   % (ht["visible_words"], ht["script_tags"], ht["inline_script_byte_ratio"],
                      ", ".join(ht["empty_mount_nodes"]) or "-"))
        out.append("  " + ht["advice"])
    out.append("")
    out.append("Browser version: %s" % report["more"])
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit robots.txt (AI search vs training crawlers), lint llms.txt and "
                    "detect empty CSR HTML shells. Stdlib only.")
    p.add_argument("--url", help="public http(s) page URL to audit live")
    p.add_argument("--robots-file", help="local robots.txt to audit offline")
    p.add_argument("--llms-file", help="local llms.txt to lint offline")
    p.add_argument("--html-file", help="local HTML file to check for SSR vs CSR shell")
    p.add_argument("--path", default=None,
                   help="URL path to evaluate robots rules against (default: the --url request "
                        "target exactly as sent on the wire, or / for --robots-file)")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument("--version", action="version", version=__version__)
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.url or args.robots_file or args.llms_file or args.html_file):
        parser.error("give --url or at least one of --robots-file / --llms-file / --html-file")
    try:
        report = run(args)
    except UnsafeURLError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    except (OSError, http.client.HTTPException) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else format_human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
