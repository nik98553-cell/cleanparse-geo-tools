"""Offline unit tests for scripts/check_llms_and_robots.py (no network access).

Only loopback socket.socketpair() connections are used for the real-socket tests;
socket.getaddrinfo / socket.create_connection are always patched.

Run:  python -B -m unittest discover -s tests -v
"""
import csv
import email.message
import gzip
import http.client
import importlib.util
import inspect
import io
import ipaddress
import itertools
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zlib
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
_spec = importlib.util.spec_from_file_location("check_llms_and_robots", ROOT / "scripts" / "check_llms_and_robots.py")
cl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cl)


def _no_network(*_a, **_k):
    raise AssertionError("unit tests must not touch the network")


class NoNetworkTestCase(unittest.TestCase):
    def setUp(self):
        patches = [
            mock.patch.object(socket, "getaddrinfo", _no_network),
            mock.patch.object(socket, "create_connection", _no_network),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


class RobotsTests(NoNetworkTestCase):
    def test_sample_allows_search_blocks_training(self):
        text = (EXAMPLES / "sample_robots.txt").read_text(encoding="utf-8")
        r = cl.audit_robots(text, "/")
        for bot in ("OAI-SearchBot", "Claude-SearchBot", "PerplexityBot"):
            self.assertTrue(r["search_crawlers"][bot]["allowed"], bot)
            self.assertEqual(r["search_crawlers"][bot]["group"], bot)
        for bot in ("GPTBot", "ClaudeBot"):
            self.assertFalse(r["training_crawlers"][bot]["allowed"], bot)
        self.assertEqual(r["policy"], "search_allowed_training_blocked")

    def test_sample_private_path_blocked_for_search(self):
        text = (EXAMPLES / "sample_robots.txt").read_text(encoding="utf-8")
        r = cl.audit_robots(text, "/account/settings")
        self.assertFalse(r["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_blocking_gptbot_does_not_block_oai_searchbot(self):
        text = "User-agent: GPTBot\nDisallow: /\n"
        r = cl.audit_robots(text)
        self.assertFalse(r["training_crawlers"]["GPTBot"]["allowed"])
        self.assertTrue(r["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertEqual(r["search_crawlers"]["OAI-SearchBot"]["group"], "(none)")

    def test_specific_group_overrides_wildcard(self):
        text = "User-agent: *\nDisallow: /\n\nUser-agent: OAI-SearchBot\nAllow: /\n"
        r = cl.audit_robots(text)
        self.assertTrue(r["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertFalse(r["search_crawlers"]["PerplexityBot"]["allowed"])
        self.assertEqual(r["search_crawlers"]["PerplexityBot"]["group"], "*")
        self.assertFalse(r["training_crawlers"]["GPTBot"]["allowed"])

    def test_wildcard_block_blocks_search_with_note(self):
        r = cl.audit_robots("User-agent: *\nDisallow: /\n")
        self.assertFalse(any(v["allowed"] for v in r["search_crawlers"].values()))
        self.assertTrue(any("blocked" in n for n in r["notes"]))

    def test_longest_match_wins(self):
        rules = [(False, "/docs/"), (True, "/docs/public/")]
        self.assertTrue(cl.is_allowed(rules, "/docs/public/a.html")[0])
        self.assertFalse(cl.is_allowed(rules, "/docs/private/a.html")[0])

    def test_equal_length_allow_wins(self):
        rules = [(False, "/page"), (True, "/page")]
        self.assertTrue(cl.is_allowed(rules, "/page")[0])

    def test_wildcards_and_end_anchor(self):
        rules = [(False, "/*.pdf$"), (False, "/*?session=")]
        self.assertFalse(cl.is_allowed(rules, "/files/report.pdf")[0])
        self.assertTrue(cl.is_allowed(rules, "/files/report.pdf.html")[0])
        self.assertFalse(cl.is_allowed(rules, "/cart?session=abc")[0])

    def test_case_insensitive_agent_and_merged_groups(self):
        text = ("user-agent: gptbot\ndisallow: /a/\n\n"
                "User-agent: GPTBot\nDisallow: /b/\n")
        rules, group = cl.select_rules(cl.parse_robots(text), "GPTBot")
        self.assertEqual(group, "GPTBot")
        self.assertEqual(len(rules), 2)

    def test_empty_disallow_allows_everything(self):
        r = cl.audit_robots("User-agent: ClaudeBot\nDisallow:\n")
        self.assertTrue(r["training_crawlers"]["ClaudeBot"]["allowed"])

    def test_comments_and_sitemap_ignored(self):
        text = "# hi\nUser-agent: PerplexityBot # inline\nDisallow: /x # c\nSitemap: https://e.com/s.xml\n"
        r = cl.audit_robots(text, "/x/y")
        self.assertFalse(r["search_crawlers"]["PerplexityBot"]["allowed"])

    # --- defect 2: UTF-8 BOM
    def test_leading_bom_does_not_break_first_group(self):
        r = cl.audit_robots("\ufeffUser-agent: GPTBot\nDisallow: /\n")
        self.assertFalse(r["training_crawlers"]["GPTBot"]["allowed"])
        self.assertEqual(r["training_crawlers"]["GPTBot"]["group"], "GPTBot")

    # --- defect 3: linear matcher + percent-encoding normalization
    def test_normalize_path(self):
        self.assertEqual(cl.normalize_path("/%7euser"), "/~user")
        self.assertEqual(cl.normalize_path("/%64ocs"), "/docs")
        self.assertEqual(cl.normalize_path("/a%2fb"), "/a%2Fb")
        self.assertEqual(cl.normalize_path("/caf%c3%a9"), "/caf%C3%A9")
        self.assertEqual(cl.normalize_path("/café"), "/caf%C3%A9")
        self.assertEqual(cl.normalize_path("/100%"), "/100%25")
        self.assertEqual(cl.normalize_path("/a b"), "/a%20b")

    def test_unreserved_percent_encoding_matches(self):
        self.assertFalse(cl.is_allowed([(False, "/%64ocs")], "/docs/a")[0])
        self.assertFalse(cl.is_allowed([(False, "/docs")], "/%64ocs/a")[0])

    def test_utf8_path_matches_percent_encoded(self):
        self.assertFalse(cl.is_allowed([(False, "/café")], "/caf%C3%A9/menu")[0])
        self.assertFalse(cl.is_allowed([(False, "/caf%c3%a9")], "/café")[0])

    def test_rule_length_in_utf8_octets_after_normalization(self):
        # Same normalized pattern -> equal length -> allow wins.
        self.assertTrue(cl.is_allowed([(False, "/caf%C3%A9"), (True, "/café")], "/café")[0])
        # "/é" is 7 octets once encoded, longer than "/abcd" (5): disallow wins.
        self.assertFalse(cl.is_allowed([(True, "/*"), (False, "/é")], "/é")[0])

    def test_wildcard_semantics(self):
        self.assertTrue(cl.wildcard_match(*cl._pattern_parts("/a*b*c$")[:2], "/axbxc"))
        self.assertFalse(cl.wildcard_match(*cl._pattern_parts("/a*b*c$")[:2], "/axbxcx"))
        self.assertFalse(cl.wildcard_match(*cl._pattern_parts("/ab*ba$")[:2], "/aba"))

    def test_matcher_is_linear_no_redos(self):
        self.assertFalse(hasattr(cl, "_pattern_to_regex"))
        rules = [(False, "/*a*a*a*a*a*a*a*a*a*a*b"), (False, "/" + "a*" * 2000 + "b$")]
        start = time.perf_counter()
        allowed, _ = cl.is_allowed(rules, "/" + "a" * 4000)
        self.assertTrue(allowed)
        self.assertLess(time.perf_counter() - start, 1.0)

    # --- audit item 3: RFC 9309 2.2.3 literal '*' / '$' vs %2A / %24
    def test_normalize_path_encodes_rule_operators_in_uris(self):
        self.assertEqual(cl.normalize_path("/foo*bar"), "/foo%2Abar")
        self.assertEqual(cl.normalize_path("/foo$bar"), "/foo%24bar")
        self.assertEqual(cl.normalize_path("/foo%2abar"), "/foo%2Abar")
        self.assertEqual(cl.normalize_path("/foo*bar$", encode_rule_ops=False), "/foo*bar$")

    def test_rfc9309_percent_encoded_star_matches_literal_star(self):
        rules = [(False, "/foo%2Abar")]
        self.assertFalse(cl.is_allowed(rules, "/foo*bar")[0])
        self.assertFalse(cl.is_allowed(rules, "/foo%2Abar")[0])
        self.assertTrue(cl.is_allowed(rules, "/fooXbar")[0], "%2A must not act as a wildcard")

    def test_rfc9309_percent_encoded_dollar_matches_literal_dollar(self):
        self.assertFalse(cl.is_allowed([(False, "/foo%24bar")], "/foo$bar")[0])
        self.assertFalse(cl.is_allowed([(False, "/foo%24")], "/foo$")[0])
        self.assertTrue(cl.is_allowed([(False, "/foo%24")], "/foo")[0], "%24 must not anchor")

    def test_non_trailing_dollar_is_literal(self):
        self.assertFalse(cl.is_allowed([(False, "/foo$bar")], "/foo$bar/x")[0])
        self.assertTrue(cl.is_allowed([(False, "/foo$bar")], "/foo")[0])
        # Both rules normalize to "/foo%24bar" (10 octets): equal length -> allow wins.
        self.assertTrue(cl.is_allowed([(False, "/foo%24bar"), (True, "/foo$bar")], "/foo$bar")[0])

    def test_rfc9309_wildcard_gif_end_anchor(self):
        rules = [(False, "/*.gif$")]
        self.assertFalse(cl.is_allowed(rules, "/a.gif")[0])
        self.assertFalse(cl.is_allowed(rules, "/x/y/b.gif")[0])
        self.assertTrue(cl.is_allowed(rules, "/a.gif?size=2")[0])
        self.assertTrue(cl.is_allowed(rules, "/a.gifx")[0])

    def test_pattern_parts_splits_operators_before_normalizing(self):
        segments, anchored, length = cl._pattern_parts("/foo%2A*bar$")
        self.assertEqual(segments, ["/foo%2A", "bar"])
        self.assertTrue(anchored)
        self.assertEqual(length, len("/foo%2A") + 1 + len("bar") + 1)
        self.assertEqual(cl._pattern_parts("/a$b")[:2], (["/a%24b"], False))

    # --- audit item 4: no silent truncation at 4,096 characters
    def test_rule_differing_at_char_4097_does_not_match(self):
        base = "/" + "a" * 4095  # 4,096 characters
        self.assertEqual(len(base), 4096)
        rules = [(False, base + "X")]
        self.assertTrue(cl.is_allowed(rules, base + "Y")[0])
        self.assertFalse(cl.is_allowed(rules, base + "X")[0])
        self.assertTrue(cl.is_allowed([(False, base + "X$")], base + "XY")[0])

    def test_long_paths_are_evaluated_in_full(self):
        base = "/" + "b" * 30000
        rules = [(False, "/"), (True, base + "/public")]
        self.assertTrue(cl.is_allowed(rules, base + "/public/x")[0])
        self.assertFalse(cl.is_allowed(rules, base + "/private/x")[0])

    def test_oversized_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            cl.is_allowed([(False, "/")], "/" + "a" * cl.MAX_MATCH_CHARS)

    # --- R2 defect 4: the /robots.txt exception covers ONLY the exact URI (no query)
    def test_robots_txt_exact_path_always_allowed_under_disallow_all(self):
        rules = [(False, "/")]
        self.assertEqual(cl.is_allowed(rules, "/robots.txt"), (True, None))
        self.assertEqual(cl.is_allowed(rules, "/%72obots.txt"), (True, None))
        self.assertEqual(cl.is_allowed(rules, "robots.txt"), (True, None))
        self.assertFalse(cl.is_allowed(rules, "/robots.txt.bak")[0])
        self.assertFalse(cl.is_allowed(rules, "/sub/robots.txt")[0])

    def test_robots_txt_with_query_is_not_exempt(self):
        self.assertEqual(cl.is_allowed([(False, "/")], "/robots.txt?v=2"), (False, "Disallow: /"))
        self.assertFalse(cl.is_allowed([(False, "/")], "/robots.txt?")[0])
        rules = [(False, "/robots.txt?")]
        self.assertEqual(cl.is_allowed(rules, "/robots.txt"), (True, None))
        self.assertEqual(cl.is_allowed(rules, "/robots.txt?foo=1"), (False, "Disallow: /robots.txt?"))
        # Query-bearing robots URIs still follow normal longest-match evaluation.
        self.assertTrue(cl.is_allowed([(False, "/"), (True, "/robots.txt?v=")], "/robots.txt?v=1")[0])
        self.assertTrue(cl.is_allowed([(False, "/private/")], "/robots.txt?foo=1")[0])

    def test_audit_robots_txt_path_allowed_for_all_bots(self):
        r = cl.audit_robots("User-agent: *\nDisallow: /\n", "/robots.txt")
        self.assertTrue(all(v["allowed"] for v in r["search_crawlers"].values()))
        self.assertTrue(all(v["allowed"] for v in r["training_crawlers"].values()))
        self.assertEqual(r["notes"][-1:], ["No AI-crawler-specific groups found; every bot falls back to the '*' group."])

    def test_audit_robots_txt_query_path_blocked_by_rules(self):
        r = cl.audit_robots("User-agent: *\nDisallow: /robots.txt?\n", "/robots.txt?foo=1")
        self.assertFalse(any(v["allowed"] for v in r["search_crawlers"].values()))
        self.assertFalse(any(v["allowed"] for v in r["training_crawlers"].values()))

    # --- R3 defect 5: unified component-aware normalization
    def test_normalize_path_encodes_brackets_and_non_delimiter_ascii(self):
        self.assertEqual(cl.normalize_path("/catalog?tag[]=blue"), "/catalog?tag%5B%5D=blue")
        self.assertEqual(cl.normalize_path("/catalog?tag%5b%5d=blue"), "/catalog?tag%5B%5D=blue")
        self.assertEqual(cl.normalize_path('/a b^c{d}e|f<g>h"i\\j`k'),
                         "/a%20b%5Ec%7Bd%7De%7Cf%3Cg%3Eh%22i%5Cj%60k")
        # URI delimiters are preserved.
        delims = "/p?a=1&b=2;c:d@e!f'g(h)i+j,k"
        self.assertEqual(cl.normalize_path(delims), delims)
        self.assertEqual(cl.normalize_path("/a[b]*c$", encode_rule_ops=False), "/a%5Bb%5D*c$")

    def test_brackets_normalize_identically_for_uri_path_and_rule(self):
        uris = ["/catalog?tag[]=blue", "/catalog?tag%5B%5D=blue", "/catalog?tag%5b%5d=blue"]
        rules = ["/catalog?tag%5B%5D=", "/catalog?tag[]=", "/catalog?tag%5b%5d="]
        for uri in uris:
            for rule in rules:
                with self.subTest(uri=uri, rule=rule):
                    self.assertEqual(cl.is_allowed([(False, rule)], uri), (False, "Disallow: " + rule))
        for char, enc in (("{", "%7B"), ("}", "%7D"), ("|", "%7C"), ("^", "%5E"),
                          ("<", "%3C"), (">", "%3E"), ('"', "%22"), (" ", "%20")):
            with self.subTest(char=char):
                self.assertFalse(cl.is_allowed([(False, "/x" + enc)], "/x" + char + "y")[0])
                self.assertFalse(cl.is_allowed([(False, "/x" + char)], "/x" + enc + "y")[0])

    def test_rule_wildcards_still_operators_with_brackets(self):
        self.assertFalse(cl.is_allowed([(False, "/*[]=blue$")], "/catalog?tag%5B%5D=blue")[0])
        self.assertTrue(cl.is_allowed([(False, "/*[]=blue$")], "/catalog?tag[]=blue&x")[0])

    def test_request_target_uses_same_normalization(self):
        parts = urllib.parse.urlsplit("http://example.com/catalog?tag[]=blue")
        self.assertEqual(cl._request_target(parts), "/catalog?tag%5B%5D=blue")
        self.assertEqual(cl._request_target(parts), cl.normalize_path("/catalog?tag[]=blue", False))
        self.assertEqual(cl._request_target(urllib.parse.urlsplit("http://e.com")), "/")
        self.assertEqual(cl._request_target(urllib.parse.urlsplit("http://e.com/a*b$?q=$")), "/a*b$?q=$")

    # --- R4 defect 2: explicit empty query marker (RFC 3986 6.2.3)
    def test_urlsplit_drops_empty_query_but_request_target_keeps_it(self):
        self.assertEqual(urllib.parse.urlsplit("https://example.com/catalog?").query, "")
        self.assertEqual(cl._request_target("https://example.com/catalog?"), "/catalog?")
        self.assertEqual(cl._request_target("https://example.com/catalog?#top"), "/catalog?")
        self.assertEqual(cl._request_target("https://example.com?"), "/?")
        self.assertEqual(cl._request_target("https://example.com/catalog#a?b"), "/catalog")
        self.assertEqual(cl._request_target("https://example.com/catalog"), "/catalog")
        parts = urllib.parse.urlsplit("https://example.com/catalog?")
        self.assertEqual(cl._request_target(parts), "/catalog", "SplitResult alone cannot see the '?'")
        self.assertEqual(cl._request_target(parts, query_marker=True), "/catalog?")
        self.assertTrue(cl._has_query_marker("https://e.com/a?#f"))
        self.assertFalse(cl._has_query_marker("https://e.com/a#f?"))

    def test_empty_query_matches_anchored_rule(self):
        rules = [(False, "/catalog?$")]
        self.assertEqual(cl.is_allowed(rules, "/catalog?"), (False, "Disallow: /catalog?$"))
        self.assertTrue(cl.is_allowed(rules, "/catalog")[0])
        self.assertTrue(cl.is_allowed(rules, "/catalog?page=2")[0])
        live = cl._request_target("https://example.com/catalog?")
        self.assertEqual(cl.is_allowed(rules, live), cl.is_allowed(rules, "/catalog?"))

    def test_redirect_resolution_preserves_empty_query(self):
        cases = [
            ("http://e.com/a", "/catalog?", "http://e.com/catalog?"),
            ("http://e.com/a", "/catalog?#frag", "http://e.com/catalog?"),
            ("http://e.com/a?x=1", "?", "http://e.com/a?"),
            ("http://e.com/a?x=1", "?#f", "http://e.com/a?"),
            ("http://e.com/a?x=1", "?y=2", "http://e.com/a?y=2"),
            ("http://e.com/dir/a", "c?", "http://e.com/dir/c?"),
            ("http://e.com/dir/a", "../x?", "http://e.com/x?"),
            ("http://e.com/a", "https://o.example.com/p?", "https://o.example.com/p?"),
            ("http://e.com/a", "//o.example.com/p?", "http://o.example.com/p?"),
            ("http://e.com/catalog?", "#top", "http://e.com/catalog?"),
            ("http://e.com/a?x", "#frag", "http://e.com/a?x"),
            ("http://e.com/a", " /b?q=1#f ", "http://e.com/b?q=1"),
            ("http://e.com/a?x=1", "/final#frag", "http://e.com/final"),
        ]
        for base, location, expected in cases:
            with self.subTest(base=base, location=location):
                self.assertEqual(cl._resolve_redirect(base, location), expected)

    # --- R5 defect 2: empty path segments are preserved (RFC 3986 5.2)
    def test_urljoin_collapses_empty_segments_but_resolver_does_not(self):
        # urllib.parse.urljoin filters empty segments of relative references.
        self.assertEqual(urllib.parse.urljoin("http://e.com/news/start", "reports//daily"),
                         "http://e.com/news/reports/daily")
        cases = [
            ("http://e.com/news/start", "reports//daily", "http://e.com/news/reports//daily"),
            ("http://e.com/news/start", "/news/reports//daily", "http://e.com/news/reports//daily"),
            ("http://e.com/a//b/c", "d", "http://e.com/a//b/d"),
            ("http://e.com/a//b/c", "../d", "http://e.com/a//d"),
            ("http://e.com/a//b/c", "?q", "http://e.com/a//b/c?q"),
            ("http://e.com/x", "a///b/", "http://e.com/a///b/"),
            ("http://e.com/x", "//o.example.com//p", "http://o.example.com//p"),
            ("http://e.com", "x", "http://e.com/x"),
            ("http://e.com/x", "http:y", "http://e.com/y"),
        ]
        for base, location, expected in cases:
            with self.subTest(base=base, location=location):
                self.assertEqual(cl._resolve_redirect(base, location), expected)

    def test_rfc3986_reference_resolution_examples(self):
        base = "http://a/b/c/d;p?q"
        cases = {
            "g:h": "g:h", "g": "http://a/b/c/g", "./g": "http://a/b/c/g", "g/": "http://a/b/c/g/",
            "/g": "http://a/g", "//g": "http://g", "?y": "http://a/b/c/d;p?y",
            "g?y": "http://a/b/c/g?y", "#s": "http://a/b/c/d;p?q", "g#s": "http://a/b/c/g",
            "g?y#s": "http://a/b/c/g?y", ";x": "http://a/b/c/;x", "g;x": "http://a/b/c/g;x",
            "g;x?y#s": "http://a/b/c/g;x?y", "": "http://a/b/c/d;p?q", ".": "http://a/b/c/",
            "./": "http://a/b/c/", "..": "http://a/b/", "../": "http://a/b/", "../g": "http://a/b/g",
            "../..": "http://a/", "../../": "http://a/", "../../g": "http://a/g",
            "../../../g": "http://a/g", "../../../../g": "http://a/g", "/./g": "http://a/g",
            "/../g": "http://a/g", "g.": "http://a/b/c/g.", ".g": "http://a/b/c/.g",
            "g..": "http://a/b/c/g..", "..g": "http://a/b/c/..g", "./../g": "http://a/b/g",
            "./g/.": "http://a/b/c/g/", "g/./h": "http://a/b/c/g/h", "g/../h": "http://a/b/c/h",
            "g;x=1/./y": "http://a/b/c/g;x=1/y", "g;x=1/../y": "http://a/b/c/y",
            "g?y/./x": "http://a/b/c/g?y/./x", "g?y/../x": "http://a/b/c/g?y/../x",
            "g#s/./x": "http://a/b/c/g", "http:g": "http://a/b/c/g",
        }
        for ref, expected in cases.items():
            with self.subTest(ref=ref):
                self.assertEqual(cl._resolve_redirect(base, ref), expected)

    def test_remove_dot_segments_keeps_empty_segments(self):
        self.assertEqual(cl._remove_dot_segments("/a/b/c/./../../g"), "/a/g")
        self.assertEqual(cl._remove_dot_segments("mid/content=5/../6"), "mid/6")
        self.assertEqual(cl._remove_dot_segments("/news/reports//daily"), "/news/reports//daily")
        self.assertEqual(cl._remove_dot_segments("//x//"), "//x//")
        self.assertEqual(cl._remove_dot_segments("/a//./b"), "/a//b")

    def test_double_slash_target_matches_double_slash_rule_only(self):
        target = cl._request_target("http://e.com/news/reports//daily")
        self.assertEqual(target, "/news/reports//daily")
        self.assertFalse(cl.is_allowed([(False, "/news/reports//")], target)[0])
        self.assertTrue(cl.is_allowed([(False, "/news/reports//")], "/news/reports/daily")[0],
                        "a collapsed path would wrongly escape the rule")

    # --- R5 defect 3: RFC 9309 2.2 CR/LF-only record splitting, ASCII space/tab trimming
    def test_unicode_line_separators_inside_comment_never_split_records(self):
        for sep in ("\u2028", "\u2029", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85"):
            with self.subTest(sep=repr(sep)):
                text = "User-agent: *\n# comment" + sep + "Disallow: /\n"
                self.assertEqual(cl.parse_robots(text), [{"agents": ["*"], "rules": []}])
                r = cl.audit_robots(text, "/private/page")
                self.assertTrue(all(v["allowed"] for v in r["search_crawlers"].values()))
                self.assertTrue(all(v["allowed"] for v in r["training_crawlers"].values()))

    def test_unicode_separator_inside_value_does_not_create_directive(self):
        text = "User-agent: *\nDisallow: /a\u2028Disallow: /\n"
        rules = cl.parse_robots(text)[0]["rules"]
        self.assertEqual(rules, [(False, "/a\u2028Disallow: /")])
        self.assertTrue(cl.audit_robots(text, "/b")["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_cr_lf_and_crlf_still_split_records(self):
        text = "User-agent: *\r\nDisallow: /a\rDisallow: /b\nDisallow: /c"
        self.assertEqual(cl.parse_robots(text)[0]["rules"], [(False, "/a"), (False, "/b"), (False, "/c")])
        self.assertFalse(cl.audit_robots(text, "/b/x")["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_only_ascii_space_and_tab_are_trimmed(self):
        text = "User-agent:\t* \t\n \tDisallow:\t/x \t\nDisallow: /private\u00a0\n\u00a0Disallow: /\n"
        rules = cl.parse_robots(text)[0]["rules"]
        self.assertEqual(rules, [(False, "/x"), (False, "/private\u00a0")])
        r = cl.audit_robots(text, "/private/page")
        self.assertTrue(r["search_crawlers"]["OAI-SearchBot"]["allowed"], "NBSP is part of the rule")
        self.assertFalse(cl.audit_robots(text, "/x/y")["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertEqual(r["search_crawlers"]["OAI-SearchBot"]["group"], "*")

    # --- R5 defect 1: robots.txt status classes (RFC 9309 2.3.1)
    def test_robots_status_classes(self):
        body = "User-agent: *\nDisallow: /private/\n"
        ok = cl._robots_report_for_status(200, body, "/", "http://e.com/robots.txt")
        self.assertTrue(ok["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertFalse(cl._robots_report_for_status(200, body, "/private/x", "r")
                         ["search_crawlers"]["OAI-SearchBot"]["allowed"])
        for status in (400, 401, 403, 404, 410, 499):
            with self.subTest(status=status):
                r = cl._robots_report_for_status(status, "", "/private/x", "r")
                self.assertTrue(all(v["allowed"] for v in r["search_crawlers"].values()))
                self.assertFalse(any("disallow all" in n for n in r["notes"]))
        for status in (100, 101, 103, 199, 300, 301, 302, 304, 399, 500, 503, 599):
            with self.subTest(status=status):
                r = cl._robots_report_for_status(status, "", "/", "r")
                self.assertFalse(any(v["allowed"] for v in r["search_crawlers"].values()))
                self.assertFalse(any(v["allowed"] for v in r["training_crawlers"].values()))
                self.assertTrue(any("disallow all" in n for n in r["notes"]))
                self.assertEqual(r["http_status"], status)


class LlmsTests(NoNetworkTestCase):
    def test_sample_is_valid(self):
        r = cl.audit_llms((EXAMPLES / "sample_llms.txt").read_text(encoding="utf-8"))
        self.assertTrue(r["valid"], r["errors"])
        self.assertEqual(r["title"], "Example Docs")
        self.assertTrue(r["summary"])
        self.assertEqual([s["name"] for s in r["sections"]], ["Guides", "Reference", "Optional"])
        self.assertEqual(r["total_links"], 6)
        self.assertEqual(r["warnings"], [])

    def test_missing_title_is_error(self):
        r = cl.audit_llms("Some text\n## Docs\n- [A](https://e.com/a)\n")
        self.assertFalse(r["valid"])

    def test_missing_summary_is_warning(self):
        r = cl.audit_llms("# T\n\n## Docs\n- [A](https://e.com/a)\n")
        self.assertTrue(r["valid"])
        self.assertTrue(any("summary" in w for w in r["warnings"]))

    def test_no_sections_is_error(self):
        r = cl.audit_llms("# T\n> s\n")
        self.assertFalse(r["valid"])

    def test_bad_list_items_and_relative_links_warn(self):
        r = cl.audit_llms("# T\n> s\n## Docs\n- just text\n- [A](docs/a.html)\n")
        self.assertTrue(r["valid"])
        self.assertTrue(any("not '- [name](url)" in w for w in r["warnings"]))
        self.assertTrue(any("not an absolute" in w for w in r["warnings"]))

    def test_empty_file(self):
        self.assertFalse(cl.audit_llms("")["valid"])

    # --- defect 5: bounded warnings
    def test_warnings_truncated_and_aggregated_across_sections(self):
        body = "# T\n> s\n" + "".join("## %s%d\n- plain item\n" % ("S" * 500, i) for i in range(1000))
        r = cl.audit_llms(body)
        self.assertLessEqual(len(r["warnings"]), 8)
        self.assertTrue(all(len(w) < 300 for w in r["warnings"]), r["warnings"])
        self.assertTrue(any("997 more section(s)" in w for w in r["warnings"]))

    def test_relative_links_aggregated_per_section(self):
        body = "# T\n> s\n## Docs\n" + "".join("- [x](%s%d.html)\n" % ("r" * 300, i) for i in range(500))
        r = cl.audit_llms(body)
        self.assertEqual(len(r["warnings"]), 1, r["warnings"])
        self.assertIn("500 link(s)", r["warnings"][0])
        self.assertIn("not an absolute", r["warnings"][0])
        self.assertLess(len(r["warnings"][0]), 300)

    def test_deep_headings_aggregated(self):
        r = cl.audit_llms("# T\n> s\n## Docs\n- [A](https://e.com/a)\n" + "### " + "h" * 400 + "\n" * 1
                          + "### more\n" * 299)
        deep = [w for w in r["warnings"] if "deeper than H2" in w]
        self.assertEqual(len(deep), 1)
        self.assertIn("300 heading(s)", deep[0])
        self.assertLess(len(deep[0]), 200)


SSR_PAGE = "<html><head><title>Pricing</title></head><body><main>" + (
    "<p>" + "CleanParse turns messy CSV exports into tidy tables with clear rules. " * 20 + "</p>"
) + "</main><script src='/a.js'></script></body></html>"


class HtmlTests(NoNetworkTestCase):
    def test_csr_sample_is_shell(self):
        r = cl.audit_html((EXAMPLES / "csr_vs_ssr_sample.html").read_text(encoding="utf-8"))
        self.assertEqual(r["verdict"], "likely_csr_shell")
        # Visible <body><noscript> fallback text (e.g. "enable JavaScript") now counts,
        # so the shell may report a handful of words - but stays far below 50.
        self.assertLess(r["visible_words"], 50)
        self.assertIn("root", r["empty_mount_nodes"])
        self.assertEqual(r["title"], "Pricing | Example App")

    def test_ssr_page(self):
        r = cl.audit_html(SSR_PAGE)
        self.assertEqual(r["verdict"], "server_rendered")
        self.assertGreater(r["visible_words"], 100)
        self.assertEqual(r["empty_mount_nodes"], [])
        self.assertEqual(r["external_scripts"], 1)

    def test_mount_with_ssr_text_not_empty(self):
        html = "<div id='app'><div><h1>Hello</h1><p>" + "word " * 200 + "</p></div></div>"
        r = cl.audit_html(html)
        self.assertEqual(r["empty_mount_nodes"], [])
        self.assertEqual(r["verdict"], "server_rendered")

    def test_script_and_style_text_not_counted(self):
        html = "<style>.a{color:red}</style><script>var hello='world world world';</script><p>one two</p>"
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 2)
        self.assertGreater(r["inline_script_byte_ratio"], 0.2)

    # --- defect 4: external scripts counted by the parser, not a regex rescan
    def test_external_scripts_counted_in_parser(self):
        html = ("<script data-src='x.js'></script><script src='/a.js'></script>"
                "<SCRIPT SRC=\"/b.js\" async></SCRIPT><script src='/c.js'/><script>inline()</script>")
        r = cl.audit_html(html)
        self.assertEqual(r["external_scripts"], 3)
        self.assertEqual(r["script_tags"], 5)
        self.assertNotIn("<script[", inspect.getsource(cl.audit_html))

    # --- audit item 7: `hidden` subtrees are not visible text
    def test_hidden_subtree_with_160_words_is_ignored(self):
        html = ("<main><div hidden><p>" + "word " * 160 + "</p></div>"
                "<p>one two three</p></main>")
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 3)
        self.assertEqual(r["verdict"], "thin_content")
        self.assertNotIn("word", r["text_preview"])

    def test_hidden_text_does_not_fill_mount_node(self):
        html = ("<div id='root'><div hidden>" + "secret " * 200 + "</div></div>"
                "<script src='/bundle.js'></script>")
        r = cl.audit_html(html)
        self.assertEqual(r["empty_mount_nodes"], ["root"])
        self.assertEqual(r["visible_words"], 0)
        self.assertEqual(r["verdict"], "likely_csr_shell")

    def test_unclosed_children_close_with_hidden_parent(self):
        html = ("<section HIDDEN><p>gone<p>also gone<span>still gone</section>"
                "<p>visible text here</p><br><img src='x.png'><p>more</p>")
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 4)
        self.assertNotIn("gone", r["text_preview"])

    def test_stray_end_tags_do_not_close_hidden_early(self):
        html = "<div hidden></span></p><p>secret</div><p>shown</p>"
        r = cl.audit_html(html)
        self.assertEqual(r["text_preview"], "shown")

    # --- R2 defect 5: HTML implied end tags before evaluating hidden state
    def test_implied_p_end_closes_hidden_paragraph_160_words(self):
        html = "<main><p hidden>secret hidden text<p>" + "word " * 160 + "</main>"
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 160)
        self.assertEqual(r["verdict"], "server_rendered")
        self.assertNotIn("secret", r["text_preview"])
        self.assertTrue(r["text_preview"].startswith("word word"))

    def test_implied_li_end_closes_hidden_item(self):
        r = cl.audit_html("<ul><li hidden>hidden<li>visible</ul>")
        self.assertEqual(r["text_preview"], "visible")
        self.assertEqual(r["visible_words"], 1)

    def test_implied_end_tags_for_other_elements(self):
        cases = [
            ("<dl><dt hidden>gone<dd>shown</dl>", "shown"),
            ("<dl><dd hidden>gone<dt>shown</dl>", "shown"),
            ("<table><tr><td hidden>gone<td>shown</table>", "shown"),
            ("<table><tr><th hidden>gone<th>shown</table>", "shown"),
            ("<table><tr><td hidden>gone<tr><td>shown</table>", "shown"),
            ("<table><tr hidden><td>gone<tr><td>shown</table>", "shown"),
            ("<table><thead hidden><tr><td>gone<tbody><tr><td>shown</table>", "shown"),
            ("<table><tbody hidden><tr><td>gone<tfoot><tr><td>shown</table>", "shown"),
            ("<p hidden>gone<hr>shown", "shown"),
            ("<p hidden>gone<div>shown</div>", "shown"),
            ("<p hidden>gone<h2>shown</h2>", "shown"),
            ("<p hidden>gone<section>shown</section>", "shown"),
            ("<p hidden>gone<blockquote>shown</blockquote>", "shown"),
            ("<p hidden>gone<span>still gone<ul><li>shown</ul>", "shown"),
            ("<li hidden>gone<p>still gone<li>shown", "shown"),
        ]
        for html, expected in cases:
            with self.subTest(html=html):
                r = cl.audit_html(html)
                self.assertEqual(r["text_preview"], expected)

    def test_implied_end_tags_respect_scope_boundaries(self):
        # A nested <li> inside an inner <ul> must NOT close the hidden outer <li>.
        r = cl.audit_html("<ul><li hidden>a<ul><li>nested</ul><li>shown</ul>")
        self.assertEqual(r["text_preview"], "shown")
        # A <div> inside <button> does not close a <p> outside the button scope.
        r = cl.audit_html("<p hidden>gone<button><div>still gone</div></button></p><p>shown</p>")
        self.assertEqual(r["text_preview"], "shown")
        # A <td> in a nested table does not close the hidden outer cell.
        r = cl.audit_html("<table><tr><td hidden><table><tr><td>inner</table>"
                          "<td>shown</table>")
        self.assertEqual(r["text_preview"], "shown")

    def test_implied_end_tag_mount_bookkeeping(self):
        r = cl.audit_html("<div id='app'><p hidden>secret<p>real content</div>")
        self.assertEqual(r["empty_mount_nodes"], [])
        self.assertEqual(r["text_preview"], "real content")

    def test_implied_end_tag_lookup_is_linear(self):
        html = "<p><button>" + "<div>" * 30000 + "x" + "<li>" * 20000
        start = time.perf_counter()
        r = cl.audit_html(html)
        self.assertLess(time.perf_counter() - start, 3.0)
        self.assertEqual(r["visible_words"], 1)

    # --- R3 defect 6: <template> subtree is isolated from the outer document
    def test_template_p_does_not_close_hidden_outer_paragraph(self):
        html = ("<p hidden>" + "hidden " * 160 + "<template><p>x</p></template> "
                "<div id=\"root\"></div><script src=\"/a.js\"></script>")
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 0)
        self.assertEqual(r["empty_mount_nodes"], ["root"])
        self.assertEqual(r["verdict"], "likely_csr_shell")

    def test_text_after_template_inside_hidden_paragraph_stays_hidden(self):
        html = ("<main><p hidden>" + "alpha " * 80 + "<template><p>x</p></template>"
                + "leak " * 160 + "<div id='root'></div></main><script src='/a.js'></script>")
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 0, r["text_preview"])
        self.assertNotIn("leak", r["text_preview"])
        self.assertEqual(r["verdict"], "likely_csr_shell")

    def test_template_does_not_touch_outer_stack_or_hidden_depth(self):
        parser = cl._VisibleTextParser()
        parser.feed("<p hidden>a<template><p>x</p><div hidden><li>y</template>")
        self.assertEqual(parser.template_depth, 0)
        self.assertEqual(parser._hidden_depth, 1)
        self.assertEqual(parser._stack, [("p", True, None)])
        parser.feed("<template><template></template></div></p>")
        self.assertEqual(parser.template_depth, 1)
        self.assertEqual(parser._stack, [("p", True, None)], "end tags inside template are inert")

    def test_template_content_never_fills_or_creates_mount_nodes(self):
        r = cl.audit_html("<div id='root'><template><p>" + "word " * 200 + "</p></template></div>"
                          "<script src='/a.js'></script>")
        self.assertEqual(r["empty_mount_nodes"], ["root"])
        self.assertEqual(r["visible_words"], 0)
        r = cl.audit_html("<template><div id='app'></div></template><p>" + "word " * 200 + "</p>")
        self.assertEqual(r["empty_mount_nodes"], [])
        self.assertEqual(r["verdict"], "server_rendered")

    def test_stray_template_end_tag_is_ignored(self):
        r = cl.audit_html("</template><p hidden>gone</template><p>shown</p>")
        self.assertEqual(r["text_preview"], "shown")

    # --- R5 defect 5: Declarative Shadow DOM
    def test_declarative_shadow_root_160_words_with_plain_template_in_hidden_paragraph(self):
        html = ("<p hidden>" + "hidden " * 160 + "<template><p>x</p></template></p>"
                '<div id="host"><template shadowrootmode="open"><p>' + "shadow " * 160
                + '</p></template></div><script src="/a.js"></script>')
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 160)
        self.assertEqual(r["verdict"], "server_rendered")
        self.assertEqual(r["external_scripts"], 1)
        self.assertTrue(r["text_preview"].startswith("shadow shadow"))
        self.assertNotIn("hidden", r["text_preview"])
        self.assertNotIn("x", r["text_preview"].split())

    def test_declarative_shadow_root_modes_are_case_insensitive(self):
        for mode in ("open", "closed", "OPEN", "Closed"):
            with self.subTest(mode=mode):
                html = ("<div id='root'><template shadowrootmode='%s'><p>%s</p></template></div>"
                        "<script src='/a.js'></script>" % (mode, "word " * 160))
                r = cl.audit_html(html)
                self.assertEqual(r["visible_words"], 160)
                self.assertEqual(r["empty_mount_nodes"], [])
                self.assertEqual(r["verdict"], "server_rendered")
        for mode in ("", "none", "opened"):
            with self.subTest(mode=mode):
                r = cl.audit_html("<div><template shadowrootmode='%s'><p>gone</p></template></div>"
                                  "<p>shown</p>" % mode)
                self.assertEqual(r["text_preview"], "shown", "invalid mode stays an inert template")

    def test_declarative_shadow_root_nested_exclusions(self):
        html = ("<div><template shadowrootmode='open'>"
                "<p>visible one</p>"
                "<script>var a = 'script words here';</script>"
                "<style>.b{color:red}</style>"
                "<span hidden>secret</span>"
                "<div style='display:none'>gone</div>"
                "<template><p>inert</p></template>"
                "<dialog>closed</dialog>"
                "<p>visible two</p>"
                "</template></div>")
        r = cl.audit_html(html)
        self.assertEqual(r["text_preview"], "visible one visible two")
        self.assertEqual(r["script_tags"], 1)
        self.assertGreater(r["inline_script_byte_ratio"], 0.0)

    def test_declarative_shadow_root_is_isolated_from_outer_open_elements(self):
        parser = cl._VisibleTextParser()
        parser.feed("<p hidden>a<template shadowrootmode='open'><p>b</p><li>c")
        self.assertEqual(parser._hidden_depth, 1, "the host's hidden state still applies")
        self.assertEqual(parser._stack[:2], [("p", True, None), ("template", False, None)])
        parser.feed("</p></template>d")
        self.assertEqual(parser._stack, [("p", True, None)], "inner tags never closed the outer <p>")
        self.assertEqual(parser.text_parts, [])
        parser.feed("</p>e")
        self.assertEqual(parser.text_parts, ["e"])
        r = cl.audit_html("<div hidden><template shadowrootmode='open'></div>x</template>y</div>z")
        self.assertEqual(r["text_preview"], "z")

    def test_shadow_root_inside_inert_template_stays_inert(self):
        r = cl.audit_html("<template><div><template shadowrootmode='open'><p>inert</p></template>"
                          "</div><p>still inert</p></template><p>shown</p>")
        self.assertEqual(r["text_preview"], "shown")
        parser = cl._VisibleTextParser()
        parser.feed("<template><template shadowrootmode='open'></template>")
        self.assertEqual(parser.template_depth, 1)
        self.assertEqual(parser._stack, [])

    # --- R5 defect 6: closed <dialog> subtrees are hidden
    def test_closed_dialog_160_words_is_csr_shell(self):
        html = ("<main><dialog><p>" + "word " * 160 + "</p></dialog><p>one two</p></main>"
                "<script src='/a.js'></script>")
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 2)
        self.assertEqual(r["text_preview"], "one two")
        self.assertEqual(r["verdict"], "likely_csr_shell")

    def test_open_dialog_160_words_is_server_rendered(self):
        for attr in ("open", "OPEN", "open=''", "open='false'"):
            with self.subTest(attr=attr):
                html = ("<main><dialog %s><p>%s</p></dialog></main><script src='/a.js'></script>"
                        % (attr, "word " * 160))
                r = cl.audit_html(html)
                self.assertEqual(r["visible_words"], 160)
                self.assertEqual(r["verdict"], "server_rendered")

    def test_closed_dialog_pops_cleanly(self):
        parser = cl._VisibleTextParser()
        parser.feed("<div id='app'><dialog><span>secret")
        self.assertEqual(parser._hidden_depth, 1)
        parser.feed("</dialog>shown</div>")
        self.assertEqual(parser._hidden_depth, 0)
        self.assertEqual(parser.text_parts, ["shown"])
        self.assertEqual(parser._mount_has_content, {"app": True})
        self.assertEqual(cl.audit_html("<p>a<dialog>b</dialog>c")["text_preview"], "a c")

    # --- R3 defect 7: CJK / non-space-delimited word counting
    def test_count_words_counts_cjk_characters(self):
        self.assertEqual(cl.count_words("日本語のテキスト"), 8)
        self.assertEqual(cl.count_words("한국어 문장"), 5)
        self.assertEqual(cl.count_words("hello 世界 test42"), 4)
        self.assertEqual(cl.count_words("使用Python3处理"), 5)
        self.assertEqual(cl.count_words("plain english words"), 3)
        self.assertEqual(cl.count_words("，。・！"), 0)

    def test_chinese_ssr_article_with_external_script_is_server_rendered(self):
        sentences = ["第%d段：我们的工具可以把杂乱的表格整理成清晰的数据，并且完整保留原始格式与注释。" % (i + 1)
                     for i in range(35)]
        html = ("<html lang='zh-CN'><head><title>数据整理指南</title></head><body><main><article>"
                + "".join("<p>%s</p>" % s for s in sentences)
                + "</article></main><script src=\"/app.js\"></script></body></html>")
        # The old \w+ count treats each run of Han characters as ONE word.
        self.assertLess(len(re.findall(r"\w+", " ".join(sentences))), 150)
        r = cl.audit_html(html)
        self.assertEqual(r["verdict"], "server_rendered")
        self.assertGreater(r["visible_words"], 700)
        self.assertEqual(r["external_scripts"], 1)
        self.assertEqual(r["title"], "数据整理指南")

    # --- R4 defect 3: visible <body><noscript> fallback text counts
    def test_body_noscript_fallback_170_words_is_server_rendered(self):
        html = ("<html><head><title>Docs</title><noscript><style>.x{}</style>ignored head words"
                "</noscript></head><body><div id=\"root\"></div><noscript><p>"
                + "fallback " * 170 + "</p></noscript><script src=\"/a.js\"></script></body></html>")
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 170)
        self.assertEqual(r["verdict"], "server_rendered")
        self.assertNotIn("ignored", r["text_preview"])
        self.assertTrue(r["text_preview"].startswith("fallback fallback"))
        self.assertEqual(r["title"], "Docs")
        self.assertEqual(r["external_scripts"], 1)

    def test_head_noscript_text_is_ignored(self):
        r = cl.audit_html("<html><head><noscript>" + "secret " * 170 + "</noscript></head>"
                          "<body><p>one</p></body></html>")
        self.assertEqual(r["visible_words"], 1)
        self.assertEqual(r["text_preview"], "one")

    def test_body_start_closes_unclosed_head_before_noscript(self):
        r = cl.audit_html("<html><head><title>T</title><body><noscript>shown text</noscript></body>")
        self.assertEqual(r["text_preview"], "shown text")
        r = cl.audit_html("<head><title>T</title><div><noscript>also shown</noscript></div>")
        self.assertEqual(r["text_preview"], "also shown")

    def test_hidden_body_noscript_is_excluded(self):
        for attrs in (" hidden", " style='display:none'", " style='visibility: hidden'"):
            with self.subTest(attrs=attrs):
                html = "<body><noscript%s>%s</noscript><p>one two</p></body>" % (attrs, "word " * 170)
                r = cl.audit_html(html)
                self.assertEqual(r["visible_words"], 2)
                self.assertEqual(r["text_preview"], "one two")

    def test_noscript_fallback_fills_mount_node(self):
        r = cl.audit_html("<div id='app'><noscript>Please enable JavaScript to use this app.</noscript>"
                          "</div><script src='/a.js'></script>")
        self.assertEqual(r["empty_mount_nodes"], [])
        self.assertEqual(r["visible_words"], 7)
        self.assertEqual(r["verdict"], "likely_csr_shell")

    def test_script_style_template_inside_body_noscript_still_excluded(self):
        r = cl.audit_html("<body><noscript><script>var a='x y z';</script><style>.b{}</style>"
                          "<template><p>inert</p></template><p>visible</p></noscript></body>")
        self.assertEqual(r["text_preview"], "visible")
        self.assertEqual(r["visible_words"], 1)

    # --- R4 defect 4: inline display:none / visibility:hidden subtrees
    def test_inline_display_none_subtree_excluded_from_text_and_mount(self):
        html = ('<div id="root"><div style="display: none">' + "word " * 170
                + '</div></div><script src="/a.js"></script>')
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 0)
        self.assertEqual(r["empty_mount_nodes"], ["root"])
        self.assertEqual(r["verdict"], "likely_csr_shell")

    def test_inline_hiding_style_variants(self):
        hiding = ("display:none", "DISPLAY : NONE", "color: red; display: none !important",
                  "visibility:hidden", "margin:0;Visibility: Hidden;", " display:none;")
        for style in hiding:
            with self.subTest(style=style):
                r = cl.audit_html('<main><div style="%s"><p>gone</p><span>gone</span></div>'
                                  '<p>shown</p></main>' % style)
                self.assertEqual(r["text_preview"], "shown")
        visible = ("display: block", "display: nonexistent", "content: 'display:none'",
                   "visibility: visible", "", "color: red")
        for style in visible:
            with self.subTest(style=style):
                r = cl.audit_html('<main><div style="%s"><p>gone</p></div><p>shown</p></main>' % style)
                self.assertEqual(r["text_preview"], "gone shown")

    def test_inline_hiding_style_respects_implied_end_tags_and_stack(self):
        self.assertEqual(cl.audit_html('<p style="display:none">gone<p>shown')["text_preview"], "shown")
        self.assertEqual(cl.audit_html('<ul><li style="visibility:hidden">gone<li>shown</ul>')["text_preview"],
                         "shown")
        parser = cl._VisibleTextParser()
        parser.feed('<div style="display:none"><span>x')
        self.assertEqual(parser._hidden_depth, 1)
        self.assertEqual(parser._stack, [("div", True, None), ("span", False, None)])
        parser.feed("</div>after")
        self.assertEqual(parser._hidden_depth, 0)
        self.assertEqual(parser.text_parts, ["after"])

    # --- R5 defect 7: per-property CSS cascade for inline style
    def _style_preview(self, style):
        return cl.audit_html('<main><div style="%s"><p>gone</p></div><p>shown</p></main>'
                             % style)["text_preview"]

    def test_later_normal_display_overrides_earlier_normal_none(self):
        self.assertEqual(self._style_preview("display:none; display:block"), "gone shown")

    def test_earlier_important_none_beats_later_normal_display(self):
        self.assertEqual(self._style_preview("display:none !important; display:block"), "shown")

    def test_inline_style_cascade_matrix(self):
        hidden = (
            "display:block; display:none",
            "display:none !important; display:block",
            "DISPLAY:NONE !IMPORTANT; display:block",
            "display:none ! important; display:block",
            "display:none!important;display:flex",
            "display:block !important; display:none !important",
            "display:none; display: bogus",
            "display:none; display: none block",
            "display: none /* comment */ ; color: red",
            "visibility:visible; visibility:hidden",
            "visibility:hidden !important; visibility:visible",
            "visibility: collapse",
            "display:block; visibility:hidden",
            "color: red; display: none; font-family: 'a;b'",
        )
        for style in hidden:
            with self.subTest(style=style):
                self.assertEqual(self._style_preview(style), "shown")
        visible = (
            "display:none; display:block",
            "display:block !important; display:none",
            "display:none; display:block !important",
            "display:none !important; display:block !important",
            "display:none; display: inline flex",
            "display:none; display: inherit",
            "visibility:hidden; visibility:visible",
            "visibility:hidden; visibility: bogus; visibility: visible",
            "content: 'a;display:none'",
            "/* display:none */ color: red",
            "display: none-ish",
            "x-display: none",
            "display:!important",
        )
        for style in visible:
            with self.subTest(style=style):
                self.assertEqual(self._style_preview(style), "gone shown")

    def test_resolve_inline_style_winners(self):
        self.assertEqual(cl._resolve_inline_style("display:none !important; display:block; Visibility:Hidden"),
                         {"display": ("none", True), "visibility": ("hidden", False)})
        self.assertEqual(cl._resolve_inline_style("display:none; display:block"),
                         {"display": ("block", False)})
        self.assertEqual(cl._split_css_declarations("a:'x;y'; b:url(a;b); c:1 /* ; */"),
                         ["a:'x;y'", " b:url(a;b)", " c:1  "])

    def test_first_duplicate_style_attribute_wins(self):
        r = cl.audit_html('<main><div style="display:block" style="display:none"><p>gone</p></div>'
                          '<p>shown</p></main>')
        self.assertEqual(r["text_preview"], "gone shown")

    # --- R4 defect 5: JSON-LD / JSON data blocks are not executable scripts
    def test_json_ld_only_page_is_thin_content_not_csr_shell(self):
        data = json.dumps({"@context": "https://schema.org", "@type": "Article",
                           "articleBody": "lorem ipsum " * 4000})
        html = ("<html><head><title>T</title><script type=\"application/ld+json\">" + data
                + "</script></head><body><p>one two three four five six seven</p></body></html>")
        r = cl.audit_html(html)
        self.assertEqual(r["visible_words"], 7)
        self.assertEqual(r["script_tags"], 0)
        self.assertEqual(r["external_scripts"], 0)
        self.assertEqual(r["data_script_tags"], 1)
        self.assertEqual(r["inline_script_byte_ratio"], 0.0)
        self.assertEqual(r["verdict"], "thin_content")
        self.assertNotIn("lorem", r["text_preview"])

    def test_data_script_types_are_not_executable(self):
        for script_type in ("application/ld+json", "application/json", "importmap",
                            "APPLICATION/LD+JSON; charset=utf-8", "text/x-template", "speculationrules"):
            with self.subTest(type=script_type):
                html = ('<script type="%s" src="/d.json">{"a": "%s"}</script><p>one two</p>'
                        % (script_type, "x" * 5000))
                r = cl.audit_html(html)
                self.assertEqual((r["script_tags"], r["external_scripts"], r["data_script_tags"]), (0, 0, 1))
                self.assertEqual(r["inline_script_byte_ratio"], 0.0)
                self.assertEqual(r["verdict"], "thin_content")

    def test_executable_script_types_still_counted(self):
        for script_type in (None, "", "text/javascript", "application/javascript; charset=utf-8",
                            "MODULE", "module", "text/ecmascript", "application/ecmascript",
                            " Text/JavaScript "):
            with self.subTest(type=script_type):
                attr = "" if script_type is None else ' type="%s"' % script_type
                r = cl.audit_html("<script%s src='/a.js'></script><p>one two</p>" % attr)
                self.assertEqual((r["script_tags"], r["external_scripts"], r["data_script_tags"]), (1, 1, 0))
                self.assertEqual(r["verdict"], "likely_csr_shell")
        self.assertEqual(cl.audit_html("<script language='JavaScript' src='/a.js'></script>")["script_tags"], 1)
        self.assertEqual(cl.audit_html("<script language='vbscript'>x</script>")["script_tags"], 0)

    def test_mixed_executable_and_data_scripts(self):
        html = ("<script type='application/ld+json'>" + "{}" * 3000 + "</script>"
                "<script>" + "var a=1;" * 10 + "</script><p>one two</p>")
        r = cl.audit_html(html)
        self.assertEqual((r["script_tags"], r["data_script_tags"]), (1, 1))
        self.assertLess(r["inline_script_byte_ratio"], 0.1, "data block bytes must not count")


class SsrfTests(NoNetworkTestCase):
    BAD = [
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://user:pass@example.com/",
        "http://user@example.com/",
        "http://localhost/",
        "http://app.localhost/",
        "http://printer.local/",
        "http://intranet/",
        "http://127.0.0.1/",
        "http://127.1.2.3:8080/",
        "http://0.0.0.0/",
        "http://10.0.0.5/",
        "http://172.16.3.4/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://[::1]/",
        "http://[fd00::1]/",
        "http://[fe80::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://127.1/",
        "https://example.com:22/",
        "http:///nohost",
    ]

    def test_rejects_unsafe_urls(self):
        for url in self.BAD:
            with self.subTest(url=url):
                with self.assertRaises(cl.UnsafeURLError):
                    cl.validate_public_url(url, resolve=False)

    def test_accepts_public_urls_without_dns(self):
        for url in ("https://cleanparse.com/", "http://example.com/path?q=1", "https://93.184.215.14/",
                    "https://example.com:443/", "https://example.com/catalog?"):
            with self.subTest(url=url):
                self.assertEqual(cl.validate_public_url(url, resolve=False), url)

    def test_dns_result_pointing_to_private_ip_is_rejected(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake):
            with self.assertRaises(cl.UnsafeURLError):
                cl.validate_public_url("https://rebind.example.com/")

    def test_dns_result_public_is_accepted(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake):
            self.assertEqual(cl.validate_public_url("https://example.com/"), "https://example.com/")

    def test_resolve_public_url_returns_deduplicated_ips(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.15", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake) as ga:
            url, ips = cl.resolve_public_url(" https://example.com/ ")
        self.assertEqual(url, "https://example.com/")
        self.assertEqual(ips, ["93.184.215.14", "93.184.215.15"])
        self.assertEqual(ga.call_count, 1)

    def test_cli_refuses_private_url_with_exit_2(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            code = cl.main(["--url", "http://192.168.0.10/"])
        self.assertEqual(code, 2)
        self.assertIn("refused", err.getvalue())

    # --- audit item 1: IPv6 site-local and explicit address-class guard
    def test_ipv6_site_local_literal_rejected(self):
        self.assertTrue(ipaddress.IPv6Address("fec0::1").is_site_local)
        for url in ("http://[fec0::1]/", "https://[fec0::abcd:1]:8443/", "http://[FEFF::1]/"):
            with self.subTest(url=url):
                with self.assertRaises(cl.UnsafeURLError):
                    cl.validate_public_url(url, resolve=False)

    def test_dns_result_ipv6_site_local_rejected(self):
        fake = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fec0::1", 443, 0, 0))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake):
            with self.assertRaises(cl.UnsafeURLError):
                cl.validate_public_url("https://sitelocal.example.com/")
            with self.assertRaises(cl.UnsafeURLError):
                cl.resolve_public_url("https://sitelocal.example.com/")

    def test_mixed_dns_results_rejected_if_any_is_unsafe(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fec0::2", 443, 0, 0))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake):
            with self.assertRaises(cl.UnsafeURLError):
                cl.resolve_public_url("https://mixed.example.com/")

    def test_check_ip_rejects_every_non_public_class(self):
        for addr in ("fec0::1", "fc00::1", "::", "::1", "ff02::1", "fe80::1", "::ffff:192.168.0.1",
                     "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1",
                     "255.255.255.255", "100.64.0.1"):
            with self.subTest(addr=addr):
                with self.assertRaises(cl.UnsafeURLError):
                    cl._check_ip(ipaddress.ip_address(addr), addr)

    def test_check_ip_accepts_public_addresses(self):
        for addr in ("93.184.215.14", "2606:4700:4700::1111", "::ffff:93.184.215.14"):
            with self.subTest(addr=addr):
                cl._check_ip(ipaddress.ip_address(addr), addr)

    # --- R3 defect 1: IDNA host names converted once to ASCII
    def test_idna_hosts_converted_to_ascii_once(self):
        cases = {"https://Bücher.example.com/x": "xn--bcher-kva.example.com",
                 "http://münchen.de/": "xn--mnchen-3ya.de"}
        for url, expected in cases.items():
            with self.subTest(url=url):
                cleaned, _parts, host, _port, ips = cl._validate_url(url, resolve=False)
                self.assertEqual(host, expected)
                self.assertEqual(cleaned, url)
                self.assertEqual(ips, [])
        zh = cl._validate_url("https://例子.测试/", resolve=False)[2]
        self.assertTrue(zh.isascii())
        self.assertTrue(all(label.startswith("xn--") for label in zh.split(".")), zh)
        self.assertEqual(zh, "例子.测试".encode("idna").decode("ascii"))

    def test_idna_host_is_what_dns_resolves(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake) as ga:
            cl.resolve_public_url("https://münchen.de/")
            cl.resolve_public_url("https://例子.测试/")
        self.assertEqual(ga.call_args_list[0][0][0], "xn--mnchen-3ya.de")
        self.assertEqual(ga.call_args_list[1][0][0], "例子.测试".encode("idna").decode("ascii"))
        self.assertTrue(all(call[0][0].isascii() for call in ga.call_args_list))

    def test_invalid_or_tricky_idna_hosts_rejected(self):
        for url in ("http://１２７.０.０.１/",       # full-width digits -> 127.0.0.1
                    "http://127。0。0。1/",           # ideographic full stops -> 127.0.0.1
                    "http://１０.０.０.５/",
                    "http://ｌｏｃａｌｈｏｓｔ/",     # full-width "localhost"
                    "http://例子/",                   # single label after IDNA
                    "http://a..例子.com/",            # empty label
                    "http://" + "ü" * 64 + ".de/",    # label too long
                    "http://a..com/"):
            with self.subTest(url=url):
                with self.assertRaises(cl.UnsafeURLError):
                    cl.validate_public_url(url, resolve=False)

    def test_host_header_and_connections_use_idna(self):
        self.assertEqual(cl._host_header("bücher.example.com", 8080, "http"), "xn--bcher-kva.example.com:8080")
        self.assertEqual(cl._host_header("münchen.de", 443, "https"), "xn--mnchen-3ya.de")
        self.assertEqual(cl._host_header("2606:4700::1", 443, "https"), "[2606:4700::1]")
        ctx = _passthrough_context()
        with mock.patch.object(socket, "create_connection", return_value=FakeSocket(b"")):
            conn = cl._PinnedHTTPSConnection("münchen.de", 443, "93.184.215.14", 5.0, context=ctx)
            conn.connect()
        self.assertEqual(ctx.wrap_socket.call_args.kwargs["server_hostname"], "xn--mnchen-3ya.de")
        self.assertEqual(cl._PinnedHTTPConnection("bücher.example.com", 80, "93.184.215.14", 5.0).host,
                         "xn--bcher-kva.example.com")


# --------------------------------------------------------------------------- defect 6: fetch_text

PUBLIC_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))]
TWO_IP_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0)),
              (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.15", 0))]
PRIVATE_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))]

EARLY_HINTS = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\n"


def _http(status=200, reason="OK", headers=None, body=b""):
    hdrs = {"Content-Length": str(len(body)), "Connection": "close"}
    hdrs.update(headers or {})
    head = "HTTP/1.1 %d %s\r\n" % (status, reason) + "".join("%s: %s\r\n" % kv for kv in hdrs.items())
    return (head + "\r\n").encode("latin-1") + body


def _raw_deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return comp.compress(data) + comp.flush()


class FakeSocket:
    """Minimal socket double: records the request, replays a canned HTTP response."""

    def __init__(self, response: bytes):
        self._response = response
        self.sent = b""
        self.timeouts: list[float] = []
        self.closed = False

    def sendall(self, data):
        self.sent += bytes(data)

    def makefile(self, *_a, **_k):
        return io.BytesIO(self._response)

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


class _ClockedReader(io.BytesIO):
    """Response stream that advances a fake clock when a given line is read."""

    def __init__(self, data: bytes, clock: list, trigger: bytes, jump: float):
        super().__init__(data)
        self._clock = clock
        self._trigger = trigger
        self._jump = jump

    def readline(self, *args):
        line = super().readline(*args)
        if line.startswith(self._trigger):
            self._clock[0] += self._jump
        return line


class ClockedSocket(FakeSocket):
    def __init__(self, response: bytes, clock: list, trigger: bytes, jump: float):
        super().__init__(response)
        self._clock = clock
        self._trigger = trigger
        self._jump = jump

    def makefile(self, *_a, **_k):
        return _ClockedReader(self._response, self._clock, self._trigger, self._jump)


class _StalledReader:
    """File double that never yields response bytes until the socket is shut down."""

    def __init__(self, released: threading.Event):
        self._released = released

    def readline(self, *_a):
        self._released.wait(5)
        return b""

    def read(self, *_a):
        self._released.wait(5)
        return b""

    def close(self):
        pass


class StallingSocket(FakeSocket):
    """Accepts the request but stalls the status line / headers forever."""

    def __init__(self):
        super().__init__(b"")
        self.released = threading.Event()

    def makefile(self, *_a, **_k):
        return _StalledReader(self.released)

    def shutdown(self, _how):
        self.released.set()


class StallingTLSSocket(StallingSocket):
    """TLS socket double whose handshake stalls until the watchdog shuts it down."""

    def __init__(self):
        super().__init__()
        self.handshakes = 0

    def do_handshake(self):
        self.handshakes += 1
        if self.released.wait(5):
            raise OSError("TLS handshake aborted by socket shutdown")


def _passthrough_context():
    """ssl.SSLContext double: wrap_socket returns the raw socket unchanged."""
    ctx = mock.Mock()
    ctx.wrap_socket.side_effect = lambda raw, server_hostname=None, **_kw: raw
    return ctx


class FetchTests(NoNetworkTestCase):
    def _net(self, responses, dns=None):
        sockets: list[FakeSocket] = []

        def connect(_addr, _timeout=None, *_a, **_k):
            s = FakeSocket(responses[min(len(sockets), len(responses) - 1)])
            sockets.append(s)
            return s

        cc = mock.patch.object(socket, "create_connection", side_effect=connect)
        ga = mock.patch.object(socket, "getaddrinfo", side_effect=dns or (lambda *_a, **_k: PUBLIC_DNS))
        m_cc, m_ga = cc.start(), ga.start()
        self.addCleanup(cc.stop)
        self.addCleanup(ga.stop)
        return m_cc, m_ga, sockets

    def _main_json(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cl.main(argv + ["--json"])
        self.assertEqual(code, 0)
        return json.loads(out.getvalue())

    def test_connects_to_pinned_ip_with_single_dns_lookup(self):
        m_cc, m_ga, socks = self._net([_http(headers={"Content-Type": "text/plain; charset=utf-8"},
                                             body=b"hello")])
        self.assertEqual(cl.fetch_text("http://example.com/a/b?q=1"), (200, "hello"))
        self.assertEqual(m_ga.call_count, 1)
        (addr, timeout), _ = m_cc.call_args
        self.assertEqual(addr, ("93.184.215.14", 80))
        self.assertLessEqual(timeout, cl.FETCH_TIMEOUT)
        sent = socks[0].sent
        self.assertTrue(sent.startswith(b"GET /a/b?q=1 HTTP/1.1\r\n"))
        self.assertIn(b"Host: example.com\r\n", sent)
        self.assertIn(b"Accept-Encoding: identity\r\n", sent)

    def test_request_target_percent_encodes_brackets_on_the_wire(self):
        _cc, _ga, socks = self._net([_http(body=b"ok")])
        self.assertEqual(cl.fetch_text("http://example.com/catalog?tag[]=blue"), (200, "ok"))
        self.assertTrue(socks[0].sent.startswith(b"GET /catalog?tag%5B%5D=blue HTTP/1.1\r\n"))

    def test_env_proxies_are_ignored(self):
        env = {"http_proxy": "http://10.9.9.9:3128", "HTTP_PROXY": "http://10.9.9.9:3128",
               "https_proxy": "http://10.9.9.9:3128", "HTTPS_PROXY": "http://10.9.9.9:3128"}
        m_cc, _ga, _s = self._net([_http(body=b"ok")])
        with mock.patch.dict(os.environ, env):
            self.assertEqual(cl.fetch_text("http://example.com/"), (200, "ok"))
        self.assertEqual(m_cc.call_args[0][0], ("93.184.215.14", 80))

    def test_https_uses_sni_and_cert_hostname(self):
        ctx = _passthrough_context()
        m_cc, _ga, _s = self._net([_http(body=b"secure")])
        with mock.patch.object(cl.ssl, "create_default_context", return_value=ctx):
            self.assertEqual(cl.fetch_text("https://example.com/x"), (200, "secure"))
        self.assertEqual(m_cc.call_args[0][0], ("93.184.215.14", 443))
        self.assertEqual(ctx.wrap_socket.call_args.kwargs["server_hostname"], "example.com")
        self.assertIs(ctx.wrap_socket.call_args.kwargs["do_handshake_on_connect"], False)
        self.assertTrue(issubclass(cl._PinnedHTTPSConnection, cl.http.client.HTTPSConnection))

    def test_redirect_followed_and_every_hop_resolved(self):
        m_cc, m_ga, socks = self._net([_http(301, "Moved", {"Location": "/final#frag"}), _http(body=b"done")])
        self.assertEqual(cl.fetch_text("http://example.com/start"), (200, "done"))
        self.assertEqual(m_ga.call_count, 2)
        self.assertEqual(m_cc.call_count, 2)
        self.assertTrue(socks[1].sent.startswith(b"GET /final HTTP/1.1\r\n"))

    def test_redirect_to_private_ip_literal_rejected(self):
        m_cc, _ga, _s = self._net([_http(302, "Found", {"Location": "http://10.0.0.1/admin"})])
        with self.assertRaises(cl.UnsafeURLError):
            cl.fetch_text("http://example.com/")
        self.assertEqual(m_cc.call_count, 1)

    def test_redirect_to_privately_resolving_host_rejected(self):
        dns = lambda host, *_a, **_k: PRIVATE_DNS if host == "evil.example.net" else PUBLIC_DNS
        m_cc, _ga, _s = self._net([_http(302, "Found", {"Location": "http://evil.example.net/"})], dns)
        with self.assertRaises(cl.UnsafeURLError):
            cl.fetch_text("http://example.com/")
        self.assertEqual(m_cc.call_count, 1)

    def test_too_many_redirects(self):
        m_cc, _ga, _s = self._net([_http(302, "Found", {"Location": "/again"})])
        with self.assertRaises(cl.FetchError):
            cl.fetch_text("http://example.com/")
        self.assertEqual(m_cc.call_count, cl.MAX_REDIRECTS + 1)

    def test_single_deadline_spans_all_hops(self):
        m_cc, _ga, _s = self._net([_http(302, "Found", {"Location": "/again"})])
        with mock.patch.object(cl, "_now", side_effect=itertools.count(0.0, 0.5)):
            with self.assertRaises(TimeoutError):
                cl.fetch_text("http://example.com/")
        self.assertGreaterEqual(m_cc.call_count, 2)
        self.assertLess(m_cc.call_count, cl.MAX_REDIRECTS + 1)

    def test_body_read_in_bounded_chunks_with_deadline(self):
        # Stopping at the MAX_FETCH_BYTES cap is intentional, NOT a premature EOF.
        _cc, _ga, socks = self._net([_http(body=b"x" * 1000)])
        with mock.patch.object(cl, "MAX_FETCH_BYTES", 100), mock.patch.object(cl, "FETCH_CHUNK", 30):
            status, text = cl.fetch_text("http://example.com/")
        self.assertEqual((status, len(text)), (200, 100))
        self.assertGreaterEqual(len(socks[0].timeouts), 4)
        self.assertTrue(all(0 < t <= cl.FETCH_TIMEOUT for t in socks[0].timeouts))

    def test_unknown_charset_falls_back_to_utf8(self):
        self._net([_http(headers={"Content-Type": "text/html; charset=x-bogus-charset"},
                         body="café".encode("utf-8"))])
        self.assertEqual(cl.fetch_text("http://example.com/"), (200, "café"))

    def test_http_error_returns_empty_body(self):
        self._net([_http(404, "Not Found", body=b"nope")])
        self.assertEqual(cl.fetch_text("http://example.com/missing"), (404, ""))

    # --- audit item 2: wall-clock deadline across DNS + full HTTP exchange
    def test_blocked_dns_lookup_honours_deadline(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def stuck_dns(*_a, **_k):
            release.wait(5)
            return PUBLIC_DNS

        m_cc, _ga, _s = self._net([_http(body=b"late")], dns=stuck_dns)
        with mock.patch.object(cl, "FETCH_TIMEOUT", 0.3):
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                cl.fetch_text("http://example.com/")
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0)
        self.assertEqual(m_cc.call_count, 0)

    def test_resolve_host_times_out_without_blocking(self):
        release = threading.Event()
        self.addCleanup(release.set)
        with mock.patch.object(socket, "getaddrinfo", side_effect=lambda *_a, **_k: release.wait(5)):
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                cl._resolve_host("example.com", 443, 0.2)
        self.assertLess(time.monotonic() - start, 2.0)

    def test_dns_failure_is_unsafe_url_error(self):
        def failing(*_a, **_k):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        with mock.patch.object(socket, "getaddrinfo", side_effect=failing):
            with self.assertRaises(cl.UnsafeURLError):
                cl.resolve_public_url("https://nx.example.com/")

    def test_slow_header_read_aborted_by_watchdog(self):
        stalled = StallingSocket()
        self.addCleanup(stalled.released.set)
        with mock.patch.object(socket, "create_connection", return_value=stalled), \
                mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS), \
                mock.patch.object(cl, "FETCH_TIMEOUT", 0.3):
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                cl.fetch_text("http://example.com/")
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 3.0)
        self.assertTrue(stalled.released.is_set(), "watchdog must shut the socket down")

    def test_expired_deadline_before_headers_rejected_cleanly(self):
        # The clock jumps past the deadline as soon as the request has been sent, so
        # the settimeout() right before getresponse() must raise TimeoutError.
        _cc, _ga, socks = self._net([_http(body=b"never read")])
        clock = lambda: 99.0 if socks and socks[0].sent else 0.0
        with mock.patch.object(cl, "_now", side_effect=clock):
            with self.assertRaises(TimeoutError):
                cl.fetch_text("http://example.com/")
        self.assertTrue(socks[0].sent.startswith(b"GET / HTTP/1.1\r\n"))

    def test_204_returns_empty_body(self):
        self._net([_http(204, "No Content")])
        self.assertEqual(cl.fetch_text("http://example.com/robots.txt"), (204, ""))

    # --- R2 defect 2: TCP connect + TLS handshake share ONE deadline and watchdog
    def test_slow_tcp_and_stalled_tls_share_one_deadline_and_watchdog(self):
        tls = StallingTLSSocket()
        self.addCleanup(tls.released.set)
        tcp_timeouts: list[float] = []

        def slow_tcp(_addr, timeout=None, *_a, **_k):
            tcp_timeouts.append(timeout)
            time.sleep(0.2)
            return FakeSocket(b"")

        ctx = mock.Mock()
        ctx.wrap_socket.side_effect = lambda raw, **_kw: tls
        with mock.patch.object(socket, "create_connection", side_effect=slow_tcp), \
                mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS), \
                mock.patch.object(cl.ssl, "create_default_context", return_value=ctx), \
                mock.patch.object(cl, "FETCH_TIMEOUT", 0.6):
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                cl.fetch_text("https://example.com/")
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.5, "TCP + TLS must not get a fresh timeout each")
        self.assertEqual(tls.handshakes, 1)
        self.assertTrue(tls.released.is_set(), "watchdog must abort the stalled TLS handshake")
        self.assertLessEqual(tcp_timeouts[0], 0.6)
        self.assertLess(tls.timeouts[0], 0.45, "TLS timeout must be the time LEFT after TCP")
        self.assertTrue(tls.closed)

    # --- R3 defect 1: IDNA hosts reach DNS, TLS SNI and Host header as ASCII punycode
    def test_chinese_idna_host_https_uses_punycode_everywhere(self):
        host_u = "例子.测试"
        expected = host_u.encode("idna").decode("ascii")
        self.assertTrue(expected.isascii())
        ctx = _passthrough_context()
        _cc, m_ga, socks = self._net([_http(body=b"ok")])
        with mock.patch.object(cl.ssl, "create_default_context", return_value=ctx):
            self.assertEqual(cl.fetch_text("https://%s/路径?q=值" % host_u), (200, "ok"))
        self.assertEqual(m_ga.call_args[0][0], expected)
        self.assertEqual(ctx.wrap_socket.call_args.kwargs["server_hostname"], expected)
        sent = socks[0].sent
        self.assertTrue(sent.isascii())
        self.assertIn(b"Host: " + expected.encode("ascii") + b"\r\n", sent)
        target = urllib.parse.quote("/路径") + "?q=" + urllib.parse.quote("值")
        self.assertTrue(sent.startswith(("GET %s HTTP/1.1\r\n" % target).encode("ascii")))

    def test_german_idna_host_http_uses_punycode_everywhere(self):
        m_cc, m_ga, socks = self._net([_http(body=b"ja")])
        self.assertEqual(cl.fetch_text("http://münchen.de/straße"), (200, "ja"))
        self.assertEqual(m_ga.call_args[0][0], "xn--mnchen-3ya.de")
        self.assertEqual(m_cc.call_args[0][0], ("93.184.215.14", 80))
        self.assertIn(b"Host: xn--mnchen-3ya.de\r\n", socks[0].sent)
        self.assertTrue(socks[0].sent.startswith(b"GET /stra%C3%9Fe HTTP/1.1\r\n"))

    def test_german_idna_host_https_sni_with_custom_port(self):
        ctx = _passthrough_context()
        _cc, _ga, socks = self._net([_http(body=b"ok")])
        with mock.patch.object(cl.ssl, "create_default_context", return_value=ctx):
            self.assertEqual(cl.fetch_text("https://bücher.example.com:8443/"), (200, "ok"))
        self.assertEqual(ctx.wrap_socket.call_args.kwargs["server_hostname"], "xn--bcher-kva.example.com")
        self.assertIn(b"Host: xn--bcher-kva.example.com:8443\r\n", socks[0].sent)

    # --- R3 defect 2: failover across all validated DNS IPs
    def test_failover_to_second_validated_ip_after_connection_refused(self):
        attempts: list = []
        good = FakeSocket(_http(body=b"second"))

        def connect(addr, timeout=None, *_a, **_k):
            attempts.append((addr, timeout))
            if addr[0] == "93.184.215.14":
                raise ConnectionRefusedError(111, "Connection refused")
            return good

        with mock.patch.object(socket, "create_connection", side_effect=connect), \
                mock.patch.object(socket, "getaddrinfo", return_value=TWO_IP_DNS) as m_ga:
            self.assertEqual(cl.fetch_text("http://example.com/x"), (200, "second"))
        self.assertEqual([a for a, _t in attempts], [("93.184.215.14", 80), ("93.184.215.15", 80)])
        self.assertEqual(m_ga.call_count, 1, "no second DNS lookup during failover")
        self.assertTrue(all(0 < t <= cl.FETCH_TIMEOUT for _a, t in attempts))
        self.assertLessEqual(attempts[1][1], attempts[0][1])
        self.assertTrue(good.sent.startswith(b"GET /x HTTP/1.1\r\n"))

    def test_https_failover_keeps_sni_hostname(self):
        ctx = _passthrough_context()
        good = FakeSocket(_http(body=b"tls"))

        def connect(addr, timeout=None, *_a, **_k):
            if addr[0] == "93.184.215.14":
                raise ConnectionRefusedError(111, "Connection refused")
            return good

        with mock.patch.object(socket, "create_connection", side_effect=connect), \
                mock.patch.object(socket, "getaddrinfo", return_value=TWO_IP_DNS), \
                mock.patch.object(cl.ssl, "create_default_context", return_value=ctx):
            self.assertEqual(cl.fetch_text("https://example.com/"), (200, "tls"))
        self.assertEqual(ctx.wrap_socket.call_count, 1)
        self.assertEqual(ctx.wrap_socket.call_args.kwargs["server_hostname"], "example.com")

    def test_failover_shares_one_monotonic_deadline(self):
        clock = [100.0]
        attempts: list = []
        good = FakeSocket(_http(body=b"ok"))

        def connect(addr, timeout=None, *_a, **_k):
            attempts.append((addr, timeout))
            if addr[0] == "93.184.215.14":
                clock[0] += 3.0  # the refused attempt burns 3 seconds
                raise ConnectionRefusedError(111, "Connection refused")
            return good

        with mock.patch.object(cl, "_now", side_effect=lambda: clock[0]), \
                mock.patch.object(socket, "create_connection", side_effect=connect), \
                mock.patch.object(socket, "getaddrinfo", return_value=TWO_IP_DNS):
            self.assertEqual(cl.fetch_text("http://example.com/"), (200, "ok"))
        self.assertEqual(attempts[0][1], float(cl.FETCH_TIMEOUT))
        self.assertEqual(attempts[1][1], cl.FETCH_TIMEOUT - 3.0, "second IP gets only the time LEFT")

    def test_failover_never_extends_an_expired_deadline(self):
        clock = [100.0]
        attempts: list = []

        def connect(addr, timeout=None, *_a, **_k):
            attempts.append(addr)
            clock[0] += cl.FETCH_TIMEOUT + 1.0
            raise ConnectionRefusedError(111, "Connection refused")

        with mock.patch.object(cl, "_now", side_effect=lambda: clock[0]), \
                mock.patch.object(socket, "create_connection", side_effect=connect), \
                mock.patch.object(socket, "getaddrinfo", return_value=TWO_IP_DNS):
            with self.assertRaises(TimeoutError):
                cl.fetch_text("http://example.com/")
        self.assertEqual(attempts, [("93.184.215.14", 80)])

    def test_all_validated_ips_failing_raises_last_connect_error(self):
        attempts: list = []

        def refuse(addr, timeout=None, *_a, **_k):
            attempts.append(addr)
            raise ConnectionRefusedError(111, "refused %s" % addr[0])

        with mock.patch.object(socket, "create_connection", side_effect=refuse), \
                mock.patch.object(socket, "getaddrinfo", return_value=TWO_IP_DNS):
            with self.assertRaises(ConnectionRefusedError) as cm:
                cl.fetch_text("http://example.com/")
        self.assertEqual(len(attempts), 2)
        self.assertIn("93.184.215.15", str(cm.exception))

    def test_no_failover_after_a_response_was_received(self):
        # The first IP answers 500: that is a response, so the second IP is never tried.
        attempts: list = []

        def connect(addr, timeout=None, *_a, **_k):
            attempts.append(addr)
            return FakeSocket(_http(500, "Server Error", body=b"x"))

        with mock.patch.object(socket, "create_connection", side_effect=connect), \
                mock.patch.object(socket, "getaddrinfo", return_value=TWO_IP_DNS):
            self.assertEqual(cl.fetch_text("http://example.com/"), (500, ""))
        self.assertEqual(attempts, [("93.184.215.14", 80)])

    # --- R3 defect 3: premature EOF is a failed fetch, not truncated 200 text
    def test_content_length_truncation_raises_fetch_error(self):
        self._net([_http(headers={"Content-Length": "100"}, body=b"User-agent")])
        with self.assertRaises(cl.FetchError) as cm:
            cl.fetch_text("http://example.com/robots.txt")
        self.assertIn("Incomplete HTTP response body", str(cm.exception))

    def test_truncated_chunked_body_raises_fetch_error(self):
        for raw in (b"5\r\nhel", b"5\r\nhello\r\n"):
            with self.subTest(raw=raw):
                response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + raw
                with mock.patch.object(socket, "create_connection", return_value=FakeSocket(response)), \
                        mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS):
                    with self.assertRaises(cl.FetchError) as cm:
                        cl.fetch_text("http://example.com/robots.txt")
                self.assertIn("Incomplete HTTP response body", str(cm.exception))

    def test_complete_body_exactly_at_content_length_is_fine(self):
        self._net([_http(body=b"x" * 64)])
        with mock.patch.object(cl, "FETCH_CHUNK", 16):
            self.assertEqual(cl.fetch_text("http://example.com/"), (200, "x" * 64))

    # --- R3 defect 4: internal helper exposes every redirect hop
    def test_fetch_with_chain_returns_every_hop_url(self):
        self._net([_http(302, "Found", {"Location": "/restricted?x=1#frag"}), _http(body=b"done")])
        status, text, visited = cl._fetch_with_chain(" http://example.com/start ")
        self.assertEqual((status, text), (200, "done"))
        self.assertEqual(visited, ["http://example.com/start", "http://example.com/restricted?x=1"])

    def test_fetch_with_chain_single_hop(self):
        self._net([_http(body=b"one")])
        self.assertEqual(cl._fetch_with_chain("http://example.com/"), (200, "one", ["http://example.com/"]))

    # --- R4 defect 2: explicit empty query on the wire and across redirects
    def test_empty_query_marker_sent_on_the_wire(self):
        _cc, _ga, socks = self._net([_http(body=b"ok")])
        self.assertEqual(cl.fetch_text("http://example.com/catalog?"), (200, "ok"))
        self.assertTrue(socks[0].sent.startswith(b"GET /catalog? HTTP/1.1\r\n"))

    def test_redirect_preserves_empty_query_marker(self):
        _cc, _ga, socks = self._net([_http(301, "Moved", {"Location": "/catalog?#frag"}), _http(body=b"ok")])
        status, text, visited = cl._fetch_with_chain("http://example.com/start")
        self.assertEqual((status, text), (200, "ok"))
        self.assertEqual(visited, ["http://example.com/start", "http://example.com/catalog?"])
        self.assertTrue(socks[1].sent.startswith(b"GET /catalog? HTTP/1.1\r\n"))

    # --- R5 defect 1: interim 1xx responses
    def test_103_early_hints_before_200_returns_final_response(self):
        _cc, _ga, socks = self._net([EARLY_HINTS + _http(headers={"Content-Type": "text/plain"},
                                                         body=b"User-agent: *\nDisallow: /\n")])
        self.assertEqual(cl.fetch_text("http://example.com/robots.txt"),
                         (200, "User-agent: *\nDisallow: /\n"))
        self.assertEqual(len(socks), 1, "interim responses are read on the same connection")

    def test_several_interim_responses_are_consumed(self):
        interim = (b"HTTP/1.1 100 Continue\r\n\r\n"
                   b"HTTP/1.1 102 Processing\r\nX-Step: 1\r\n\r\n" + EARLY_HINTS + EARLY_HINTS)
        _cc, _ga, socks = self._net([interim + _http(body=b"final")])
        self.assertEqual(cl.fetch_text("http://example.com/"), (200, "final"))
        # The remaining deadline is re-applied after every interim response.
        self.assertGreaterEqual(len(socks[0].timeouts), 2 + 4)
        self.assertTrue(all(0 < t <= cl.FETCH_TIMEOUT for t in socks[0].timeouts))

    def test_interim_responses_before_redirect_and_error(self):
        self._net([EARLY_HINTS + _http(301, "Moved", {"Location": "/next"}),
                   EARLY_HINTS + _http(404, "Not Found", body=b"x")])
        status, text, visited = cl._fetch_with_chain("http://example.com/start")
        self.assertEqual((status, text), (404, ""))
        self.assertEqual(visited, ["http://example.com/start", "http://example.com/next"])

    def test_too_many_interim_responses_is_fetch_error(self):
        self._net([EARLY_HINTS * (cl.MAX_INTERIM_RESPONSES + 1) + _http(body=b"x")])
        with self.assertRaises(cl.FetchError) as cm:
            cl.fetch_text("http://example.com/")
        self.assertIn("interim", str(cm.exception))

    def test_101_switching_protocols_is_not_fetchable(self):
        self._net([b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"])
        with self.assertRaises(cl.FetchError) as cm:
            cl.fetch_text("http://example.com/robots.txt")
        self.assertIn("101", str(cm.exception))

    def test_interim_response_shares_the_fetch_deadline(self):
        clock = [100.0]
        sock = ClockedSocket(EARLY_HINTS + _http(body=b"late"), clock, b"Link:", 99.0)
        with mock.patch.object(cl, "_now", side_effect=lambda: clock[0]), \
                mock.patch.object(socket, "create_connection", return_value=sock), \
                mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS):
            with self.assertRaises(TimeoutError):
                cl.fetch_text("http://example.com/")

    def test_url_mode_103_before_200_disallow_all_blocks_every_crawler(self):
        page = _http(headers={"Content-Type": "text/html; charset=utf-8"}, body=SSR_PAGE.encode("utf-8"))
        robots = EARLY_HINTS + _http(headers={"Content-Type": "text/plain"},
                                     body=b"User-agent: *\nDisallow: /\n")
        self._net([page, robots, _http(404, "Not Found")])
        data = self._main_json(["--url", "http://example.com/"])
        rb = data["robots"]
        self.assertEqual(rb["http_status"], 200)
        self.assertEqual(rb["groups_found"], 1)
        for group in ("search_crawlers", "training_crawlers"):
            for name, verdict in rb[group].items():
                with self.subTest(crawler=name):
                    self.assertFalse(verdict["allowed"])
                    self.assertEqual(verdict["matched_rule"], "Disallow: /")
        self.assertEqual(rb["policy"], "all_ai_blocked_or_search_partially_blocked")

    # --- R5 defect 2: '//' preserved through redirect, wire and robots evaluation
    def test_url_mode_redirect_preserves_double_slash_segments(self):
        page = _http(headers={"Content-Type": "text/html"}, body=SSR_PAGE.encode("utf-8"))
        _cc, _ga, socks = self._net([
            _http(301, "Moved", {"Location": "reports//daily"}), page,
            _http(body=b"User-agent: *\nDisallow: /news/reports//\n"), _http(404, "Not Found")])
        data = self._main_json(["--url", "http://example.com/news/start"])
        self.assertTrue(socks[0].sent.startswith(b"GET /news/start HTTP/1.1\r\n"))
        self.assertTrue(socks[1].sent.startswith(b"GET /news/reports//daily HTTP/1.1\r\n"))
        rb = data["robots"]
        self.assertEqual([hop["url"] for hop in rb["redirect_chain"]],
                         ["http://example.com/news/start", "http://example.com/news/reports//daily"])
        self.assertEqual([hop["path"] for hop in rb["redirect_chain"]],
                         ["/news/start", "/news/reports//daily"])
        self.assertTrue(rb["redirect_chain"][0]["search_crawlers"]["OAI-SearchBot"]["allowed"])
        oai = rb["search_crawlers"]["OAI-SearchBot"]
        self.assertFalse(oai["allowed"])
        self.assertEqual(oai["matched_rule"], "Disallow: /news/reports//")
        self.assertEqual(oai["blocked_at"], "http://example.com/news/reports//daily")
        self.assertEqual(data["final_url"], "http://example.com/news/reports//daily")
        self.assertEqual(data["html"]["source"], "http://example.com/news/reports//daily")

    # --- R5 defect 4: final media type
    def test_fetch_url_details_reports_media_type_essence(self):
        self._net([_http(301, "Moved", {"Location": "/api", "Content-Type": "text/html"}),
                   _http(headers={"Content-Type": "Application/JSON; charset=utf-8"}, body=b"{}"),
                   _http(body=b"no type")])
        details = cl._fetch_url_details("http://example.com/start")
        self.assertEqual(details, {"status": 200, "text": "{}", "content_type": "application/json",
                                   "visited": ["http://example.com/start", "http://example.com/api"]})
        self.assertIsNone(cl._fetch_url_details("http://example.com/plain")["content_type"])
        self.assertEqual(cl._media_type_essence(" text/HTML ;charset=x"), "text/html")
        self.assertIsNone(cl._media_type_essence(""))
        self.assertIsNone(cl._media_type_essence(None))
        self.assertIsNone(cl._media_type_essence(" ; charset=utf-8"))

    def test_url_mode_json_response_with_161_words_is_unsupported_content(self):
        body = json.dumps({"text": "word " * 161}).encode("utf-8")
        self.assertEqual(cl.audit_html(body.decode("utf-8"))["verdict"], "server_rendered",
                         "parsed as HTML this JSON would be misclassified")
        self._net([_http(headers={"Content-Type": "application/json; charset=utf-8"}, body=body),
                   _http(404, "Not Found"), _http(404, "Not Found")])
        data = self._main_json(["--url", "http://example.com/api"])
        self.assertEqual(data["html"], {
            "source": "http://example.com/api",
            "http_status": 200,
            "content_type": "application/json",
            "verdict": "unsupported_content",
            "advice": "Response has non-HTML Content-Type (application/json); skipping HTML shell check.",
            "visible_words": 0,
            "script_tags": 0,
            "external_scripts": 0,
            "data_script_tags": 0,
            "inline_script_byte_ratio": 0.0,
            "empty_mount_nodes": [],
            "title": "",
            "text_preview": "",
        })

    # --- R4 defect 1: HTTP Content-Encoding
    def test_gzip_robots_txt_is_decoded_and_blocks_crawlers(self):
        plain = b"User-agent: *\nDisallow: /\n"
        self._net([_http(headers={"Content-Encoding": "gzip", "Content-Type": "text/plain; charset=utf-8"},
                         body=gzip.compress(plain))])
        status, text = cl.fetch_text("http://example.com/robots.txt")
        self.assertEqual((status, text), (200, plain.decode("ascii")))
        report = cl._robots_report_for_status(status, text, "/", "http://example.com/robots.txt")
        self.assertEqual(report["groups_found"], 1)
        self.assertFalse(any(v["allowed"] for v in report["search_crawlers"].values()))
        self.assertFalse(any(v["allowed"] for v in report["training_crawlers"].values()))
        self.assertEqual(report["search_crawlers"]["OAI-SearchBot"]["matched_rule"], "Disallow: /")

    def test_url_mode_gzip_robots_blocks_crawlers_end_to_end(self):
        page = _http(headers={"Content-Type": "text/html; charset=utf-8"}, body=SSR_PAGE.encode("utf-8"))
        robots = _http(headers={"Content-Encoding": "gzip"},
                       body=gzip.compress(b"User-agent: *\nDisallow: /\n"))
        self._net([page, robots, _http(404, "Not Found")])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cl.main(["--url", "http://example.com/", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["robots"]["groups_found"], 1)
        self.assertFalse(any(v["allowed"] for v in data["robots"]["search_crawlers"].values()))
        self.assertEqual(data["html"]["verdict"], "server_rendered")

    def test_url_mode_unsupported_encoding_robots_is_error_not_allow_all(self):
        page = _http(body=SSR_PAGE.encode("utf-8"))
        robots = _http(headers={"Content-Encoding": "br"}, body=b"\x8b\x05\x80binary-brotli")
        self._net([page, robots, _http(404, "Not Found")])
        err = io.StringIO()
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(err):
            code = cl.main(["--url", "http://example.com/", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("Unsupported Content-Encoding", err.getvalue())

    def test_x_gzip_and_multi_member_gzip(self):
        self._net([_http(headers={"Content-Encoding": "x-gzip"}, body=gzip.compress(b"alpha")),
                   _http(headers={"Content-Encoding": "GZIP"},
                         body=gzip.compress(b"one ") + gzip.compress(b"two"))])
        self.assertEqual(cl.fetch_text("http://example.com/a"), (200, "alpha"))
        self.assertEqual(cl.fetch_text("http://example.com/b"), (200, "one two"))

    def test_deflate_zlib_and_raw_streams(self):
        plain = b"User-agent: GPTBot\nDisallow: /\n" * 10
        self._net([_http(headers={"Content-Encoding": "deflate"}, body=zlib.compress(plain)),
                   _http(headers={"Content-Encoding": "deflate"}, body=_raw_deflate(plain))])
        with mock.patch.object(cl, "FETCH_CHUNK", 7):
            self.assertEqual(cl.fetch_text("http://example.com/zlib"), (200, plain.decode("ascii")))
            self.assertEqual(cl.fetch_text("http://example.com/raw"), (200, plain.decode("ascii")))

    def test_identity_content_encoding_is_plain(self):
        self._net([_http(headers={"Content-Encoding": "identity"}, body=b"plain"),
                   _http(headers={"Content-Encoding": ""}, body=b"also plain")])
        self.assertEqual(cl.fetch_text("http://example.com/a"), (200, "plain"))
        self.assertEqual(cl.fetch_text("http://example.com/b"), (200, "also plain"))

    def test_gzip_bomb_raises_fetch_error(self):
        bomb = gzip.compress(b"\0" * 1_000_000)
        self.assertLess(len(bomb), 4096)
        self._net([_http(headers={"Content-Encoding": "gzip"}, body=bomb)])
        with mock.patch.object(cl, "MAX_FETCH_BYTES", 4096):
            with self.assertRaises(cl.FetchError) as cm:
                cl.fetch_text("http://example.com/robots.txt")
        self.assertIn("exceeds", str(cm.exception))

    def test_gzip_bomb_at_real_limit_raises_fetch_error(self):
        bomb = gzip.compress(b"\0" * (cl.MAX_FETCH_BYTES + 1))
        self._net([_http(headers={"Content-Encoding": "gzip"}, body=bomb)])
        with self.assertRaises(cl.FetchError) as cm:
            cl.fetch_text("http://example.com/")
        self.assertIn("exceeds", str(cm.exception))

    def test_decompressed_output_exactly_at_limit_is_fine(self):
        plain = b"x" * 5000
        self._net([_http(headers={"Content-Encoding": "gzip"}, body=gzip.compress(plain)),
                   _http(headers={"Content-Encoding": "gzip"}, body=gzip.compress(plain))])
        with mock.patch.object(cl, "MAX_FETCH_BYTES", 5000):
            self.assertEqual(cl.fetch_text("http://example.com/"), (200, "x" * 5000))
        with mock.patch.object(cl, "MAX_FETCH_BYTES", 4999):
            with self.assertRaises(cl.FetchError):
                cl.fetch_text("http://example.com/")

    def test_compressed_body_decoder_never_exceeds_limit(self):
        for coding, data in (("gzip", gzip.compress(b"A" * 500_000)),
                             ("deflate", zlib.compress(b"A" * 500_000)),
                             ("deflate", _raw_deflate(b"A" * 500_000))):
            with self.subTest(coding=coding):
                decoder = cl._CompressedBody(coding, 1000, "http://example.com/")
                with self.assertRaises(cl.FetchError):
                    decoder.feed(data)
                self.assertLessEqual(decoder.size, 1001)

    def test_corrupt_or_truncated_gzip_raises_fetch_error(self):
        good = gzip.compress(b"User-agent: *\nDisallow: /\n")
        bad_crc = bytearray(good)
        bad_crc[-8] ^= 0xFF
        for body in (b"\x1f\x8b\x08\x00" + b"\xff" * 20, b"User-agent: *\nDisallow: /\n",
                     good[:-4], good[:5], bytes(bad_crc), good + b"garbage!!"):
            with self.subTest(body=body[:12]):
                with mock.patch.object(socket, "create_connection",
                                       return_value=FakeSocket(_http(headers={"Content-Encoding": "gzip"},
                                                                     body=body))), \
                        mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS):
                    with self.assertRaises(cl.FetchError):
                        cl.fetch_text("http://example.com/robots.txt")

    def test_corrupt_deflate_and_trailing_garbage_raise_fetch_error(self):
        for body in (b"\xff\xff\xff\xff", zlib.compress(b"ok") + b"junk", zlib.compress(b"ok")[:-3]):
            with self.subTest(body=body):
                with mock.patch.object(socket, "create_connection",
                                       return_value=FakeSocket(_http(headers={"Content-Encoding": "deflate"},
                                                                     body=body))), \
                        mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS):
                    with self.assertRaises(cl.FetchError):
                        cl.fetch_text("http://example.com/")

    def test_unsupported_content_encoding_raises_fetch_error(self):
        for coding in ("br", "zstd", "compress", "gzip, br", "gzip, gzip", "x-unknown"):
            with self.subTest(coding=coding):
                with mock.patch.object(socket, "create_connection",
                                       return_value=FakeSocket(_http(headers={"Content-Encoding": coding},
                                                                     body=b"\x1b\x00compressed"))), \
                        mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS):
                    with self.assertRaises(cl.FetchError) as cm:
                        cl.fetch_text("http://example.com/robots.txt")
                self.assertIn("Unsupported Content-Encoding", str(cm.exception))

    def test_compressed_empty_body_is_empty_text(self):
        self._net([_http(204, "No Content", {"Content-Encoding": "br"}),
                   _http(headers={"Content-Encoding": "gzip"}, body=b"")])
        self.assertEqual(cl.fetch_text("http://example.com/a"), (204, ""))
        self.assertEqual(cl.fetch_text("http://example.com/b"), (200, ""))


class PinnedConnectionDeadlineTests(NoNetworkTestCase):
    def test_https_connect_uses_one_clock_for_tcp_and_tls(self):
        clock = [100.0]
        raw, tls = FakeSocket(b""), FakeSocket(b"")
        handshakes: list[float] = []
        tls.do_handshake = lambda: handshakes.append(clock[0])
        tcp_timeouts: list[float] = []

        def slow_tcp(_addr, timeout=None, *_a, **_k):
            tcp_timeouts.append(timeout)
            clock[0] += 4.0
            return raw

        def slow_wrap(sock, **_kw):
            self.assertIs(sock, raw)
            clock[0] += 3.0
            return tls

        ctx = mock.Mock()
        ctx.wrap_socket.side_effect = slow_wrap
        notified: list = []
        with mock.patch.object(cl, "_now", side_effect=lambda: clock[0]), \
                mock.patch.object(socket, "create_connection", side_effect=slow_tcp):
            conn = cl._PinnedHTTPSConnection("example.com", 443, "93.184.215.14", 10.0, context=ctx,
                                             deadline=110.0, on_socket=notified.append)
            conn.connect()
        self.assertEqual(tcp_timeouts, [10.0])
        self.assertEqual(raw.timeouts, [6.0], "raw socket timeout reset after TCP connect")
        self.assertEqual(tls.timeouts, [3.0], "TLS handshake gets only the time left")
        self.assertEqual(handshakes, [107.0])
        self.assertEqual(notified, [raw, tls])
        self.assertIs(conn.sock, tls)
        self.assertEqual(ctx.wrap_socket.call_args.kwargs,
                         {"server_hostname": "example.com", "do_handshake_on_connect": False})

    def test_https_connect_deadline_expired_after_tcp_skips_tls(self):
        clock = [100.0]
        raw = FakeSocket(b"")

        def slow_tcp(_addr, timeout=None, *_a, **_k):
            clock[0] += 11.0
            return raw

        ctx = mock.Mock()
        with mock.patch.object(cl, "_now", side_effect=lambda: clock[0]), \
                mock.patch.object(socket, "create_connection", side_effect=slow_tcp):
            conn = cl._PinnedHTTPSConnection("example.com", 443, "93.184.215.14", 10.0, context=ctx,
                                             deadline=110.0)
            with self.assertRaises(TimeoutError):
                conn.connect()
        ctx.wrap_socket.assert_not_called()
        self.assertTrue(raw.closed)
        self.assertIsNone(conn.sock)

    def test_https_constructor_backward_compatible_without_deadline(self):
        raw = FakeSocket(b"")
        ctx = _passthrough_context()
        with mock.patch.object(socket, "create_connection", return_value=raw) as m_cc:
            conn = cl._PinnedHTTPSConnection("example.com", 443, "93.184.215.14", 7.0, ctx)
            conn.connect()
        self.assertEqual(m_cc.call_args[0], (("93.184.215.14", 443), 7.0))
        self.assertEqual(raw.timeouts, [7.0, 7.0])
        self.assertIs(conn.sock, raw)

    def test_http_connect_uses_remaining_budget_and_notifies(self):
        sock = FakeSocket(b"")
        notified: list = []
        with mock.patch.object(cl, "_now", return_value=100.0), \
                mock.patch.object(socket, "create_connection", return_value=sock) as m_cc:
            conn = cl._PinnedHTTPConnection("example.com", 80, "93.184.215.14", 10.0,
                                            deadline=104.0, on_socket=notified.append)
            conn.connect()
        self.assertEqual(m_cc.call_args[0], (("93.184.215.14", 80), 4.0))
        self.assertEqual(notified, [sock])
        self.assertIs(conn.sock, sock)

    def test_http_connect_refuses_expired_deadline(self):
        m_cc = mock.Mock()
        with mock.patch.object(cl, "_now", return_value=50.0), \
                mock.patch.object(socket, "create_connection", m_cc):
            conn = cl._PinnedHTTPConnection("example.com", 80, "93.184.215.14", 10.0, deadline=50.0)
            with self.assertRaises(TimeoutError):
                conn.connect()
        m_cc.assert_not_called()

    def test_watchdog_shuts_down_socket_attached_after_expiry(self):
        dog = cl._Watchdog(0.0)
        dog.start()
        self.assertTrue(dog.fired.wait(2))
        late = StallingSocket()
        dog.attach(late)
        self.assertTrue(late.released.is_set())
        dog.cancel()

    def test_pinned_connections_use_interim_skipping_response(self):
        self.assertIs(cl._PinnedHTTPConnection.response_class, cl._FinalResponse)
        self.assertIs(cl._PinnedHTTPSConnection.response_class, cl._FinalResponse)
        self.assertTrue(issubclass(cl._FinalResponse, cl.http.client.HTTPResponse))


# --------------------------------------------------------------------------- R2 defect 1: real sockets

class RealSocketFetchTests(NoNetworkTestCase):
    """fetch_text over a REAL loopback socket.socketpair() (no external network).

    With Content-Length + Connection: close, http.client closes the response and the
    underlying socket as soon as the final body byte is read. Calling
    sock.settimeout() afterwards raises OSError (WinError 10038 on Windows, EBADF
    elsewhere); fetch_text must stop the body loop cleanly instead.
    """

    def _serve(self, response: bytes, close_after_send: bool = False):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        request = bytearray()
        release = threading.Event()

        def serve():
            try:
                server.settimeout(5)
                while b"\r\n\r\n" not in request:
                    data = server.recv(4096)
                    if not data:
                        return
                    request.extend(data)
                server.sendall(response)
                if close_after_send:
                    server.shutdown(socket.SHUT_WR)
                # Keep the server end open: the client must finish via resp.isclosed(),
                # not because the peer sent EOF.
                release.wait(5)
            except OSError:
                pass

        thread = threading.Thread(target=serve, name="socketpair-server", daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(release.set)
        return client, request

    def _fetch(self, url, client, **patches):
        ctx = _passthrough_context()
        with mock.patch.object(socket, "create_connection", return_value=client), \
                mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS), \
                mock.patch.object(cl.ssl, "create_default_context", return_value=ctx), \
                mock.patch.multiple(cl, **patches) if patches else _nullcontext():
            return cl.fetch_text(url)

    def test_http_content_length_close_over_real_socket(self):
        body = "Plain body over a real socket – café".encode("utf-8")
        client, request = self._serve(_http(headers={"Content-Type": "text/plain; charset=utf-8"},
                                            body=body))
        self.assertEqual(self._fetch("http://example.com/page", client),
                         (200, body.decode("utf-8")))
        self.assertTrue(bytes(request).startswith(b"GET /page HTTP/1.1\r\n"))
        self.assertEqual(client.fileno(), -1, "http.client closed the socket after the last byte")

    def test_http_content_length_close_many_small_chunks(self):
        body = b"0123456789" * 5
        client, _request = self._serve(_http(body=body))
        self.assertEqual(self._fetch("http://example.com/", client, FETCH_CHUNK=7),
                         (200, body.decode("ascii")))
        self.assertEqual(client.fileno(), -1)

    def test_http_empty_content_length_over_real_socket(self):
        client, _request = self._serve(_http(body=b""))
        self.assertEqual(self._fetch("http://example.com/empty", client), (200, ""))

    def test_http_chunked_close_over_real_socket(self):
        response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                    b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        client, _request = self._serve(response)
        self.assertEqual(self._fetch("http://example.com/", client), (200, "hello world"))
        self.assertEqual(client.fileno(), -1)

    def test_http_close_delimited_body_over_real_socket(self):
        response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil-eof"
        client, _request = self._serve(response, close_after_send=True)
        self.assertEqual(self._fetch("http://example.com/", client), (200, "until-eof"))

    def test_https_content_length_close_over_real_socket(self):
        body = b"secure body over a real socket"
        client, request = self._serve(_http(body=body))
        self.assertEqual(self._fetch("https://example.com/s?x=1", client),
                         (200, body.decode("ascii")))
        self.assertTrue(bytes(request).startswith(b"GET /s?x=1 HTTP/1.1\r\n"))
        self.assertIn(b"Host: example.com\r\n", bytes(request))
        self.assertEqual(client.fileno(), -1)

    # --- R3 defect 3: premature EOF over a real socket
    def test_premature_eof_before_content_length_over_real_socket(self):
        response = (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
                    b"User-agent")
        client, _request = self._serve(response, close_after_send=True)
        with self.assertRaises(cl.FetchError) as cm:
            self._fetch("http://example.com/robots.txt", client)
        self.assertIn("Incomplete HTTP response body", str(cm.exception))

    def test_premature_eof_in_chunked_body_over_real_socket(self):
        response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    b"a\r\nUser-ag")
        client, _request = self._serve(response, close_after_send=True)
        with self.assertRaises(cl.FetchError):
            self._fetch("http://example.com/robots.txt", client)

    # --- R4 defect 1: gzip over a real socket
    def test_gzip_body_over_real_socket(self):
        plain = b"User-agent: *\nDisallow: /\n" * 50
        client, _request = self._serve(_http(headers={"Content-Encoding": "gzip"}, body=gzip.compress(plain)))
        self.assertEqual(self._fetch("http://example.com/robots.txt", client, FETCH_CHUNK=11),
                         (200, plain.decode("ascii")))

    def test_gzip_chunked_body_over_real_socket(self):
        gz = gzip.compress(b"hello gzip world")
        response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n"
                    b"Connection: close\r\n\r\n" + b"%x\r\n" % len(gz) + gz + b"\r\n0\r\n\r\n")
        client, _request = self._serve(response)
        self.assertEqual(self._fetch("http://example.com/", client), (200, "hello gzip world"))

    # --- R5 defect 1: interim responses in the same buffered stream over a real socket
    def test_103_early_hints_then_200_over_real_socket(self):
        body = b"User-agent: *\nDisallow: /\n"
        client, _request = self._serve(EARLY_HINTS + _http(body=body))
        self.assertEqual(self._fetch("http://example.com/robots.txt", client),
                         (200, body.decode("ascii")))


class _nullcontext:
    def __enter__(self):
        return None

    def __exit__(self, *_exc):
        return False


class CharsetTests(NoNetworkTestCase):
    # --- audit item 8: safe charset decoding
    def test_idna_charset_falls_back_to_utf8(self):
        with mock.patch.object(socket, "create_connection",
                               return_value=FakeSocket(_http(headers={"Content-Type": "text/html; charset=idna"},
                                                             body="café".encode("utf-8")))), \
                mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS):
            self.assertEqual(cl.fetch_text("http://example.com/"), (200, "café"))

    def test_decode_body_rejects_transform_and_malformed_codecs(self):
        raw = "café".encode("utf-8")
        for charset in ("idna", "punycode", "hex", "base64", "rot13", "rot-13", "bz2", "zlib",
                        "quopri", "uu", "undefined", "unicode_escape", "utf-8\x00", "../../etc",
                        "x" * 200, "", None):
            with self.subTest(charset=charset):
                self.assertEqual(cl._decode_body(raw, charset), "café")

    def test_decode_body_honours_real_text_charsets(self):
        self.assertEqual(cl._decode_body("café".encode("latin-1"), "iso-8859-1"), "café")
        self.assertEqual(cl._decode_body("café".encode("cp1252"), '"windows-1252"'), "café")
        self.assertEqual(cl._decode_body("日本".encode("shift_jis"), "Shift_JIS"), "日本")

    def test_gzip_body_honours_declared_charset(self):
        with mock.patch.object(socket, "create_connection",
                               return_value=FakeSocket(_http(
                                   headers={"Content-Type": "text/plain; charset=iso-8859-1",
                                            "Content-Encoding": "gzip"},
                                   body=gzip.compress("café".encode("latin-1"))))), \
                mock.patch.object(socket, "getaddrinfo", return_value=PUBLIC_DNS):
            self.assertEqual(cl.fetch_text("http://example.com/"), (200, "café"))


class CliTests(NoNetworkTestCase):
    def test_offline_json_report(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cl.main([
                "--robots-file", str(EXAMPLES / "sample_robots.txt"),
                "--llms-file", str(EXAMPLES / "sample_llms.txt"),
                "--html-file", str(EXAMPLES / "csr_vs_ssr_sample.html"),
                "--json",
            ])
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["robots"]["policy"], "search_allowed_training_blocked")
        self.assertEqual(data["robots"]["path"], "/")
        self.assertTrue(data["llms"]["valid"])
        self.assertEqual(data["html"]["verdict"], "likely_csr_shell")

    def test_offline_human_report(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cl.main(["--robots-file", str(EXAMPLES / "sample_robots.txt")])
        self.assertEqual(code, 0)
        self.assertIn("OAI-SearchBot", out.getvalue())
        self.assertIn("BLOCK", out.getvalue())

    # --- defect 1: --url path default
    def _main_with(self, argv, robots=(200, "User-agent: *\nDisallow: /docs/\n"),
                   llms=(404, ""), page=(200, SSR_PAGE), chain=None, robots_by_origin=None,
                   page_type="text/html"):
        calls: list[str] = []

        def fake_fetch(url):
            calls.append(url)
            if url.endswith("/robots.txt"):
                value = robots_by_origin[url[:-len("/robots.txt")]] if robots_by_origin else robots
            elif url.endswith("/llms.txt"):
                value = llms
            else:
                value = page
            if isinstance(value, BaseException):
                raise value
            return value

        def fake_details(url):
            calls.append(url)
            status, body = page
            return {"status": status, "text": body, "visited": list(chain) if chain else [url],
                    "content_type": page_type}

        self.fetch_calls = calls
        out = io.StringIO()
        with mock.patch.object(cl, "fetch_text", side_effect=fake_fetch), \
                mock.patch.object(cl, "_fetch_url_details", side_effect=fake_details), \
                redirect_stdout(out):
            code = cl.main(argv)
        return code, out.getvalue()

    def _run_url(self, argv, **responses):
        code, out = self._main_with(argv + ["--json"], **responses)
        self.assertEqual(code, 0)
        return json.loads(out)

    def test_url_mode_defaults_to_page_path_and_query(self):
        data = self._run_url(["--url", "https://example.com/docs/page?x=1"])
        self.assertEqual(data["robots"]["path"], "/docs/page?x=1")
        self.assertFalse(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_url_mode_bare_origin_defaults_to_root(self):
        data = self._run_url(["--url", "https://example.com"])
        self.assertEqual(data["robots"]["path"], "/")
        self.assertTrue(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_url_mode_explicit_path_overrides(self):
        data = self._run_url(["--url", "https://example.com/docs/page", "--path", "/other"])
        self.assertEqual(data["robots"]["path"], "/other")
        self.assertTrue(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    # --- R2 defect 3: default robots path == request target sent on the wire
    def test_url_mode_default_path_matches_wire_request_target(self):
        url = "https://example.com/catalog?tag[]=blue"
        data = self._run_url(["--url", url],
                             robots=(200, "User-agent: *\nDisallow: /catalog?tag%5B%5D=\n"))
        self.assertEqual(data["robots"]["path"], "/catalog?tag%5B%5D=blue")
        self.assertEqual(data["robots"]["path"], cl._request_target(urllib.parse.urlsplit(url)))
        self.assertFalse(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertEqual(data["robots"]["search_crawlers"]["OAI-SearchBot"]["matched_rule"],
                         "Disallow: /catalog?tag%5B%5D=")

    def test_url_mode_default_path_encodes_spaces_like_the_wire(self):
        data = self._run_url(["--url", "https://example.com/docs/a b"],
                             robots=(200, "User-agent: *\nDisallow: /docs/a%20b\n"))
        self.assertEqual(data["robots"]["path"], "/docs/a%20b")
        self.assertFalse(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    # --- R3 defect 5: --url, --path and rules evaluate brackets identically
    def test_brackets_identical_through_url_path_and_rules(self):
        argvs = (["--url", "https://example.com/catalog?tag[]=blue"],
                 ["--url", "https://example.com/catalog?tag%5B%5D=blue"],
                 ["--url", "https://example.com/", "--path", "/catalog?tag[]=blue"],
                 ["--url", "https://example.com/", "--path", "/catalog?tag%5b%5d=blue"])
        for rule in ("/catalog?tag%5B%5D=", "/catalog?tag[]="):
            for argv in argvs:
                with self.subTest(rule=rule, argv=argv):
                    data = self._run_url(list(argv), robots=(200, "User-agent: *\nDisallow: %s\n" % rule))
                    oai = data["robots"]["search_crawlers"]["OAI-SearchBot"]
                    self.assertFalse(oai["allowed"])
                    self.assertEqual(oai["matched_rule"], "Disallow: " + rule)

    def test_brackets_identical_for_offline_robots_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            robots = Path(tmp) / "robots.txt"
            robots.write_text("User-agent: *\nDisallow: /catalog?tag%5B%5D=\n", encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = cl.main(["--robots-file", str(robots), "--path", "/catalog?tag[]=blue", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertFalse(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    # --- R4 defect 2: "/catalog?" identical in live --url, --path and offline mode
    def test_empty_query_identical_through_url_path_and_offline(self):
        robots = (200, "User-agent: *\nDisallow: /catalog?$\n")
        for argv in (["--url", "https://example.com/catalog?"],
                     ["--url", "https://example.com/catalog?#top"],
                     ["--url", "https://example.com/", "--path", "/catalog?"]):
            with self.subTest(argv=argv):
                data = self._run_url(list(argv), robots=robots)
                self.assertEqual(data["robots"]["path"], "/catalog?")
                oai = data["robots"]["search_crawlers"]["OAI-SearchBot"]
                self.assertFalse(oai["allowed"])
                self.assertEqual(oai["matched_rule"], "Disallow: /catalog?$")
        data = self._run_url(["--url", "https://example.com/catalog"], robots=robots)
        self.assertEqual(data["robots"]["path"], "/catalog")
        self.assertTrue(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "robots.txt"
            path.write_text(robots[1], encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = cl.main(["--robots-file", str(path), "--path", "/catalog?", "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out.getvalue())["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_redirect_hop_with_empty_query_is_evaluated_with_marker(self):
        chain = ["https://example.com/start", "https://example.com/catalog?"]
        data = self._run_url(["--url", "https://example.com/start"], chain=chain,
                             robots=(200, "User-agent: *\nDisallow: /catalog?$\n"))
        rb = data["robots"]
        self.assertEqual([hop["path"] for hop in rb["redirect_chain"]], ["/start", "/catalog?"])
        self.assertFalse(rb["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertEqual(rb["search_crawlers"]["OAI-SearchBot"]["blocked_at"], "https://example.com/catalog?")

    # --- audit item 6: 2xx robots.txt and failed page fetches
    def test_url_mode_204_robots_allows_all_and_404_page_is_fetch_failed(self):
        data = self._run_url(["--url", "https://example.com/docs/page"],
                             robots=(204, ""), page=(404, ""))
        self.assertEqual(data["robots"]["http_status"], 204)
        self.assertTrue(all(v["allowed"] for v in data["robots"]["search_crawlers"].values()))
        self.assertTrue(all(v["allowed"] for v in data["robots"]["training_crawlers"].values()))
        self.assertFalse(any("disallow all" in n for n in data["robots"]["notes"]))
        html = data["html"]
        self.assertEqual(html["verdict"], "fetch_failed")
        self.assertEqual(html["http_status"], 404)
        self.assertIn("HTTP 404", html["advice"])
        self.assertEqual(html["visible_words"], 0)
        self.assertEqual(html["empty_mount_nodes"], [])
        self.assertEqual(set(html) - {"http_status"}, set(cl.audit_html("")))

    def test_url_mode_other_2xx_robots_is_parsed(self):
        data = self._run_url(["--url", "https://example.com/docs/page"],
                             robots=(203, "User-agent: *\nDisallow: /docs/\n"))
        self.assertFalse(data["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_url_mode_5xx_robots_disallows_all(self):
        data = self._run_url(["--url", "https://example.com/"], robots=(503, ""))
        self.assertFalse(any(v["allowed"] for v in data["robots"]["search_crawlers"].values()))
        self.assertTrue(any("disallow all" in n for n in data["robots"]["notes"]))

    # --- R5 defect 1: non-2xx / non-4xx robots statuses are "disallow all"
    def test_url_mode_unfollowable_3xx_robots_disallows_all(self):
        for status in (301, 304, 300):
            with self.subTest(status=status):
                data = self._run_url(["--url", "https://example.com/"], robots=(status, ""))
                self.assertEqual(data["robots"]["http_status"], status)
                self.assertFalse(any(v["allowed"] for v in data["robots"]["search_crawlers"].values()))
                self.assertFalse(any(v["allowed"] for v in data["robots"]["training_crawlers"].values()))
                self.assertTrue(any("disallow all" in n for n in data["robots"]["notes"]))

    def test_url_mode_4xx_robots_allows_all(self):
        data = self._run_url(["--url", "https://example.com/docs/x"], robots=(404, ""))
        self.assertTrue(all(v["allowed"] for v in data["robots"]["search_crawlers"].values()))
        self.assertTrue(any("allow all" in n for n in data["robots"]["notes"]))

    def test_url_mode_5xx_page_is_fetch_failed(self):
        data = self._run_url(["--url", "https://example.com/"], page=(500, ""))
        self.assertEqual(data["html"]["verdict"], "fetch_failed")
        self.assertEqual(data["html"]["http_status"], 500)

    def test_url_mode_human_report_with_fetch_failed_page(self):
        code, out = self._main_with(["--url", "https://example.com/"], robots=(204, ""), page=(404, ""))
        self.assertEqual(code, 0)
        self.assertIn("fetch_failed", out)
        self.assertIn("HTTP 404", out)

    # --- R5 defect 4: non-HTML Content-Type skips the HTML audit
    def test_url_mode_json_content_type_is_unsupported_content(self):
        body = json.dumps({"text": "word " * 161})
        data = self._run_url(["--url", "https://example.com/api"], page=(200, body),
                             page_type="application/json")
        html = data["html"]
        self.assertEqual(html["verdict"], "unsupported_content")
        self.assertEqual(html["content_type"], "application/json")
        self.assertEqual(html["http_status"], 200)
        self.assertEqual(html["source"], "https://example.com/api")
        self.assertEqual(html["visible_words"], 0)
        self.assertEqual(html["advice"],
                         "Response has non-HTML Content-Type (application/json); skipping HTML shell check.")
        self.assertEqual(set(html) - {"http_status", "content_type"}, set(cl.audit_html("")))

    def test_url_mode_other_non_html_types_are_unsupported(self):
        for media_type in ("text/plain", "application/pdf", "image/svg+xml", "application/xml"):
            with self.subTest(media_type=media_type):
                data = self._run_url(["--url", "https://example.com/x"], page_type=media_type)
                self.assertEqual(data["html"]["verdict"], "unsupported_content")
                self.assertEqual(data["html"]["content_type"], media_type)

    def test_url_mode_html_types_and_missing_type_are_audited(self):
        for media_type in ("text/html", "application/xhtml+xml", None):
            with self.subTest(media_type=media_type):
                data = self._run_url(["--url", "https://example.com/x"], page_type=media_type)
                self.assertEqual(data["html"]["verdict"], "server_rendered")
                self.assertNotIn("content_type", data["html"])

    def test_url_mode_non_2xx_json_is_fetch_failed(self):
        data = self._run_url(["--url", "https://example.com/x"], page=(404, ""),
                             page_type="application/json")
        self.assertEqual(data["html"]["verdict"], "fetch_failed")

    def test_url_mode_human_report_with_unsupported_content(self):
        code, out = self._main_with(["--url", "https://example.com/api"], page_type="application/json")
        self.assertEqual(code, 0)
        self.assertIn("unsupported_content", out)
        self.assertIn("non-HTML Content-Type (application/json)", out)

    # --- R3 defect 3: a truncated robots.txt is a failed fetch, never "allow all"
    def test_url_mode_truncated_robots_is_error_not_allow_all(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code, out = self._main_with(
                ["--url", "https://example.com/", "--json"],
                robots=cl.FetchError("Incomplete HTTP response body from https://example.com/robots.txt"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("Incomplete HTTP response body", err.getvalue())

    # --- R3 defect 4: every redirect hop is evaluated; html source is the final URL
    def test_url_mode_single_hop_schema_unchanged(self):
        data = self._run_url(["--url", "https://example.com/docs/page"])
        self.assertEqual(set(data["robots"]), {"source", "path", "groups_found", "search_crawlers",
                                               "training_crawlers", "policy", "notes", "http_status"})
        self.assertNotIn("final_url", data)
        self.assertEqual(data["html"]["source"], "https://example.com/docs/page")
        self.assertEqual(set(data["robots"]["search_crawlers"]["OAI-SearchBot"]),
                         {"allowed", "group", "matched_rule"})

    def test_url_mode_redirect_to_disallowed_hop_is_not_allowed(self):
        chain = ["https://example.com/start", "https://example.com/restricted"]
        robots = (200, "User-agent: *\nDisallow: /restricted\n")
        data = self._run_url(["--url", "https://example.com/start"], robots=robots, chain=chain)
        rb = data["robots"]
        for group in ("search_crawlers", "training_crawlers"):
            for name, verdict in rb[group].items():
                with self.subTest(crawler=name):
                    self.assertFalse(verdict["allowed"])
                    self.assertEqual(verdict["blocked_at"], "https://example.com/restricted")
                    self.assertEqual(verdict["matched_rule"], "Disallow: /restricted")
        self.assertEqual(rb["policy"], "all_ai_blocked_or_search_partially_blocked")
        self.assertEqual(rb["path"], "/start", "first-hop keys stay backward compatible")
        self.assertEqual([hop["url"] for hop in rb["redirect_chain"]], chain)
        self.assertEqual([hop["path"] for hop in rb["redirect_chain"]], ["/start", "/restricted"])
        self.assertEqual(rb["final_url"], "https://example.com/restricted")
        self.assertEqual(data["final_url"], "https://example.com/restricted")
        self.assertEqual(data["html"]["source"], "https://example.com/restricted")
        self.assertEqual(self.fetch_calls.count("https://example.com/robots.txt"), 1,
                         "robots.txt is fetched once per origin")

    def test_url_mode_redirect_human_report_never_says_allow(self):
        chain = ["https://example.com/start", "https://example.com/restricted"]
        code, out = self._main_with(["--url", "https://example.com/start"],
                                    robots=(200, "User-agent: *\nDisallow: /restricted\n"), chain=chain)
        self.assertEqual(code, 0)
        self.assertNotIn("ALLOW", out)
        self.assertIn("BLOCK", out)
        self.assertIn("[html] https://example.com/restricted", out)

    def test_url_mode_cross_origin_redirect_uses_each_hops_robots(self):
        chain = ["https://a.example.com/start", "https://b.example.com/landing"]
        data = self._run_url(["--url", "https://a.example.com/start"], chain=chain, robots_by_origin={
            "https://a.example.com": (200, "User-agent: *\nDisallow:\n"),
            "https://b.example.com": (200, "User-agent: *\nDisallow: /\n"),
        })
        rb = data["robots"]
        self.assertFalse(rb["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertEqual(rb["search_crawlers"]["OAI-SearchBot"]["blocked_at"], "https://b.example.com/landing")
        self.assertEqual([hop["robots_source"] for hop in rb["redirect_chain"]],
                         ["https://a.example.com/robots.txt", "https://b.example.com/robots.txt"])
        self.assertTrue(rb["redirect_chain"][0]["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertEqual(self.fetch_calls.count("https://a.example.com/robots.txt"), 1)
        self.assertEqual(self.fetch_calls.count("https://b.example.com/robots.txt"), 1)
        self.assertEqual(data["html"]["source"], "https://b.example.com/landing")

    def test_url_mode_redirect_allowed_at_every_hop_stays_allowed(self):
        chain = ["https://example.com/old", "https://example.com/new"]
        data = self._run_url(["--url", "https://example.com/old"], chain=chain,
                             robots=(200, "User-agent: *\nDisallow: /private/\n"))
        rb = data["robots"]
        self.assertTrue(all(v["allowed"] for v in rb["search_crawlers"].values()))
        self.assertTrue(all(v["blocked_at"] is None for v in rb["search_crawlers"].values()))
        self.assertEqual(rb["policy"], "search_allowed_training_allowed_or_mixed")

    def test_url_mode_explicit_path_applies_to_first_hop_only(self):
        chain = ["https://example.com/start", "https://example.com/restricted"]
        data = self._run_url(["--url", "https://example.com/start", "--path", "/other"], chain=chain,
                             robots=(200, "User-agent: *\nDisallow: /restricted\n"))
        rb = data["robots"]
        self.assertEqual(rb["path"], "/other")
        self.assertFalse(rb["search_crawlers"]["OAI-SearchBot"]["allowed"])

    # --- R5 defect 2: '//' hop paths are evaluated exactly
    def test_url_mode_double_slash_hop_path_is_evaluated_exactly(self):
        chain = ["https://example.com/news/start", "https://example.com/news/reports//daily"]
        data = self._run_url(["--url", "https://example.com/news/start"], chain=chain,
                             robots=(200, "User-agent: *\nDisallow: /news/reports//\n"))
        rb = data["robots"]
        self.assertEqual([hop["path"] for hop in rb["redirect_chain"]], ["/news/start", "/news/reports//daily"])
        self.assertFalse(rb["search_crawlers"]["OAI-SearchBot"]["allowed"])

    # --- audit item 4: oversized --path is a clean CLI error, not a traceback
    def test_cli_oversized_path_is_error_exit_1(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cl.main(["--robots-file", str(EXAMPLES / "sample_robots.txt"),
                            "--path", "/" + "a" * (cl.MAX_MATCH_CHARS + 1)])
        self.assertEqual(code, 1)
        self.assertIn("too long", err.getvalue())


class ProtocolHardeningTests(FetchTests):
    """Offline regression tests for R7 protocol, encoding, and HTML visibility fixes."""

    def test_robots_truncated_at_max_bytes_drops_unfinished_line(self):
        section = b"User-agent: *\n"
        partial = b"Disallow: /"
        limit = cl.MAX_FETCH_BYTES
        pad = b"#" * (limit - len(section) - len(partial) - 1)
        policy = section + pad + b"\n" + partial + b"account/\n"
        self._net([_http(body=b"<p>Home</p>"), _http(body=policy), _http(404)])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cl.main(["--url", "http://example.com/", "--json"])
        self.assertEqual(code, 0)
        report = json.loads(out.getvalue())
        self.assertTrue(report["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

    def test_206_partial_content_robots_and_page_rejected(self):
        rb = cl._robots_report_for_status(206, "User-agent: *\nAllow: /\n", "/", "http://example.com/robots.txt")
        self.assertFalse(rb["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self._net([_http(206, "Partial Content", body=b"<p>Partial</p>"), _http(206, "Partial Content", body=b"User-agent: *\n"), _http(404)])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cl.main(["--url", "http://example.com/", "--json"])
        self.assertEqual(code, 0)
        rep = json.loads(out.getvalue())
        self.assertFalse(rep["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])
        self.assertEqual(rep["html"]["verdict"], "fetch_failed")

    def test_unsupported_transfer_encoding_rejected(self):
        self._net([_http(headers={"Transfer-Encoding": "gzip, chunked"}, body=b"0\r\n\r\n")])
        with self.assertRaises(cl.FetchError):
            cl.fetch_text("http://example.com/robots.txt")

    def test_robots_ignores_latin1_header_and_html_honours_utf16_bom(self):
        utf8_robots = "User-agent: *\nDisallow: /café\n".encode("utf-8")
        self._net([
            _http(body=b"<p>Home</p>"),
            _http(headers={"Content-Type": "text/plain; charset=iso-8859-1"}, body=utf8_robots),
            _http(404),
        ])
        out = io.StringIO()
        with redirect_stdout(out):
            code = cl.main(["--url", "http://example.com/caf%C3%A9", "--json"])
        self.assertEqual(code, 0)
        rep = json.loads(out.getvalue())
        self.assertFalse(rep["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

        utf16_html = b"\xff\xfe" + "<div id=\"root\"></div><script src=\"/app.js\"></script>".encode("utf-16-le")
        self._net([_http(headers={"Content-Type": "text/html"}, body=utf16_html)])
        st, text = cl.fetch_text("http://example.com/")
        self.assertEqual(st, 200)
        self.assertEqual(cl.audit_html(text)["verdict"], "likely_csr_shell")

    def test_malformed_marked_section_and_textarea_literal_script_safe(self):
        words = " ".join(f"word{i}" for i in range(160))
        html = f"<![bad[decl]]><textarea><script>not a tag</textarea><article>{words}</article>"
        res = cl.audit_html(html)
        self.assertEqual(res["verdict"], "server_rendered")
        self.assertGreaterEqual(res["visible_words"], 160)

    def test_visibility_visible_restores_child_unless_display_none(self):
        words = " ".join(f"word{i}" for i in range(160))
        html_ok = f'<div style="visibility:hidden"><p style="visibility:visible">{words}</p></div><script src="/a.js"></script>'
        self.assertEqual(cl.audit_html(html_ok)["verdict"], "server_rendered")
        html_dn = f'<div style="display:none"><p style="visibility:visible">{words}</p></div><div id="root"></div><script src="/a.js"></script>'
        res_dn = cl.audit_html(html_dn)
        self.assertEqual(res_dn["visible_words"], 0)
        self.assertEqual(res_dn["verdict"], "likely_csr_shell")

    def test_closed_details_hides_body_while_open_details_counts(self):
        words = " ".join(f"word{i}" for i in range(160))
        closed_html = f'<div id="root"></div><details><summary>More info</summary><p>{words}</p></details><script src="/a.js"></script>'
        res_closed = cl.audit_html(closed_html)
        self.assertEqual(res_closed["visible_words"], 2)
        self.assertEqual(res_closed["verdict"], "likely_csr_shell")
        open_html = f'<details open><summary>More info</summary><p>{words}</p></details><script src="/a.js"></script>'
        self.assertEqual(cl.audit_html(open_html)["verdict"], "server_rendered")

    def test_cr_robots_cutoff_and_exact_cap_eof_and_framing(self):
        # 1. CR-delimited robots.txt with complete Disallow: / before 2 MiB cutoff stays BLOCK
        rule = b"User-agent: *\rDisallow: /\r"
        pad = b"#" * (cl.MAX_FETCH_BYTES - len(rule) + 32)
        self._net([_http(body=b"<p>Home</p>"), _http(body=rule + pad), _http(404)])
        rep = self._main_json(["--url", "http://example.com/"])
        self.assertFalse(rep["robots"]["search_crawlers"]["OAI-SearchBot"]["allowed"])

        # 2. Exact cap premature EOF raises FetchError
        self._net([_http(headers={"Content-Length": str(cl.MAX_FETCH_BYTES + 10)}, body=b"x" * cl.MAX_FETCH_BYTES)])
        with self.assertRaises(cl.FetchError):
            cl.fetch_text("http://example.com/")

        # 3. Repeated chunked TE and conflicting Content-Length rejected
        self._net([_http(headers={"Transfer-Encoding": "chunked, chunked"}, body=b"0\r\n\r\n")])
        with self.assertRaises(cl.FetchError):
            cl.fetch_text("http://example.com/")
        self._net([b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 20\r\nConnection: close\r\n\r\nUser-agent: *\n"])
        with self.assertRaises(cl.FetchError):
            cl.fetch_text("http://example.com/")
        self._net([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked \r\nConnection: close\r\n\r\n0\r\n\r\n"])
        with self.assertRaises(cl.FetchError):
            cl.fetch_text("http://example.com/robots.txt")
        self._net([b"HTTP/1.1 200 OK\r\nContent-Length: 20, 20\r\nConnection: close\r\n\r\nUser-agent: *\n"])
        with self.assertRaises(cl.FetchError):
            cl.fetch_text("http://example.com/robots.txt")

    def test_hidden_textarea_second_summary_and_offline_utf16_bom(self):
        words = " ".join(f"word{i}" for i in range(160))
        h1 = f'<div id="root"></div><textarea style="display:none">{words}</textarea><script src="/a.js"></script>'
        self.assertEqual(cl.audit_html(h1)["visible_words"], 0)
        self.assertEqual(cl.audit_html(h1)["verdict"], "likely_csr_shell")
        h2 = f'<div id="root"></div><details><summary>Only first</summary><summary>{words}</summary></details><script src="/a.js"></script>'
        self.assertEqual(cl.audit_html(h2)["visible_words"], 2)
        self.assertEqual(cl.audit_html(h2)["verdict"], "likely_csr_shell")
        utf16_bytes = b"\xff\xfe" + '<div id="root"></div><script src="/a.js"></script>'.encode("utf-16-le")
        with tempfile.TemporaryDirectory() as td:
            hp = Path(td) / "bom.html"
            hp.write_bytes(utf16_bytes)
            out = io.StringIO()
            with redirect_stdout(out):
                code = cl.main(["--html-file", str(hp), "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["html"]["verdict"], "likely_csr_shell")


BENCH_DIR = ROOT / "benchmarks"
BENCH_RESULT_KEYS = {
    "slug", "name", "url", "final_url", "ok", "error", "http_status", "robots_source", "robots_policy",
    "oai_searchbot", "claude_searchbot", "perplexitybot", "gptbot", "claudebot", "crawler_groups",
    "robots_notes", "llms_source", "llms_http_status", "llms_valid", "llms_sections", "llms_total_links",
    "visible_words", "script_tags", "external_scripts", "data_script_tags", "inline_script_byte_ratio",
    "empty_mount_nodes", "html_verdict", "title",
}
BENCH_CSV_FIELDS = [
    "slug", "name", "url", "final_url", "ok", "http_status", "robots_policy", "oai_searchbot",
    "claude_searchbot", "perplexitybot", "gptbot", "claudebot", "llms_http_status", "llms_valid",
    "llms_sections", "llms_total_links", "visible_words", "script_tags", "external_scripts",
    "data_script_tags", "inline_script_byte_ratio", "empty_mount_nodes", "html_verdict", "error",
]
BENCH_SUMMARY_KEYS = {
    "total_targets", "completed_requests", "transport_errors", "http_2xx_pages", "html_parsed_pages",
    "all_search_crawlers_allowed", "any_training_crawler_blocked", "split_search_allow_training_block",
    "llms_txt_http_2xx", "llms_txt_strictly_valid", "server_rendered_2xx", "thin_or_csr_2xx",
}


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location(
        "run_public_docs_benchmark_offline", BENCH_DIR / "run_public_docs_benchmark.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeProxyResponse:
    """Minimal http.client.HTTPResponse-like double used by the --use-system-proxy tests.

    read1() mirrors http.client: `length` counts down the bytes still owed by
    Content-Length and the response closes at EOF or when `length` reaches 0.
    `headers` may be a dict or a list of (name, value) pairs (repeated headers).
    """

    def __init__(self, status=200, body=b"", headers=None, length=None, chunked=False):
        self.status = status
        self.headers = email.message.Message()
        pairs = headers.items() if isinstance(headers, dict) else (headers or [])
        for key, value in pairs:
            self.headers[key] = value
        self._buf = io.BytesIO(body)
        self.length = length
        self.chunked = chunked
        self._closed = False

    def read1(self, n=-1):
        if self._closed:
            return b""
        if self.length is not None and (n < 0 or n > self.length):
            n = self.length
        data = self._buf.read(n)
        if not data and n:
            self._closed = True
        elif self.length is not None:
            self.length -= len(data)
            if not self.length:
                self._closed = True
        return data

    read = read1

    def isclosed(self):
        return self._closed

    def close(self):
        self._closed = True


class _BytesSocket:
    """Socket double whose makefile() serves canned bytes (for real http.client parsing)."""

    def __init__(self, data: bytes):
        self._data = data

    def makefile(self, *_a, **_k):
        return io.BytesIO(self._data)


def _parsed_response(raw: bytes):
    """A real http.client.HTTPResponse parsed from canned bytes (no network)."""
    resp = http.client.HTTPResponse(_BytesSocket(raw), method="GET")
    resp.begin()
    return resp


class _ProxyTunnelSocket(FakeSocket):
    """Proxy TCP socket double: records CONNECT bytes and replays a canned CONNECT reply via recv()."""

    def __init__(self, connect_reply: bytes, response: bytes = b""):
        super().__init__(response)
        self._reply = io.BytesIO(connect_reply)
        self.shut = threading.Event()
        self.connected_to = None

    def connect(self, sockaddr):
        self.connected_to = sockaddr

    def recv(self, n):
        return self._reply.read(n)

    def shutdown(self, _how):
        self.shut.set()


class _StallingProxySocket(_ProxyTunnelSocket):
    """Proxy socket that never answers CONNECT until the watchdog shuts it down."""

    def __init__(self):
        super().__init__(b"")

    def recv(self, n):
        self.shut.wait(5)
        return b""


def _csv_cell(value):
    """Render a JSON value the way csv.DictWriter writes it."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ";".join(value)
    return str(value)


class BenchmarkDatasetTests(NoNetworkTestCase):
    """Offline checks for benchmarks/: dataset parity, summary math and the proxy SSRF guard."""

    @classmethod
    def setUpClass(cls):
        cls.bench = _load_benchmark_module()
        cls.payload = json.loads((BENCH_DIR / "public_docs_geo_2026.json").read_text(encoding="utf-8"))
        with (BENCH_DIR / "public_docs_geo_2026.csv").open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            cls.csv_header = list(reader.fieldnames or [])
            cls.csv_rows = list(reader)

    def test_json_has_twelve_complete_results_in_target_order(self):
        results = self.payload["results"]
        self.assertEqual(self.payload["benchmark"], "public_docs_geo_2026")
        self.assertEqual(self.payload["tool"], "cleanparse-geo-tools")
        self.assertRegex(self.payload["observed_at_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(len(results), 12)
        self.assertEqual(len(self.bench.TARGETS), 12)
        for (slug, name, url), row in zip(self.bench.TARGETS, results):
            self.assertEqual(set(row), BENCH_RESULT_KEYS, slug)
            self.assertEqual((row["slug"], row["name"], row["url"]), (slug, name, url))
            self.assertEqual(set(row["crawler_groups"]), {"OAI-SearchBot", "Claude-SearchBot", "PerplexityBot", "GPTBot", "ClaudeBot"})
        self.assertEqual(len({r["slug"] for r in results}), 12)

    def test_summary_matches_per_site_rows(self):
        summary = self.payload["summary"]
        self.assertEqual(set(summary), BENCH_SUMMARY_KEYS)
        self.assertEqual(self.bench._summarize(self.payload["results"]), summary)
        self.assertEqual(summary["total_targets"], 12)
        self.assertEqual(summary["completed_requests"] + summary["transport_errors"], 12)

    def test_csv_matches_json_row_for_row(self):
        self.assertEqual(self.csv_header, BENCH_CSV_FIELDS)
        self.assertEqual(len(self.csv_rows), 12)
        for row, rec in zip(self.csv_rows, self.payload["results"]):
            for key in BENCH_CSV_FIELDS:
                self.assertEqual(row[key], _csv_cell(rec[key]), f"{rec['slug']}.{key}")

    def test_write_csv_reproduces_committed_rows(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "regen.csv"
            self.bench._write_csv(out, self.payload["results"])
            with out.open(encoding="utf-8", newline="") as fh:
                regen = list(csv.DictReader(fh))
        self.assertEqual(regen, self.csv_rows)

    def test_summarize_counts_synthetic_edge_cases(self):
        base = dict(self.payload["results"][0])
        blocked = dict(base, slug="blocked", gptbot=False, robots_policy="search_allowed_training_blocked")
        csr = dict(base, slug="csr", html_verdict="likely_csr_shell", llms_http_status=404, llms_valid=False)
        no_llms_valid = dict(base, slug="lint", llms_valid=False)
        forbidden = dict(base, slug="forbidden", http_status=403, html_verdict="fetch_failed")
        error = dict(base, slug="error", ok=False, http_status=None, oai_searchbot=None)
        s = self.bench._summarize([base, blocked, csr, no_llms_valid, forbidden, error])
        self.assertEqual(s["total_targets"], 6)
        self.assertEqual(s["completed_requests"], 5)
        self.assertEqual(s["transport_errors"], 1)
        self.assertEqual(s["http_2xx_pages"], 4)
        self.assertEqual(s["html_parsed_pages"], 4)
        self.assertEqual(s["all_search_crawlers_allowed"], 5)
        self.assertEqual(s["any_training_crawler_blocked"], 1)
        self.assertEqual(s["split_search_allow_training_block"], 1)
        self.assertEqual(s["llms_txt_http_2xx"], 4)
        self.assertEqual(s["llms_txt_strictly_valid"], 3)
        self.assertEqual(s["server_rendered_2xx"], 3)
        self.assertEqual(s["thin_or_csr_2xx"], 1)

    PROXIES = {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}

    @staticmethod
    def _must_not_open():
        return mock.MagicMock(side_effect=AssertionError("proxy connection must not be opened"))

    def _proxy_env(self, proxies=None, bypass=False):
        """Patch the OS proxy map and bypass list (returns a context manager stack)."""
        active = self.PROXIES if proxies is None else proxies
        stack = ExitStack()
        stack.enter_context(
            mock.patch.multiple(
                urllib.request,
                getproxies=mock.MagicMock(return_value=active),
                getproxies_environment=mock.MagicMock(return_value=active),
                proxy_bypass=mock.MagicMock(return_value=bypass),
            )
        )
        stack.enter_context(mock.patch.object(self.bench, "_read_winreg_proxy_override", return_value=None))
        return stack

    def test_fetch_via_proxy_rejects_unsafe_urls_without_opening_connections(self):
        opener = self._must_not_open()
        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", opener):
            for bad in ("http://127.0.0.1/", "file:///etc/passwd", "http://user:pass@example.com/"):
                with self.subTest(url=bad):
                    with self.assertRaises(self.bench.clr.UnsafeURLError):
                        self.bench._fetch_via_proxy(bad)
                    with self.assertRaises(self.bench.clr.UnsafeURLError):
                        self.bench._run_via_proxy(bad)
        opener.assert_not_called()

    def test_canonical_request_rejects_backslash_and_bad_ascii_labels(self):
        unsafe = self.bench.clr.UnsafeURLError
        opener = self._must_not_open()
        bad_urls = (
            "https://exa\\mple.com/",
            "https://example.com\\.evil.org/",
            "https://exa!mple.com/",
            "https://exa$mple.com/",
            "https://exa*mple.com/",
            "https://exa%6dple.com/",
            "https://exa\tmple.com/",
        )
        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", opener):
            for bad in bad_urls:
                with self.subTest(url=bad):
                    with self.assertRaises(unsafe):
                        self.bench._canonical_request(bad)
                    with self.assertRaises(unsafe):
                        self.bench._fetch_via_proxy(bad)
        opener.assert_not_called()
        self.assertEqual(
            self.bench._canonical_request("https://EXAMPLE.com:443/catalog?#frag")[1:],
            ("https://example.com/catalog?", "https", "example.com", 443, "/catalog?"),
        )
        self.assertEqual(
            self.bench._canonical_request("https://bücher.example/a b")[1:4],
            ("https://xn--bcher-kva.example/a%20b", "https", "xn--bcher-kva.example"),
        )

    def test_proxy_hostport_requires_explicit_http_proxy_url(self):
        hp = self.bench._proxy_hostport
        unsafe = self.bench.clr.UnsafeURLError
        self.assertEqual(hp("http://127.0.0.1:7890"), ("127.0.0.1", 7890))
        self.assertEqual(hp("http://[::1]:7890/"), ("::1", 7890))
        self.assertEqual(hp("http://proxy.example:3128"), ("proxy.example", 3128))
        for bad in (None, "", "socks5://127.0.0.1:1080", "socks://127.0.0.1:1080", "https://127.0.0.1:7890",
                    "127.0.0.1:7890", "http://127.0.0.1", "http://user:pw@127.0.0.1:7890",
                    "http://127.0.0.1:7890/path", "http://[127.0.0.1]:7890", "http://127.0.0.1:0"):
            with self.subTest(proxy=bad):
                with self.assertRaises(unsafe):
                    hp(bad)
        for proxies, expected in (({}, False), ({"https": "socks5://127.0.0.1:1080"}, False),
                                  ({"https": "https://127.0.0.1:7890"}, False),
                                  ({"http": "http://127.0.0.1:7890"}, False),
                                  ({"https": "http://127.0.0.1:7890"}, True), (self.PROXIES, True)):
            with self.subTest(proxies=proxies), self._proxy_env(proxies):
                self.assertIs(self.bench._has_proxy_for_targets(), expected)
        with self._proxy_env({"http": "http://127.0.0.1:7890"}):
            self.assertTrue(self.bench._has_proxy_for_targets((("p", "P", "http://example.com/"),)))
            self.assertFalse(self.bench._has_proxy_for_targets((("p", "P", "http://example.com/"),
                                                                ("s", "S", "https://example.com/"))))

    def test_ensure_proxy_route_rejects_missing_invalid_or_bypassed_proxy(self):
        route = self.bench._ensure_proxy_route
        unsafe = self.bench.clr.UnsafeURLError
        for proxies in ({}, {"https": "socks5://127.0.0.1:1080"}, {"https": "https://127.0.0.1:7890"},
                        {"https": "http://127.0.0.1"}, {"https": ""}, {"http": "http://127.0.0.1:7890"}):
            with self.subTest(proxies=proxies), self._proxy_env(proxies):
                with self.assertRaises(unsafe) as ctx:
                    route("https", "example.com", 443)
                self.assertIn("No active HTTP/HTTPS proxy", str(ctx.exception))
        with self._proxy_env(bypass=True):
            with self.assertRaises(unsafe):
                route("https", "example.com", 443)
        with self._proxy_env():
            self.assertEqual(route("https", "example.com", 443), self.PROXIES["https"])
            self.assertEqual([c.args[0] for c in urllib.request.proxy_bypass.call_args_list],
                             ["example.com", "example.com:443"])

    def test_ensure_proxy_route_honours_port_specific_no_proxy(self):
        route = self.bench._ensure_proxy_route
        unsafe = self.bench.clr.UnsafeURLError
        opener = self._must_not_open()
        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", opener):
            urllib.request.proxy_bypass.side_effect = lambda host: host == "example.com:8443"
            with self.assertRaises(unsafe):
                route("https", "example.com", 8443)
            with self.assertRaises(unsafe):
                self.bench._fetch_via_proxy("https://example.com:8443/docs")
            self.assertEqual(route("https", "example.com", 443), self.PROXIES["https"])
            seen = [c.args[0] for c in urllib.request.proxy_bypass.call_args_list]
        self.assertIn("example.com:8443", seen)
        opener.assert_not_called()

    def test_fetch_via_proxy_never_opens_without_proxy_route(self):
        opener = self._must_not_open()
        with self._proxy_env({}), mock.patch.object(self.bench, "_open_proxy_connection", opener):
            with self.assertRaises(self.bench.clr.UnsafeURLError):
                self.bench._fetch_via_proxy("https://example.com/")
            row = self.bench.audit_target("x", "X", "https://example.com/", use_system_proxy=True)
        opener.assert_not_called()
        self.assertFalse(row["ok"])
        self.assertIn("No active HTTP/HTTPS proxy", row["error"])

    def test_fetch_via_proxy_sends_canonical_requests_only_through_proxy(self):
        ok = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
        opened = []

        def fake_open(scheme, host, port, proxy_url, remaining_fn, watchdog):
            self.assertEqual(proxy_url, self.PROXIES[scheme])
            self.assertTrue(0 < remaining_fn() <= self.bench.PROXY_FETCH_DEADLINE)
            self.assertIsInstance(watchdog, self.bench.clr._Watchdog)
            sock = FakeSocket(ok)
            opened.append((scheme, host, port, sock))
            return sock

        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", side_effect=fake_open):
            det = self.bench._fetch_via_proxy("https://EXAMPLE.com:443/catalog?#frag")
            self.bench._fetch_via_proxy("https://bücher.example/a b")
            self.bench._fetch_via_proxy("http://example.com:8080/x?q=1")
        self.assertEqual((det["status"], det["text"], det["content_type"]), (200, "ok", "text/plain"))
        self.assertEqual([o[:3] for o in opened], [("https", "example.com", 443),
                                                   ("https", "xn--bcher-kva.example", 443),
                                                   ("http", "example.com", 8080)])
        tls_get, idn_get, plain_get = (o[3].sent for o in opened)
        # Origin-form target inside the CONNECT tunnel, absolute-form for plain http via the proxy.
        self.assertTrue(tls_get.startswith(b"GET /catalog? HTTP/1.1\r\n"))
        self.assertIn(b"\r\nHost: example.com\r\n", tls_get)
        self.assertIn(b"\r\nUser-Agent: " + self.bench.clr.USER_AGENT.encode("ascii") + b"\r\n", tls_get)
        self.assertIn(b"\r\nAccept: */*\r\n", tls_get)
        self.assertIn(b"\r\nAccept-Encoding: gzip, deflate, identity\r\n", tls_get)
        self.assertIn(b"\r\nConnection: close\r\n", tls_get)
        self.assertTrue(idn_get.startswith(b"GET /a%20b HTTP/1.1\r\n"))
        self.assertIn(b"\r\nHost: xn--bcher-kva.example\r\n", idn_get)
        self.assertTrue(plain_get.startswith(b"GET http://example.com:8080/x?q=1 HTTP/1.1\r\n"))
        self.assertIn(b"\r\nHost: example.com:8080\r\n", plain_get)
        self.assertTrue(all(o[3].closed for o in opened))

    def test_fetch_via_proxy_validates_every_redirect_hop(self):
        first = FakeSocket(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 0\r\n\r\n")
        opened = []

        def fake_open(scheme, host, port, *_rest):
            opened.append((scheme, host, port))
            return first

        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", side_effect=fake_open):
            with self.assertRaises(self.bench.clr.UnsafeURLError):
                self.bench._fetch_via_proxy("https://example.com/start")
        self.assertEqual(opened, [("https", "example.com", 443)])
        self.assertTrue(first.sent.startswith(b"GET /start HTTP/1.1\r\n"))

    def test_fetch_via_proxy_expired_deadline_never_opens(self):
        opener = self._must_not_open()
        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", opener):
            with self.assertRaises(TimeoutError):
                self.bench._fetch_via_proxy("https://example.com/", deadline=self.bench.clr._now() - 1)
        opener.assert_not_called()

    def test_open_proxy_connection_connect_tunnel_tls_and_plain_http(self):
        clr = self.bench.clr
        dog = clr._Watchdog(30)
        dog.start()
        self.addCleanup(dog.cancel)
        proxy = self.PROXIES["https"]

        raw = _ProxyTunnelSocket(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n")
        tls = mock.MagicMock()
        ctx = mock.MagicMock()
        ctx.wrap_socket.return_value = tls
        make_socket = mock.MagicMock(return_value=raw)
        with mock.patch.object(socket, "socket", make_socket), \
                mock.patch.object(self.bench.ssl, "create_default_context", return_value=ctx):
            out = self.bench._open_proxy_connection("https", "example.com", 8443, proxy, lambda: 5.0, dog)
        self.assertIs(out, tls)
        make_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.assertEqual(raw.connected_to, ("127.0.0.1", 7890))
        self.assertEqual(raw.timeouts[0], 5.0)
        self.assertEqual(raw.sent, b"CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n")
        ctx.wrap_socket.assert_called_once_with(raw, server_hostname="example.com", do_handshake_on_connect=False)
        tls.settimeout.assert_called_with(5.0)
        tls.do_handshake.assert_called_once_with()

        denied = _ProxyTunnelSocket(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
        no_tls = mock.MagicMock(side_effect=AssertionError("TLS must not start after a failed CONNECT"))
        with mock.patch.object(socket, "socket", return_value=denied), \
                mock.patch.object(self.bench.ssl, "create_default_context", no_tls):
            with self.assertRaises(clr.FetchError):
                self.bench._open_proxy_connection("https", "2606:4700::1111", 443, proxy, lambda: 5.0, dog)
        self.assertEqual(denied.sent,
                         b"CONNECT [2606:4700::1111]:443 HTTP/1.1\r\nHost: [2606:4700::1111]:443\r\n\r\n")
        self.assertTrue(denied.closed)

        plain = _ProxyTunnelSocket(b"")
        with mock.patch.object(socket, "socket", return_value=plain):
            self.assertIs(self.bench._open_proxy_connection("http", "example.com", 80, proxy, lambda: 5.0, dog), plain)
        self.assertEqual(plain.sent, b"")

        with self.assertRaises(clr.UnsafeURLError):  # never reaches DNS / socket creation
            self.bench._open_proxy_connection("https", "example.com", 443, "socks5://127.0.0.1:1080", lambda: 5.0, dog)

    def test_open_proxy_connection_bounds_proxy_dns_and_tries_every_address(self):
        clr = self.bench.clr
        dog = clr._Watchdog(30)
        dog.start()
        self.addCleanup(dog.cancel)
        infos = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::7", 3128, 0, 0)),
                 (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.7", 3128))]
        refused = _ProxyTunnelSocket(b"")
        refused.connect = mock.MagicMock(side_effect=ConnectionRefusedError("refused"))
        good = _ProxyTunnelSocket(b"")
        attached = []
        real_attach = dog.attach
        resolve = mock.MagicMock(return_value=infos)
        with mock.patch.object(clr, "_resolve_host", resolve), \
                mock.patch.object(socket, "socket", side_effect=[refused, good]) as make_socket, \
                mock.patch.object(dog, "attach", side_effect=lambda s: (attached.append(s), real_attach(s))):
            out = self.bench._open_proxy_connection("http", "example.com", 80, "http://proxy.example:3128",
                                                    lambda: 4.0, dog)
        self.assertIs(out, good)
        resolve.assert_called_once_with("proxy.example", 3128, 4.0)
        self.assertEqual([c.args for c in make_socket.call_args_list],
                         [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP),
                          (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)])
        self.assertEqual(attached[:2], [refused, good], "each attempt is attached BEFORE connect()")
        self.assertTrue(refused.closed)
        self.assertEqual(good.connected_to, ("192.0.2.7", 3128))

        last = _ProxyTunnelSocket(b"")
        last.connect = mock.MagicMock(side_effect=ConnectionRefusedError("refused"))
        with mock.patch.object(clr, "_resolve_host", return_value=infos[1:]), \
                mock.patch.object(socket, "socket", return_value=last):
            with self.assertRaises(ConnectionRefusedError):
                self.bench._open_proxy_connection("http", "example.com", 80, "http://proxy.example:3128",
                                                  lambda: 4.0, dog)
        self.assertTrue(last.closed)

        slow_dns = mock.MagicMock(side_effect=TimeoutError("DNS lookup for proxy.example exceeded 0.1s."))
        with mock.patch.object(clr, "_resolve_host", slow_dns), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("no socket after DNS timeout")):
            with self.assertRaises(TimeoutError):
                self.bench._open_proxy_connection("http", "example.com", 80, "http://proxy.example:3128",
                                                  lambda: 0.1, dog)

    def test_watchdog_deadline_aborts_stalled_connect_tunnel(self):
        clr = self.bench.clr
        stalled = _StallingProxySocket()
        self.addCleanup(stalled.shut.set)
        dog = clr._Watchdog(0.2)
        with mock.patch.object(socket, "socket", return_value=stalled):
            dog.start()
            t0 = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):
                    # remaining_fn alone would allow 30 s: only the watchdog can end this early.
                    self.bench._open_proxy_connection("https", "example.com", 443, self.PROXIES["https"],
                                                      lambda: 30.0, dog)
            finally:
                dog.cancel()
        self.assertLess(time.monotonic() - t0, 4)
        self.assertTrue(dog.fired.is_set())
        self.assertTrue(stalled.shut.is_set(), "watchdog must shut the proxy socket down")
        self.assertTrue(stalled.closed)

    def test_watchdog_deadline_aborts_stalled_response_headers(self):
        stalled = StallingSocket()
        self.addCleanup(stalled.released.set)
        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", return_value=stalled):
            t0 = time.monotonic()
            with self.assertRaises(TimeoutError):
                self.bench._fetch_via_proxy("https://example.com/", deadline=self.bench.clr._now() + 0.3)
        self.assertLess(time.monotonic() - t0, 4)
        self.assertTrue(stalled.released.is_set(), "watchdog must shut the stalled socket down")
        self.assertTrue(stalled.sent.startswith(b"GET / HTTP/1.1\r\n"))

    def test_read_bounded_response_rejects_te_with_content_length_and_multiple_te(self):
        fetch_error = self.bench.clr.FetchError
        read = self.bench._read_bounded_response
        url = "https://example.com/"
        both = _parsed_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
                                b"5\r\nhello\r\n0\r\n\r\n")
        with self.assertRaises(fetch_error) as ctx:
            read(both, url, False)
        self.assertIn("both Transfer-Encoding and Content-Length", str(ctx.exception))
        fake_both = _FakeProxyResponse(200, b"hello", [("Transfer-Encoding", "identity"), ("Content-Length", "5")],
                                       length=5)
        with self.assertRaises(fetch_error):
            read(fake_both, url, False)
        dup = _parsed_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
                               b"5\r\nhello\r\n0\r\n\r\n")
        with self.assertRaises(fetch_error) as ctx:
            read(dup, url, False)
        self.assertIn("Ambiguous Transfer-Encoding", str(ctx.exception))
        layered = _parsed_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
                                   b"5\r\nhello\r\n0\r\n\r\n")
        with self.assertRaises(fetch_error):
            read(layered, url, False)
        ok = _parsed_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
                              b"5\r\nhello\r\n0\r\n\r\n")
        self.assertEqual(read(ok, url, False), (200, "hello", "text/plain"))

    def test_read_bounded_response_truncated_chunked_and_short_content_length(self):
        fetch_error = self.bench.clr.FetchError
        read = self.bench._read_bounded_response
        url = "https://example.com/"
        for raw in (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nhel"):
            with self.subTest(raw=raw):
                with self.assertRaises(fetch_error) as ctx:
                    read(_parsed_response(raw), url, False)
                self.assertIn("truncated chunked body", str(ctx.exception))
        with self.assertRaises(fetch_error) as ctx:
            read(_parsed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nabc"), url, False)
        self.assertIn("Incomplete HTTP response body", str(ctx.exception))
        exact = _parsed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!")
        self.assertEqual(read(exact, url, False)[:2], (200, "hello world!"))

    def test_read_bounded_response_truncated_content_length_raises(self):
        resp = _FakeProxyResponse(200, b"abc", {"Content-Type": "text/html", "Content-Length": "12"}, length=12)
        with self.assertRaises(self.bench.clr.FetchError) as ctx:
            self.bench._read_bounded_response(resp, "https://example.com/", False)
        self.assertIn("Incomplete HTTP response body", str(ctx.exception))
        full = _FakeProxyResponse(200, b"hello world!", {"Content-Length": "12"}, length=12)
        status, text, _mt = self.bench._read_bounded_response(full, "https://example.com/", False)
        self.assertEqual((status, text), (200, "hello world!"))
        unenforced = _FakeProxyResponse(200, b"abc", {"Content-Length": "12"}, length=None)
        with self.assertRaises(self.bench.clr.FetchError):
            self.bench._read_bounded_response(unenforced, "https://example.com/", False)
        bad_te = _FakeProxyResponse(200, b"abc", {"Transfer-Encoding": "gzip, chunked"})
        with self.assertRaises(self.bench.clr.FetchError):
            self.bench._read_bounded_response(bad_te, "https://example.com/", False)
        expired = _FakeProxyResponse(200, b"abc", {})
        with self.assertRaises(TimeoutError):
            self.bench._read_bounded_response(expired, "https://example.com/", False,
                                              deadline=self.bench.clr._now() - 1)

    def _fake_fetch(self, table, calls):
        def fake(url, force_utf8=False, deadline=None):
            calls.append(url)
            value = table[url]
            if isinstance(value, BaseException):
                raise value
            status, text, visited, ctype = value
            return {"status": status, "text": text, "visited": list(visited or [url]), "content_type": ctype}
        return fake

    def test_llms_204_and_page_206_status_preserved(self):
        page = "https://example.com/docs"
        table = {
            page: (206, "<p>partial</p>", None, "text/html"),
            "https://example.com/robots.txt": (200, "User-agent: *\nAllow: /\n", None, "text/plain"),
            "https://example.com/llms.txt": (204, "", None, None),
        }
        calls = []
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, calls)):
            row = self.bench.audit_target("p", "Partial", page, use_system_proxy=True)
        self.assertTrue(row["ok"])
        self.assertEqual(row["error"], "")
        self.assertEqual(row["http_status"], 206)
        self.assertEqual(row["html_verdict"], "fetch_failed")
        self.assertEqual(row["llms_http_status"], 204)
        self.assertFalse(row["llms_valid"])
        s = self.bench._summarize([row])
        self.assertEqual(s["http_2xx_pages"], 1)
        self.assertEqual(s["html_parsed_pages"], 0)
        self.assertEqual(s["server_rendered_2xx"], 0)

    def test_llms_200_records_http_status(self):
        page = "https://example.com/"
        llms = "# Example\n\n> Summary.\n\n## Docs\n\n- [Guide](https://example.com/guide): Guide.\n"
        table = {
            page: (200, "<main>" + "word " * 200 + "</main>", None, "text/html"),
            "https://example.com/robots.txt": (404, "", None, None),
            "https://example.com/llms.txt": (200, llms, None, "text/plain"),
        }
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, [])):
            row = self.bench.audit_target("e", "Example", page, use_system_proxy=True)
        self.assertEqual(row["llms_http_status"], 200)
        self.assertEqual(row["html_verdict"], "server_rendered")
        self.assertEqual(self.bench._summarize([row])["html_parsed_pages"], 1)

    def test_secondary_robots_and_llms_errors_preserve_observed_status(self):
        page = "https://example.com/"
        table = {
            page: (500, "", None, "text/html"),
            "https://example.com/robots.txt": self.bench.clr.FetchError("robots boom"),
            "https://example.com/llms.txt": TimeoutError("llms slow"),
        }
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, [])):
            row = self.bench.audit_target("f", "ServerError", page, use_system_proxy=True)
        self.assertEqual(set(row), BENCH_RESULT_KEYS)
        self.assertTrue(row["ok"])
        self.assertEqual(row["http_status"], 500)
        self.assertEqual(row["html_verdict"], "fetch_failed")
        self.assertEqual(row["robots_policy"], "error")
        self.assertIsNone(row["oai_searchbot"])
        self.assertIsNone(row["llms_http_status"])
        self.assertIn("robots boom", row["error"])
        self.assertIn("llms slow", row["error"])
        s = self.bench._summarize([row])
        self.assertEqual((s["completed_requests"], s["http_2xx_pages"], s["all_search_crawlers_allowed"]), (1, 0, 0))

    def test_page_403_and_429_stop_immediately_without_auxiliary_fetches(self):
        page = "https://example.com/"
        for status in (403, 429):
            for mode, target in (("proxy", "_fetch_via_proxy"), ("direct", "_fetch_direct")):
                with self.subTest(status=status, mode=mode):
                    table = {
                        page: (status, "<html>blocked</html>", None, "text/html"),
                        "https://example.com/robots.txt": AssertionError("robots.txt must not be fetched"),
                        "https://example.com/llms.txt": AssertionError("llms.txt must not be fetched"),
                    }
                    calls = []
                    with mock.patch.object(self.bench, target, side_effect=self._fake_fetch(table, calls)):
                        row = self.bench.audit_target("b", "Blocked", page, use_system_proxy=(mode == "proxy"))
                    self.assertEqual(calls, [page])
                    self.assertEqual(set(row), BENCH_RESULT_KEYS)
                    self.assertTrue(row["ok"])
                    self.assertEqual(row["http_status"], status)
                    self.assertEqual(row["html_verdict"], "fetch_failed")
                    self.assertEqual(row["robots_policy"], "error")
                    self.assertEqual(row["robots_source"], "")
                    for bot in ("oai_searchbot", "claude_searchbot", "perplexitybot", "gptbot", "claudebot"):
                        self.assertIsNone(row[bot], bot)
                    self.assertIsNone(row["llms_http_status"])
                    self.assertFalse(row["llms_valid"])
                    self.assertEqual(row["llms_source"], "")
                    self.assertIn("auxiliary fetches skipped", row["error"])
                    self.assertIn(f"HTTP {status}", row["error"])
                    s = self.bench._summarize([row])
                    self.assertEqual((s["completed_requests"], s["http_2xx_pages"], s["all_search_crawlers_allowed"]), (1, 0, 0))
                    self.assertEqual(s["llms_txt_http_2xx"], 0)

    def test_page_403_after_redirect_still_stops_before_any_robots_fetch(self):
        page = "https://example.com/start"
        final = "https://www.example.com/blocked"
        table = {
            page: (403, "", [page, final], "text/html"),
            "https://example.com/robots.txt": AssertionError("robots.txt must not be fetched"),
            "https://www.example.com/robots.txt": AssertionError("robots.txt must not be fetched"),
            "https://example.com/llms.txt": AssertionError("llms.txt must not be fetched"),
        }
        calls = []
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, calls)):
            row = self.bench.audit_target("r", "Redirected", page, use_system_proxy=True)
        self.assertEqual(calls, [page])
        self.assertEqual(row["final_url"], final)
        self.assertEqual(row["robots_policy"], "error")
        self.assertIn("stop-on-block", row["error"])

    def test_robots_429_keeps_rfc9309_verdict_but_skips_llms_on_that_origin(self):
        page = "https://example.com/"
        table = {
            page: (200, "<main>" + "word " * 200 + "</main>", None, "text/html"),
            "https://example.com/robots.txt": (429, "", None, "text/plain"),
            "https://example.com/llms.txt": AssertionError("llms.txt must not be fetched after robots.txt 429"),
        }
        calls = []
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, calls)):
            row = self.bench.audit_target("t", "Throttled", page, use_system_proxy=True)
        self.assertEqual(calls, [page, "https://example.com/robots.txt"])
        self.assertEqual((row["http_status"], row["html_verdict"]), (200, "server_rendered"))
        # The existing RFC 9309 4xx semantics for robots.txt are unchanged (allow all).
        self.assertEqual(row["oai_searchbot"], True)
        self.assertNotEqual(row["robots_policy"], "error")
        self.assertIsNone(row["llms_http_status"])
        self.assertFalse(row["llms_valid"])
        self.assertEqual(row["llms_source"], "https://example.com/llms.txt")
        self.assertIn("robots.txt returned HTTP 429", row["error"])

    def test_robots_429_on_redirect_target_does_not_skip_llms_on_submitted_origin(self):
        page = "https://example.com/start"
        final = "https://docs.example.org/final"
        table = {
            page: (200, "<main>" + "word " * 200 + "</main>", [page, final], "text/html"),
            "https://example.com/robots.txt": (200, "User-agent: *\nAllow: /\n", None, "text/plain"),
            "https://docs.example.org/robots.txt": (429, "", None, "text/plain"),
            "https://example.com/llms.txt": (404, "", None, None),
        }
        calls = []
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, calls)):
            row = self.bench.audit_target("x", "X", page, use_system_proxy=True)
        self.assertIn("https://example.com/llms.txt", calls)
        self.assertEqual(row["llms_http_status"], 404)
        self.assertEqual(row["error"], "")

    def test_non_default_readme_proxy_command_keeps_targets_and_name(self):
        row = dict(self.payload["results"][0])
        payload = {
            "benchmark": "indie_and_ai_web_2026",
            "summary": self.bench._summarize([row]),
            "observed_at_utc": "2026-01-01T00:00:00Z",
            "tool_version": self.bench.clr.__version__,
            "results": [row],
        }
        text = self.bench._readme_text(payload)
        self.assertIn(
            "python3 -B benchmarks/run_public_docs_benchmark.py --use-system-proxy "
            "--targets-json benchmarks/targets_indie_and_ai_web_2026.json --benchmark-name indie_and_ai_web_2026",
            text,
        )
        self.assertNotIn("python3 -B benchmarks/run_public_docs_benchmark.py --use-system-proxy\n", text)
        self.assertIn("**Stop-on-block**", text)
        default_text = self.bench._readme_text(dict(payload, benchmark=self.bench.DEFAULT_BENCHMARK_NAME))
        self.assertIn("python3 -B benchmarks/run_public_docs_benchmark.py --use-system-proxy\n", default_text)
        self.assertNotIn("--targets-json", default_text)
        self.assertNotIn("**Stop-on-block**", default_text)

    def test_cross_origin_redirect_fetches_llms_from_submitted_origin_in_both_modes(self):
        page = "https://example.com/start"
        final = "https://docs.example.org/final"
        table = {
            page: (200, "<main>" + "word " * 200 + "</main>", [page, final], "text/html"),
            "https://example.com/robots.txt": (200, "User-agent: *\nAllow: /\n", None, "text/plain"),
            "https://docs.example.org/robots.txt": (200, "User-agent: *\nAllow: /\n", None, "text/plain"),
            "https://example.com/llms.txt": (404, "", None, None),
        }
        rows = {}
        for mode, target in (("proxy", "_fetch_via_proxy"), ("direct", "_fetch_direct")):
            calls = []
            with mock.patch.object(self.bench, target, side_effect=self._fake_fetch(table, calls)):
                rows[mode] = self.bench.audit_target("x", "X", page, use_system_proxy=(mode == "proxy"))
            with self.subTest(mode=mode):
                self.assertIn("https://example.com/llms.txt", calls)
                self.assertNotIn("https://docs.example.org/llms.txt", calls)
                self.assertIn("https://docs.example.org/robots.txt", calls)
        self.assertEqual(rows["proxy"], rows["direct"])
        self.assertEqual(rows["proxy"]["llms_source"], "https://example.com/llms.txt")
        self.assertEqual(rows["proxy"]["final_url"], final)
        self.assertEqual(rows["proxy"]["llms_http_status"], 404)

    def test_audit_target_reports_guard_rejection_as_error_row(self):
        opener = self._must_not_open()
        with self._proxy_env(), mock.patch.object(self.bench, "_open_proxy_connection", opener):
            row = self.bench.audit_target("loop", "Loopback", "http://127.0.0.1/", use_system_proxy=True)
        opener.assert_not_called()
        self.assertFalse(row["ok"])
        self.assertEqual(row["html_verdict"], "fetch_error")
        self.assertEqual(set(row), BENCH_RESULT_KEYS)
        self.assertTrue(row["error"])

    def test_page_204_is_no_content_counted_as_2xx_but_not_parsed(self):
        page = "https://example.com/empty"
        table = {
            page: (204, "", None, None),
            "https://example.com/robots.txt": (200, "User-agent: *\nAllow: /\n", None, "text/plain"),
            "https://example.com/llms.txt": (404, "", None, None),
        }
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, [])):
            row = self.bench.audit_target("n", "NoContent", page, use_system_proxy=True)
        self.assertEqual(set(row), BENCH_RESULT_KEYS)
        self.assertTrue(row["ok"])
        self.assertEqual(row["http_status"], 204)
        self.assertEqual(row["html_verdict"], "no_content")
        self.assertEqual((row["visible_words"], row["script_tags"], row["external_scripts"]), (0, 0, 0))
        self.assertEqual((row["data_script_tags"], row["inline_script_byte_ratio"]), (0, 0.0))
        self.assertEqual((row["empty_mount_nodes"], row["title"]), ([], ""))
        section = self.bench._html_no_content(page)
        self.assertEqual(section["verdict"], "no_content")
        self.assertEqual(section["http_status"], 204)
        self.assertEqual(section["advice"], "Page returned HTTP 204 No Content (no HTML body).")
        self.assertEqual(section["text_preview"], "")
        s = self.bench._summarize([row])
        self.assertEqual(s["http_2xx_pages"], 1)
        self.assertEqual(s["html_parsed_pages"], 0)
        self.assertEqual(s["server_rendered_2xx"], 0)
        self.assertEqual(s["thin_or_csr_2xx"], 0)

    def test_llms_failure_preserves_robots_policy_and_renders_err(self):
        page = "https://example.com/"
        robots = "User-agent: GPTBot\nDisallow: /\n\nUser-agent: ClaudeBot\nDisallow: /\n"
        table = {
            page: (200, "<main>" + "word " * 200 + "</main>", None, "text/html"),
            "https://example.com/robots.txt": (200, robots, None, "text/plain"),
            "https://example.com/llms.txt": self.bench.clr.FetchError("llms down"),
        }
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, [])):
            row = self.bench.audit_target("e", "Example", page, use_system_proxy=True)
        self.assertTrue(row["ok"])
        self.assertEqual(row["http_status"], 200)
        self.assertEqual(row["html_verdict"], "server_rendered")
        self.assertEqual(row["robots_policy"], "search_allowed_training_blocked")
        self.assertEqual((row["oai_searchbot"], row["gptbot"], row["claudebot"]), (True, False, False))
        self.assertIsNone(row["llms_http_status"])
        self.assertIn("llms down", row["error"])
        payload = {
            "summary": self.bench._summarize([row]),
            "observed_at_utc": "2026-01-01T00:00:00Z",
            "tool_version": self.bench.clr.__version__,
            "results": [row],
        }
        text = self.bench._readme_text(payload)
        self.assertNotIn("HTTP None", text)
        line = next(ln for ln in text.splitlines() if ln.startswith("| [Example]"))
        self.assertIn("| ERR |", line)
        self.assertIn("| BLOCK |", line)
        self.assertIn("**`robots.txt` fetch failure**", text)
        self.assertIn("**`/llms.txt` fetch failure**", text)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "README.md"
            self.bench._write_readme(out, payload)
            self.assertEqual(out.read_text(encoding="utf-8"), text)

    def test_robots_failure_preserves_llms_and_page_status(self):
        page = "https://example.com/"
        llms = "# Example\n\n> Summary.\n\n## Docs\n\n- [Guide](https://example.com/guide): Guide.\n"
        table = {
            page: (200, "<main>" + "word " * 200 + "</main>", None, "text/html"),
            "https://example.com/robots.txt": TimeoutError("robots slow"),
            "https://example.com/llms.txt": (200, llms, None, "text/plain"),
        }
        with mock.patch.object(self.bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, [])):
            row = self.bench.audit_target("r", "Robots", page, use_system_proxy=True)
        self.assertEqual((row["http_status"], row["html_verdict"]), (200, "server_rendered"))
        self.assertEqual(row["robots_policy"], "error")
        self.assertIsNone(row["oai_searchbot"])
        self.assertEqual((row["llms_http_status"], row["llms_valid"]), (200, True))
        self.assertIn("robots slow", row["error"])

    def test_normalize_robots_notes_for_missing_wildcard_group(self):
        bench = self.bench
        clr_note = "No AI-crawler-specific groups found; every bot falls back to the '*' group."
        new_note = "No matching robots.txt groups (no '*' wildcard group present); RFC 9309 defaults to allow all."
        self.assertEqual((bench._CLR_WILDCARD_NOTE, bench._NO_GROUP_NOTE), (clr_note, new_note))
        names = ("OAI-SearchBot", "Claude-SearchBot", "PerplexityBot", "GPTBot", "ClaudeBot")
        none_groups = {k: "(none)" for k in names}
        star_groups = {k: "*" for k in names}
        other = "robots.txt returned HTTP 404; RFC 9309 lets crawlers treat an unavailable (4xx) robots.txt as 'allow all'."
        self.assertEqual(bench._normalize_robots_notes([clr_note, other], none_groups), [new_note, other])
        self.assertEqual(bench._normalize_robots_notes([clr_note], star_groups), [clr_note])
        self.assertEqual(bench._normalize_robots_notes([clr_note], {}), [clr_note])
        # check_llms_and_robots.py itself still emits its original note.
        self.assertIn(clr_note, bench.clr.audit_robots("User-agent: Googlebot\nDisallow: /x\n")["notes"])
        page = "https://example.com/"
        table = {
            page: (200, "<main>" + "word " * 200 + "</main>", None, "text/html"),
            "https://example.com/robots.txt": (404, "", None, None),
            "https://example.com/llms.txt": (404, "", None, None),
        }
        with mock.patch.object(bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, [])):
            row = bench.audit_target("e", "Example", page, use_system_proxy=True)
        self.assertEqual(set(row["crawler_groups"].values()), {"(none)"})
        self.assertIn(new_note, row["robots_notes"])
        self.assertNotIn(clr_note, row["robots_notes"])
        none_slugs = []
        for rec in self.payload["results"]:
            if set(rec["crawler_groups"].values()) == {"(none)"}:
                none_slugs.append(rec["slug"])
                self.assertIn(new_note, rec["robots_notes"], rec["slug"])
                self.assertNotIn(clr_note, rec["robots_notes"], rec["slug"])
            else:
                self.assertNotIn(new_note, rec["robots_notes"], rec["slug"])
        self.assertEqual(none_slugs, ["nextjs", "vite", "docusaurus", "tailwindcss"])

    def test_committed_readme_matches_write_readme_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "README.md"
            self.bench._write_readme(out, self.payload)
            regen = out.read_bytes()
        self.assertEqual(regen, (BENCH_DIR / "README.md").read_bytes())
        self.assertNotIn(b"HTTP None", regen)

    def test_default_readme_ignores_robots_checked_and_stays_byte_identical(self):
        committed = (BENCH_DIR / "README.md").read_bytes()
        self.assertEqual(self.bench._readme_text(self.payload).encode("utf-8"), committed)
        # The default README keeps completed_requests as its crawler denominator even if robots_checked differs.
        skewed = dict(self.payload, summary=dict(self.payload["summary"], robots_checked=1))
        self.assertEqual(self.bench._readme_text(skewed).encode("utf-8"), committed)
        self.assertNotIn(b"robots.txt checked on", committed)

    def _crawler_bullets(self, text):
        prefixes = (
            "- **All 3 AI search crawlers allowed",
            "- **At least one AI training crawler blocked",
            "- **Split policy (allow search, block training)**",
        )
        lines = [ln for ln in text.splitlines() if ln.startswith(prefixes)]
        self.assertEqual(len(lines), 3, lines)
        return lines

    def test_non_default_readme_uses_robots_checked_denominator_for_crawler_bullets(self):
        summary = {
            "total_targets": 60, "completed_requests": 59, "transport_errors": 1,
            "robots_checked": 57, "robots_skipped_blocked": 2,
            "http_2xx_pages": 57, "html_parsed_pages": 57,
            "all_search_crawlers_allowed": 57, "any_training_crawler_blocked": 0,
            "split_search_allow_training_block": 0,
            "llms_txt_http_2xx": 46, "llms_txt_strictly_valid": 38,
            "server_rendered_2xx": 54, "thin_or_csr_2xx": 3,
        }
        payload = {
            "benchmark": "indie_and_ai_web_2026",
            "summary": summary,
            "observed_at_utc": "2026-01-01T00:00:00Z",
            "tool_version": self.bench.clr.__version__,
            "results": [],
        }
        text = self.bench._readme_text(payload)
        search, training, split = self._crawler_bullets(text)
        note = " (robots.txt checked on 57 of 59 completed requests; 2 hit stop-on-block or a robots.txt fetch error)"
        self.assertTrue(search.endswith(": 57 / 57" + note), search)
        self.assertTrue(training.endswith(": 0 / 57" + note), training)
        self.assertTrue(split.endswith(": 0 / 57" + note), split)
        for line in (search, training, split):
            self.assertIsNone(re.search(r": \d+ / 59\b", line), line)

        # Reproduce snippets point at the committed cohort file, which exists relative to the starter root.
        self.assertIn("--targets-json benchmarks/targets_indie_and_ai_web_2026.json --benchmark-name indie_and_ai_web_2026", text)
        self.assertNotIn("<targets.json>", text)
        self.assertTrue((BENCH_DIR.parent / "benchmarks" / "targets_indie_and_ai_web_2026.json").is_file())

        # No committed cohort file for this name: keep the placeholder instead of a non-existent path.
        other = self.bench._readme_text(dict(payload, benchmark="other_cohort_2026"))
        self.assertFalse((BENCH_DIR / "targets_other_cohort_2026.json").exists())
        self.assertIn("--targets-json <targets.json> --benchmark-name other_cohort_2026", other)
        self.assertNotIn("targets_other_cohort_2026.json", other)

        # Equal denominators need no note.
        full = self.bench._readme_text(dict(payload, summary=dict(summary, robots_checked=59)))
        self.assertTrue(self._crawler_bullets(full)[0].endswith(": 57 / 59"))
        self.assertNotIn("robots.txt checked on", full)

    def test_committed_indie_payload_derives_robots_checked_from_stop_on_block_rows(self):
        payload = json.loads((BENCH_DIR / "indie_and_ai_web_2026.json").read_text(encoding="utf-8"))
        self.assertNotIn("robots_checked", payload["summary"])
        blocked = [r for r in payload["results"] if r["ok"] and r["robots_policy"] == "error"]
        self.assertEqual(payload["summary"]["completed_requests"] - len(blocked), self.bench._robots_checked(payload))
        search = self._crawler_bullets(self.bench._readme_text(payload))[0]
        checked = self.bench._robots_checked(payload)
        self.assertIn(f": {payload['summary']['all_search_crawlers_allowed']} / {checked} (", search)
        self.assertLessEqual(payload["summary"]["all_search_crawlers_allowed"], checked)

    def test_use_system_proxy_preflight_exits_2_without_touching_files(self):
        bench = self.bench
        with tempfile.TemporaryDirectory() as td:
            paths = [Path(td) / name for name in ("snap.json", "snap.csv", "README.md")]
            for p in paths:
                p.write_text("sentinel\n", encoding="utf-8")
            argv = ["--use-system-proxy", "--json-out", str(paths[0]), "--csv-out", str(paths[1]),
                    "--readme-out", str(paths[2])]
            for proxies in ({}, {"https": "socks5://127.0.0.1:1080"}, {"http": "https://127.0.0.1:7890"}):
                audit = mock.MagicMock(side_effect=AssertionError("no target may run without a proxy"))
                err, out = io.StringIO(), io.StringIO()
                with self.subTest(proxies=proxies), self._proxy_env(proxies), \
                        mock.patch.object(bench, "audit_target", audit), \
                        redirect_stderr(err), redirect_stdout(out):
                    self.assertEqual(bench.main(argv), 2)
                    with self.assertRaises(bench.ProxyPreflightError):
                        bench.run_benchmark(json_out=paths[0], csv_out=paths[1], readme_out=paths[2],
                                            use_system_proxy=True)
                audit.assert_not_called()
                self.assertIn("--use-system-proxy requires an explicit OS HTTP proxy", err.getvalue())
                self.assertEqual(out.getvalue(), "")
                for p in paths:
                    self.assertEqual(p.read_text(encoding="utf-8"), "sentinel\n", p.name)
            base = dict(self.payload["results"][0])

            def fake_audit(slug, name, url, use_system_proxy=False):
                self.assertTrue(use_system_proxy)
                return dict(base, slug=slug, name=name, url=url, final_url=url)

            with self._proxy_env({}), mock.patch.object(bench, "audit_target", side_effect=fake_audit):
                payload = bench.run_benchmark(json_out=paths[0], csv_out=paths[1], readme_out=paths[2],
                                              use_system_proxy=True, require_proxy=False)
            self.assertEqual(payload["fetch_transport"], "system_proxy")
            self.assertEqual(json.loads(paths[0].read_text(encoding="utf-8"))["summary"]["total_targets"], 12)

    def test_preflight_requires_proxy_for_every_target_scheme(self):
        bench = self.bench
        self.assertEqual({urllib.parse.urlsplit(u).scheme for _, _, u in bench.TARGETS}, {"https"})
        with tempfile.TemporaryDirectory() as td:
            paths = [Path(td) / name for name in ("snap.json", "snap.csv", "README.md")]
            for p in paths:
                p.write_text("sentinel\n", encoding="utf-8")
            argv = ["--use-system-proxy", "--json-out", str(paths[0]), "--csv-out", str(paths[1]),
                    "--readme-out", str(paths[2])]
            audit = mock.MagicMock(side_effect=AssertionError("no target may run without an https proxy"))
            err, out = io.StringIO(), io.StringIO()
            with self._proxy_env({"http": "http://127.0.0.1:7890"}), \
                    mock.patch.object(bench, "audit_target", audit), \
                    redirect_stderr(err), redirect_stdout(out):
                self.assertFalse(bench._has_proxy_for_targets())
                self.assertEqual(bench.main(argv), 2)
                with self.assertRaises(bench.ProxyPreflightError):
                    bench.run_benchmark(json_out=paths[0], csv_out=paths[1], readme_out=paths[2],
                                        use_system_proxy=True)
            audit.assert_not_called()
            self.assertIn("--use-system-proxy requires an explicit OS HTTP proxy", err.getvalue())
            self.assertEqual(out.getvalue(), "")
            for p in paths:
                self.assertEqual(p.read_text(encoding="utf-8"), "sentinel\n", p.name)

    def test_ensure_proxy_route_honours_bracketed_ipv6_no_proxy(self):
        route = self.bench._ensure_proxy_route
        unsafe = self.bench.clr.UnsafeURLError
        with self._proxy_env():
            urllib.request.proxy_bypass.side_effect = lambda host: host == "[2001:db8::1]:443"
            with self.assertRaises(unsafe):
                route("https", "2001:db8::1", 443)
            seen = [c.args[0] for c in urllib.request.proxy_bypass.call_args_list]
            self.assertIn("[2001:db8::1]:443", seen)
            urllib.request.proxy_bypass.reset_mock()
            self.assertEqual(route("https", "example.com", 443), self.PROXIES["https"])
            self.assertNotIn("[example.com]:443", [c.args[0] for c in urllib.request.proxy_bypass.call_args_list])

    def test_strict_rfc1123_labels_reject_underscore_and_edge_hyphens(self):
        bench = self.bench
        unsafe = bench.clr.UnsafeURLError
        opener = self._must_not_open()
        with self._proxy_env(), mock.patch.object(bench, "_open_proxy_connection", opener):
            for bad in ("https://bad_host.example/", "https://-bad.example/", "https://bad-.example/"):
                with self.subTest(url=bad):
                    with self.assertRaises(unsafe):
                        bench._canonical_request(bad)
                    with self.assertRaises(unsafe):
                        bench._fetch_via_proxy(bad)
        opener.assert_not_called()
        for bad in ("http://bad_host.example:3128", "http://-bad.example:3128", "http://bad-.example:3128"):
            with self.subTest(proxy=bad):
                with self.assertRaises(unsafe):
                    bench._proxy_hostport(bad)
        self.assertEqual(bench._canonical_request("https://good-host.example/")[3], "good-host.example")
        self.assertEqual(bench._proxy_hostport("http://Proxy-1.Example:3128"), ("proxy-1.example", 3128))

    def test_framing_validated_before_redirect_and_error_handling(self):
        fetch_error = self.bench.clr.FetchError
        responses = {
            "404": b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
            "302": (b"HTTP/1.1 302 Found\r\nLocation: https://example.com/next\r\n"
                    b"Content-Length: 0\r\nContent-Length: 7\r\n\r\n"),
        }
        for label, raw in responses.items():
            opened = []

            def fake_open(scheme, host, port, *_rest, raw=raw):
                opened.append((scheme, host, port))
                return FakeSocket(raw)

            with self.subTest(status=label), self._proxy_env(), \
                    mock.patch.object(self.bench, "_open_proxy_connection", side_effect=fake_open):
                with self.assertRaises(fetch_error):
                    self.bench._fetch_via_proxy("https://example.com/robots.txt", force_utf8=True)
            self.assertEqual(opened, [("https", "example.com", 443)], "no redirect may be followed")
        both_404 = _FakeProxyResponse(404, b"", [("Transfer-Encoding", "chunked"), ("Content-Length", "5")],
                                      chunked=True)
        with self.assertRaises(fetch_error) as ctx:
            self.bench._read_bounded_response(both_404, "https://example.com/robots.txt", True)
        self.assertIn("both Transfer-Encoding and Content-Length", str(ctx.exception))
        plain_404 = _FakeProxyResponse(404, b"", {"Content-Type": "text/html"})
        self.assertEqual(self.bench._read_bounded_response(plain_404, "https://example.com/", False),
                         (404, "", "text/html"))

    def test_hop_none_note_normalized_per_hop_before_combine(self):
        bench = self.bench
        star = "User-agent: *\nAllow: /\n"
        none = "User-agent: Googlebot\nDisallow: /x\n"
        none_report = bench.clr._robots_report_for_status(200, none, "/final", "https://docs.example.org/robots.txt")
        self.assertIn(bench._CLR_WILDCARD_NOTE, none_report["notes"])
        fixed = bench._normalize_hop_robots_report(none_report)
        self.assertIn(bench._NO_GROUP_NOTE, fixed["notes"])
        self.assertNotIn(bench._CLR_WILDCARD_NOTE, fixed["notes"])
        self.assertIn(bench._CLR_WILDCARD_NOTE, none_report["notes"], "input report is not mutated")
        star_report = bench.clr._robots_report_for_status(200, star, "/start", "https://example.com/robots.txt")
        self.assertIs(bench._normalize_hop_robots_report(star_report), star_report)

        page, final = "https://example.com/start", "https://docs.example.org/final"
        for first_robots, second_robots in ((star, none), (none, star)):
            table = {
                page: (200, "<main>" + "word " * 200 + "</main>", [page, final], "text/html"),
                "https://example.com/robots.txt": (200, first_robots, None, "text/plain"),
                "https://docs.example.org/robots.txt": (200, second_robots, None, "text/plain"),
                "https://example.com/llms.txt": (404, "", None, None),
            }
            with self.subTest(hop1=first_robots), \
                    mock.patch.object(bench, "_fetch_via_proxy", side_effect=self._fake_fetch(table, [])):
                row = bench.audit_target("r", "Redirect", page, use_system_proxy=True)
                # The '*' hop keeps its accurate fallback note; the "(none)" hop gets the no-group note.
                self.assertIn(bench._CLR_WILDCARD_NOTE, row["robots_notes"])
                self.assertIn(bench._NO_GROUP_NOTE, row["robots_notes"])

    def test_canonical_request_rejects_bracketed_non_ipv6_and_double_trailing_dots(self):
        bench = self.bench
        for bad in (
            "https://[v1.example]/",
            "https://example.com../",
            "https://8.8.8.8./",
            "https://8.8.8.8\u3002/",
            "https://.example.com/",
        ):
            with self.subTest(bad=bad), self.assertRaises(bench.clr.UnsafeURLError):
                bench._canonical_request(bad)
        for good in ("https://[2606:4700::1111]/", "https://example.com./"):
            with self.subTest(good=good):
                cleaned, _req, _scheme, host, _port, _target = bench._canonical_request(good)
                self.assertEqual(cleaned, good)
                self.assertTrue(host)

    def test_ensure_proxy_route_honours_windows_registry_port_override(self):
        bench = self.bench
        override = (
            "localhost;example.com:8443;*.corp.example:8443;"
            "[2001:db8::1]:443;http=onlyhttp.example:443"
        )
        with (
            mock.patch.object(
                bench.urllib.request,
                "getproxies",
                return_value={"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"},
            ),
            mock.patch.object(bench.urllib.request, "getproxies_environment", return_value={}),
            mock.patch.object(bench.urllib.request, "proxy_bypass", return_value=False),
            mock.patch.object(bench, "_read_winreg_proxy_override", return_value=override),
        ):
            for scheme, host, port in (
                ("https", "example.com", 8443),
                ("https", "api.corp.example", 8443),
                ("https", "2001:db8::1", 443),
                ("http", "onlyhttp.example", 443),
            ):
                with self.subTest(blocked=(scheme, host, port)), self.assertRaises(bench.clr.UnsafeURLError):
                    bench._ensure_proxy_route(scheme, host, port)
            for scheme, host, port in (
                ("https", "example.com", 443),
                ("https", "2001:db8::1", 8443),
                ("https", "onlyhttp.example", 443),
            ):
                with self.subTest(allowed=(scheme, host, port)):
                    self.assertEqual(bench._ensure_proxy_route(scheme, host, port), "http://127.0.0.1:7897")


class IndieAiWebCohortTests(NoNetworkTestCase):
    """Offline checks for the 60-site cohort JSON, load_targets_json validation and run_benchmark(targets=...)."""

    COHORT = BENCH_DIR / "targets_indie_and_ai_web_2026.json"
    HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")

    @classmethod
    def setUpClass(cls):
        cls.bench = _load_benchmark_module()
        cls.payload = json.loads((BENCH_DIR / "public_docs_geo_2026.json").read_text(encoding="utf-8"))

    def test_cohort_json_has_sixty_unique_public_https_targets(self):
        raw = json.loads(self.COHORT.read_text(encoding="utf-8"))
        self.assertEqual(len(raw), 60)
        for item in raw:
            self.assertEqual(set(item), {"slug", "name", "url", "category"}, item)
        self.assertEqual(
            {item["category"] for item in raw},
            {"ai_dev", "indie_saas", "dev_infra", "framework_docs", "nocode_forms"},
        )
        targets = self.bench.load_targets_json(self.COHORT)
        self.assertEqual(len(targets), 60)
        self.assertEqual([t[0] for t in targets], [item["slug"] for item in raw])
        self.assertEqual(len({t[0] for t in targets}), 60)
        self.assertEqual(len({t[2] for t in targets}), 60)
        for slug, name, url in targets:
            parts = urllib.parse.urlsplit(url)
            self.assertEqual(parts.scheme, "https", slug)
            self.assertEqual(url, f"https://{parts.hostname}/", slug)
            self.assertIsNotNone(self.HOST_RE.fullmatch(parts.hostname), slug)
            self.assertNotIn(parts.hostname.rsplit(".", 1)[-1], {"local", "localhost", "test", "example", "invalid"}, slug)
            self.assertTrue(name.strip(), slug)

    def test_load_targets_json_rejects_non_canonical_or_private_urls(self):
        good = {"slug": "ok", "name": "OK", "url": "https://example-indie.dev/", "category": "indie_saas"}
        bad_urls = (
            "http://example-indie.dev/", "https://Example-Indie.dev/", "https://example-indie.dev:8443/",
            "https://example-indie.dev/docs", "https://user@example-indie.dev/", "https://127.0.0.1/",
            "https://[::1]/", "https://service.local/", "https://app.test/", "https://example.com/",
            "https://exa_mple.dev/",
        )
        for url in bad_urls:
            with self.subTest(url=url), tempfile.TemporaryDirectory() as td:
                p = Path(td) / "targets.json"
                p.write_text(json.dumps([dict(good, url=url)]), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.bench.load_targets_json(p)

    def test_load_targets_json_rejects_duplicates_and_bad_slugs(self):
        good = {"slug": "ok", "name": "OK", "url": "https://example-indie.dev/", "category": "indie_saas"}
        cases = (
            [good, dict(good, slug="other")],
            [good, dict(good)],
            [dict(good, slug="Bad Slug")],
            [dict(good, category="")],
        )
        for data in cases:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as td:
                p = Path(td) / "targets.json"
                p.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.bench.load_targets_json(p)

    def test_run_benchmark_runs_cohort_with_mocked_audit_and_writes_custom_names(self):
        bench = self.bench
        targets = bench.load_targets_json(self.COHORT)
        base = dict(self.payload["results"][0])

        def fake_audit(slug, name, url, use_system_proxy=False):
            return dict(base, slug=slug, name=name, url=url, final_url=url)

        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            with mock.patch.object(bench, "audit_target", side_effect=fake_audit) as audit:
                payload = bench.run_benchmark(
                    json_out=out / "c.json", csv_out=out / "c.csv", readme_out=out / "README_c.md",
                    targets=targets, benchmark_name="indie_and_ai_web_2026",
                )
            self.assertEqual([c.args[0] for c in audit.call_args_list], [t[0] for t in targets])
            self.assertEqual(payload["benchmark"], "indie_and_ai_web_2026")
            self.assertEqual(payload["summary"]["total_targets"], 60)
            written = json.loads((out / "c.json").read_text(encoding="utf-8"))
            self.assertEqual(written["summary"]["total_targets"], 60)
            readme = (out / "README_c.md").read_text(encoding="utf-8")
        self.assertIn("# 2026 Indie SaaS & AI Web Apps AI Search Visibility Benchmark", readme)
        self.assertIn("- **Targets tested**: 60 public indie SaaS", readme)
        self.assertIn("All 60 measured sites", readme)
        self.assertNotIn("11 measured sites", readme)
        self.assertNotIn("Live web page counterpart", readme)

    def test_run_benchmark_rejects_unsafe_benchmark_name_before_auditing(self):
        audit = mock.MagicMock(side_effect=AssertionError("no target may run for an unsafe name"))
        with mock.patch.object(self.bench, "audit_target", audit):
            for bad in ("../escape", "Upper", "", "a/b"):
                with self.subTest(name=bad), self.assertRaises(ValueError):
                    self.bench.run_benchmark(benchmark_name=bad, targets=self.bench.TARGETS[:1])
        audit.assert_not_called()

    def test_main_refuses_targets_json_that_would_overwrite_committed_dataset(self):
        err = io.StringIO()
        with mock.patch.object(self.bench, "audit_target", mock.MagicMock(side_effect=AssertionError)), \
                redirect_stderr(err):
            self.assertEqual(self.bench.main(["--targets-json", str(self.COHORT)]), 2)
        self.assertIn("never overwritten", err.getvalue())


if __name__ == "__main__":
    unittest.main()
