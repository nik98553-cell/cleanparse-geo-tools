"""Offline unit tests for scripts/check_llms_and_robots.py (no network access).

Only loopback socket.socketpair() connections are used for the real-socket tests;
socket.getaddrinfo / socket.create_connection are always patched.

Run:  python -B -m unittest discover -s tests -v
"""
import gzip
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
import urllib.parse
import zlib
from contextlib import redirect_stderr, redirect_stdout
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


if __name__ == "__main__":
    unittest.main()
