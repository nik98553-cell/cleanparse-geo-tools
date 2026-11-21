#!/usr/bin/env python3
"""Live empirical AI-search & static-HTML visibility benchmark across 12 public docs sites.

Imports overseas_v1/github_public_starter/scripts/check_llms_and_robots.py directly
(zero third-party packages, zero CAPTCHA/403 bypasses, strictly read-only HTTP GET).

Run:
    python -B overseas_v1/github_public_starter/benchmarks/run_public_docs_benchmark.py
    python -B overseas_v1/github_public_starter/benchmarks/run_public_docs_benchmark.py --use-system-proxy
"""
from __future__ import annotations

import argparse
import csv
import functools
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BENCH_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = BENCH_DIR.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_llms_and_robots as clr  # noqa: E402

TARGETS: tuple[tuple[str, str, str], ...] = (
    ("cleanparse", "CleanParse Studio", "https://cleanparse.com/"),
    ("nextjs", "Next.js Docs", "https://nextjs.org/docs"),
    ("react", "React Docs", "https://react.dev/learn"),
    ("astro", "Astro", "https://astro.build/"),
    ("vite", "Vite Guide", "https://vite.dev/guide/"),
    ("vue", "Vue.js Guide", "https://vuejs.org/guide/introduction.html"),
    ("svelte", "Svelte Docs", "https://svelte.dev/docs"),
    ("nuxt", "Nuxt Docs", "https://nuxt.com/docs"),
    ("docusaurus", "Docusaurus Docs", "https://docusaurus.io/docs"),
    ("tailwindcss", "Tailwind CSS Docs", "https://tailwindcss.com/docs"),
    ("python", "Python 3 Docs", "https://docs.python.org/3/"),
    ("mdn", "MDN Web Docs", "https://developer.mozilla.org/en-US/"),
)

# One monotonic deadline per fetched URL, shared by every redirect hop, the proxy TCP
# connect, the CONNECT tunnel, TLS, interim 1xx responses, headers and every body read.
PROXY_FETCH_DEADLINE = 15.0

# Upper bound on the proxy's CONNECT response (status line + headers).
MAX_CONNECT_RESPONSE_BYTES = 16 * 1024

_NO_PROXY_ROUTE_MSG = (
    "No active HTTP/HTTPS proxy for host in --use-system-proxy mode; "
    "run default direct pinned-IP mode instead."
)

_NO_PROXY_PREFLIGHT_MSG = (
    "--use-system-proxy requires an explicit OS HTTP proxy (http://host:port) for every URL scheme "
    "used by the benchmark targets (https), but at least one of them has none configured. "
    "No targets were run and no output files were modified."
)

# clr's note for a robots.txt without AI-crawler groups, and the accurate wording when
# there is not even a '*' group (every crawler group is "(none)").
_CLR_WILDCARD_NOTE = "No AI-crawler-specific groups found; every bot falls back to the '*' group."
_NO_GROUP_NOTE = "No matching robots.txt groups (no '*' wildcard group present); RFC 9309 defaults to allow all."

# RFC 3986 authority characters (unreserved / sub-delims / ':' / IP-literal brackets).
# '%' (pct-encoding), '@' (userinfo), '\\', '/' and every other ASCII character are rejected;
# non-ASCII characters are only accepted as IDN host names, converted once by clr._idna_host.
_AUTHORITY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:[]"
)

_CONNECT_STATUS_RE = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?\r\n")

# Strict RFC 1123 DNS label (lower-case ASCII): letters / digits / inner hyphens, 1-63 chars.
# Unlike clr._ASCII_LABEL_RE it rejects '_' and leading / trailing '-'.
_STRICT_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Transport/guard failures that turn a secondary fetch (robots.txt, /llms.txt) into an
# "error" section without discarding the already-observed page status.
_FETCH_ERRORS: tuple[type[BaseException], ...] = (
    clr.UnsafeURLError,
    ValueError,
    OSError,
    http.client.HTTPException,
    urllib.error.URLError,
    TimeoutError,
)


class ProxyPreflightError(RuntimeError):
    """--use-system-proxy was requested but no explicit OS HTTP proxy is configured."""


def _remaining(deadline: float, url: str) -> float:
    """Seconds left before the per-URL monotonic deadline; TimeoutError once it has passed."""
    left = deadline - clr._now()
    if left <= 0:
        raise TimeoutError(
            f"Fetch of {url[:200]} exceeded the {PROXY_FETCH_DEADLINE:g}s deadline (--use-system-proxy)."
        )
    return left


def _apply_socket_timeout(resp: Any, left: float) -> None:
    """Re-apply the remaining deadline to the response socket, if it is still open."""
    sock = getattr(getattr(getattr(resp, "fp", None), "raw", None), "_sock", None)
    settimeout = getattr(sock, "settimeout", None)
    if settimeout is None:
        return
    try:
        settimeout(left)
    except OSError:
        pass  # socket already closed by http.client after the last body byte


def _set_timeout(resp: Any, sock: Any, left: float) -> None:
    """Apply `left` seconds to the active socket unless the response is already closed."""
    if _is_closed(resp):
        return
    if sock is None:
        _apply_socket_timeout(resp, left)
        return
    try:
        sock.settimeout(left)
    except OSError:
        pass  # http.client already released the socket after the last body byte


def _is_closed(resp: Any) -> bool:
    isclosed = getattr(resp, "isclosed", None)
    return bool(isclosed()) if callable(isclosed) else False


def _has_unsafe_authority_char(value: str) -> bool:
    return any(ch == "%" or ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _check_authority(raw_authority: str | None, parts: urllib.parse.SplitResult, ascii_host: str) -> None:
    """Strict RFC 3986 authority check on the raw (pre-normalization) URL spelling."""
    if not raw_authority:
        raise clr.UnsafeURLError("URL has no authority.")
    if (_has_unsafe_authority_char(raw_authority)
            or _has_unsafe_authority_char(parts.netloc)
            or _has_unsafe_authority_char(ascii_host)):
        raise clr.UnsafeURLError(
            "ASCII control characters, whitespace or '%' are not allowed in the URL host."
        )
    bad = sorted({ch for ch in raw_authority if ch.isascii() and ch not in _AUTHORITY_CHARS})
    if bad:
        raise clr.UnsafeURLError(
            "Characters %s are not allowed in the URL authority." % ", ".join(repr(ch) for ch in bad)
        )
    if parts.username is not None or parts.password is not None:
        raise clr.UnsafeURLError("Credentials in URLs are not allowed.")
    if raw_authority.startswith("["):
        close = raw_authority.find("]")
        if close <= 1:
            raise clr.UnsafeURLError(f"Malformed bracketed authority {raw_authority[:200]!r}.")
        inner = raw_authority[1:close]
        tail = raw_authority[close + 1:]
        if "[" in inner or (tail and (not tail.startswith(":") or not all("0" <= c <= "9" for c in tail[1:]))):
            raise clr.UnsafeURLError(f"Malformed bracketed authority {raw_authority[:200]!r}.")
        try:
            ip_v6 = ipaddress.IPv6Address(inner)
        except ValueError:
            raise clr.UnsafeURLError(f"Bracketed host {inner[:200]!r} is not a valid IPv6 address.") from None
        if getattr(ip_v6, "scope_id", None) is not None:
            raise clr.UnsafeURLError("IPv6 zone identifiers are not allowed.")
    else:
        if "[" in raw_authority or "]" in raw_authority:
            raise clr.UnsafeURLError(f"Malformed brackets in authority {raw_authority[:200]!r}.")
        host_raw, sep, port_raw = raw_authority.partition(":")
        if sep and (":" in port_raw or not all("0" <= c <= "9" for c in port_raw)):
            raise clr.UnsafeURLError(f"Malformed port in authority {raw_authority[:200]!r}.")
        host_dots = host_raw.replace("\u3002", ".").replace("\uff0e", ".").replace("\uff61", ".")
        if not host_dots or host_dots.startswith(".") or ".." in host_dots:
            raise clr.UnsafeURLError(f"Host name {raw_authority[:200]!r} has invalid dot placement.")
        raw_host_no_fqdn = host_dots[:-1] if host_dots.endswith(".") else host_dots
        if not raw_host_no_fqdn:
            raise clr.UnsafeURLError(f"Host name {raw_authority[:200]!r} is empty.")
        try:
            ip_lit = ipaddress.ip_address(ascii_host)
        except ValueError:
            if host_dots.endswith("."):
                try:
                    ipaddress.IPv4Address(raw_host_no_fqdn)
                except ValueError:
                    pass
                else:
                    raise clr.UnsafeURLError(f"Trailing dot is not allowed on IP literal {host_raw[:200]!r}.") from None
            if not ascii_host.isascii() or not all(
                    _STRICT_DNS_LABEL_RE.match(label.lower()) for label in ascii_host.split(".")):
                raise clr.UnsafeURLError(f"Host name {ascii_host[:200]!r} has an invalid ASCII label.") from None
        else:
            if host_raw != str(ip_lit):
                raise clr.UnsafeURLError(f"Non-canonical IP literal {host_raw[:200]!r} is not allowed.")


def _canonical_request(current: str) -> tuple[str, str, str, str, int, str]:
    """Validate one hop URL and build its canonical ASCII request URL.

    Returns (cleaned_url, request_url, scheme, ascii_host, port, target). The authority is
    rebuilt from the validated ASCII (IDNA) host + port via clr._host_header; the request
    target uses clr._request_target, i.e. the same normalized path / query that robots
    matching and the direct pinned-IP fetcher use, preserving an explicit empty trailing "?".
    The raw authority is checked strictly (no '\\', '/', '@', '%', whitespace or other
    non-RFC 3986 characters) and every DNS label must be a strict RFC 1123 label
    (_STRICT_DNS_LABEL_RE: no '_', no leading / trailing '-').
    """
    cleaned, parts, ascii_host, port, _ips = clr._validate_url(current, resolve=False)
    _scheme, raw_authority, _path, _query = clr._split_uri(cleaned.split("#", 1)[0])
    _check_authority(raw_authority, parts, ascii_host)
    scheme = parts.scheme.lower()
    target = clr._request_target(parts, query_marker=clr._has_query_marker(cleaned))
    request_url = f"{scheme}://{clr._host_header(ascii_host, port, scheme)}{target}"
    if not request_url.isascii() or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in request_url):
        raise clr.UnsafeURLError("Canonical request URL contains control, whitespace or non-ASCII characters.")
    return cleaned, request_url, scheme, ascii_host, port, target


def _proxy_hostport(proxy_url: str | None) -> tuple[str, int]:
    """Parse (host, port) from an explicit "http://host:port" / "http://[v6]:port" proxy URL.

    Missing, empty, SOCKS, HTTPS-to-proxy, credential-bearing, port-less or otherwise
    malformed proxy URLs raise UnsafeURLError.
    """
    detail = "expected an explicit http://host:port proxy URL"
    if not isinstance(proxy_url, str) or not proxy_url.strip():
        raise clr.UnsafeURLError(f"{_NO_PROXY_ROUTE_MSG} ({detail})")
    value = proxy_url.strip()
    if not value.isascii() or _has_unsafe_authority_char(value):
        raise clr.UnsafeURLError(f"{_NO_PROXY_ROUTE_MSG} ({detail})")
    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port
    except ValueError:
        raise clr.UnsafeURLError(f"{_NO_PROXY_ROUTE_MSG} ({detail})") from None
    host = parts.hostname or ""
    if (parts.scheme.lower() != "http"
            or "@" in parts.netloc
            or parts.path not in ("", "/")
            or parts.query or parts.fragment
            or not host
            or port is None or not 0 < port < 65536):
        raise clr.UnsafeURLError(f"{_NO_PROXY_ROUTE_MSG} ({detail})")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if "[" in parts.netloc:
        if not isinstance(ip, ipaddress.IPv6Address):
            raise clr.UnsafeURLError(f"{_NO_PROXY_ROUTE_MSG} ({detail})")
    elif ip is None and not all(
            _STRICT_DNS_LABEL_RE.match(label.lower()) for label in host.rstrip(".").split(".")):
        raise clr.UnsafeURLError(f"{_NO_PROXY_ROUTE_MSG} ({detail})")
    return host, port


def _has_proxy_for_targets(targets: tuple[tuple[str, str, str], ...] = TARGETS) -> bool:
    """True only if EVERY URL scheme used by `targets` has a valid explicit OS HTTP proxy.

    All 12 TARGETS are https://, so an OS map with only an "http" proxy (no "https"
    route) fails this preflight instead of failing every target later at run time.
    """
    proxies = urllib.request.getproxies() or {}
    schemes = {urllib.parse.urlsplit(u).scheme.lower() for _, _, u in targets}
    if not schemes:
        return False
    for scheme in schemes:
        try:
            _proxy_hostport(proxies.get(scheme))
        except clr.UnsafeURLError:
            return False
    return True


def _read_winreg_proxy_override() -> str | None:
    """Return Windows Internet Settings ProxyOverride when winreg proxy is enabled."""
    import sys

    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not enabled:
                return None
            override, _ = winreg.QueryValueEx(key, "ProxyOverride")
            return override.strip() if isinstance(override, str) and override.strip() else None
    except OSError:
        return None


def _matches_winreg_override(ascii_host: str, port: int, scheme: str, override: str) -> bool:
    """Port-aware matcher for Windows Registry ProxyOverride entries."""
    import re

    host_lower = ascii_host.lower().rstrip(".")
    scheme_lower = scheme.lower()
    for raw_tok in override.split(";"):
        tok = raw_tok.strip().lower()
        if not tok:
            continue
        if tok == "<local>":
            if "." not in host_lower and ":" not in host_lower:
                return True
            continue
        if "://" in tok:
            tok_scheme, _, tok = tok.partition("://")
            if tok_scheme != scheme_lower:
                continue
        elif "=" in tok:
            tok_scheme, _, tok = tok.partition("=")
            if tok_scheme != scheme_lower:
                continue
        tok = tok.split("/", 1)[0]
        if not tok:
            continue
        if tok.startswith("["):
            close = tok.find("]")
            if close <= 1:
                continue
            pat_host = tok[1:close]
            tail = tok[close + 1:]
            if tail:
                if not tail.startswith(":") or not tail[1:].isascii() or not tail[1:].isdigit():
                    continue
                if int(tail[1:]) != port:
                    continue
        else:
            colon_count = tok.count(":")
            if colon_count == 1:
                pat_host, _, pat_port = tok.partition(":")
                if not pat_port.isascii() or not pat_port.isdigit() or int(pat_port) != port:
                    continue
            else:
                pat_host = tok
        if not pat_host:
            continue
        pat_host = pat_host.rstrip(".")
        pattern = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pat_host)
        if re.fullmatch(pattern, host_lower):
            return True
        if "*" not in pat_host and "?" not in pat_host:
            try:
                if ipaddress.ip_address(pat_host) == ipaddress.ip_address(host_lower):
                    return True
            except ValueError:
                pass
    return False


def _ensure_proxy_route(scheme: str, ascii_host: str, port: int) -> str:
    """Return the OS HTTP proxy URL for this hop, or raise UnsafeURLError.

    Rejects the hop when the OS has no valid explicit HTTP proxy for `scheme`, or when
    urllib.request.proxy_bypass matches the bare host, "host:port" or the Host-header
    form (so a port-specific no_proxy entry such as "example.com:8443" is honoured).
    IPv6 literals are also checked as "[v6]:port" (e.g. a "[2001:db8::1]:443" entry).
    This mode never falls back to a direct connection to the origin.
    """
    proxy_url = (urllib.request.getproxies() or {}).get(scheme)
    try:
        _proxy_hostport(proxy_url)
    except clr.UnsafeURLError:
        raise clr.UnsafeURLError(_NO_PROXY_ROUTE_MSG) from None
    candidates = [ascii_host, f"{ascii_host}:{port}", clr._host_header(ascii_host, port, scheme)]
    if ":" in ascii_host:
        candidates.append(f"[{ascii_host}]:{port}")
    for candidate in dict.fromkeys(candidates):
        if urllib.request.proxy_bypass(candidate):
            raise clr.UnsafeURLError(_NO_PROXY_ROUTE_MSG)
    if not urllib.request.getproxies_environment():
        override = _read_winreg_proxy_override()
        if override and _matches_winreg_override(ascii_host, port, scheme, override):
            raise clr.UnsafeURLError(_NO_PROXY_ROUTE_MSG)
    return proxy_url


def _check_watchdog(watchdog: Any) -> None:
    if watchdog is not None and watchdog.fired.is_set():
        raise TimeoutError(f"Proxy fetch exceeded the {PROXY_FETCH_DEADLINE:g}s deadline (--use-system-proxy).")


def _read_connect_response(sock: Any, host_port: str, remaining_fn: Callable[[], float], watchdog: Any) -> None:
    """Read the proxy's CONNECT reply byte by byte (never past "\\r\\n\\r\\n"); require 200."""
    buf = bytearray()
    while not buf.endswith(b"\r\n\r\n"):
        if len(buf) >= MAX_CONNECT_RESPONSE_BYTES:
            raise clr.FetchError(f"Proxy CONNECT response for {host_port} exceeds {MAX_CONNECT_RESPONSE_BYTES} bytes.")
        _check_watchdog(watchdog)
        sock.settimeout(remaining_fn())
        byte = sock.recv(1)
        if not byte:
            _check_watchdog(watchdog)
            raise clr.FetchError(f"Proxy closed the connection during CONNECT {host_port}.")
        buf += byte
    match = _CONNECT_STATUS_RE.match(bytes(buf))
    if match is None or match.group(1) != b"200":
        status_line = bytes(buf).split(b"\r\n", 1)[0][:100].decode("latin-1")
        raise clr.FetchError(f"Proxy CONNECT {host_port} failed: {status_line!r}")


def _proxy_addrinfos(proxy_host: str, proxy_port: int, remaining_fn: Callable[[], float]) -> list:
    """getaddrinfo-style tuples for the proxy, DNS bounded by the shared deadline.

    IP-literal proxies are built directly (no lookup); host names go through
    clr._resolve_host, which caps socket.getaddrinfo at `remaining_fn()` seconds.
    """
    try:
        ip = ipaddress.ip_address(proxy_host)
    except ValueError:
        ip = None
    if isinstance(ip, ipaddress.IPv6Address):
        return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (proxy_host, proxy_port, 0, 0))]
    if ip is not None:
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (proxy_host, proxy_port))]
    infos = clr._resolve_host(proxy_host, proxy_port, remaining_fn())
    if not infos:
        raise clr.FetchError(f"DNS lookup for proxy {proxy_host[:200]} returned no addresses.")
    return list(infos)


def _connect_proxy_socket(
    proxy_host: str,
    proxy_port: int,
    remaining_fn: Callable[[], float],
    watchdog: Any,
) -> Any:
    """TCP-connect to the proxy, trying every resolved address under one deadline + watchdog.

    Mirrors clr's pinned connect: each attempt socket is attached to `watchdog` BEFORE
    connect(), gets the remaining deadline as its timeout, and is closed on failure;
    the last address re-raises its error.
    """
    _check_watchdog(watchdog)
    infos = _proxy_addrinfos(proxy_host, proxy_port, remaining_fn)
    for index, info in enumerate(infos):
        af, socktype, proto, _canon, sockaddr = info
        _check_watchdog(watchdog)
        attempt = socket.socket(af, socktype, proto)
        try:
            watchdog.attach(attempt)
            attempt.settimeout(remaining_fn())
            attempt.connect(sockaddr)
            return attempt
        except BaseException as exc:
            clr._close_quietly(attempt)
            _check_watchdog(watchdog)
            if not isinstance(exc, OSError) or index == len(infos) - 1:
                raise
            remaining_fn()  # TimeoutError once the shared deadline has passed
    raise clr.FetchError(f"No address to connect to proxy {proxy_host[:200]}.")  # pragma: no cover


def _open_proxy_connection(
    scheme: str,
    ascii_host: str,
    port: int,
    proxy_url: str,
    remaining_fn: Callable[[], float],
    watchdog: Any,
) -> Any:
    """Open the hop's socket strictly through the explicit HTTP proxy (never direct to origin).

    The caller arms and starts `watchdog` BEFORE this call. Plain http returns the TCP
    socket to the proxy (the request then uses an absolute-form target). https sends
    "CONNECT host:port", requires a 200 reply, then wraps the tunnel in TLS (SNI and
    certificate verification against `ascii_host`) and returns the TLS socket. Every
    blocking step (proxy DNS, every TCP connect attempt, CONNECT, TLS) is bounded by
    `remaining_fn()` and attached to `watchdog`.
    """
    proxy_host, proxy_port = _proxy_hostport(proxy_url)
    try:
        raw = _connect_proxy_socket(proxy_host, proxy_port, remaining_fn, watchdog)
    except Exception:
        if watchdog.fired.is_set():
            raise TimeoutError(
                f"Proxy fetch exceeded the {PROXY_FETCH_DEADLINE:g}s deadline (--use-system-proxy)."
            ) from None
        raise
    tls = None
    try:
        _check_watchdog(watchdog)
        raw.settimeout(remaining_fn())
        if scheme != "https":
            return raw
        host_port = f"[{ascii_host}]:{port}" if ":" in ascii_host else f"{ascii_host}:{port}"
        raw.sendall(f"CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n\r\n".encode("ascii"))
        _read_connect_response(raw, host_port, remaining_fn, watchdog)
        raw.settimeout(remaining_fn())
        tls = ssl.create_default_context().wrap_socket(
            raw, server_hostname=ascii_host, do_handshake_on_connect=False
        )
        watchdog.attach(tls)
        tls.settimeout(remaining_fn())
        tls.do_handshake()
        _check_watchdog(watchdog)
        return tls
    except BaseException as exc:
        if tls is not None:
            clr._close_quietly(tls)
        clr._close_quietly(raw)
        if isinstance(exc, Exception) and watchdog.fired.is_set():
            raise TimeoutError(
                f"Proxy fetch exceeded the {PROXY_FETCH_DEADLINE:g}s deadline (--use-system-proxy)."
            ) from None
        raise


class _ProxyOnlyHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection bound to an already-open proxy / tunnel socket.

    connect() is disabled: this transport must never dial the origin directly.
    """

    def connect(self) -> None:
        raise clr.FetchError("Proxy-only connection has no socket; refusing a direct connection.")


def _header_values(headers: Any, name: str) -> list[str]:
    """Every value of header `name` (falls back to .get() for objects without get_all)."""
    if headers is None:
        return []
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name) or []
    else:
        value = headers.get(name)
        values = [value] if value else []
    return [str(v) for v in values]


def _validate_response_framing(resp: Any) -> None:
    """Strict message framing for ANY final response (2xx, 3xx redirect or 4xx/5xx).

    Rejects Transfer-Encoding + Content-Length together, unsupported / ambiguous
    Transfer-Encoding (all header lines joined) and conflicting or unenforced
    Content-Length. 204 / 304 skip the Content-Length enforcement check because
    http.client always treats their body length as 0.
    """
    headers = getattr(resp, "headers", None)
    chunked = bool(getattr(resp, "chunked", False))
    te_vals = _header_values(headers, "Transfer-Encoding")
    cl_vals = _header_values(headers, "Content-Length")
    if te_vals and cl_vals:
        raise clr.FetchError("Ambiguous response: both Transfer-Encoding and Content-Length present.")
    clr._check_transfer_encoding(", ".join(te_vals) if te_vals else None, chunked)
    if int(resp.status) not in (204, 304):
        clr._check_content_length(headers, getattr(resp, "length", None), chunked)


def _read_bounded_response(
    resp: Any,
    url: str,
    force_utf8: bool,
    deadline: float | None = None,
    sock: Any = None,
    watchdog: Any = None,
    framing_validated: bool = False,
) -> tuple[int, str, str | None]:
    """Read one final response body with strict framing (mirrors clr._fetch_url_details).

    Unless the caller already ran it (framing_validated=True, as _proxy_hop does right
    after getresponse()), _validate_response_framing runs first, for every status,
    including 4xx/5xx. Truncated chunked bodies (http.client.IncompleteRead) and short
    Content-Length bodies are rejected. The deadline and watchdog guard every body read.
    """
    deadline = deadline if deadline is not None else clr._now() + PROXY_FETCH_DEADLINE
    if not framing_validated:
        _validate_response_framing(resp)
    status = int(resp.status)
    headers = resp.headers
    media_type = clr._media_type_essence(headers.get("Content-Type")) if headers else None
    if status >= 400:
        return status, "", media_type

    chunked = bool(getattr(resp, "chunked", False))
    expected_len = None if chunked else getattr(resp, "length", None)

    coding = clr._content_coding(headers.get("Content-Encoding") if headers else None, getattr(resp, "length", None))
    decoder = clr._CompressedBody(coding, clr.MAX_FETCH_BYTES, url) if coding else None
    read1 = getattr(resp, "read1", None) or resp.read
    chunks: list[bytes] = []
    total = 0  # raw (on-the-wire) body bytes read

    def read_chunk(size: int) -> bytes:
        _check_watchdog(watchdog)
        _set_timeout(resp, sock, _remaining(deadline, url))
        try:
            chunk = read1(size)
        except http.client.IncompleteRead:
            _check_watchdog(watchdog)
            raise clr.FetchError(
                f"Incomplete HTTP response body from {url[:200]}: connection closed after {total} bytes "
                "(truncated chunked body)."
            ) from None
        _check_watchdog(watchdog)
        if not chunk:
            left_len = getattr(resp, "length", None)
            if isinstance(left_len, int) and left_len > 0:
                raise clr.FetchError(
                    f"Incomplete HTTP response body from {url[:200]}: connection closed after {total} bytes, "
                    f"{left_len} more declared by Content-Length."
                )
        return chunk

    def check_complete() -> None:
        left_len = getattr(resp, "length", None)
        if expected_len is not None and (total < expected_len or (isinstance(left_len, int) and left_len > 0)):
            raise clr.FetchError(
                f"Incomplete HTTP response body from {url[:200]}: connection closed after {total} bytes, "
                f"{expected_len} declared by Content-Length."
            )

    while total < clr.MAX_FETCH_BYTES and not _is_closed(resp):
        chunk = read_chunk(min(clr.FETCH_CHUNK, clr.MAX_FETCH_BYTES - total))
        if not chunk:
            break
        total += len(chunk)
        if decoder is None:
            chunks.append(chunk)
        else:
            decoder.feed(chunk)

    if total < clr.MAX_FETCH_BYTES:
        check_complete()
        has_more = False
    elif _is_closed(resp):
        has_more = False
    else:
        has_more = bool(read_chunk(1))

    if decoder is None:
        body = b"".join(chunks)
        if force_utf8 and has_more:
            cut = max(body.rfind(b"\n"), body.rfind(b"\r"))
            body = body[:cut + 1] if cut >= 0 else b""
    else:
        if has_more:
            raise clr.FetchError(
                f"Compressed response body from {url[:200]} exceeds {clr.MAX_FETCH_BYTES}-byte limit."
            )
        body = decoder.finish()  # FetchError if the compressed stream ended early

    try:
        charset = headers.get_content_charset() if headers else None
    except Exception:
        charset = None
    return status, clr._decode_body(body, charset, force_utf8=force_utf8), media_type


def _proxy_hop(
    url: str,
    cleaned: str,
    request_url: str,
    scheme: str,
    ascii_host: str,
    port: int,
    target: str,
    proxy_url: str,
    force_utf8: bool,
    deadline: float,
) -> tuple[int, str, str | None, str | None]:
    """One GET through the proxy. Returns (status, text, media_type, redirect_location)."""
    timeout_msg = f"Fetch of {url[:200]} exceeded the {PROXY_FETCH_DEADLINE:g}s deadline (--use-system-proxy)."

    def remaining() -> float:
        return _remaining(deadline, url)

    remaining()
    # Absolute-form target for plain http through the proxy; origin-form inside a CONNECT tunnel.
    wire_target = target if scheme == "https" else request_url
    headers = {
        "Host": clr._host_header(ascii_host, port, scheme),
        "User-Agent": clr.USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, identity",
        "Connection": "close",
    }
    watchdog = clr._Watchdog(max(0.0, deadline - clr._now()))
    sock = None
    conn = None
    resp = None
    try:
        watchdog.start()
        sock = _open_proxy_connection(scheme, ascii_host, port, proxy_url, remaining, watchdog)
        watchdog.attach(sock)  # the active (TLS or proxy TCP) socket guards headers + body reads
        if watchdog.fired.is_set():
            raise TimeoutError(timeout_msg)
        conn = _ProxyOnlyHTTPConnection(ascii_host, port)
        conn.sock = sock

        def on_interim(sock=sock) -> None:
            # After each interim 1xx response: same deadline, same watchdog.
            if watchdog.fired.is_set():
                raise TimeoutError(timeout_msg)
            sock.settimeout(remaining())

        conn.response_class = functools.partial(clr._FinalResponse, on_interim=on_interim)
        sock.settimeout(remaining())
        conn.request("GET", wire_target, headers=headers)
        if watchdog.fired.is_set():
            raise TimeoutError(timeout_msg)
        sock.settimeout(remaining())
        resp = conn.getresponse()
        if watchdog.fired.is_set():
            raise TimeoutError(timeout_msg)
        # Framing is checked BEFORE redirect / error handling, so a 3xx or 4xx with
        # ambiguous Transfer-Encoding / Content-Length is a FetchError, not a status.
        _validate_response_framing(resp)
        status = int(resp.status)
        media_type = clr._media_type_essence(resp.getheader("Content-Type"))
        if status in clr._REDIRECT_CODES:
            return status, "", media_type, resp.getheader("Location")
        if status >= 400:
            return status, "", media_type, None
        _status, text, _mt = _read_bounded_response(resp, cleaned, force_utf8, deadline, sock=sock,
                                                    watchdog=watchdog, framing_validated=True)
        return status, text, media_type, None
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
            try:
                conn.close()
            except Exception:
                pass
        elif sock is not None:
            clr._close_quietly(sock)


def _fetch_via_proxy(url: str, force_utf8: bool = False, deadline: float | None = None) -> dict[str, Any]:
    """Read-only GET strictly through the explicit OS HTTP proxy.

    Every URL and redirect hop is validated (clr._validate_url + strict authority check)
    and rebuilt as a canonical ASCII request; _ensure_proxy_route runs before every hop
    and _open_proxy_connection only ever dials the proxy, so this mode can never fall
    back to unpinned direct TCP. One monotonic deadline (PROXY_FETCH_DEADLINE) plus a
    per-hop clr._Watchdog cover the proxy connect, CONNECT tunnel, TLS, interim 1xx
    responses, headers and every body read across all redirect hops.
    """
    deadline = deadline if deadline is not None else clr._now() + PROXY_FETCH_DEADLINE
    visited: list[str] = []
    current = url
    for _hop in range(clr.MAX_REDIRECTS + 1):
        cleaned, request_url, scheme, ascii_host, port, target = _canonical_request(current)
        visited.append(cleaned)
        proxy_url = _ensure_proxy_route(scheme, ascii_host, port)
        _remaining(deadline, url)
        status, text, media_type, location = _proxy_hop(
            url, cleaned, request_url, scheme, ascii_host, port, target, proxy_url, force_utf8, deadline
        )
        if status in clr._REDIRECT_CODES and location:
            current = clr._resolve_redirect(cleaned, location)
            continue
        return {
            "status": status,
            "text": text,
            "visited": visited,
            "content_type": media_type,
        }
    raise clr.FetchError(f"Too many redirects (more than {clr.MAX_REDIRECTS}) for {url[:200]}")


def _fetch_direct(url: str, force_utf8: bool = False) -> dict[str, Any]:
    """Default transport: clr's SSRF-guarded, DNS-pinned direct fetcher."""
    return clr._fetch_url_details(url, force_utf8=force_utf8)


def _robots_error_section(source: str, path: str, message: str) -> dict[str, Any]:
    return {
        "source": source,
        "path": path,
        "policy": "error",
        "groups_found": 0,
        "search_crawlers": {},
        "training_crawlers": {},
        "notes": [message],
    }


def _llms_section(status: int, text: str, llms_url: str) -> dict[str, Any]:
    if 200 <= status < 300 and status not in (204, 206):
        section = clr.audit_llms(text, llms_url)
    else:
        if status == 204:
            err = "llms.txt returned HTTP 204 No Content (an empty body is not a valid llms.txt)."
        elif status == 206:
            err = "llms.txt returned HTTP 206 Partial Content (treated as unavailable)."
        else:
            err = f"llms.txt not found (HTTP {status})."
        section = {"source": llms_url, "valid": False, "errors": [err], "warnings": []}
    section["http_status"] = status
    return section


def _html_no_content(source: str) -> dict[str, Any]:
    """HTML section for an HTTP 204 page: a 2xx response with no HTML body to parse."""
    return {
        "source": source,
        "http_status": 204,
        "verdict": "no_content",
        "advice": "Page returned HTTP 204 No Content (no HTML body).",
        "visible_words": 0,
        "script_tags": 0,
        "external_scripts": 0,
        "data_script_tags": 0,
        "inline_script_byte_ratio": 0.0,
        "empty_mount_nodes": [],
        "title": "",
        "text_preview": "",
    }


def _run_audit(url: str, fetch: Any) -> dict[str, Any]:
    """Audit one target URL with `fetch` payloads and clr's pure RFC/HTML evaluators.

    Mirrors clr.run(): every redirect hop is evaluated against its own origin's robots.txt
    and /llms.txt is fetched from the SUBMITTED origin. The page result is computed first,
    so a later robots.txt or /llms.txt transport failure never erases the observed page
    status / parsed HTML; it is reported in report["errors"] instead.
    """
    page_url = clr.validate_public_url(url, resolve=False)
    report: dict[str, Any] = {"tool": "cleanparse-geo-tools", "version": clr.__version__, "url": page_url}
    errors: list[str] = []

    details = fetch(page_url)
    page_status = details["status"]
    page_body = details["text"]
    media_type = details.get("content_type")
    visited = list(details["visited"]) or [page_url]
    final_url = visited[-1]

    if not 200 <= page_status < 300 or page_status == 206:
        html = clr.html_fetch_failed(final_url, page_status)
    elif page_status == 204:
        html = _html_no_content(final_url)
    elif media_type is not None and media_type not in clr._HTML_MEDIA_TYPES:
        html = clr.html_unsupported_content(final_url, page_status, media_type)
    else:
        html = clr.audit_html(page_body, final_url)
    html["http_status"] = page_status

    robots_cache: dict[tuple[str, str, int], tuple[str, int, str]] = {}
    hops: list[tuple[str, dict]] = []
    robots_url = ""
    hop_path = "/"
    try:
        for hop_url in visited:
            key, hop_origin = clr._robots_origin(hop_url)
            hop_path = clr._request_target(hop_url)
            if key not in robots_cache:
                robots_url = hop_origin + "/robots.txt"
                r_det = fetch(robots_url, force_utf8=True)
                robots_cache[key] = (robots_url, r_det["status"], r_det["text"])
            robots_url, r_status, r_body = robots_cache[key]
            hop_report = clr._robots_report_for_status(r_status, r_body, hop_path, robots_url)
            hops.append((hop_url, _normalize_hop_robots_report(hop_report)))
        report["robots"] = clr.combine_robots_hops(hops)
    except _FETCH_ERRORS as exc:
        msg = f"robots.txt fetch failed ({robots_url[:200]}): {exc}"
        errors.append(msg)
        report["robots"] = _robots_error_section(robots_url, hop_path, msg)

    orig = urllib.parse.urlsplit(page_url)
    llms_url = f"{orig.scheme}://{orig.netloc}/llms.txt"
    try:
        ll_det = fetch(llms_url)
        report["llms"] = _llms_section(ll_det["status"], ll_det["text"], llms_url)
    except _FETCH_ERRORS as exc:
        msg = f"llms.txt fetch failed ({llms_url[:200]}): {exc}"
        errors.append(msg)
        report["llms"] = {"source": llms_url, "valid": False, "http_status": None, "errors": [msg], "warnings": []}

    report["html"] = html
    if len(visited) > 1:
        report["final_url"] = final_url
    if errors:
        report["errors"] = errors
    report["more"] = "https://cleanparse.com/ai-search-visibility-checker"
    return report


def _run_via_proxy(url: str) -> dict[str, Any]:
    """Audit one target URL strictly through the OS HTTP proxy (--use-system-proxy)."""
    return _run_audit(url, _fetch_via_proxy)


def _run_direct(url: str) -> dict[str, Any]:
    """Audit one target URL with the default direct, DNS-pinned transport."""
    return _run_audit(url, _fetch_direct)


def _crawler_allowed(section: dict[str, Any], name: str) -> bool | None:
    entry = (section or {}).get(name)
    if isinstance(entry, dict) and "allowed" in entry:
        return bool(entry["allowed"])
    return None


def _crawler_group(section: dict[str, Any], name: str) -> str:
    entry = (section or {}).get(name)
    if isinstance(entry, dict):
        return str(entry.get("group") or "")
    return ""


def _normalize_robots_notes(notes: list[str], groups: dict[str, str]) -> list[str]:
    """Replace clr's "falls back to the '*' group" note when no '*' group exists at all.

    If every crawler matched "(none)", there is no wildcard group to fall back to; RFC 9309
    then allows everything. check_llms_and_robots.py itself is left unchanged.
    """
    if groups and all(v == "(none)" for v in groups.values()):
        return [_NO_GROUP_NOTE if n == _CLR_WILDCARD_NOTE else n for n in notes]
    return list(notes)


def _normalize_hop_robots_report(hop_report: dict) -> dict:
    """Apply _normalize_robots_notes to ONE hop's robots report, before combine_robots_hops.

    Normalizing per hop means a multi-hop redirect never carries hop 1's '*'-fallback
    note onto a hop whose robots.txt has no group at all (every crawler "(none)"), and
    never rewrites a later hop's genuine '*'-fallback note because hop 1 was "(none)".
    """
    groups = {
        f"{kind}:{name}": str((entry or {}).get("group") or "")
        for kind in ("search_crawlers", "training_crawlers")
        for name, entry in (hop_report.get(kind) or {}).items()
    }
    notes = list(hop_report.get("notes") or [])
    normalized = _normalize_robots_notes(notes, groups)
    if normalized == notes:
        return hop_report
    return dict(hop_report, notes=normalized)


def audit_target(slug: str, name: str, url: str, use_system_proxy: bool = False) -> dict[str, Any]:
    """Run one read-only live audit and normalize key telemetry fields.

    A page fetch failure yields an error row (ok=False). A later robots.txt failure keeps
    the observed page http_status / HTML fields and sets robots_policy "error"; a later
    /llms.txt failure keeps the robots policy and sets llms_http_status None. Either
    message is recorded in "error".
    """
    try:
        report = _run_via_proxy(url) if use_system_proxy else _run_direct(url)
    except _FETCH_ERRORS as exc:
        return {
            "slug": slug,
            "name": name,
            "url": url,
            "final_url": url,
            "ok": False,
            "error": str(exc),
            "http_status": None,
            "robots_source": "",
            "robots_policy": "error",
            "oai_searchbot": None,
            "claude_searchbot": None,
            "perplexitybot": None,
            "gptbot": None,
            "claudebot": None,
            "crawler_groups": {},
            "robots_notes": [],
            "llms_source": "",
            "llms_http_status": None,
            "llms_valid": False,
            "llms_sections": 0,
            "llms_total_links": 0,
            "visible_words": None,
            "script_tags": None,
            "external_scripts": None,
            "data_script_tags": None,
            "inline_script_byte_ratio": None,
            "empty_mount_nodes": [],
            "html_verdict": "fetch_error",
            "title": "",
        }

    rb = report.get("robots") or {}
    search = rb.get("search_crawlers") or {}
    training = rb.get("training_crawlers") or {}
    ll = report.get("llms") or {}
    ht = report.get("html") or {}

    llms_status = ll.get("http_status")

    groups = {
        k: _crawler_group(search if k in clr.SEARCH_CRAWLERS else training, k)
        for k in (*clr.SEARCH_CRAWLERS, *clr.TRAINING_CRAWLERS)
    }

    return {
        "slug": slug,
        "name": name,
        "url": url,
        "final_url": report.get("final_url", url),
        "ok": True,
        "error": "; ".join(report.get("errors") or []),
        "http_status": ht.get("http_status"),
        "robots_source": rb.get("source", ""),
        "robots_policy": rb.get("policy", ""),
        "oai_searchbot": _crawler_allowed(search, "OAI-SearchBot"),
        "claude_searchbot": _crawler_allowed(search, "Claude-SearchBot"),
        "perplexitybot": _crawler_allowed(search, "PerplexityBot"),
        "gptbot": _crawler_allowed(training, "GPTBot"),
        "claudebot": _crawler_allowed(training, "ClaudeBot"),
        "crawler_groups": groups,
        # Already normalized per hop in _run_audit (_normalize_hop_robots_report).
        "robots_notes": list(rb.get("notes") or []),
        "llms_source": ll.get("source", ""),
        "llms_http_status": llms_status,
        "llms_valid": bool(ll.get("valid", False)),
        "llms_sections": len(ll.get("sections") or []),
        "llms_total_links": int(ll.get("total_links") or 0),
        "visible_words": ht.get("visible_words"),
        "script_tags": ht.get("script_tags"),
        "external_scripts": ht.get("external_scripts"),
        "data_script_tags": ht.get("data_script_tags"),
        "inline_script_byte_ratio": ht.get("inline_script_byte_ratio"),
        "empty_mount_nodes": list(ht.get("empty_mount_nodes") or []),
        "html_verdict": ht.get("verdict", ""),
        "title": ht.get("title", ""),
    }


_HTML_PARSED_VERDICTS = ("server_rendered", "thin_content", "likely_csr_shell")


def _summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [r for r in results if r["ok"]]
    # 204 (no_content) and 206 pages are 2xx responses but are never parsed as HTML.
    http_2xx = [r for r in completed if isinstance(r["http_status"], int) and 200 <= r["http_status"] < 300]
    search_all_ok = [
        r for r in completed
        if r["oai_searchbot"] is True and r["claude_searchbot"] is True and r["perplexitybot"] is True
    ]
    any_training_blocked = [
        r for r in completed
        if r["gptbot"] is False or r["claudebot"] is False
    ]
    split_policy = [
        r for r in completed
        if r["robots_policy"] == "search_allowed_training_blocked"
    ]
    llms_present = [
        r for r in completed
        if isinstance(r["llms_http_status"], int) and 200 <= r["llms_http_status"] < 300
    ]
    llms_valid = [r for r in llms_present if r["llms_valid"]]
    html_parsed = [r for r in completed if r["html_verdict"] in _HTML_PARSED_VERDICTS]
    server_rendered = [r for r in http_2xx if r["html_verdict"] == "server_rendered"]
    csr_or_thin = [r for r in http_2xx if r["html_verdict"] in ("likely_csr_shell", "thin_content")]
    return {
        "total_targets": len(results),
        "completed_requests": len(completed),
        "transport_errors": len(results) - len(completed),
        "http_2xx_pages": len(http_2xx),
        "html_parsed_pages": len(html_parsed),
        "all_search_crawlers_allowed": len(search_all_ok),
        "any_training_crawler_blocked": len(any_training_blocked),
        "split_search_allow_training_block": len(split_policy),
        "llms_txt_http_2xx": len(llms_present),
        "llms_txt_strictly_valid": len(llms_valid),
        "server_rendered_2xx": len(server_rendered),
        "thin_or_csr_2xx": len(csr_or_thin),
    }


def _bool_label(val: bool | None) -> str:
    if val is True:
        return "ALLOW"
    if val is False:
        return "BLOCK"
    return "ERROR"


def _llms_cell(r: dict[str, Any]) -> str:
    if not r["ok"] or r["llms_http_status"] is None:
        return "ERR"
    if r["llms_http_status"] == 200:
        return f"200 ({r['llms_total_links']} links, {'valid' if r['llms_valid'] else 'non-standard'})"
    return f"HTTP {r['llms_http_status']}"


def _write_csv(path: Path, results: list[dict[str, Any]]) -> None:
    fieldnames = [
        "slug",
        "name",
        "url",
        "final_url",
        "ok",
        "http_status",
        "robots_policy",
        "oai_searchbot",
        "claude_searchbot",
        "perplexitybot",
        "gptbot",
        "claudebot",
        "llms_http_status",
        "llms_valid",
        "llms_sections",
        "llms_total_links",
        "visible_words",
        "script_tags",
        "external_scripts",
        "data_script_tags",
        "inline_script_byte_ratio",
        "empty_mount_nodes",
        "html_verdict",
        "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = {k: r.get(k) for k in fieldnames}
            row["empty_mount_nodes"] = ";".join(r.get("empty_mount_nodes") or [])
            writer.writerow(row)


def _readme_text(payload: dict[str, Any]) -> str:
    s = payload["summary"]
    obs = payload["observed_at_utc"]
    lines = [
        "# 2026 Public Documentation AI Search Visibility Benchmark",
        "",
        f"Snapshot captured at `{obs}` using [`scripts/check_llms_and_robots.py`](../scripts/check_llms_and_robots.py) (`v{payload['tool_version']}`).",
        "",
        "> Live web page counterpart: <https://cleanparse.com/ai-crawler-visibility-benchmark>",
        "",
        "## Summary of Observed Snapshot",
        "",
        f"- **Targets tested**: {s['total_targets']} public developer documentation & tool homepages",
        f"- **HTTP 2xx pages**: {s['http_2xx_pages']} / {s['total_targets']}",
        f"- **HTML pages parsed (excluding 204 / 206)**: {s['html_parsed_pages']} / {s['total_targets']}",
        f"- **All 3 AI search crawlers allowed (`OAI-SearchBot`, `Claude-SearchBot`, `PerplexityBot`)**: {s['all_search_crawlers_allowed']} / {s['completed_requests']}",
        f"- **At least one AI training crawler blocked (`GPTBot` / `ClaudeBot`)**: {s['any_training_crawler_blocked']} / {s['completed_requests']}",
        f"- **Split policy (allow search, block training)**: {s['split_search_allow_training_block']} / {s['completed_requests']}",
        f"- **`/llms.txt` HTTP 2xx / strict structural valid**: {s['llms_txt_http_2xx']} / {s['llms_txt_strictly_valid']}",
        f"- **Static HTML `server_rendered` (among 2xx)**: {s['server_rendered_2xx']} / {s['http_2xx_pages']}",
        "",
        "## Results Table",
        "",
        "| Site | HTTP | OAI-SearchBot | Claude-SearchBot | PerplexityBot | GPTBot | ClaudeBot | /llms.txt | Non-JS Words | HTML Verdict |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in payload["results"]:
        words_cell = "-" if r["visible_words"] is None else str(r["visible_words"])
        http_cell = str(r["http_status"]) if r["http_status"] is not None else "ERR"
        lines.append(
            f"| [{r['name']}]({r['url']}) | {http_cell} | {_bool_label(r['oai_searchbot'])} | "
            f"{_bool_label(r['claude_searchbot'])} | {_bool_label(r['perplexitybot'])} | "
            f"{_bool_label(r['gptbot'])} | {_bool_label(r['claudebot'])} | "
            f"{_llms_cell(r)} | {words_cell} | `{r['html_verdict']}` |"
        )
    lines.extend([
        "",
        "## Methodology & Caveats",
        "",
        "- **Read-only single-pass GETs**: Each target is audited once via RFC 9309 `robots.txt` evaluation, `/llms.txt` structure checks, and raw HTML visible-text extraction without executing JavaScript.",
        "- **No anti-bot or firewall bypass**: HTTP status codes are recorded verbatim without retries, spoofed headers, or workarounds. 403/429 or non-2xx statuses yield `fetch_failed`; HTTP 200 challenge pages enter static word counting without JS execution or WAF bypass.",
        "- **HTTP 204 / 206**: an HTTP 204 page counts as 2xx with verdict `no_content` (no HTML body, not parsed); an HTTP 206 partial page counts as 2xx but is not parsed (`fetch_failed`); a `/llms.txt` HTTP 204 (empty body) is not a valid `llms.txt`.",
        "- **`robots.txt` fetch failure**: if `robots.txt` fails after the page was fetched, the observed page HTTP status and HTML fields are kept, `robots_policy` becomes `error` (crawler cells show `ERROR`) and the message is recorded in `error`.",
        "- **`/llms.txt` fetch failure**: if `/llms.txt` fails, the robots policy and crawler verdicts are kept, `llms_http_status` is `null` (table cell `ERR`) and the message is recorded in `error`.",
        "- **No `*` group**: when a `robots.txt` has no group matching any AI crawler and no `*` wildcard group, the row notes that RFC 9309 defaults to allow all.",
        "- **Point-in-time snapshot**: Crawler policies, `robots.txt`, and server rendering change over time. Verify any site's current status live via:",
        "",
        "```bash",
        "python3 scripts/check_llms_and_robots.py --url https://cleanparse.com/",
        "```",
        "",
        "## Reproduce",
        "",
        "```bash",
        "python3 -B benchmarks/run_public_docs_benchmark.py",
        "```",
        "",
        "Add `--use-system-proxy` (routes through local OS proxy; proxy egress DNS is outside local SSRF IP pinning). "
        "It requires an explicit `http://host:port` OS proxy, exits with code 2 before touching any output file when none "
        "is configured, and never falls back to unpinned direct TCP.",
        "",
        "```bash",
        "python3 -B benchmarks/run_public_docs_benchmark.py --use-system-proxy",
        "```",
        "",
        "MIT Licensed dataset (`public_docs_geo_2026.json` & `public_docs_geo_2026.csv`). "
        "The other 11 measured sites are not affiliated with and do not endorse this benchmark "
        "(CleanParse Studio is our own site).",
        "",
    ])
    return "\n".join(lines)


def _write_readme(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(_readme_text(payload), encoding="utf-8", newline="\n")


def run_benchmark(
    json_out: Path | None = None,
    csv_out: Path | None = None,
    readme_out: Path | None = None,
    use_system_proxy: bool = False,
    require_proxy: bool = True,
) -> dict[str, Any]:
    """Run every target and write JSON, CSV and README.

    With use_system_proxy=True the OS proxy is checked FIRST (unless require_proxy=False,
    an internal hook for offline tests that mock the transport): without an explicit HTTP
    proxy, ProxyPreflightError is raised before any target runs or any file is written.
    """
    if use_system_proxy and require_proxy and not _has_proxy_for_targets(TARGETS):
        raise ProxyPreflightError(_NO_PROXY_PREFLIGHT_MSG)
    results = [audit_target(slug, name, url, use_system_proxy=use_system_proxy) for slug, name, url in TARGETS]
    payload: dict[str, Any] = {
        "benchmark": "public_docs_geo_2026",
        "tool": "cleanparse-geo-tools",
        "tool_version": clr.__version__,
        "observed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fetch_transport": "system_proxy" if use_system_proxy else "direct_pinned_ip",
        "summary": _summarize(results),
        "results": results,
    }
    json_path = json_out or (BENCH_DIR / "public_docs_geo_2026.json")
    csv_path = csv_out or (BENCH_DIR / "public_docs_geo_2026.csv")
    readme_path = readme_out or (BENCH_DIR / "README.md")
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    _write_csv(csv_path, results)
    _write_readme(readme_path, payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run live public docs AI crawler & static HTML benchmark.")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--csv-out", default=None)
    ap.add_argument("--readme-out", default=None)
    ap.add_argument(
        "--use-system-proxy",
        action="store_true",
        help=(
            "Opt-in transport via an explicit OS HTTP proxy (e.g. behind 198.18.0.0/15 fake-IP DNS) using identical "
            "RFC/HTML evaluators; proxy egress DNS is outside local SSRF IP pinning. Exits with code 2 before "
            "touching any output file if no HTTP proxy is configured."
        ),
    )
    args = ap.parse_args(argv)
    if args.use_system_proxy and not _has_proxy_for_targets(TARGETS):
        print(f"error: {_NO_PROXY_PREFLIGHT_MSG}", file=sys.stderr)
        return 2
    try:
        payload = run_benchmark(
            json_out=Path(args.json_out) if args.json_out else None,
            csv_out=Path(args.csv_out) if args.csv_out else None,
            readme_out=Path(args.readme_out) if args.readme_out else None,
            use_system_proxy=args.use_system_proxy,
        )
    except ProxyPreflightError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"observed_at_utc": payload["observed_at_utc"], "summary": payload["summary"]}, indent=2, ensure_ascii=False))
    for r in payload["results"]:
        print(
            f"- {r['slug']:12s} status={r['http_status']} policy={r['robots_policy']} "
            f"llms={r['llms_http_status']}(valid={r['llms_valid']},links={r['llms_total_links']}) "
            f"words={r['visible_words']} verdict={r['html_verdict']}"
            + (f" err={r['error']}" if r["error"] else "")
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
