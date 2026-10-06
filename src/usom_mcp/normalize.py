"""Input normalization for URLs, domains and IP addresses.

The USOM data set stores values without a scheme, domains lower-cased and IDNs as
punycode, and IPv6 addresses in an uncompressed form. Everything that is compared
(stored rows and user queries) goes through this module so both sides agree.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

import idna

IndicatorKind = Literal["domain", "ip", "url", "network"]

MAX_INPUT_LENGTH = 4096
_ALLOWED_SCHEMES = frozenset({"http", "https", "ftp", "ftps"})
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_CONTROL_OR_SPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
_STORED_DOMAIN_RE = re.compile(r"^[a-z0-9_.\-]{1,253}$")
_MAX_STORED_URL_LENGTH = 4096
_REFANG = (
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[://\]"), "://"),
)


class InvalidInputError(ValueError):
    """Raised when user input cannot be turned into a valid indicator."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True, slots=True)
class Indicator:
    """A validated, canonical lookup target."""

    kind: IndicatorKind
    #: canonical value: host for domain/ip, ``host/path?query`` for url, CIDR for network
    value: str
    #: host part (domain, IP string or URL host); ``None`` for networks
    host: str | None = None
    #: ``path?query`` of a URL including the leading ``/``; empty when absent
    path: str = ""
    host_is_ip: bool = False
    warnings: tuple[str, ...] = ()


def _refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def _clean(raw: object) -> str:
    if not isinstance(raw, str):
        raise InvalidInputError("input must be a string")
    text = raw.strip()
    if not text:
        raise InvalidInputError("input is empty", "provide a URL, domain or IP address")
    if len(text) > MAX_INPUT_LENGTH:
        raise InvalidInputError(f"input is longer than {MAX_INPUT_LENGTH} characters")
    if _CONTROL_OR_SPACE_RE.search(text):
        raise InvalidInputError(
            "input contains whitespace or control characters",
            "pass a single value without spaces",
        )
    return _refang(text)


def canonical_ip(text: str) -> str:
    """Return the canonical string of an IPv4/IPv6 address; raise ``ValueError`` otherwise."""
    addr = ipaddress.ip_address(text.strip("[]"))
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _is_ip(text: str) -> bool:
    try:
        canonical_ip(text)
    except ValueError:
        return False
    return True


def canonical_network(text: str) -> str:
    net = ipaddress.ip_network(text, strict=False)
    return str(net)


def _normalize_hostname(host: str) -> str:
    host = host.rstrip(".").lower() if host.isascii() else host.rstrip(".")
    if not host:
        raise InvalidInputError("host is empty")
    if not host.isascii():
        try:
            host = idna.encode(host, uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError) as exc:
            raise InvalidInputError(f"invalid internationalized domain name: {exc}") from exc
    if len(host) > 253:
        raise InvalidInputError("domain is longer than 253 characters")
    labels = host.split(".")
    if len(labels) < 2:
        raise InvalidInputError(
            "single-label hostnames are not valid indicators",
            "use a fully qualified domain such as example.com",
        )
    for label in labels:
        if not _LABEL_RE.match(label):
            raise InvalidInputError(f"invalid domain label {label!r}")
    if labels[-1].isdigit():
        raise InvalidInputError(
            "top-level label is numeric; not a valid domain or a complete IPv4 address"
        )
    return host


def _split_authority(authority: str) -> tuple[str, int | None]:
    """Strip userinfo and port from ``[user@]host[:port]``; return (host, port)."""
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise InvalidInputError("unterminated IPv6 bracket")
        host, rest = authority[1:end], authority[end + 1 :]
        if rest and not rest.startswith(":"):
            raise InvalidInputError("unexpected characters after IPv6 address")
        port_text = rest[1:]
    elif authority.count(":") > 1:
        # Bare IPv6 without brackets (valid for the IP tools, ambiguous for URLs).
        return authority, None
    elif ":" in authority:
        host, port_text = authority.rsplit(":", 1)
    else:
        host, port_text = authority, ""
    port: int | None = None
    if port_text:
        if not port_text.isdigit() or not 0 <= int(port_text) <= 65535:
            raise InvalidInputError(f"invalid port {port_text!r}")
        port = int(port_text)
    return host, port


def _host_indicator(host: str) -> tuple[str, bool]:
    """Return (canonical host, is_ip)."""
    try:
        return canonical_ip(host), True
    except ValueError:
        pass
    return _normalize_hostname(host), False


def normalize_ip(raw: object) -> Indicator:
    text = _clean(raw)
    if "://" in text or "/" in text:
        raise InvalidInputError(
            "expected a bare IP address",
            "use check_url for URLs, or pass CIDR networks to watch_add",
        )
    try:
        value = canonical_ip(text)
    except ValueError as exc:
        raise InvalidInputError(f"not a valid IP address: {text!r}") from exc
    addr = ipaddress.ip_address(value)
    warnings: tuple[str, ...] = ()
    if not addr.is_global:
        warnings = ("address is private, loopback or otherwise reserved",)
    return Indicator("ip", value, host=value, host_is_ip=True, warnings=warnings)


def normalize_domain(raw: object) -> Indicator:
    text = _clean(raw)
    if any(c in text for c in ":/?#@") and not _is_ip(text):
        # Be forgiving: accept a URL and use its host, but never a path.
        url = normalize_url(text)
        if url.host_is_ip:
            raise InvalidInputError("expected a domain name, got an IP address", "use check_ip")
        assert url.host is not None
        return Indicator("domain", url.host, host=url.host, warnings=("host extracted from URL",))
    host, _ = _split_authority(text)
    value, is_ip = _host_indicator(host)
    if is_ip:
        raise InvalidInputError("expected a domain name, got an IP address", "use check_ip")
    return Indicator("domain", value, host=value)


def normalize_url(raw: object) -> Indicator:
    text = _clean(raw)
    scheme_match = _SCHEME_RE.match(text)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise InvalidInputError(f"unsupported URL scheme {scheme!r}")
        text = text[scheme_match.end() :]
    elif text.startswith("//"):
        text = text[2:]
    elif re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:(?!\d)", text):
        raise InvalidInputError(
            "unsupported or malformed URL scheme", "use http(s)://host/path or a bare host"
        )
    text = text.split("#", 1)[0]
    cut = min((i for i in (text.find("/"), text.find("?")) if i != -1), default=len(text))
    authority, tail = text[:cut], text[cut:]
    if not authority:
        raise InvalidInputError("URL has no host")
    host_raw, _ = _split_authority(authority)
    host, is_ip = _host_indicator(host_raw)
    if tail.startswith("?"):
        tail = "/" + tail
    path = "" if tail in ("", "/") else tail
    value = f"{host}{path}" if path else host
    return Indicator("url", value, host=host, path=path, host_is_ip=is_ip)


def normalize_network(raw: object) -> Indicator:
    text = _clean(raw)
    try:
        value = canonical_network(text)
    except ValueError as exc:
        raise InvalidInputError(f"not a valid CIDR network: {text!r}") from exc
    return Indicator("network", value)


def normalize_indicator(raw: object) -> Indicator:
    """Auto-detect the kind of an indicator (used by the watch list)."""
    text = _clean(raw)
    if "/" in text and "://" not in text:
        head = text.split("/", 1)[0]
        try:
            ipaddress.ip_address(head.strip("[]"))
        except ValueError:
            pass
        else:
            return normalize_network(text)
    try:
        canonical_ip(text)
    except ValueError:
        pass
    else:
        return normalize_ip(text)
    if "://" in text or "/" in text or "?" in text:
        url = normalize_url(text)
        return (
            url
            if url.path
            else Indicator(
                "ip" if url.host_is_ip else "domain",
                url.value,
                host=url.host,
                host_is_ip=url.host_is_ip,
            )
        )
    return normalize_domain(text)


def url_value_candidates(indicator: Indicator) -> list[str]:
    """Stored-form variants of a URL that count as an exact match (slash tolerance)."""
    assert indicator.host is not None
    path = indicator.path
    if not path:
        return []
    bare = path.rstrip("/")
    variants = {path, bare, bare + "/"} if "?" not in path else {path}
    return [f"{indicator.host}{p}" for p in sorted(variants) if p]


def canonical_stored(value: str, type_: str) -> tuple[str, str | None] | None:
    """Normalize a value read from the USOM list; ``None`` if it cannot be used.

    Returns ``(value, host)``. This is intentionally lenient: the upstream data is
    already normalized, so only case, IPv6 compression and stray schemes are fixed.
    """
    text = value.strip()
    # Upstream data is partly crowd-sourced and ends up in tool output read by an LLM:
    # reject anything with whitespace/control characters instead of passing it on.
    if not text or len(text) > _MAX_STORED_URL_LENGTH or _CONTROL_OR_SPACE_RE.search(text):
        return None
    try:
        if type_ in ("ip", "ip6") and "/" in text:
            return canonical_network(text), None
        if type_ in ("ip", "ip6"):
            canonical = canonical_ip(text)
            return canonical, canonical
        if type_ == "ip6net":
            return canonical_network(text), None
        if type_ == "domain":
            host = text.rstrip(".")
            host = host.lower() if host.isascii() else idna.encode(host, uts46=True).decode()
            if not _STORED_DOMAIN_RE.match(host) or ".." in host or host.startswith("."):
                return None
            return host, host
        if type_ == "url":
            scheme_match = _SCHEME_RE.match(text)
            if scheme_match:
                text = text[scheme_match.end() :]
            text = text.split("#", 1)[0]
            cut = min((i for i in (text.find("/"), text.find("?")) if i != -1), default=len(text))
            authority, tail = text[:cut], text[cut:]
            host, _ = _split_authority(authority)
            host = host.lower().rstrip(".")
            if not host:
                return None
            try:
                host = canonical_ip(host)
            except ValueError:
                if not host.isascii():
                    host = idna.encode(host, uts46=True).decode()
            if tail in ("", "/"):
                return host, host
            return f"{host}{tail}", host
    except (ValueError, idna.IDNAError, UnicodeError, InvalidInputError):
        return None
    return None


def domain_candidates(host: str) -> list[tuple[str, str]]:
    """Return ``(candidate, match_type)`` pairs to look up for a domain.

    ``exact`` first, then parents (a listed parent covers its subdomains), then the
    ``www.`` variant. Parents stop at two labels; a bare TLD is never a candidate.
    """
    result: list[tuple[str, str]] = [(host, "exact")]
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        result.append((".".join(labels[i:]), "subdomain"))
    if not host.startswith("www."):
        result.append((f"www.{host}", "www_variant"))
    return result
