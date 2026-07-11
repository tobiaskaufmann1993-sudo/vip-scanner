#!/usr/bin/env python3
"""MezaVPN subscription quality scanner.

The scanner downloads one or more standard V2Ray subscription feeds, removes
functional duplicates, validates supported nodes with Xray-core, measures real
end-to-end HTTPS response latency through each proxy, performs a small download
speed test on the best candidates, and publishes a stable subscription set.

Supported share links: vless://, vmess://, trojan:// and SIP002 ss:// links
without external plugins.
"""

from __future__ import annotations

import argparse
import base64
import collections
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import html
import json
import math
import os
import random
import re
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

SUPPORTED_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")
SCANNER_VERSION = "1.1.0"
UTC = dt.timezone.utc


class ScannerError(RuntimeError):
    pass


class UnsupportedNode(ScannerError):
    pass


@dataclasses.dataclass(slots=True)
class Settings:
    elite_latency_ms: float = 800.0
    max_latency_ms: float = 3000.0
    max_jitter_ms: float = 600.0
    max_output: int = 450
    max_configs: int = 1800
    scan_workers: int = 20
    speed_workers: int = 6
    primary_attempts: int = 3
    retest_attempts: int = 2
    probe_timeout_seconds: float = 7.0
    xray_start_timeout_seconds: float = 4.0
    source_timeout_seconds: float = 25.0
    speed_test_max: int = 450
    speed_test_bytes: int = 262_144
    min_speed_mbps: float = 0.5
    grace_scans: int = 1
    grace_max_age_minutes: int = 120
    catastrophic_ratio: float = 0.15
    max_scan_seconds: int = 1_320
    output_format: str = "base64"
    speed_test_url: str = "https://speed.cloudflare.com/__down?bytes={bytes}"
    probe_urls: tuple[str, ...] = (
        "https://www.gstatic.com/generate_204",
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://detectportal.firefox.com/success.txt",
        "https://captive.apple.com/hotspot-detect.html",
        "https://www.cloudflare.com/cdn-cgi/trace",
    )

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = cls()

        def env_int(name: str, default: int) -> int:
            value = os.getenv(name)
            return int(value) if value not in (None, "") else default

        def env_float(name: str, default: float) -> float:
            value = os.getenv(name)
            return float(value) if value not in (None, "") else default

        probe_urls = tuple(
            item.strip()
            for item in os.getenv("PROBE_URLS", "").splitlines()
            if item.strip()
        ) or defaults.probe_urls

        settings = cls(
            elite_latency_ms=env_float("ELITE_LATENCY_MS", defaults.elite_latency_ms),
            max_latency_ms=env_float("MAX_LATENCY_MS", defaults.max_latency_ms),
            max_jitter_ms=env_float("MAX_JITTER_MS", defaults.max_jitter_ms),
            max_output=env_int("MAX_OUTPUT", defaults.max_output),
            max_configs=env_int("MAX_CONFIGS", defaults.max_configs),
            scan_workers=env_int("SCAN_WORKERS", defaults.scan_workers),
            speed_workers=env_int("SPEED_WORKERS", defaults.speed_workers),
            primary_attempts=env_int("PRIMARY_ATTEMPTS", defaults.primary_attempts),
            retest_attempts=env_int("RETEST_ATTEMPTS", defaults.retest_attempts),
            probe_timeout_seconds=env_float(
                "PROBE_TIMEOUT_SECONDS", defaults.probe_timeout_seconds
            ),
            xray_start_timeout_seconds=env_float(
                "XRAY_START_TIMEOUT_SECONDS", defaults.xray_start_timeout_seconds
            ),
            source_timeout_seconds=env_float(
                "SOURCE_TIMEOUT_SECONDS", defaults.source_timeout_seconds
            ),
            speed_test_max=env_int("SPEED_TEST_MAX", defaults.speed_test_max),
            speed_test_bytes=env_int("SPEED_TEST_BYTES", defaults.speed_test_bytes),
            min_speed_mbps=env_float("MIN_SPEED_MBPS", defaults.min_speed_mbps),
            grace_scans=env_int("GRACE_SCANS", defaults.grace_scans),
            grace_max_age_minutes=env_int(
                "GRACE_MAX_AGE_MINUTES", defaults.grace_max_age_minutes
            ),
            catastrophic_ratio=env_float(
                "CATASTROPHIC_RATIO", defaults.catastrophic_ratio
            ),
            max_scan_seconds=env_int("MAX_SCAN_SECONDS", defaults.max_scan_seconds),
            output_format=os.getenv("OUTPUT_FORMAT", defaults.output_format).strip().lower(),
            speed_test_url=os.getenv("SPEED_TEST_URL", defaults.speed_test_url).strip(),
            probe_urls=probe_urls,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not 0 < self.elite_latency_ms <= self.max_latency_ms:
            raise ScannerError("ELITE_LATENCY_MS must be > 0 and <= MAX_LATENCY_MS")
        if self.max_jitter_ms <= 0:
            raise ScannerError("MAX_JITTER_MS must be positive")
        if self.max_output < 1 or self.max_configs < 1:
            raise ScannerError("MAX_OUTPUT and MAX_CONFIGS must be positive")
        if not 1 <= self.scan_workers <= 50:
            raise ScannerError("SCAN_WORKERS must be between 1 and 50")
        if not 1 <= self.speed_workers <= 20:
            raise ScannerError("SPEED_WORKERS must be between 1 and 20")
        if self.primary_attempts < 2 or self.retest_attempts < 0:
            raise ScannerError("Probe attempt counts are invalid")
        if self.output_format not in {"base64", "raw"}:
            raise ScannerError("OUTPUT_FORMAT must be base64 or raw")
        if not self.probe_urls:
            raise ScannerError("At least one PROBE_URL is required")


@dataclasses.dataclass(slots=True)
class Node:
    uri: str
    protocol: str
    name: str
    fingerprint: str
    outbound: dict[str, Any]
    host: str
    port: int
    source_ids: set[str] = dataclasses.field(default_factory=set)


@dataclasses.dataclass(slots=True)
class ProbeSample:
    ok: bool
    latency_ms: float | None = None
    total_ms: float | None = None
    http_code: int | None = None
    reason: str = ""


@dataclasses.dataclass(slots=True)
class TestResult:
    fingerprint: str
    passed: bool
    success_count: int
    attempt_count: int
    latency_ms: float | None
    jitter_ms: float | None
    success_rate: float
    reason: str
    speed_mbps: float | None = None
    speed_samples: list[float] = dataclasses.field(default_factory=list)
    speed_confirmed_slow: bool = False
    exit_country: str | None = None


@dataclasses.dataclass(slots=True)
class SourceResult:
    source_id: str
    ok: bool
    links: list[str]
    reason: str = ""


_PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with _PRINT_LOCK:
        print(message, flush=True)


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def b64decode_loose(value: str) -> bytes:
    compact = re.sub(r"\s+", "", value)
    compact += "=" * (-len(compact) % 4)
    errors: list[Exception] = []
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(compact.encode("ascii"))
        except Exception as exc:  # pragma: no cover - decoder fallback
            errors.append(exc)
    raise ValueError(f"invalid base64: {errors[-1] if errors else 'unknown'}")


def b64encode_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def qfirst(query: dict[str, list[str]], *names: str, default: str = "") -> str:
    lower = {key.lower(): values for key, values in query.items()}
    for name in names:
        values = lower.get(name.lower())
        if values:
            return values[0]
    return default


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def source_id_for(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


# ISO 3166-1 alpha-2 codes. Keeping this local avoids a runtime dependency or
# an external geolocation API for parsing names supplied by collectors.
ISO_COUNTRY_CODES = frozenset(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split()
)

COUNTRY_NAME_ALIASES = {
    "afghanistan": "AF", "albania": "AL", "algeria": "DZ", "argentina": "AR",
    "armenia": "AM", "australia": "AU", "austria": "AT", "azerbaijan": "AZ",
    "bahrain": "BH", "bangladesh": "BD", "belarus": "BY", "belgium": "BE",
    "bolivia": "BO", "bosnia": "BA", "brazil": "BR", "bulgaria": "BG",
    "cambodia": "KH", "cameroon": "CM", "canada": "CA", "chile": "CL",
    "china": "CN", "colombia": "CO", "costa rica": "CR", "croatia": "HR",
    "cuba": "CU", "cyprus": "CY", "czech republic": "CZ", "czechia": "CZ",
    "denmark": "DK", "dominican republic": "DO", "ecuador": "EC", "egypt": "EG",
    "estonia": "EE", "finland": "FI", "france": "FR", "georgia": "GE",
    "germany": "DE", "ghana": "GH", "greece": "GR", "hong kong": "HK",
    "hungary": "HU", "iceland": "IS", "india": "IN", "indonesia": "ID",
    "iran": "IR", "iraq": "IQ", "ireland": "IE", "israel": "IL", "italy": "IT",
    "japan": "JP", "jordan": "JO", "kazakhstan": "KZ", "kenya": "KE",
    "kuwait": "KW", "kyrgyzstan": "KG", "laos": "LA", "latvia": "LV",
    "lebanon": "LB", "lithuania": "LT", "luxembourg": "LU", "macao": "MO",
    "macau": "MO", "malaysia": "MY", "maldives": "MV", "malta": "MT",
    "mexico": "MX", "moldova": "MD", "monaco": "MC", "mongolia": "MN",
    "montenegro": "ME", "morocco": "MA", "myanmar": "MM", "nepal": "NP",
    "netherlands": "NL", "new zealand": "NZ", "nigeria": "NG",
    "north korea": "KP", "north macedonia": "MK", "norway": "NO", "oman": "OM",
    "pakistan": "PK", "panama": "PA", "paraguay": "PY", "peru": "PE",
    "philippines": "PH", "poland": "PL", "portugal": "PT", "puerto rico": "PR",
    "qatar": "QA", "romania": "RO", "russia": "RU", "saudi arabia": "SA",
    "serbia": "RS", "singapore": "SG", "slovakia": "SK", "slovenia": "SI",
    "south africa": "ZA", "south korea": "KR", "spain": "ES", "sri lanka": "LK",
    "sweden": "SE", "switzerland": "CH", "syria": "SY", "taiwan": "TW",
    "tajikistan": "TJ", "thailand": "TH", "tunisia": "TN", "turkey": "TR",
    "turkiye": "TR", "turkmenistan": "TM", "ukraine": "UA",
    "united arab emirates": "AE", "uae": "AE", "united kingdom": "GB",
    "great britain": "GB", "england": "GB", "united states": "US",
    "united states of america": "US", "usa": "US", "uruguay": "UY",
    "uzbekistan": "UZ", "venezuela": "VE", "vietnam": "VN",
    "andorra": "AD", "angola": "AO", "antigua and barbuda": "AG",
    "bahamas": "BS", "barbados": "BB", "belize": "BZ", "benin": "BJ",
    "bhutan": "BT", "botswana": "BW", "brunei": "BN", "burkina faso": "BF",
    "burundi": "BI", "cape verde": "CV", "cabo verde": "CV",
    "central african republic": "CF", "chad": "TD", "comoros": "KM",
    "democratic republic of the congo": "CD", "dr congo": "CD", "drc": "CD",
    "republic of the congo": "CG", "congo brazzaville": "CG", "congo kinshasa": "CD",
    "dominica": "DM", "djibouti": "DJ", "el salvador": "SV",
    "equatorial guinea": "GQ", "eritrea": "ER", "eswatini": "SZ",
    "swaziland": "SZ", "ethiopia": "ET", "fiji": "FJ", "gabon": "GA",
    "gambia": "GM", "grenada": "GD", "guatemala": "GT", "guinea": "GN",
    "guinea bissau": "GW", "guyana": "GY", "haiti": "HT", "honduras": "HN",
    "ivory coast": "CI", "cote d ivoire": "CI", "cote divoire": "CI", "jamaica": "JM",
    "kiribati": "KI", "lesotho": "LS", "liberia": "LR", "libya": "LY",
    "liechtenstein": "LI", "madagascar": "MG", "malawi": "MW", "mali": "ML",
    "marshall islands": "MH", "mauritania": "MR", "mauritius": "MU",
    "micronesia": "FM", "federated states of micronesia": "FM",
    "mozambique": "MZ", "namibia": "NA", "nauru": "NR", "nicaragua": "NI",
    "niger": "NE", "palau": "PW", "papua new guinea": "PG", "rwanda": "RW",
    "saint kitts and nevis": "KN", "saint lucia": "LC",
    "saint vincent and the grenadines": "VC", "samoa": "WS", "san marino": "SM",
    "sao tome and principe": "ST", "senegal": "SN", "seychelles": "SC",
    "sierra leone": "SL", "solomon islands": "SB", "somalia": "SO",
    "south sudan": "SS", "sudan": "SD", "suriname": "SR", "tanzania": "TZ",
    "timor leste": "TL", "east timor": "TL", "togo": "TG", "tonga": "TO",
    "trinidad and tobago": "TT", "tuvalu": "TV", "uganda": "UG", "vanuatu": "VU",
    "vatican city": "VA", "holy see": "VA", "yemen": "YE", "zambia": "ZM",
    "zimbabwe": "ZW", "kosovo": "XK", "palestine": "PS",
    # Common collector spellings and local-language names.
    "holland": "NL", "nederland": "NL", "deutschland": "DE", "osterreich": "AT",
    "schweiz": "CH", "suisse": "CH", "espana": "ES", "polska": "PL",
    "cesko": "CZ", "rossiya": "RU", "viet nam": "VN", "korea": "KR",
    # Frequently seen territories and special regions.
    "aland islands": "AX", "american samoa": "AS", "anguilla": "AI",
    "antarctica": "AQ", "aruba": "AW", "bermuda": "BM", "bonaire": "BQ",
    "british virgin islands": "VG", "cayman islands": "KY", "curacao": "CW",
    "faroe islands": "FO", "french guiana": "GF", "french polynesia": "PF",
    "gibraltar": "GI", "greenland": "GL", "guadeloupe": "GP", "guam": "GU",
    "guernsey": "GG", "isle of man": "IM", "jersey": "JE", "martinique": "MQ",
    "mayotte": "YT", "new caledonia": "NC", "northern mariana islands": "MP",
    "reunion": "RE", "saint martin": "MF", "sint maarten": "SX",
    "turks and caicos islands": "TC", "us virgin islands": "VI",
}

# XK is widely returned for Kosovo by IP geolocation providers even though it
# is a user-assigned rather than officially allocated ISO 3166-1 code.
ISO_COUNTRY_CODES = frozenset((*ISO_COUNTRY_CODES, "XK"))


def flag_for_country(code: str) -> str:
    code = code.upper()
    if code not in ISO_COUNTRY_CODES:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def country_from_name(name: str) -> str | None:
    value = html.unescape(urllib.parse.unquote(name or ""))
    # A flag is the strongest source-name signal and may be followed by noisy
    # provider/service country codes that refer to something else.
    for index in range(len(value) - 1):
        first, second = ord(value[index]), ord(value[index + 1])
        if 0x1F1E6 <= first <= 0x1F1FF and 0x1F1E6 <= second <= 0x1F1FF:
            code = chr(first - 0x1F1E6 + ord("A")) + chr(second - 0x1F1E6 + ord("A"))
            if code in ISO_COUNTRY_CODES:
                return code

    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"[^a-z]+", " ", ascii_value.lower()).strip()
    # Prefer longer aliases so "united states of america" wins over shorter
    # phrases and country words embedded in collector labels remain usable.
    for alias in sorted(COUNTRY_NAME_ALIASES, key=len, reverse=True):
        if re.search(rf"(?:^|\s){re.escape(alias)}(?:$|\s)", normalized):
            return COUNTRY_NAME_ALIASES[alias]

    for token in re.findall(r"(?<![A-Za-z0-9])([A-Za-z]{2})(?![A-Za-z0-9])", value):
        code = token.upper()
        if code == "UK":
            return "GB"
        if code in ISO_COUNTRY_CODES:
            return code
    return None


def set_uri_display_name(uri: str, name: str) -> str:
    if uri.lower().startswith("vmess://"):
        encoded = uri[len("vmess://") :].split("#", 1)[0].strip()
        data = json.loads(b64decode_loose(encoded).decode("utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("invalid VMess payload")
        data["ps"] = name
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        return "vmess://" + b64encode_text(payload).rstrip("=")

    parsed = urllib.parse.urlsplit(uri)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.query, urllib.parse.quote(name, safe=""))
    )


def extract_source_urls(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            raise ScannerError("SUB_URLS JSON must be an array")
        candidates = [str(item).strip() for item in parsed]
    else:
        candidates = [line.strip() for line in raw.splitlines()]
    urls: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate.startswith("#"):
            continue
        parsed = urllib.parse.urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ScannerError("Every SUB_URLS line must be a valid http(s) URL")
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
    return urls


def fetch_bytes(url: str, timeout: float, retries: int = 3) -> bytes:
    headers = {
        "User-Agent": "MezaVPN-Quality-Scanner/1.0",
        "Accept": "text/plain, application/octet-stream, */*",
        "Cache-Control": "no-cache",
    }
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if response.status >= 400:
                    raise ScannerError(f"HTTP {response.status}")
                return response.read(20 * 1024 * 1024)
        except Exception as exc:
            last_error = exc
            if attempt + 1 < retries:
                time.sleep(1.5 * (attempt + 1))
    raise ScannerError(f"source download failed: {type(last_error).__name__}")


def decode_subscription(payload: bytes) -> str:
    text = payload.decode("utf-8-sig", errors="ignore").strip()
    if any(prefix in text.lower() for prefix in SUPPORTED_SCHEMES):
        return text

    candidate = text
    for _ in range(2):
        try:
            decoded = b64decode_loose(candidate).decode("utf-8-sig", errors="ignore").strip()
        except Exception:
            break
        if any(prefix in decoded.lower() for prefix in SUPPORTED_SCHEMES):
            return decoded
        candidate = decoded
    return text


def extract_links(text: str) -> list[str]:
    links: list[str] = []
    for line in text.replace("\r", "\n").split("\n"):
        value = line.strip().strip("\ufeff")
        if not value or value.startswith("#"):
            continue
        # Some collectors embed share links in HTML/XML-derived text and leave
        # query separators escaped (``&amp;``).  Without unescaping first, every
        # parameter after the first one becomes part of the previous value and
        # Xray is built with the wrong transport/TLS settings.
        value = html.unescape(value)
        if "%3A%2F%2F" in value.upper():
            value = urllib.parse.unquote(value)
        lower = value.lower()
        if lower.startswith(SUPPORTED_SCHEMES):
            links.append(value)
            continue
        for match in re.finditer(r"(?i)(?:vless|vmess|trojan|ss)://[^\s]+", value):
            links.append(match.group(0))
    return links


def fetch_source(url: str, settings: Settings) -> SourceResult:
    sid = source_id_for(url)
    try:
        payload = fetch_bytes(url, settings.source_timeout_seconds)
        links = extract_links(decode_subscription(payload))
        if not links:
            return SourceResult(sid, False, [], "no supported links found")
        return SourceResult(sid, True, links)
    except Exception as exc:
        return SourceResult(sid, False, [], str(exc))


def make_tls_settings(
    security: str,
    query: dict[str, list[str]],
    server_host: str,
) -> tuple[str, dict[str, Any]]:
    security = (security or "none").lower()
    if security in {"", "none"}:
        return "none", {}

    server_name = qfirst(query, "sni", "serverName", default=server_host)
    fingerprint = qfirst(query, "fp", "fingerprint")
    alpn = split_csv(qfirst(query, "alpn"))

    if security == "tls":
        settings: dict[str, Any] = {
            "serverName": server_name,
            "allowInsecure": parse_bool(qfirst(query, "allowInsecure"), False),
        }
        if fingerprint:
            settings["fingerprint"] = fingerprint
        if alpn:
            settings["alpn"] = alpn
        return "tls", {"tlsSettings": settings}

    if security == "reality":
        public_key = qfirst(query, "pbk", "publicKey", "password")
        short_id = qfirst(query, "sid", "shortId")
        if not public_key or not server_name:
            raise UnsupportedNode("REALITY link is missing public key or SNI")
        settings = {
            "show": False,
            "serverName": server_name,
            "fingerprint": fingerprint or "chrome",
            "password": public_key,
            "shortId": short_id,
            "spiderX": qfirst(query, "spx", "spiderX", default="/"),
        }
        mldsa = qfirst(query, "pqv", "mldsa65Verify")
        if mldsa:
            settings["mldsa65Verify"] = mldsa
        return "reality", {"realitySettings": settings}

    raise UnsupportedNode(f"unsupported transport security: {security}")


def make_stream_settings(
    network: str,
    security: str,
    query: dict[str, list[str]],
    server_host: str,
) -> dict[str, Any]:
    network = (network or "tcp").lower()
    aliases = {
        "tcp": "raw",
        "ws": "websocket",
        "kcp": "mkcp",
        "h2": "http",  # legacy Xray transport alias
        "splithttp": "xhttp",
    }
    network = aliases.get(network, network)
    supported = {"raw", "websocket", "grpc", "httpupgrade", "xhttp", "http", "mkcp", "quic"}
    if network not in supported:
        raise UnsupportedNode(f"unsupported transport: {network}")

    stream: dict[str, Any] = {"network": network}
    normalized_security, security_settings = make_tls_settings(security, query, server_host)
    stream["security"] = normalized_security
    stream.update(security_settings)

    host = qfirst(query, "host")
    path = urllib.parse.unquote(qfirst(query, "path", default="/")) or "/"
    header_type = qfirst(query, "headerType", "header", default="none").lower()

    if network == "websocket":
        ws: dict[str, Any] = {"path": path}
        if host:
            ws["host"] = host
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        service_name = qfirst(query, "serviceName") or path.lstrip("/")
        grpc: dict[str, Any] = {"serviceName": service_name}
        mode = qfirst(query, "mode")
        if mode.lower() in {"multi", "gun"}:
            grpc["multiMode"] = True
        authority = qfirst(query, "authority")
        if authority:
            grpc["authority"] = authority
        stream["grpcSettings"] = grpc
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host or server_host}
    elif network == "xhttp":
        xhttp: dict[str, Any] = {"path": path, "host": host or server_host}
        mode = qfirst(query, "mode")
        if mode:
            xhttp["mode"] = mode
        extra = qfirst(query, "extra")
        if extra:
            try:
                xhttp["extra"] = json.loads(urllib.parse.unquote(extra))
            except json.JSONDecodeError:
                pass
        stream["xhttpSettings"] = xhttp
    elif network == "http":
        http_settings: dict[str, Any] = {"path": path}
        if host:
            http_settings["host"] = split_csv(host) or [host]
        stream["httpSettings"] = http_settings
    elif network == "raw" and header_type == "http":
        stream["rawSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": split_csv(path) or [path],
                    "headers": {"Host": split_csv(host) or ([host] if host else [server_host])},
                },
            }
        }
    elif network == "mkcp":
        # Modern Xray removed legacy mKCP header/seed fields. Basic mKCP links
        # remain testable; legacy-obfuscated links are allowed to fail validation
        # rather than being reported as healthy incorrectly.
        kcp: dict[str, Any] = {}
        for key, minimum, maximum in (("mtu", 576, 1460), ("tti", 10, 5000)):
            value = qfirst(query, key)
            if value.isdigit() and minimum <= int(value) <= maximum:
                kcp[key] = int(value)
        stream["kcpSettings"] = kcp
    elif network == "quic":
        stream["quicSettings"] = {
            "security": qfirst(query, "quicSecurity", "security", default="none"),
            "key": qfirst(query, "key"),
            "header": {"type": header_type if header_type != "none" else "none"},
        }

    return stream


def _parsed_host_port(parsed: urllib.parse.SplitResult) -> tuple[str, int]:
    host = parsed.hostname or ""
    try:
        port = parsed.port or 0
    except ValueError as exc:
        raise UnsupportedNode("invalid port") from exc
    if not host or not (1 <= port <= 65535):
        raise UnsupportedNode("missing or invalid host/port")
    return host, port


def _node_from_outbound(
    uri: str,
    protocol: str,
    name: str,
    outbound: dict[str, Any],
    host: str,
    port: int,
) -> Node:
    canonical = {key: value for key, value in outbound.items() if key != "tag"}
    fingerprint = hashlib.sha256(stable_json(canonical).encode("utf-8")).hexdigest()
    return Node(uri, protocol, name, fingerprint, outbound, host, port)


def parse_vless_or_trojan(uri: str, protocol: str) -> Node:
    parsed = urllib.parse.urlsplit(uri)
    host, port = _parsed_host_port(parsed)
    credential = urllib.parse.unquote(parsed.username or "")
    if not credential:
        raise UnsupportedNode("missing credential")
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    network = qfirst(query, "type", "network", default="tcp")
    security = qfirst(query, "security", default="none")
    stream = make_stream_settings(network, security, query, host)
    name = urllib.parse.unquote(parsed.fragment or "").strip()

    if protocol == "vless":
        settings: dict[str, Any] = {
            "address": host,
            "port": port,
            "id": credential,
            "encryption": qfirst(query, "encryption", default="none") or "none",
            "level": 0,
        }
        flow = qfirst(query, "flow")
        if flow:
            settings["flow"] = flow
    else:
        settings = {
            "address": host,
            "port": port,
            "password": credential,
            "level": 0,
        }

    outbound = {
        "tag": "proxy",
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream,
        "mux": {"enabled": False},
    }
    return _node_from_outbound(uri, protocol, name, outbound, host, port)


def parse_vmess(uri: str) -> Node:
    encoded = uri[len("vmess://") :].split("#", 1)[0].strip()
    try:
        data = json.loads(b64decode_loose(encoded).decode("utf-8-sig"))
    except Exception as exc:
        raise UnsupportedNode("invalid VMess JSON") from exc
    if not isinstance(data, dict):
        raise UnsupportedNode("invalid VMess payload")

    host = str(data.get("add", "")).strip()
    try:
        port = int(data.get("port", 0))
    except (TypeError, ValueError) as exc:
        raise UnsupportedNode("invalid VMess port") from exc
    user_id = str(data.get("id", "")).strip()
    if not host or not (1 <= port <= 65535) or not user_id:
        raise UnsupportedNode("VMess is missing host, port or id")

    query: dict[str, list[str]] = {}
    for source_key, target_key in (
        ("host", "host"),
        ("path", "path"),
        ("sni", "sni"),
        ("fp", "fp"),
        ("alpn", "alpn"),
        ("type", "headerType"),
    ):
        value = data.get(source_key)
        if value not in (None, ""):
            query[target_key] = [str(value)]

    network = str(data.get("net") or "tcp")
    tls_value = str(data.get("tls") or "none").lower()
    security = "tls" if tls_value in {"tls", "1", "true"} else tls_value
    stream = make_stream_settings(network, security, query, host)
    try:
        alter_id = int(data.get("aid", 0) or 0)
    except (TypeError, ValueError):
        alter_id = 0
    settings: dict[str, Any] = {
        "address": host,
        "port": port,
        "id": user_id,
        "security": str(data.get("scy") or data.get("security") or "auto"),
        "level": 0,
    }
    # alterId is obsolete. Keeping a non-zero value would make a modern-core
    # result ambiguous, so such links are rejected instead of misclassified.
    if alter_id != 0:
        raise UnsupportedNode("legacy VMess alterId is not supported by modern Xray")
    outbound = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": settings,
        "streamSettings": stream,
        "mux": {"enabled": False},
    }
    return _node_from_outbound(
        uri, "vmess", str(data.get("ps") or "").strip(), outbound, host, port
    )


def parse_ss(uri: str) -> Node:
    parsed = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if qfirst(query, "plugin"):
        raise UnsupportedNode("Shadowsocks plugins are not supported by Xray directly")

    fragment = urllib.parse.unquote(parsed.fragment or "").strip()
    raw = uri[len("ss://") :]
    raw = raw.split("#", 1)[0].split("?", 1)[0]

    method = password = host = ""
    port = 0
    if "@" in raw:
        userinfo, server = raw.rsplit("@", 1)
        try:
            decoded_userinfo = b64decode_loose(userinfo).decode("utf-8") if ":" not in userinfo else urllib.parse.unquote(userinfo)
        except Exception as exc:
            raise UnsupportedNode("invalid Shadowsocks userinfo") from exc
        if ":" not in decoded_userinfo:
            raise UnsupportedNode("invalid Shadowsocks method/password")
        method, password = decoded_userinfo.split(":", 1)
        server_parsed = urllib.parse.urlsplit("//" + server)
        host, port = _parsed_host_port(server_parsed)
    else:
        try:
            decoded = b64decode_loose(raw).decode("utf-8")
        except Exception as exc:
            raise UnsupportedNode("invalid Shadowsocks payload") from exc
        match = re.match(r"^([^:]+):(.+)@\[?([^\]]+)\]?:([0-9]+)$", decoded)
        if not match:
            raise UnsupportedNode("invalid Shadowsocks legacy format")
        method, password, host, port_text = match.groups()
        port = int(port_text)

    method = urllib.parse.unquote(method).strip()
    password = urllib.parse.unquote(password)
    if not method or not password or not host or not (1 <= port <= 65535):
        raise UnsupportedNode("Shadowsocks is missing required fields")

    outbound = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "address": host,
            "port": port,
            "method": method,
            "password": password,
            "level": 0,
        },
        "mux": {"enabled": False},
    }
    return _node_from_outbound(uri, "ss", fragment, outbound, host, port)


def parse_node(uri: str) -> Node:
    lower = uri.lower()
    if lower.startswith("vless://"):
        return parse_vless_or_trojan(uri, "vless")
    if lower.startswith("trojan://"):
        return parse_vless_or_trojan(uri, "trojan")
    if lower.startswith("vmess://"):
        return parse_vmess(uri)
    if lower.startswith("ss://"):
        return parse_ss(uri)
    raise UnsupportedNode("unsupported scheme")


def load_previous_state(url: str | None, timeout: float) -> dict[str, Any]:
    if not url:
        return {}
    try:
        payload = fetch_bytes(url, timeout=min(timeout, 12), retries=1)
        state = json.loads(payload.decode("utf-8"))
        if isinstance(state, dict) and state.get("version") == 1:
            return state
    except Exception:
        pass
    return {}


def available_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_xray_config(node: Node, socks_port: int) -> dict[str, Any]:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "sniffing": {"enabled": False},
            }
        ],
        "outbounds": [node.outbound],
    }


def wait_for_port(proc: subprocess.Popen[bytes], port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.06)
    return False


class XraySession:
    def __init__(self, xray_bin: str, node: Node, startup_timeout: float):
        self.xray_bin = xray_bin
        self.node = node
        self.startup_timeout = startup_timeout
        self.tempdir: tempfile.TemporaryDirectory[str] | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self.port: int | None = None

    def __enter__(self) -> int:
        self.tempdir = tempfile.TemporaryDirectory(prefix="meza-xray-")
        self.port = available_local_port()
        config_path = Path(self.tempdir.name) / "config.json"
        config_path.write_text(
            json.dumps(build_xray_config(self.node, self.port), ensure_ascii=False),
            encoding="utf-8",
        )
        self.proc = subprocess.Popen(
            [self.xray_bin, "run", "-config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if not wait_for_port(self.proc, self.port, self.startup_timeout):
            self.close()
            raise ScannerError("xray failed to start")
        return self.port

    def close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=1)
        if self.tempdir is not None:
            self.tempdir.cleanup()
        self.proc = None
        self.tempdir = None

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def curl_measure(
    socks_port: int,
    url: str,
    timeout: float,
    expected_min_bytes: int = 0,
) -> tuple[bool, dict[str, float | int | str], str]:
    marker = "__MEZA_METRICS__"
    fmt = marker + "%{http_code}\t%{time_starttransfer}\t%{time_total}\t%{size_download}\t%{speed_download}\n"
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "3",
        "--http1.1",
        "--proxy",
        f"socks5h://127.0.0.1:{socks_port}",
        "--connect-timeout",
        str(min(4.0, timeout)),
        "--max-time",
        str(timeout),
        "--output",
        "/dev/null",
        "--write-out",
        fmt,
        "--user-agent",
        "MezaVPN-Quality-Scanner/1.0",
        url,
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2.0,
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return False, {}, "curl timeout"

    output = completed.stdout
    position = output.rfind(marker)
    if position < 0:
        return False, {}, "missing curl metrics"
    fields = output[position + len(marker) :].strip().split("\t")
    if len(fields) != 5:
        return False, {}, "invalid curl metrics"
    try:
        code = int(fields[0])
        ttfb = float(fields[1])
        total = float(fields[2])
        size = int(float(fields[3]))
        speed = float(fields[4])
    except ValueError:
        return False, {}, "unparseable curl metrics"

    accepted_code = code in {200, 204}
    enough_data = size >= expected_min_bytes if expected_min_bytes else True
    ok = completed.returncode == 0 and accepted_code and enough_data
    metrics: dict[str, float | int | str] = {
        "http_code": code,
        "ttfb_seconds": ttfb,
        "total_seconds": total,
        "size_download": size,
        "speed_download": speed,
    }
    if not ok:
        stderr = completed.stderr.strip().splitlines()
        reason = stderr[-1][:140] if stderr else f"HTTP {code}"
        if accepted_code and not enough_data:
            reason = "speed endpoint returned too few bytes"
        return False, metrics, reason
    return True, metrics, ""


def probe_once(port: int, url: str, settings: Settings) -> ProbeSample:
    ok, metrics, reason = curl_measure(port, url, settings.probe_timeout_seconds)
    if not ok:
        return ProbeSample(False, reason=reason)
    return ProbeSample(
        True,
        latency_ms=float(metrics["ttfb_seconds"]) * 1000.0,
        total_ms=float(metrics["total_seconds"]) * 1000.0,
        http_code=int(metrics["http_code"]),
    )


def detect_exit_country(socks_port: int, timeout: float) -> str | None:
    """Return the proxy egress ISO country reported by Cloudflare trace."""
    command = [
        "curl", "--silent", "--show-error", "--fail", "--http1.1",
        "--proxy", f"socks5h://127.0.0.1:{socks_port}",
        "--connect-timeout", str(min(4.0, timeout)), "--max-time", str(timeout),
        "--user-agent", "MezaVPN-Quality-Scanner/1.0",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2.0,
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return None
    if completed.returncode != 0:
        return None
    match = re.search(r"(?m)^loc=([A-Z]{2})\s*$", completed.stdout)
    code = match.group(1) if match else ""
    return code if code in ISO_COUNTRY_CODES else None


def summarize_samples(samples: list[ProbeSample]) -> tuple[int, float | None, float | None, float]:
    successful = [sample.latency_ms for sample in samples if sample.ok and sample.latency_ms is not None]
    success_count = len(successful)
    success_rate = success_count / len(samples) if samples else 0.0
    if not successful:
        return 0, None, None, success_rate
    ordered = sorted(successful)
    median = statistics.median(ordered)
    # With four or more successful samples, ignore one worst high-latency
    # outlier when calculating stability. The median still uses all samples.
    stable_values = ordered[:-1] if len(ordered) >= 4 else ordered
    jitter = max(stable_values) - min(stable_values) if len(stable_values) > 1 else 0.0
    return success_count, float(median), float(jitter), success_rate


def test_node(node: Node, xray_bin: str, settings: Settings) -> TestResult:
    samples: list[ProbeSample] = []
    try:
        with XraySession(xray_bin, node, settings.xray_start_timeout_seconds) as port:
            seed = int(node.fingerprint[:8], 16)
            urls = list(settings.probe_urls)
            random.Random(seed).shuffle(urls)
            for index in range(settings.primary_attempts):
                samples.append(probe_once(port, urls[index % len(urls)], settings))

            success_count, median, jitter, success_rate = summarize_samples(samples)
            needs_retest = (
                success_count < settings.primary_attempts
                or median is None
                or median > settings.elite_latency_ms
                or (jitter is not None and jitter > settings.max_jitter_ms * 0.6)
            )
            if needs_retest:
                for index in range(settings.retest_attempts):
                    samples.append(
                        probe_once(
                            port,
                            urls[(settings.primary_attempts + index) % len(urls)],
                            settings,
                        )
                    )
    except Exception as exc:
        return TestResult(
            node.fingerprint,
            False,
            0,
            max(1, len(samples)),
            None,
            None,
            0.0,
            "confirmed_unreachable",
        )

    success_count, median, jitter, success_rate = summarize_samples(samples)
    failures = len(samples) - success_count
    minimum_successes = settings.primary_attempts
    if success_count == 0:
        reason = "confirmed_unreachable"
    elif success_count < minimum_successes:
        reason = "insufficient_successes"
    elif failures > 1 or success_rate < 0.75:
        reason = "unstable"
    elif median is None or median > settings.max_latency_ms:
        reason = "consistently_high_latency"
    elif jitter is not None and jitter > settings.max_jitter_ms:
        reason = "unstable_jitter"
    else:
        reason = "ok"
    stable_enough = reason == "ok"
    return TestResult(
        node.fingerprint,
        stable_enough,
        success_count,
        len(samples),
        median,
        jitter,
        success_rate,
        reason,
    )


def speed_test_node(
    node: Node, xray_bin: str, settings: Settings
) -> tuple[float | None, list[float], bool, str | None]:
    samples: list[float] = []
    exit_country: str | None = None
    try:
        with XraySession(xray_bin, node, settings.xray_start_timeout_seconds) as port:
            exit_country = detect_exit_country(
                port, min(6.0, settings.probe_timeout_seconds)
            )
            url = settings.speed_test_url.format(bytes=settings.speed_test_bytes)
            for _ in range(2):
                ok, metrics, _ = curl_measure(
                    port,
                    url,
                    timeout=max(8.0, settings.probe_timeout_seconds + 3.0),
                    expected_min_bytes=int(settings.speed_test_bytes * 0.80),
                )
                if ok:
                    mbps = float(metrics["speed_download"]) * 8.0 / 1_000_000.0
                    if math.isfinite(mbps) and mbps > 0:
                        samples.append(mbps)
                if samples and samples[-1] >= settings.min_speed_mbps:
                    break
    except Exception:
        return None, [], False, exit_country

    if not samples:
        return None, [], False, exit_country
    measured = statistics.median(samples)
    confirmed_slow = len(samples) >= 2 and max(samples) < settings.min_speed_mbps
    return float(measured), samples, confirmed_slow, exit_country


def normalize_published_names(
    records: list[dict[str, Any]], results: dict[str, TestResult]
) -> tuple[int, int]:
    counters: collections.Counter[str] = collections.Counter()
    detected = 0
    unknown = 0
    for record in records:
        fingerprint = str(record.get("fingerprint", ""))
        result = results.get(fingerprint)
        code = result.exit_country if result is not None else None
        if not code:
            code = country_from_name(str(record.get("name", "")))
        if code not in ISO_COUNTRY_CODES:
            code = "UN"
            unknown += 1
        else:
            detected += 1
        counters[code] += 1
        display_name = f"{flag_for_country(code)} {code} | Server {counters[code]}"
        try:
            record["uri"] = set_uri_display_name(str(record["uri"]), display_name)
        except Exception:
            # A URI was already parsed successfully, but retaining the original
            # is safer than dropping a healthy node if display-name rewriting
            # ever encounters a collector-specific edge case.
            pass
        record["name"] = display_name
        record["country"] = code
    return detected, unknown


def record_score(record: dict[str, Any], settings: Settings) -> float:
    latency = float(record.get("latency_ms") or settings.max_latency_ms)
    jitter = float(record.get("jitter_ms") or 0.0)
    success_rate = float(record.get("success_rate") or 0.0)
    speed = record.get("speed_mbps")

    # Latency dominates ranking. Throughput only breaks close quality ties.
    latency_score = max(0.0, 1.0 - latency / settings.max_latency_ms) * 100.0
    stability_score = success_rate * 15.0 - min(10.0, jitter / 75.0)
    elite_bonus = 15.0 if latency <= settings.elite_latency_ms else 0.0
    speed_bonus = 0.0
    if isinstance(speed, (int, float)) and speed > 0:
        speed_bonus = min(8.0, math.log2(1.0 + float(speed)) * 2.0)
    grace_penalty = 30.0 if record.get("status") == "grace" else 0.0
    return round(latency_score + stability_score + elite_bonus + speed_bonus - grace_penalty, 5)


def parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def previous_record_is_fresh(record: dict[str, Any], settings: Settings) -> bool:
    timestamp = parse_iso(str(record.get("last_success", "")))
    if timestamp is None:
        return False
    age = utc_now() - timestamp.astimezone(UTC)
    return age <= dt.timedelta(minutes=settings.grace_max_age_minutes)


def make_record(node: Node, result: TestResult, now: str) -> dict[str, Any]:
    return {
        "uri": node.uri,
        "protocol": node.protocol,
        "name": node.name,
        "source_ids": sorted(node.source_ids),
        "status": "healthy",
        "last_success": now,
        "failure_streak": 0,
        "latency_ms": round(float(result.latency_ms or 0.0), 2),
        "jitter_ms": round(float(result.jitter_ms or 0.0), 2),
        "success_rate": round(float(result.success_rate), 4),
        "attempts": result.attempt_count,
        "speed_mbps": round(result.speed_mbps, 3) if result.speed_mbps is not None else None,
    }


def write_outputs(
    output_dir: Path,
    records: list[dict[str, Any]],
    all_records: dict[str, dict[str, Any]],
    status: dict[str, Any],
    suspicious_streak: int,
    settings: Settings,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = "\n".join(str(record["uri"]) for record in records)
    if raw:
        raw += "\n"
    encoded = b64encode_text(raw)

    (output_dir / "sub-raw.txt").write_text(raw, encoding="utf-8", newline="\n")
    (output_dir / "sub-base64.txt").write_text(encoded + "\n", encoding="ascii", newline="\n")
    primary = encoded + "\n" if settings.output_format == "base64" else raw
    (output_dir / "sub.txt").write_text(primary, encoding="utf-8", newline="\n")

    state = {
        "version": 1,
        "scanner_version": SCANNER_VERSION,
        "generated_at": status["generated_at"],
        "suspicious_streak": suspicious_streak,
        "selected": [record["fingerprint"] for record in records],
        "nodes": all_records,
    }
    (output_dir / "state.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output_dir / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output_dir / "robots.txt").write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")

    status_html = html.escape(json.dumps(status, ensure_ascii=False, indent=2))
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MezaVPN Subscription Status</title><style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 18px;line-height:1.55}}
pre{{white-space:pre-wrap;background:#f4f4f5;padding:18px;border-radius:12px;overflow:auto}}
a{{display:inline-block;margin-right:14px}}
</style></head><body><h1>MezaVPN Subscription Status</h1>
<p><a href="sub.txt">sub.txt</a><a href="sub-raw.txt">sub-raw.txt</a><a href="status.json">status.json</a></p>
<pre>{status_html}</pre></body></html>"""
    (output_dir / "index.html").write_text(page, encoding="utf-8")

    summary_lines = [
        "# MezaVPN scan result",
        "",
        f"- Generated: `{status['generated_at']}`",
        f"- Sources successful: `{status['sources']['successful']}/{status['sources']['total']}`",
        f"- Unique supported configs: `{status['configs']['unique_supported']}`",
        f"- Passed current tests: `{status['configs']['passed_current']}`",
        f"- Published: `{status['configs']['published']}`",
        f"- Broken/rejected: `{status['broken']['total']}`",
        f"- Elite (≤ {settings.elite_latency_ms:.0f} ms): `{status['quality']['elite']}`",
        f"- Acceptable (≤ {settings.max_latency_ms:.0f} ms): `{status['quality']['acceptable']}`",
        f"- Safety mode: `{status['safety_mode']}`",
    ]
    (output_dir / "summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    settings = Settings.from_env()
    xray_bin = os.path.abspath(args.xray)
    if not os.path.isfile(xray_bin) or not os.access(xray_bin, os.X_OK):
        raise ScannerError(f"Xray binary is missing or not executable: {xray_bin}")
    if shutil.which("curl") is None:
        raise ScannerError("curl is required")

    source_urls = extract_source_urls(os.getenv("SUB_URLS", ""))
    if not source_urls:
        raise ScannerError("SUB_URLS secret is empty")

    previous_state = load_previous_state(args.previous_state_url, settings.source_timeout_seconds)
    previous_nodes: dict[str, dict[str, Any]] = previous_state.get("nodes", {}) if previous_state else {}
    previous_selected: list[str] = previous_state.get("selected", []) if previous_state else []
    previous_suspicious_streak = int(previous_state.get("suspicious_streak", 0) or 0) if previous_state else 0

    log(f"Downloading {len(source_urls)} subscription source(s)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(source_urls))) as executor:
        source_results = list(executor.map(lambda url: fetch_source(url, settings), source_urls))

    failed_source_ids = {result.source_id for result in source_results if not result.ok}
    successful_sources = [result for result in source_results if result.ok]
    for result in source_results:
        log(f"Source {result.source_id}: {'ok' if result.ok else 'failed'} ({len(result.links)} links)")
    if not successful_sources and not previous_state:
        raise ScannerError("All subscription sources failed and no previous state exists")

    nodes: dict[str, Node] = {}
    unsupported = 0
    invalid = 0
    total_links = 0
    for source in successful_sources:
        for uri in source.links:
            total_links += 1
            try:
                node = parse_node(uri)
            except UnsupportedNode:
                unsupported += 1
                continue
            except Exception:
                invalid += 1
                continue
            existing = nodes.get(node.fingerprint)
            if existing is None:
                node.source_ids.add(source.source_id)
                nodes[node.fingerprint] = node
            else:
                existing.source_ids.add(source.source_id)

    if len(nodes) > settings.max_configs:
        prioritized = sorted(
            nodes.values(),
            key=lambda item: (0 if item.fingerprint in previous_nodes else 1, item.fingerprint),
        )[: settings.max_configs]
        nodes = {item.fingerprint: item for item in prioritized}

    log(
        f"Parsed {total_links} links -> {len(nodes)} unique supported configs "
        f"({unsupported} unsupported, {invalid} invalid)."
    )

    ordered_nodes = sorted(
        nodes.values(),
        key=lambda item: (
            0 if item.fingerprint in previous_selected else 1,
            float(previous_nodes.get(item.fingerprint, {}).get("latency_ms") or 99_999),
            item.fingerprint,
        ),
    )

    results: dict[str, TestResult] = {}
    deadline = started + settings.max_scan_seconds
    if ordered_nodes:
        log(f"Testing configs with {settings.scan_workers} parallel workers...")
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=settings.scan_workers)
        pending: dict[concurrent.futures.Future[TestResult], Node] = {}
        try:
            for node in ordered_nodes:
                if time.monotonic() >= deadline:
                    break
                pending[executor.submit(test_node, node, xray_bin, settings)] = node
            completed_count = 0
            for future in concurrent.futures.as_completed(pending):
                result = future.result()
                results[result.fingerprint] = result
                completed_count += 1
                if completed_count % 50 == 0 or completed_count == len(pending):
                    passed_so_far = sum(1 for item in results.values() if item.passed)
                    log(f"Tested {completed_count}/{len(pending)}; passed: {passed_so_far}")
                if time.monotonic() >= deadline:
                    for item in pending:
                        item.cancel()
                    break
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    passed_results = [result for result in results.values() if result.passed]
    speed_candidates = sorted(
        passed_results,
        key=lambda item: (
            0 if (item.latency_ms or 99_999) <= settings.elite_latency_ms else 1,
            item.latency_ms or 99_999,
            item.jitter_ms or 99_999,
        ),
    )[: settings.speed_test_max]

    if speed_candidates and time.monotonic() < deadline:
        log(f"Running small speed tests on {len(speed_candidates)} top candidates...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=settings.speed_workers) as executor:
            future_map = {
                executor.submit(speed_test_node, nodes[result.fingerprint], xray_bin, settings): result
                for result in speed_candidates
            }
            for future in concurrent.futures.as_completed(future_map):
                result = future_map[future]
                speed, samples, confirmed_slow, exit_country = future.result()
                result.speed_mbps = speed
                result.speed_samples = samples
                result.speed_confirmed_slow = confirmed_slow
                result.exit_country = exit_country
                if confirmed_slow:
                    result.passed = False
                    result.reason = "confirmed_slow"

    now = iso_now()
    current_records: dict[str, dict[str, Any]] = {}
    passed_current = 0
    grace_count = 0

    for fingerprint, node in nodes.items():
        result = results.get(fingerprint)
        if result is not None and result.passed:
            record = make_record(node, result, now)
            current_records[fingerprint] = record
            passed_current += 1
            continue

        previous = previous_nodes.get(fingerprint)
        if (
            isinstance(previous, dict)
            and (result is None or result.success_count >= 1)
            and (
                result is None
                or result.reason
                not in {"confirmed_unreachable", "consistently_high_latency", "confirmed_slow"}
            )
            and int(previous.get("failure_streak", 0) or 0) < settings.grace_scans
            and previous_record_is_fresh(previous, settings)
        ):
            record = dict(previous)
            record["uri"] = node.uri
            record["source_ids"] = sorted(node.source_ids)
            record["status"] = "grace"
            record["failure_streak"] = int(previous.get("failure_streak", 0) or 0) + 1
            current_records[fingerprint] = record
            grace_count += 1

    # If a whole source temporarily fails, retain its previously published nodes for one grace run.
    for fingerprint, previous in previous_nodes.items():
        if fingerprint in current_records or fingerprint in nodes or not isinstance(previous, dict):
            continue
        previous_sources = set(str(item) for item in previous.get("source_ids", []))
        if (
            previous_sources.intersection(failed_source_ids)
            and int(previous.get("failure_streak", 0) or 0) < settings.grace_scans
            and previous_record_is_fresh(previous, settings)
        ):
            record = dict(previous)
            record["status"] = "grace"
            record["failure_streak"] = int(previous.get("failure_streak", 0) or 0) + 1
            current_records[fingerprint] = record
            grace_count += 1

    for fingerprint, record in current_records.items():
        record["fingerprint"] = fingerprint
        record["score"] = record_score(record, settings)

    eligible = [
        record
        for record in current_records.values()
        if float(record.get("latency_ms") or 99_999) <= settings.max_latency_ms
    ]
    eligible.sort(
        key=lambda record: (
            0 if float(record.get("latency_ms") or 99_999) <= settings.elite_latency_ms else 1,
            -float(record.get("score") or 0),
            float(record.get("latency_ms") or 99_999),
            str(record.get("fingerprint")),
        )
    )
    selected = eligible[: settings.max_output]

    previous_selected_records = []
    for fingerprint in previous_selected:
        previous = previous_nodes.get(fingerprint)
        if not isinstance(previous, dict):
            continue
        # Catastrophic-output protection must never resurrect a node that this
        # run conclusively found unreachable, extremely slow, or far beyond
        # the broad viability latency ceiling. Nodes that were not testable
        # because a source/run failed may still be preserved once.
        result = results.get(fingerprint)
        if result is not None and (
            result.success_count == 0
            or result.reason in {"consistently_high_latency", "confirmed_slow"}
        ):
            continue
        previous_selected_records.append(dict(previous, fingerprint=fingerprint))
    suspicious = False
    if previous_selected_records:
        threshold = max(3, math.ceil(len(previous_selected_records) * settings.catastrophic_ratio))
        suspicious = len(selected) < threshold

    safety_mode = "normal"
    suspicious_streak = 0
    if suspicious and previous_suspicious_streak < 1:
        selected = previous_selected_records[: settings.max_output]
        current_records = {record["fingerprint"]: record for record in selected}
        for record in current_records.values():
            record.setdefault("source_ids", [])
            record.setdefault("status", "preserved")
            record.setdefault("score", record_score(record, settings))
        safety_mode = "preserved_previous_output_once"
        suspicious_streak = previous_suspicious_streak + 1
    elif suspicious:
        safety_mode = "accepted_after_repeated_degradation"
        suspicious_streak = 0

    country_detected, country_unknown = normalize_published_names(selected, results)
    elite_count = sum(
        1 for record in selected if float(record.get("latency_ms") or 99_999) <= settings.elite_latency_ms
    )
    acceptable_count = len(selected) - elite_count
    rejection_reasons = collections.Counter(
        result.reason for result in results.values() if not result.passed
    )
    tested_rejected = sum(rejection_reasons.values())
    broken_total = unsupported + invalid + tested_rejected
    status = {
        "generated_at": now,
        "scanner_version": SCANNER_VERSION,
        "latency_metric": "median HTTPS time-to-first-byte through Xray/SOCKS5h",
        "dns_probe_mode": "destination hostname is passed to the proxy via SOCKS5h; this is not an Android DNS-leak audit",
        "sources": {
            "total": len(source_urls),
            "successful": len(successful_sources),
            "failed": len(failed_source_ids),
        },
        "configs": {
            "received_links": total_links,
            "unique_supported": len(nodes),
            "unsupported": unsupported,
            "invalid": invalid,
            "tested": len(results),
            "passed_current": passed_current,
            "grace_retained": grace_count,
            "published": len(selected),
            "broken_or_rejected": broken_total,
        },
        "broken": {
            "total": broken_total,
            "unparseable_supported_links": unsupported + invalid,
            "confirmed_unreachable": rejection_reasons["confirmed_unreachable"],
            "insufficient_successes": rejection_reasons["insufficient_successes"],
            "unstable": rejection_reasons["unstable"]
            + rejection_reasons["unstable_jitter"],
            "consistently_high_latency": rejection_reasons["consistently_high_latency"],
            "confirmed_slow": rejection_reasons["confirmed_slow"],
            "other_test_failures": tested_rejected
            - sum(
                rejection_reasons[key]
                for key in (
                    "confirmed_unreachable",
                    "insufficient_successes",
                    "unstable",
                    "unstable_jitter",
                    "consistently_high_latency",
                    "confirmed_slow",
                )
            ),
            "note": "Duplicates are not counted as broken; unsupported external protocols are not extracted by this scanner.",
        },
        "quality": {
            "elite": elite_count,
            "acceptable": acceptable_count,
            "elite_threshold_ms": settings.elite_latency_ms,
            "maximum_threshold_ms": settings.max_latency_ms,
            "maximum_jitter_ms": settings.max_jitter_ms,
        },
        "speed_test": {
            "tested": len(speed_candidates),
            "sample_bytes": settings.speed_test_bytes,
            "confirmed_slow_removed": sum(1 for result in speed_candidates if result.speed_confirmed_slow),
        },
        "naming": {
            "format": "FLAG CC | Server N",
            "country_detected": country_detected,
            "country_unknown": country_unknown,
        },
        "safety_mode": safety_mode,
        "duration_seconds": round(time.monotonic() - started, 2),
    }

    output_dir = Path(args.output_dir)
    published_records = {record["fingerprint"]: record for record in selected}
    write_outputs(
        output_dir,
        selected,
        published_records,
        status,
        suspicious_streak,
        settings,
    )
    log(f"Published {len(selected)} configs to {output_dir / 'sub.txt'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", required=True, help="Path to the Xray executable")
    parser.add_argument("--output-dir", default="public", help="Static output directory")
    parser.add_argument(
        "--previous-state-url",
        default=os.getenv("PREVIOUS_STATE_URL", "") or None,
        help="Existing public state.json URL used for graceful retention",
    )
    return parser


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except KeyboardInterrupt:
        log("Interrupted")
        return 130
    except Exception as exc:
        log(f"Fatal error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
