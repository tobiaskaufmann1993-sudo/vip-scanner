#!/usr/bin/env python3
"""MezaVPN subscription quality scanner.

The scanner downloads one or more standard V2Ray subscription feeds, removes
functional duplicates, validates supported nodes with Xray-core, measures real
end-to-end HTTPS response latency through each proxy, performs budgeted
streaming-quality tests, tracks recent reliability, and publishes a stable
subscription set.

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
import ipaddress
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
SCANNER_VERSION = "1.3.4"
UTC = dt.timezone.utc
SERVER_ID_MIN = 1000
SERVER_ID_FOUR_DIGIT_MAX = 9999
SERVER_ID_MAX = 99999
HARD_REJECTION_REASONS = frozenset(
    {
        "confirmed_unreachable",
        "insufficient_successes",
        "unstable",
        "unstable_jitter",
        "consistently_high_latency",
        "confirmed_slow",
        "stream_stall",
        "stream_below_target",
        "stream_unverified",
        "stream_multi_endpoint_failed",
        "stream_inconsistent",
    }
)


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
    stream_test_bytes: int = 1_048_576
    speed_budget_bytes: int = 100_663_296
    speed_retry_reserve_bytes: int = 12_582_912
    min_speed_mbps: float = 1.1
    good_speed_mbps: float = 1.5
    strong_speed_mbps: float = 2.5
    stream_low_speed_seconds: int = 3
    stream_history_scans: int = 6
    grace_scans: int = 1
    grace_max_age_minutes: int = 120
    catastrophic_ratio: float = 0.15
    max_scan_seconds: int = 1_320
    output_format: str = "base64"
    geoip_db_path: str = ".cache/geoip/dbip-city-lite.mmdb"
    geo_city_max_distance_km: float = 80.0
    speed_test_url: str = "https://speed.cloudflare.com/__down?bytes={bytes}"
    speed_retry_url: str = "https://proof.ovh.net/files/1Mb.dat"
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
            stream_test_bytes=env_int("STREAM_TEST_BYTES", defaults.stream_test_bytes),
            speed_budget_bytes=env_int("SPEED_BUDGET_BYTES", defaults.speed_budget_bytes),
            speed_retry_reserve_bytes=env_int(
                "SPEED_RETRY_RESERVE_BYTES", defaults.speed_retry_reserve_bytes
            ),
            min_speed_mbps=env_float("MIN_SPEED_MBPS", defaults.min_speed_mbps),
            good_speed_mbps=env_float("GOOD_SPEED_MBPS", defaults.good_speed_mbps),
            strong_speed_mbps=env_float(
                "STRONG_SPEED_MBPS", defaults.strong_speed_mbps
            ),
            stream_low_speed_seconds=env_int(
                "STREAM_LOW_SPEED_SECONDS", defaults.stream_low_speed_seconds
            ),
            stream_history_scans=env_int(
                "STREAM_HISTORY_SCANS", defaults.stream_history_scans
            ),
            grace_scans=env_int("GRACE_SCANS", defaults.grace_scans),
            grace_max_age_minutes=env_int(
                "GRACE_MAX_AGE_MINUTES", defaults.grace_max_age_minutes
            ),
            catastrophic_ratio=env_float(
                "CATASTROPHIC_RATIO", defaults.catastrophic_ratio
            ),
            max_scan_seconds=env_int("MAX_SCAN_SECONDS", defaults.max_scan_seconds),
            output_format=os.getenv("OUTPUT_FORMAT", defaults.output_format).strip().lower(),
            geoip_db_path=os.getenv(
                "GEOIP_DB_PATH", defaults.geoip_db_path
            ).strip(),
            geo_city_max_distance_km=env_float(
                "GEO_CITY_MAX_DISTANCE_KM", defaults.geo_city_max_distance_km
            ),
            speed_test_url=os.getenv("SPEED_TEST_URL", defaults.speed_test_url).strip(),
            speed_retry_url=os.getenv(
                "SPEED_RETRY_URL", defaults.speed_retry_url
            ).strip(),
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
        if self.speed_test_max < 1:
            raise ScannerError("SPEED_TEST_MAX must be positive")
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
        if "{bytes}" not in self.speed_test_url:
            raise ScannerError("SPEED_TEST_URL must contain the {bytes} placeholder")
        speed_url = urllib.parse.urlsplit(
            self.speed_test_url.format(bytes=self.speed_test_bytes)
        )
        if speed_url.scheme != "https" or not speed_url.netloc:
            raise ScannerError("SPEED_TEST_URL must be a valid HTTPS URL")
        retry_url = urllib.parse.urlsplit(self.speed_retry_url)
        if retry_url.scheme != "https" or not retry_url.netloc:
            raise ScannerError("SPEED_RETRY_URL must be a valid HTTPS URL")
        if self.speed_test_bytes < 65_536 or self.stream_test_bytes < self.speed_test_bytes:
            raise ScannerError(
                "SPEED_TEST_BYTES must be >= 65536 and STREAM_TEST_BYTES must be at least as large"
            )
        if self.speed_budget_bytes < self.speed_test_bytes:
            raise ScannerError("SPEED_BUDGET_BYTES is too small for one quick test")
        if not 0 <= self.speed_retry_reserve_bytes < self.speed_budget_bytes:
            raise ScannerError(
                "SPEED_RETRY_RESERVE_BYTES must be non-negative and below SPEED_BUDGET_BYTES"
            )
        if not 0 < self.min_speed_mbps <= self.good_speed_mbps <= self.strong_speed_mbps:
            raise ScannerError(
                "Speed thresholds must satisfy 0 < MIN_SPEED_MBPS <= GOOD_SPEED_MBPS <= STRONG_SPEED_MBPS"
            )
        if not 2 <= self.stream_low_speed_seconds <= 10:
            raise ScannerError("STREAM_LOW_SPEED_SECONDS must be between 2 and 10")
        if not 3 <= self.stream_history_scans <= 12:
            raise ScannerError("STREAM_HISTORY_SCANS must be between 3 and 12")
        if not 10 <= self.geo_city_max_distance_km <= 250:
            raise ScannerError("GEO_CITY_MAX_DISTANCE_KM must be between 10 and 250")


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
    speed_floor_mbps: float | None = None
    speed_confirmed_slow: bool = False
    stream_attempts: int = 0
    stream_completed: int = 0
    stream_stalls: int = 0
    stream_bytes_downloaded: int = 0
    stream_deep_tested: bool = False
    stream_quality: str = "unverified"
    exit_country: str | None = None
    exit_ip: str | None = None
    exit_country_name: str | None = None
    exit_city: str | None = None
    geo_city_confident: bool = False


@dataclasses.dataclass(slots=True)
class StreamTestResult:
    speed_mbps: float | None
    speed_samples: list[float]
    speed_floor_mbps: float | None
    attempts: int
    completed: int
    stalls: int
    bytes_downloaded: int
    deep_tested: bool
    quality: str
    confirmed_slow: bool
    reason: str
    exit_country: str | None
    exit_ip: str | None = None
    exit_country_name: str | None = None
    exit_city: str | None = None
    geo_city_confident: bool = False


@dataclasses.dataclass(slots=True, frozen=True)
class ExitTrace:
    ip: str | None
    country: str | None
    colo: str | None


@dataclasses.dataclass(slots=True, frozen=True)
class ExitGeo:
    ip: str | None
    country_code: str | None
    country_name: str | None
    city: str | None
    city_confident: bool


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

# Short, product-facing labels. GeoIP provider wording is deliberately not used
# verbatim because it may contain articles or formal political names that are
# unsuitable for a compact VPN server list.
COUNTRY_DISPLAY_OVERRIDES = {
    "AE": "UAE",
    "BA": "Bosnia & Herzegovina",
    "CD": "DR Congo",
    "CG": "Congo",
    "CZ": "Czechia",
    "GB": "United Kingdom",
    "KR": "South Korea",
    "MO": "Macau",
    "NL": "Netherlands",
    "RU": "Russia",
    "US": "USA",
    "BL": "Saint Barthelemy",
    "BV": "Bouvet Island",
    "CC": "Cocos Islands",
    "CK": "Cook Islands",
    "CX": "Christmas Island",
    "EH": "Western Sahara",
    "FK": "Falkland Islands",
    "GS": "South Georgia Islands",
    "HM": "Heard & McDonald Islands",
    "IO": "British Indian Ocean",
    "MS": "Montserrat",
    "NF": "Norfolk Island",
    "NU": "Niue",
    "PM": "Saint Pierre & Miquelon",
    "PN": "Pitcairn Islands",
    "SH": "Saint Helena",
    "SJ": "Svalbard & Jan Mayen",
    "TF": "French Southern Lands",
    "TK": "Tokelau",
    "UM": "US Outlying Islands",
    "WF": "Wallis & Futuna",
}

TOKYO_SPECIAL_WARDS = frozenset(
    {
        "adachi", "arakawa", "bunkyo", "chiyoda", "chuo", "edogawa",
        "itabashi", "katsushika", "kita", "koto", "meguro", "minato",
        "nakano", "nerima", "ota", "setagaya", "shibuya", "shinagawa",
        "shinjuku", "suginami", "sumida", "taito", "toshima",
    }
)
MAX_CITY_DISPLAY_LENGTH = 28


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


def configured_source_urls() -> list[str]:
    """Merge private and repository-configured feeds without duplicate fetches."""
    urls: list[str] = []
    seen: set[str] = set()
    for variable in ("SUB_URLS", "ADDITIONAL_SUB_URLS"):
        raw = os.getenv(variable, "")
        if not raw.strip():
            continue
        for url in extract_source_urls(raw):
            if url not in seen:
                seen.add(url)
                urls.append(url)
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
    maximum_bytes: int = 0,
    byte_range: str = "",
    low_speed_limit_bps: int = 0,
    low_speed_seconds: int = 0,
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
    ]
    if low_speed_limit_bps > 0 and low_speed_seconds > 0:
        command.extend(
            [
                "--speed-limit",
                str(low_speed_limit_bps),
                "--speed-time",
                str(low_speed_seconds),
            ]
        )
    if maximum_bytes > 0:
        command.extend(["--max-filesize", str(maximum_bytes)])
    if byte_range:
        command.extend(["--range", byte_range])
    command.extend(["--header", "Cache-Control: no-cache", url])
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2.0,
            check=False,
            text=True,
        )
    except (subprocess.TimeoutExpired, OSError):
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

    accepted_code = code in {200, 204, 206}
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


def detect_exit_trace(socks_port: int, timeout: float) -> ExitTrace:
    """Return the actual proxy egress IP, country and Cloudflare colo."""
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
        return ExitTrace(None, None, None)
    if completed.returncode != 0:
        return ExitTrace(None, None, None)
    fields = {
        key.strip(): value.strip()
        for key, value in (
            line.split("=", 1)
            for line in completed.stdout.splitlines()
            if "=" in line
        )
    }
    raw_ip = fields.get("ip", "")
    try:
        exit_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        exit_ip = None
    raw_country = fields.get("loc", "").upper()
    country = raw_country if raw_country in ISO_COUNTRY_CODES else None
    raw_colo = fields.get("colo", "").upper()
    colo = raw_colo if re.fullmatch(r"[A-Z0-9]{3}", raw_colo) else None
    return ExitTrace(exit_ip, country, colo)


def detect_exit_country(socks_port: int, timeout: float) -> str | None:
    """Backward-compatible country-only wrapper used by older callers/tests."""
    return detect_exit_trace(socks_port, timeout).country


def country_display_name(code: str | None, suggested: str | None = None) -> str:
    """Return a short English country label suitable for a VPN server list."""
    normalized_code = (code or "").upper()
    if normalized_code in COUNTRY_DISPLAY_OVERRIDES:
        return COUNTRY_DISPLAY_OVERRIDES[normalized_code]
    for alias, alias_code in COUNTRY_NAME_ALIASES.items():
        if alias_code == normalized_code:
            words = alias.split()
            return " ".join(
                word.lower() if index and word in {"and", "of", "the"} else word.title()
                for index, word in enumerate(words)
            )
    return normalized_code or "Unknown"


def city_display_name(
    value: str | None, country_code: str | None = None
) -> str | None:
    """Return only a compact city, never a district or provider annotation."""
    clean = html.unescape(urllib.parse.unquote(value or ""))
    clean = unicodedata.normalize("NFKC", clean)
    clean = re.sub(r"[·#|/@:_\r\n]+", " ", clean)
    # GeoIP datasets sometimes append boroughs/districts in parentheses. They
    # are administrative detail, not part of the product-facing city name.
    previous = None
    while clean != previous:
        previous = clean
        clean = re.sub(r"\s*[\(\[\{][^\)\]\}]*[\)\]\}]\s*", " ", clean)
    clean = re.split(r"\s*[;,]\s*", clean, maxsplit=1)[0]
    clean = re.sub(r"^city\s+of\s+", "", clean, flags=re.IGNORECASE)
    clean = re.sub(
        r"\s+(?:(?:\d+)(?:st|nd|rd|th)?\s+)?"
        r"(?:arrondissement|district|borough|county|municipality|province|"
        r"prefecture|region|subdivision|ward)$",
        "",
        clean,
        flags=re.IGNORECASE,
    )
    clean = re.sub(r"\s+", " ", clean).strip(" .-'’")
    if not clean:
        return None
    aliases = {
        "frankfurt am main": "Frankfurt",
        "macao": "Macau",
        "new york city": "New York",
        "washington, d.c.": "Washington DC",
    }
    folded = clean.casefold()
    normalized_country = (country_code or "").upper()
    if normalized_country == "JP":
        ward = re.sub(r"\s+(?:city|ku)$", "", folded).strip()
        if ward in TOKYO_SPECIAL_WARDS:
            return "Tokyo"
    if normalized_country == "NL" and folded.startswith("amsterdam-"):
        return "Amsterdam"
    clean = aliases.get(folded, clean)
    folded = clean.casefold()
    forbidden_words = {
        "arrondissement", "borough", "county", "district", "downtown",
        "municipality", "prefecture", "province", "region", "subdivision",
        "ward",
    }
    if any(word in forbidden_words for word in re.findall(r"[a-z]+", folded)):
        return None
    if any(char.isdigit() for char in clean):
        return None
    if any(
        not (char.isalpha() or char.isspace() or char in "-'’.")
        for char in clean
    ):
        return None
    if len(clean) > MAX_CITY_DISPLAY_LENGTH or len(clean.split()) > 4:
        return None
    return clean


def location_label_key(value: str | None) -> str:
    """Normalize a location label solely for safe duplicate comparison."""
    normalized = unicodedata.normalize("NFKD", value or "").casefold()
    return "".join(char for char in normalized if char.isalnum())


def _haversine_km(
    first_lat: float, first_lon: float, second_lat: float, second_lon: float
) -> float:
    radius_km = 6371.0088
    lat1, lat2 = math.radians(first_lat), math.radians(second_lat)
    delta_lat = math.radians(second_lat - first_lat)
    delta_lon = math.radians(second_lon - first_lon)
    value = (
        math.sin(delta_lat / 2.0) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2.0) ** 2
    )
    return radius_km * 2.0 * math.asin(min(1.0, math.sqrt(value)))


def corroborate_exit_geo(
    trace: ExitTrace,
    db_record: dict[str, Any] | None,
    airport: dict[str, Any] | None,
    max_distance_km: float,
) -> ExitGeo:
    """Use DB-IP city only when live Cloudflare routing corroborates it."""
    record = db_record if isinstance(db_record, dict) else {}
    country_data = record.get("country")
    country_data = country_data if isinstance(country_data, dict) else {}
    db_country = str(country_data.get("iso_code", "")).upper()
    if db_country not in ISO_COUNTRY_CODES:
        db_country = ""
    country_code = trace.country or db_country or None
    countries_agree = bool(
        trace.country and db_country and trace.country == db_country
    )

    names = country_data.get("names")
    names = names if isinstance(names, dict) else {}
    suggested_country = (
        str(names.get("en", "")) if db_country == country_code else ""
    )
    country_name = (
        country_display_name(country_code, suggested_country)
        if country_code
        else None
    )

    city_data = record.get("city")
    city_data = city_data if isinstance(city_data, dict) else {}
    city_names = city_data.get("names")
    city_names = city_names if isinstance(city_names, dict) else {}
    city = city_display_name(str(city_names.get("en", "")), country_code)

    location = record.get("location")
    location = location if isinstance(location, dict) else {}
    airport_data = airport if isinstance(airport, dict) else {}
    airport_country = str(airport_data.get("country", "")).upper()
    try:
        distance = _haversine_km(
            float(location["latitude"]),
            float(location["longitude"]),
            float(airport_data["lat"]),
            float(airport_data["lon"]),
        )
    except (KeyError, TypeError, ValueError):
        distance = math.inf

    city_confident = bool(
        city
        and countries_agree
        and airport_country == country_code
        and distance <= max_distance_km
    )
    return ExitGeo(
        trace.ip,
        country_code,
        country_name,
        city if city_confident else None,
        city_confident,
    )


_GEO_LOCK = threading.Lock()
_GEO_READERS: dict[str, Any] = {}
_IATA_AIRPORTS: dict[str, dict[str, Any]] | None = None
_GEO_RESULT_CACHE: dict[tuple[str, str, str, str, float], ExitGeo] = {}


def resolve_exit_geo(trace: ExitTrace, settings: Settings) -> ExitGeo:
    """Resolve locally with cached DB-IP data; never call a quota-limited API."""
    if trace.ip is None:
        return ExitGeo(None, trace.country, country_display_name(trace.country) if trace.country else None, None, False)

    db_record: dict[str, Any] | None = None
    airport: dict[str, Any] | None = None
    db_path = os.path.abspath(settings.geoip_db_path)
    cache_key = (
        db_path,
        trace.ip,
        trace.country or "",
        trace.colo or "",
        settings.geo_city_max_distance_km,
    )
    try:
        with _GEO_LOCK:
            cached = _GEO_RESULT_CACHE.get(cache_key)
            if cached is not None:
                return cached
            reader = _GEO_READERS.get(db_path)
            if reader is None and os.path.isfile(db_path):
                import maxminddb

                reader = maxminddb.open_database(db_path)
                _GEO_READERS[db_path] = reader
            global _IATA_AIRPORTS
            if _IATA_AIRPORTS is None:
                import airportsdata

                _IATA_AIRPORTS = airportsdata.load("IATA")
            if reader is not None:
                found = reader.get(trace.ip)
                if isinstance(found, dict):
                    db_record = found
            if trace.colo:
                airport = _IATA_AIRPORTS.get(trace.colo)
    except (ImportError, OSError, ValueError):
        pass
    result = corroborate_exit_geo(
        trace, db_record, airport, settings.geo_city_max_distance_km
    )
    with _GEO_LOCK:
        _GEO_RESULT_CACHE[cache_key] = result
    return result


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


def assess_stream_quality(
    samples: list[float],
    attempts: int,
    completed: int,
    stalls: int,
    deep_tested: bool,
    settings: Settings,
) -> tuple[str, bool, str]:
    """Classify stream quality without treating one weak sample as certainty."""
    valid = [float(value) for value in samples if math.isfinite(value) and value > 0]
    confirmed_slow = (
        len(valid) >= 2 and max(valid) < settings.min_speed_mbps
    )
    if confirmed_slow:
        return "poor", True, "confirmed_slow"

    if stalls > 0:
        # One transient failure is not allowed to overrule two independent,
        # completed transfers. It still prevents the strongest classification.
        if stalls >= 2:
            return "unstable", False, "stream_stall"
        if completed < 2:
            return (
                "unstable" if deep_tested else "unverified",
                False,
                "stream_stall",
            )

    if not valid or completed == 0:
        return "unverified", False, "stream_unverified"
    if deep_tested and attempts >= 2 and completed < 2:
        return "unverified", False, "stream_unverified"

    ordered = sorted(valid)
    if len(ordered) == 2:
        lower, upper = ordered
        if lower < settings.good_speed_mbps <= upper:
            return "unverified", False, "stream_inconsistent"
    floor = stable_speed_floor(ordered)
    if floor is None:
        return "unverified", False, "stream_unverified"
    if floor >= settings.strong_speed_mbps:
        return ("good" if stalls else "strong"), False, "ok"
    if floor >= settings.good_speed_mbps:
        return "good", False, "ok"
    if floor >= settings.min_speed_mbps:
        return "borderline", False, "stream_below_target"
    return "poor", False, "stream_below_target"


def stable_speed_floor(samples: list[float]) -> float | None:
    """Ignore at most one low outlier once three independent samples exist."""
    valid = sorted(
        float(value) for value in samples if math.isfinite(value) and value > 0
    )
    if not valid:
        return None
    return valid[1] if len(valid) >= 3 else valid[0]


def _stream_measurement(
    port: int,
    byte_count: int,
    settings: Settings,
    endpoint_url: str | None = None,
    use_range: bool = False,
) -> tuple[bool, float | None, int, bool]:
    """Run one bounded transfer and return completion, Mbps, bytes and stall."""
    minimum_bps = max(1, int(settings.min_speed_mbps * 1_000_000.0 / 8.0))
    expected = int(byte_count * 0.90)
    minimum_transfer_seconds = byte_count * 8.0 / (
        settings.min_speed_mbps * 1_000_000.0
    )
    timeout = max(
        10.0,
        settings.probe_timeout_seconds + 3.0,
        minimum_transfer_seconds * 1.7,
    )
    endpoint = endpoint_url or settings.speed_test_url
    url = endpoint.format(bytes=byte_count) if "{bytes}" in endpoint else endpoint
    ok, metrics, _ = curl_measure(
        port,
        url,
        timeout=timeout,
        expected_min_bytes=expected,
        maximum_bytes=byte_count,
        byte_range=f"0-{byte_count - 1}" if use_range else "",
        low_speed_limit_bps=minimum_bps,
        low_speed_seconds=settings.stream_low_speed_seconds,
    )
    downloaded = int(metrics.get("size_download", 0) or 0)
    speed: float | None = None
    total_seconds = float(metrics.get("total_seconds", 0.0) or 0.0)
    ttfb_seconds = float(metrics.get("ttfb_seconds", 0.0) or 0.0)
    body_seconds = total_seconds - ttfb_seconds
    raw_speed = (
        downloaded / body_seconds
        if downloaded > 0 and body_seconds > 0.001
        else float(metrics.get("speed_download", 0.0) or 0.0)
    )
    if raw_speed > 0 and math.isfinite(raw_speed):
        speed = raw_speed * 8.0 / 1_000_000.0

    # HTTP success with a partial body or curl's low-speed abort is meaningful
    # evidence of a stream stall. Missing metrics are treated as unverified
    # rather than as proof that the proxy itself is bad.
    code = int(metrics.get("http_code", 0) or 0)
    stalled = not ok and code in {200, 206} and downloaded < expected
    return ok, speed if ok else None, downloaded, stalled


def speed_test_node(
    node: Node,
    xray_bin: str,
    settings: Settings,
    deep_test: bool = False,
    endpoint_url: str | None = None,
    use_range: bool = False,
    include_quick: bool = True,
) -> StreamTestResult:
    samples: list[float] = []
    attempts = 0
    completed = 0
    stalls = 0
    bytes_downloaded = 0
    exit_geo = ExitGeo(None, None, None, None, False)
    try:
        with XraySession(xray_bin, node, settings.xray_start_timeout_seconds) as port:
            trace = detect_exit_trace(
                port, min(6.0, settings.probe_timeout_seconds)
            )
            exit_geo = resolve_exit_geo(trace, settings)
            transfer_sizes = [settings.speed_test_bytes] if include_quick else []
            if deep_test:
                transfer_sizes.append(settings.stream_test_bytes)
            for byte_count in transfer_sizes:
                attempts += 1
                ok, speed, downloaded, stalled = _stream_measurement(
                    port,
                    byte_count,
                    settings,
                    endpoint_url=endpoint_url,
                    use_range=use_range,
                )
                bytes_downloaded += downloaded
                stalls += int(stalled)
                if ok and speed is not None:
                    completed += 1
                    samples.append(speed)
    except Exception:
        pass

    quality, confirmed_slow, reason = assess_stream_quality(
        samples,
        attempts,
        completed,
        stalls,
        deep_test,
        settings,
    )
    measured = float(statistics.median(samples)) if samples else None
    floor = stable_speed_floor(samples)
    return StreamTestResult(
        speed_mbps=measured,
        speed_samples=samples,
        speed_floor_mbps=floor,
        attempts=attempts,
        completed=completed,
        stalls=stalls,
        bytes_downloaded=bytes_downloaded,
        deep_tested=deep_test,
        quality=quality,
        confirmed_slow=confirmed_slow,
        reason=reason,
        exit_country=exit_geo.country_code,
        exit_ip=exit_geo.ip,
        exit_country_name=exit_geo.country_name,
        exit_city=exit_geo.city,
        geo_city_confident=exit_geo.city_confident,
    )


def combine_stream_results(
    primary: StreamTestResult,
    secondary: StreamTestResult,
    settings: Settings,
    multi_endpoint_retry: bool = False,
) -> StreamTestResult:
    samples = [*primary.speed_samples, *secondary.speed_samples]
    attempts = primary.attempts + secondary.attempts
    completed = primary.completed + secondary.completed
    stalls = primary.stalls + secondary.stalls
    deep_tested = primary.deep_tested or secondary.deep_tested
    quality, confirmed_slow, reason = assess_stream_quality(
        samples,
        attempts,
        completed,
        stalls,
        deep_tested,
        settings,
    )
    if (
        multi_endpoint_retry
        and completed == 0
        and stalls == 0
        and reason == "stream_unverified"
    ):
        reason = "stream_multi_endpoint_failed"
    geo_observations = [
        item for item in (primary, secondary) if item.exit_ip is not None
    ]
    observed_countries = {
        item.exit_country for item in geo_observations if item.exit_country
    }
    confident_cities = {
        city_display_name(item.exit_city, item.exit_country).casefold()
        for item in geo_observations
        if item.geo_city_confident
        and city_display_name(item.exit_city, item.exit_country)
    }
    all_geo_observations_confident = bool(geo_observations) and all(
        item.geo_city_confident
        and city_display_name(item.exit_city, item.exit_country)
        for item in geo_observations
    )
    geo_city_confident = bool(
        all_geo_observations_confident
        and len(confident_cities) == 1
        and len(observed_countries) <= 1
    )
    agreed_city = (
        primary.exit_city or secondary.exit_city
        if geo_city_confident
        else None
    )
    return StreamTestResult(
        speed_mbps=float(statistics.median(samples)) if samples else None,
        speed_samples=samples,
        speed_floor_mbps=stable_speed_floor(samples),
        attempts=attempts,
        completed=completed,
        stalls=stalls,
        bytes_downloaded=primary.bytes_downloaded + secondary.bytes_downloaded,
        deep_tested=deep_tested,
        quality=quality,
        confirmed_slow=confirmed_slow,
        reason=reason,
        exit_country=primary.exit_country or secondary.exit_country,
        exit_ip=primary.exit_ip or secondary.exit_ip,
        exit_country_name=(
            primary.exit_country_name or secondary.exit_country_name
        ),
        exit_city=agreed_city,
        geo_city_confident=geo_city_confident,
    )


def allocate_stable_server_id(
    fingerprint: str, server_ids: dict[str, int]
) -> int:
    """Assign a stable numeric ID; mappings are persisted and never reused."""
    existing = server_ids.get(fingerprint)
    if isinstance(existing, int) and SERVER_ID_MIN <= existing <= SERVER_ID_MAX:
        return existing
    used = {
        value
        for key, value in server_ids.items()
        if key != fingerprint
        and isinstance(value, int)
        and SERVER_ID_MIN <= value <= SERVER_ID_MAX
    }
    seed = hashlib.sha256(f"MezaVPN-server-id:{fingerprint}".encode()).digest()
    four_digit_span = SERVER_ID_FOUR_DIGIT_MAX - SERVER_ID_MIN + 1
    candidate = SERVER_ID_MIN + int.from_bytes(seed[:8], "big") % four_digit_span
    for _ in range(four_digit_span):
        if candidate not in used:
            server_ids[fingerprint] = candidate
            return candidate
        candidate = SERVER_ID_MIN + (
            (candidate - SERVER_ID_MIN + 1) % four_digit_span
        )

    five_digit_min = SERVER_ID_FOUR_DIGIT_MAX + 1
    five_digit_span = SERVER_ID_MAX - five_digit_min + 1
    candidate = five_digit_min + int.from_bytes(seed[8:16], "big") % five_digit_span
    for _ in range(five_digit_span):
        if candidate not in used:
            server_ids[fingerprint] = candidate
            return candidate
        candidate = five_digit_min + (
            (candidate - five_digit_min + 1) % five_digit_span
        )
    raise ScannerError("Stable server ID space is exhausted")


def normalize_published_names(
    records: list[dict[str, Any]],
    results: dict[str, TestResult],
    server_ids: dict[str, int],
) -> tuple[int, int, int, int]:
    detected = 0
    unknown = 0
    city_detected = 0
    city_omitted = 0
    for record in records:
        fingerprint = str(record.get("fingerprint", ""))
        result = results.get(fingerprint)
        code = result.exit_country if result is not None else None
        if not code:
            stored_code = str(record.get("country", "")).upper()
            code = stored_code if stored_code in ISO_COUNTRY_CODES else None
        if not code:
            code = country_from_name(str(record.get("name", "")))
        if code not in ISO_COUNTRY_CODES:
            code = "UN"
            unknown += 1
        else:
            detected += 1

        suggested_country = (
            result.exit_country_name if result is not None else None
        ) or str(record.get("country_name", ""))
        country_name = (
            country_display_name(code, suggested_country)
            if code != "UN"
            else "Unknown"
        )
        city: str | None = None
        if result is not None and result.geo_city_confident and result.exit_city:
            city = result.exit_city
        elif result is None or record.get("status") in {"grace", "preserved"}:
            stored_city = str(record.get("city", "")).strip()
            if stored_city and record.get("city_confident") is True:
                city = stored_city
        city = city_display_name(city, code)
        # City-states and same-named capitals otherwise produce labels such as
        # "Singapore · Singapore". The second copy adds no useful information.
        if city and location_label_key(city) == location_label_key(country_name):
            city = None
        if city:
            city_detected += 1
        else:
            city_omitted += 1

        server_id = allocate_stable_server_id(fingerprint, server_ids)
        display_name = (
            f"{country_name} · {city} #{server_id}"
            if city
            else f"{country_name} #{server_id}"
        )
        try:
            record["uri"] = set_uri_display_name(str(record["uri"]), display_name)
        except Exception:
            # A URI was already parsed successfully, but retaining the original
            # is safer than dropping a healthy node if display-name rewriting
            # ever encounters a collector-specific edge case.
            pass
        record["name"] = display_name
        record["country"] = code
        record["country_name"] = country_name
        record["city"] = city
        record["city_confident"] = bool(city)
        record["server_id"] = server_id
    return detected, unknown, city_detected, city_omitted


def quality_for_speed(speed: float | None, settings: Settings) -> str:
    if speed is None or not math.isfinite(float(speed)) or float(speed) <= 0:
        return "unverified"
    if float(speed) >= settings.strong_speed_mbps:
        return "strong"
    if float(speed) >= settings.good_speed_mbps:
        return "good"
    if float(speed) >= settings.min_speed_mbps:
        return "borderline"
    return "poor"


def previous_stream_is_trusted(
    record: dict[str, Any] | None, settings: Settings
) -> bool:
    if not isinstance(record, dict):
        return False
    if record.get("stream_verified") is True:
        return True
    if str(record.get("stream_quality", "")) in {"strong", "good"}:
        return True
    # Backward-compatible migration from scanner 1.1.x. Its tiny transfer is
    # not called "verified", but a currently healthy node is allowed one
    # provisional cycle instead of disappearing during the upgrade.
    legacy_speed = record.get("speed_mbps")
    return (
        isinstance(legacy_speed, (int, float))
        and float(legacy_speed) >= settings.good_speed_mbps
    )


def apply_stream_result(
    result: TestResult,
    stream: StreamTestResult | None,
    previous: dict[str, Any] | None,
    settings: Settings,
) -> None:
    if stream is not None:
        result.speed_mbps = stream.speed_mbps
        result.speed_samples = stream.speed_samples
        result.speed_floor_mbps = stream.speed_floor_mbps
        result.speed_confirmed_slow = stream.confirmed_slow
        result.stream_attempts = stream.attempts
        result.stream_completed = stream.completed
        result.stream_stalls = stream.stalls
        result.stream_bytes_downloaded = stream.bytes_downloaded
        result.stream_deep_tested = stream.deep_tested
        result.stream_quality = stream.quality
        result.exit_country = stream.exit_country
        result.exit_ip = stream.exit_ip
        result.exit_country_name = stream.exit_country_name
        result.exit_city = stream.exit_city
        result.geo_city_confident = stream.geo_city_confident

    if result.stream_quality in {"strong", "good"}:
        return
    retry_failed_independently = (
        stream is not None and stream.reason == "stream_multi_endpoint_failed"
    )
    previous_uncertain_streak = (
        int(previous.get("stream_uncertain_streak", 0) or 0)
        if isinstance(previous, dict)
        else 0
    )
    previous_failure_streak = (
        int(previous.get("stream_failure_streak", 0) or 0)
        if isinstance(previous, dict)
        else 0
    )
    weak_single_sample = (
        stream is not None
        and stream.completed < 2
        and stream.stalls == 0
        and not stream.confirmed_slow
        and stream.reason == "stream_below_target"
    )
    if (
        (
            (
                result.stream_quality == "unverified"
                and previous_uncertain_streak < 1
            )
            or (weak_single_sample and previous_failure_streak < 1)
        )
        and not retry_failed_independently
        and previous_stream_is_trusted(previous, settings)
    ):
        # One uncertain or weak transfer does not overrule trusted history.
        # The recorded streak makes this a one-scan grace, never an indefinite
        # way for a degraded node to remain published.
        return

    result.passed = False
    if stream is not None:
        result.reason = stream.reason
    else:
        result.reason = "stream_unverified"


def deep_test_priority(
    result: TestResult,
    previous: dict[str, Any] | None,
) -> tuple[int, float, float, str]:
    if isinstance(previous, dict):
        old_quality = str(previous.get("stream_quality", ""))
        old_failures = int(previous.get("stream_failure_streak", 0) or 0)
        if old_failures > 0 or old_quality in {"poor", "borderline", "unstable"}:
            group = 0
        elif not previous.get("last_deep_test"):
            group = 2
        else:
            group = 3
        stamp = parse_iso(str(previous.get("last_deep_test", "")))
        age_key = stamp.timestamp() if stamp is not None else 0.0
    else:
        group = 1
        age_key = 0.0
    return (
        group,
        age_key,
        float(result.latency_ms or 99_999),
        result.fingerprint,
    )


def initial_stream_test_count(candidate_count: int, settings: Settings) -> int:
    """Reserve enough of the fixed budget for independent confirmation tests."""
    primary_budget = max(
        settings.speed_test_bytes,
        settings.speed_budget_bytes - settings.speed_retry_reserve_bytes,
    )
    quick_capacity = primary_budget // settings.speed_test_bytes
    return min(max(0, candidate_count), settings.speed_test_max, quick_capacity)


def followup_stream_test_plan(
    primary_count: int,
    retry_needed_count: int,
    settings: Settings,
) -> tuple[int, int, int]:
    """Return retry count, deep count and total bytes without crossing the cap."""
    primary_bytes = primary_count * settings.speed_test_bytes
    remaining = max(0, settings.speed_budget_bytes - primary_bytes)
    retry_count = min(
        max(0, retry_needed_count), remaining // settings.speed_test_bytes
    )
    remaining -= retry_count * settings.speed_test_bytes
    deep_count = min(max(0, primary_count), remaining // settings.stream_test_bytes)
    planned = (
        primary_bytes
        + retry_count * settings.speed_test_bytes
        + deep_count * settings.stream_test_bytes
    )
    return retry_count, deep_count, planned


def record_score(record: dict[str, Any], settings: Settings) -> float:
    latency = float(record.get("latency_ms") or settings.max_latency_ms)
    jitter = float(record.get("jitter_ms") or 0.0)
    success_rate = float(record.get("success_rate") or 0.0)
    history_reliability = float(record.get("stream_reliability") or 0.0)
    speed = record.get("stream_floor_mbps")
    if not isinstance(speed, (int, float)) or float(speed) <= 0:
        speed = record.get("speed_floor_mbps") or record.get("speed_mbps")

    # For a globally distributed client, intrinsic reliability and sustained
    # throughput matter more than latency from one Azure runner. The app still
    # performs the final region-specific latency choice.
    health_score = success_rate * 22.0
    history_score = history_reliability * 23.0
    speed_score = 0.0
    if isinstance(speed, (int, float)) and float(speed) > 0:
        speed_score = min(35.0, float(speed) / settings.strong_speed_mbps * 35.0)
    latency_score = max(0.0, 1.0 - latency / settings.max_latency_ms) * 15.0
    verified_bonus = 7.0 if record.get("stream_verified") is True else 0.0
    jitter_penalty = min(8.0, jitter / max(1.0, settings.max_jitter_ms) * 8.0)
    history = record.get("stream_history")
    recent_stalls = (
        sum(int(item.get("stalls", 0) or 0) for item in history if isinstance(item, dict))
        if isinstance(history, list)
        else int(record.get("stream_stalls", 0) or 0)
    )
    stall_penalty = min(18.0, recent_stalls * 4.0)

    quality = str(record.get("stream_quality", "unverified"))
    quality_penalty = {
        "unverified": 12.0,
        "borderline": 18.0,
        "poor": 30.0,
        "unstable": 35.0,
    }.get(quality, 0.0)
    grace_penalty = 24.0 if record.get("status") in {"grace", "preserved"} else 0.0
    return round(
        health_score
        + history_score
        + speed_score
        + latency_score
        + verified_bonus
        - jitter_penalty
        - stall_penalty
        - quality_penalty
        - grace_penalty,
        5,
    )


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


def _history_floor(entries: list[dict[str, Any]]) -> float | None:
    values = sorted(
        float(entry["floor_mbps"])
        for entry in entries
        if isinstance(entry.get("floor_mbps"), (int, float))
        and float(entry["floor_mbps"]) > 0
    )
    if not values:
        return None
    index = int(math.floor((len(values) - 1) * 0.25))
    return values[index]


def make_record(
    node: Node,
    result: TestResult,
    now: str,
    previous: dict[str, Any] | None,
    settings: Settings,
) -> dict[str, Any]:
    history: list[dict[str, Any]] = []
    if isinstance(previous, dict):
        raw_history = previous.get("stream_history")
        if isinstance(raw_history, list):
            history = [dict(item) for item in raw_history if isinstance(item, dict)]
        elif isinstance(previous.get("speed_mbps"), (int, float)):
            legacy_speed = float(previous["speed_mbps"])
            history.append(
                {
                    "at": str(previous.get("last_success", now)),
                    "quality": quality_for_speed(legacy_speed, settings),
                    "floor_mbps": round(legacy_speed, 3),
                    "stalls": 0,
                    "deep": False,
                    "legacy": True,
                }
            )

    if result.stream_attempts > 0:
        history.append(
            {
                "at": now,
                "quality": result.stream_quality,
                "floor_mbps": (
                    round(result.speed_floor_mbps, 3)
                    if result.speed_floor_mbps is not None
                    else None
                ),
                "stalls": result.stream_stalls,
                "deep": result.stream_deep_tested,
            }
        )
    history = history[-settings.stream_history_scans :]

    decided = [
        item
        for item in history
        if str(item.get("quality", "")) != "unverified"
    ]
    good_count = sum(
        1 for item in decided if str(item.get("quality")) in {"strong", "good"}
    )
    reliability = good_count / len(decided) if decided else 0.0
    failure_streak = 0
    for item in reversed(history):
        quality = str(item.get("quality", "unverified"))
        if quality in {"poor", "borderline", "unstable"}:
            failure_streak += 1
        elif quality in {"strong", "good"}:
            break
    previous_uncertain_streak = (
        int(previous.get("stream_uncertain_streak", 0) or 0)
        if isinstance(previous, dict)
        else 0
    )
    uncertain_streak = (
        previous_uncertain_streak + 1
        if result.stream_quality == "unverified"
        else 0
    )
    verified = any(
        bool(item.get("deep"))
        and str(item.get("quality")) in {"strong", "good"}
        for item in history
    ) or (good_count >= 3 and reliability >= 0.75)

    last_deep_test = (
        now
        if result.stream_deep_tested
        else (str(previous.get("last_deep_test", "")) if isinstance(previous, dict) else "")
    )
    historical_floor = _history_floor(history)
    current_speed = (
        round(result.speed_mbps, 3) if result.speed_mbps is not None else None
    )
    if current_speed is None and isinstance(previous, dict):
        old_speed = previous.get("speed_mbps")
        current_speed = (
            round(float(old_speed), 3) if isinstance(old_speed, (int, float)) else None
        )

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
        "speed_mbps": current_speed,
        "speed_floor_mbps": (
            round(result.speed_floor_mbps, 3)
            if result.speed_floor_mbps is not None
            else None
        ),
        "stream_quality": result.stream_quality,
        "stream_stalls": result.stream_stalls,
        "stream_verified": verified,
        "stream_reliability": round(reliability, 4),
        "stream_failure_streak": failure_streak,
        "stream_uncertain_streak": uncertain_streak,
        "stream_floor_mbps": (
            round(historical_floor, 3) if historical_floor is not None else None
        ),
        "stream_history": history,
        "last_deep_test": last_deep_test or None,
        "exit_ip": result.exit_ip,
        "country": result.exit_country,
        "country_name": result.exit_country_name,
        "city": result.exit_city if result.geo_city_confident else None,
        "city_confident": result.geo_city_confident,
    }


def write_outputs(
    output_dir: Path,
    records: list[dict[str, Any]],
    all_records: dict[str, dict[str, Any]],
    status: dict[str, Any],
    suspicious_streak: int,
    settings: Settings,
    server_ids: dict[str, int],
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
        "version": 2,
        "scanner_version": SCANNER_VERSION,
        "generated_at": status["generated_at"],
        "suspicious_streak": suspicious_streak,
        "selected": [record["fingerprint"] for record in records],
        "nodes": all_records,
        "server_ids": server_ids,
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
<pre>{status_html}</pre>
<p><small><a href="https://db-ip.com">IP Geolocation by DB-IP</a></small></p>
</body></html>"""
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
        f"- Stream strong (≥ {settings.strong_speed_mbps:g} Mbps): `{status['quality']['stream_strong']}`",
        f"- Stream good (≥ {settings.good_speed_mbps:g} Mbps): `{status['quality']['stream_good']}`",
        f"- Stream stalls rejected: `{status['broken']['stream_stall']}`",
        f"- Independent fallback recoveries: `{status['stream_test']['fallback_recovered']}`",
        f"- Multi-endpoint failures: `{status['broken']['stream_multi_endpoint_failed']}`",
        f"- Confident exit cities: `{status['naming']['city_confident']}`",
        f"- City omitted as uncertain: `{status['naming']['city_omitted']}`",
        f"- Stable server IDs retained: `{status['naming']['stable_ids_registered']}`",
        f"- Stable server ID range: `{status['naming']['stable_id_range']}` "
        "(4 digits preferred)",
        f"- Stream-test traffic: `{status['stream_test']['actual_downloaded_bytes'] / 1_048_576:.1f} MiB` "
        f"(cap `{settings.speed_budget_bytes / 1_048_576:.0f} MiB`)",
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

    source_urls = configured_source_urls()
    if not source_urls:
        raise ScannerError("No subscription URLs are configured")

    previous_state = load_previous_state(args.previous_state_url, settings.source_timeout_seconds)
    previous_nodes: dict[str, dict[str, Any]] = previous_state.get("nodes", {}) if previous_state else {}
    previous_selected: list[str] = previous_state.get("selected", []) if previous_state else []
    previous_suspicious_streak = int(previous_state.get("suspicious_streak", 0) or 0) if previous_state else 0
    raw_server_ids = previous_state.get("server_ids", {}) if previous_state else {}
    server_ids: dict[str, int] = {}
    used_server_ids: set[int] = set()
    raw_items = raw_server_ids.items() if isinstance(raw_server_ids, dict) else []
    for fingerprint, server_id in sorted(raw_items):
        if (
            isinstance(server_id, int)
            and not isinstance(server_id, bool)
            and SERVER_ID_MIN <= server_id <= SERVER_ID_MAX
            and server_id not in used_server_ids
        ):
            server_ids[str(fingerprint)] = server_id
            used_server_ids.add(server_id)
    # Seamless migration if an intermediate state stored IDs only in records.
    for fingerprint, record in previous_nodes.items():
        if not isinstance(record, dict) or fingerprint in server_ids:
            continue
        old_id = record.get("server_id")
        if (
            isinstance(old_id, int)
            and not isinstance(old_id, bool)
            and SERVER_ID_MIN <= old_id <= SERVER_ID_MAX
            and old_id not in used_server_ids
        ):
            server_ids[fingerprint] = old_id
            used_server_ids.add(old_id)

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
    health_passed_current = len(passed_results)
    quick_count = initial_stream_test_count(len(passed_results), settings)
    speed_candidates = sorted(
        passed_results,
        key=lambda item: (
            0 if item.fingerprint in previous_selected else 1,
            0
            if previous_stream_is_trusted(
                previous_nodes.get(item.fingerprint), settings
            )
            else 1,
            item.latency_ms or 99_999,
            item.jitter_ms or 99_999,
            item.fingerprint,
        ),
    )[:quick_count]
    primary_outcomes: dict[str, StreamTestResult] = {}

    if speed_candidates and time.monotonic() < deadline:
        log(
            f"Running primary stream checks on {len(speed_candidates)} candidates "
            f"(fixed total cap {settings.speed_budget_bytes / 1_048_576:.1f} MiB)..."
        )
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=settings.speed_workers
        ) as executor:
            future_map = {
                executor.submit(
                    speed_test_node,
                    nodes[result.fingerprint],
                    xray_bin,
                    settings,
                ): result
                for result in speed_candidates
            }
            for future in concurrent.futures.as_completed(future_map):
                result = future_map[future]
                primary_outcomes[result.fingerprint] = future.result()

    retry_needed = sorted(
        (
            result
            for result in speed_candidates
            if primary_outcomes.get(result.fingerprint) is not None
            and primary_outcomes[result.fingerprint].quality
            not in {"strong", "good"}
        ),
        key=lambda item: (
            0
            if not previous_stream_is_trusted(
                previous_nodes.get(item.fingerprint), settings
            )
            else 1,
            deep_test_priority(item, previous_nodes.get(item.fingerprint)),
        ),
    )
    retry_slots, deep_slots, planned_stream_bytes = followup_stream_test_plan(
        len(speed_candidates), len(retry_needed), settings
    )
    retry_candidates = retry_needed[:retry_slots]
    retry_fingerprints = {item.fingerprint for item in retry_candidates}
    retry_outcomes: dict[str, StreamTestResult] = {}

    if retry_candidates and time.monotonic() < deadline:
        log(
            f"Running {len(retry_fingerprints)} independent OVH retries..."
        )
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=settings.speed_workers
        ) as executor:
            future_map = {
                executor.submit(
                    speed_test_node,
                    nodes[result.fingerprint],
                    xray_bin,
                    settings,
                    False,
                    settings.speed_retry_url,
                    True,
                    True,
                ): result
                for result in retry_candidates
            }
            for future in concurrent.futures.as_completed(future_map):
                result = future_map[future]
                retry_outcomes[result.fingerprint] = future.result()

    stream_outcomes: dict[str, StreamTestResult] = dict(primary_outcomes)
    for fingerprint, secondary in retry_outcomes.items():
        primary = primary_outcomes.get(fingerprint)
        if primary is None:
            stream_outcomes[fingerprint] = secondary
            continue
        stream_outcomes[fingerprint] = combine_stream_results(
            primary,
            secondary,
            settings,
            multi_endpoint_retry=fingerprint in retry_fingerprints,
        )

    # Allocate expensive sustained transfers only after the independent retry
    # is known. Conflicting endpoints get first priority, followed by recovered
    # and regularly rotating healthy nodes. Proven failures do not waste budget.
    def deep_followup_priority(result: TestResult) -> tuple[Any, ...]:
        fingerprint = result.fingerprint
        if fingerprint in retry_fingerprints:
            combined = stream_outcomes.get(fingerprint)
            fallback = retry_outcomes.get(fingerprint)
            if (
                combined is not None
                and fallback is not None
                and fallback.completed > 0
                and combined.reason in {"stream_inconsistent", "stream_stall"}
            ):
                group = 0
            elif (
                combined is not None
                and combined.quality in {"strong", "good"}
            ):
                group = 1
            else:
                group = 3
        else:
            group = 2
        return (
            group,
            deep_test_priority(result, previous_nodes.get(fingerprint)),
        )

    deep_pool = [
        result
        for result in speed_candidates
        if result.fingerprint not in retry_fingerprints
        or (
            result.fingerprint in retry_outcomes
            and (
                stream_outcomes[result.fingerprint].quality in {"strong", "good"}
                or (
                    retry_outcomes[result.fingerprint].completed > 0
                    and stream_outcomes[result.fingerprint].reason
                    in {"stream_inconsistent", "stream_stall"}
                )
            )
        )
    ]
    deep_candidates = sorted(deep_pool, key=deep_followup_priority)[:deep_slots]
    deep_fingerprints = {item.fingerprint for item in deep_candidates}
    deep_outcomes: dict[str, StreamTestResult] = {}
    planned_stream_bytes = (
        len(speed_candidates) * settings.speed_test_bytes
        + len(retry_candidates) * settings.speed_test_bytes
        + len(deep_candidates) * settings.stream_test_bytes
    )

    if deep_candidates and time.monotonic() < deadline:
        log(
            f"Running {len(deep_candidates)} targeted deep stream tests; "
            f"max total {planned_stream_bytes / 1_048_576:.1f} MiB..."
        )
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=settings.speed_workers
        ) as executor:
            future_map = {}
            for result in deep_candidates:
                is_retry = result.fingerprint in retry_fingerprints
                future = executor.submit(
                    speed_test_node,
                    nodes[result.fingerprint],
                    xray_bin,
                    settings,
                    True,
                    settings.speed_retry_url if is_retry else settings.speed_test_url,
                    is_retry,
                    False,
                )
                future_map[future] = result
            for future in concurrent.futures.as_completed(future_map):
                result = future_map[future]
                deep_outcomes[result.fingerprint] = future.result()

    for fingerprint, deep in deep_outcomes.items():
        current = stream_outcomes.get(fingerprint)
        if current is None:
            stream_outcomes[fingerprint] = deep
            continue
        stream_outcomes[fingerprint] = combine_stream_results(
            current,
            deep,
            settings,
        )

    for result in passed_results:
        apply_stream_result(
            result,
            stream_outcomes.get(result.fingerprint),
            previous_nodes.get(result.fingerprint),
            settings,
        )

    completed_primary_nodes = sum(
        1 for stream in primary_outcomes.values() if stream.completed > 0
    )
    stream_endpoint_degraded = (
        len(primary_outcomes) >= 10
        and completed_primary_nodes / len(primary_outcomes) < 0.15
    )
    if stream_endpoint_degraded:
        log(
            "Warning: the stream endpoint appears degraded; only previously "
            "trusted nodes may pass without a current transfer result."
        )
    fallback_recovered = sum(
        1
        for fingerprint in retry_fingerprints
        if fingerprint in stream_outcomes
        and stream_outcomes[fingerprint].quality in {"strong", "good"}
    )

    now = iso_now()
    current_records: dict[str, dict[str, Any]] = {}
    passed_current = 0
    grace_count = 0

    for fingerprint, node in nodes.items():
        result = results.get(fingerprint)
        if result is not None and result.passed:
            record = make_record(
                node,
                result,
                now,
                previous_nodes.get(fingerprint),
                settings,
            )
            current_records[fingerprint] = record
            passed_current += 1
            continue

        previous = previous_nodes.get(fingerprint)
        if (
            isinstance(previous, dict)
            and (result is None or result.success_count >= 1)
            and (
                result is None
                or result.reason not in HARD_REJECTION_REASONS
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
            0 if record.get("stream_verified") is True else 1,
            {
                "strong": 0,
                "good": 1,
                "unverified": 2,
            }.get(str(record.get("stream_quality", "unverified")), 3),
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
            or result.reason in HARD_REJECTION_REASONS
        ):
            continue
        if result is None and not previous_stream_is_trusted(previous, settings):
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

    (
        country_detected,
        country_unknown,
        city_detected,
        city_omitted,
    ) = normalize_published_names(selected, results, server_ids)
    elite_count = sum(
        1 for record in selected if float(record.get("latency_ms") or 99_999) <= settings.elite_latency_ms
    )
    acceptable_count = len(selected) - elite_count
    rejection_reasons = collections.Counter(
        result.reason for result in results.values() if not result.passed
    )
    tested_rejected = sum(rejection_reasons.values())
    broken_total = unsupported + invalid + tested_rejected
    stream_quality_counts = collections.Counter(
        str(record.get("stream_quality", "unverified")) for record in selected
    )
    stream_actual_bytes = sum(
        stream.bytes_downloaded for stream in stream_outcomes.values()
    )
    stream_completed_transfers = sum(
        stream.completed for stream in stream_outcomes.values()
    )
    stream_stalled_transfers = sum(
        stream.stalls for stream in stream_outcomes.values()
    )
    stream_verified_count = sum(
        1 for record in selected if record.get("stream_verified") is True
    )
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
            "health_passed": health_passed_current,
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
            "stream_stall": rejection_reasons["stream_stall"],
            "stream_below_target": rejection_reasons["stream_below_target"],
            "stream_unverified": rejection_reasons["stream_unverified"],
            "stream_inconsistent": rejection_reasons["stream_inconsistent"],
            "stream_multi_endpoint_failed": rejection_reasons[
                "stream_multi_endpoint_failed"
            ],
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
                    "stream_stall",
                    "stream_below_target",
                    "stream_unverified",
                    "stream_inconsistent",
                    "stream_multi_endpoint_failed",
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
            "stream_strong": stream_quality_counts["strong"],
            "stream_good": stream_quality_counts["good"],
            "stream_provisional": stream_quality_counts["unverified"],
            "stream_verified": stream_verified_count,
        },
        "speed_test": {
            "tested": len(stream_outcomes),
            "sample_bytes": settings.speed_test_bytes,
            "confirmed_slow_removed": rejection_reasons["confirmed_slow"],
        },
        "stream_test": {
            "mode": "primary Cloudflare transfer, independent OVH retry for uncertain results, plus rotating sustained transfer",
            "tested_nodes": len(stream_outcomes),
            "primary_tested_nodes": len(primary_outcomes),
            "fallback_retry_planned": len(retry_fingerprints),
            "fallback_retry_tested": sum(
                1
                for fingerprint in retry_fingerprints
                if fingerprint in retry_outcomes
            ),
            "fallback_recovered": fallback_recovered,
            "multi_endpoint_failed": rejection_reasons[
                "stream_multi_endpoint_failed"
            ],
            "deep_tested_nodes": sum(
                1 for stream in stream_outcomes.values() if stream.deep_tested
            ),
            "completed_transfers": stream_completed_transfers,
            "stalled_transfers": stream_stalled_transfers,
            "endpoint_degraded": stream_endpoint_degraded,
            "quick_bytes": settings.speed_test_bytes,
            "deep_bytes": settings.stream_test_bytes,
            "planned_bytes": planned_stream_bytes,
            "actual_downloaded_bytes": stream_actual_bytes,
            "budget_bytes": settings.speed_budget_bytes,
            "retry_reserve_bytes": settings.speed_retry_reserve_bytes,
            "primary_endpoint": "speed.cloudflare.com",
            "fallback_endpoint": "proof.ovh.net",
            "minimum_mbps": settings.min_speed_mbps,
            "good_mbps": settings.good_speed_mbps,
            "strong_mbps": settings.strong_speed_mbps,
            "low_speed_window_seconds": settings.stream_low_speed_seconds,
            "history_scans": settings.stream_history_scans,
        },
        "naming": {
            "format": "Country · City #StableID (city omitted when uncertain)",
            "country_label_policy": "canonical short product label; never raw GeoIP wording",
            "city_label_policy": "city only; administrative qualifiers removed; suspicious labels omitted",
            "city_label_max_characters": MAX_CITY_DISPLAY_LENGTH,
            "country_detected": country_detected,
            "country_unknown": country_unknown,
            "city_confident": city_detected,
            "city_omitted": city_omitted,
            "stable_ids_registered": len(server_ids),
            "stable_id_range": "1000-99999",
            "stable_id_policy": "prefer 4 digits; use 5 digits only after 1000-9999 is exhausted",
            "geoip_mode": "actual egress IP; DB-IP City corroborated by Cloudflare country and colo distance",
            "geoip_database_available": os.path.isfile(settings.geoip_db_path),
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
        server_ids,
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
