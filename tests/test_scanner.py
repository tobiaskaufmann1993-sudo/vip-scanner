import base64
import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scanner


UUID = "11111111-1111-4111-8111-111111111111"


class ScannerParserTests(unittest.TestCase):
    def _test_result_for_samples(self, samples):
        settings = scanner.Settings()
        node = scanner.parse_node(
            f"vless://{UUID}@example.com:443?security=tls&type=tcp#health"
        )
        session = mock.MagicMock()
        session.__enter__.return_value = 19080
        session.__exit__.return_value = None
        with mock.patch.object(scanner, "XraySession", return_value=session), mock.patch.object(
            scanner, "probe_once", side_effect=samples
        ) as probe, mock.patch.object(
            scanner, "detect_exit_trace", return_value=scanner.ExitTrace(None, "DE", None)
        ):
            result = scanner.test_node(node, "xray", settings)
        self.probe_calls = probe.call_count
        return result

    def test_vless_ws_tls(self):
        uri = (
            f"vless://{UUID}@example.com:443?encryption=none&security=tls"
            "&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws#Node-A"
        )
        node = scanner.parse_node(uri)
        self.assertEqual(node.protocol, "vless")
        self.assertEqual(node.host, "example.com")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.outbound["streamSettings"]["network"], "websocket")
        self.assertEqual(node.outbound["streamSettings"]["security"], "tls")

    def test_vless_reality(self):
        uri = (
            f"vless://{UUID}@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision"
            "&security=reality&sni=www.example.com&fp=chrome&pbk=PUBLICKEY&sid=abcd&type=tcp#R"
        )
        node = scanner.parse_node(uri)
        reality = node.outbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["password"], "PUBLICKEY")
        self.assertEqual(reality["shortId"], "abcd")

    def test_vmess(self):
        payload = {
            "v": "2",
            "ps": "vmess-test",
            "add": "vm.example.com",
            "port": "443",
            "id": UUID,
            "aid": "0",
            "scy": "auto",
            "net": "grpc",
            "type": "none",
            "host": "",
            "path": "grpc-service",
            "tls": "tls",
            "sni": "vm.example.com",
            "fp": "chrome",
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        node = scanner.parse_node("vmess://" + encoded)
        self.assertEqual(node.protocol, "vmess")
        self.assertEqual(node.outbound["streamSettings"]["network"], "grpc")
        self.assertEqual(
            node.outbound["streamSettings"]["grpcSettings"]["serviceName"],
            "grpc-service",
        )

    def test_trojan(self):
        uri = "trojan://secret@example.com:443?security=tls&sni=example.com&type=tcp#T"
        node = scanner.parse_node(uri)
        self.assertEqual(node.protocol, "trojan")
        self.assertEqual(
            node.outbound["settings"]["password"], "secret"
        )

    def test_shadowsocks_sip002(self):
        userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:password").decode().rstrip("=")
        node = scanner.parse_node(f"ss://{userinfo}@example.com:8388#SS")
        server = node.outbound["settings"]
        self.assertEqual(server["method"], "aes-256-gcm")
        self.assertEqual(server["password"], "password")

    def test_duplicate_ignores_display_name(self):
        base = f"vless://{UUID}@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fx"
        first = scanner.parse_node(base + "#One")
        second = scanner.parse_node(base + "#Two")
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_subscription_base64_decode(self):
        raw = (
            f"vless://{UUID}@example.com:443?security=tls&type=tcp#A\n"
            "trojan://pass@example.net:443?security=tls&type=tcp#B\n"
        )
        encoded = base64.b64encode(raw.encode())
        decoded = scanner.decode_subscription(encoded)
        links = scanner.extract_links(decoded)
        self.assertEqual(len(links), 2)

    def test_private_and_additional_sources_are_merged_and_deduplicated(self):
        first = "https://example.com/private-one"
        second = "https://example.com/private-two"
        retired = (
            "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/"
            "refs/heads/main/xray_final.txt"
        )
        public_one = (
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
            "refs/heads/main/BLACK_VLESS_RUS.txt"
        )
        public_two = (
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
            "refs/heads/main/BLACK_VLESS_RUS_mobile.txt"
        )
        with mock.patch.dict(
            scanner.os.environ,
            {
                "SUB_URLS": f"{first}\n{second}\n{retired}\n{public_one}",
                "ADDITIONAL_SUB_URLS": f"{public_one}\n{public_two}",
            },
            clear=False,
        ):
            self.assertEqual(
                scanner.configured_source_urls(),
                [first, second, public_one, public_two],
            )

    def test_html_escaped_query_separators_are_restored(self):
        raw = (
            f"vless://{UUID}@example.com:443?security=tls&amp;sni=cdn.example.com"
            "&amp;type=ws&amp;host=cdn.example.com&amp;path=%2Fws#HTML"
        )
        links = scanner.extract_links(raw)
        self.assertEqual(len(links), 1)
        self.assertNotIn("&amp;", links[0])
        node = scanner.parse_node(links[0])
        stream = node.outbound["streamSettings"]
        self.assertEqual(stream["network"], "websocket")
        self.assertEqual(stream["tlsSettings"]["serverName"], "cdn.example.com")
        self.assertEqual(stream["wsSettings"]["host"], "cdn.example.com")

    def test_vless_security_false_is_treated_as_no_tls(self):
        uri = (
            f"vless://{UUID}@example.com:80?security=false&type=ws"
            "&host=cdn.example.com&path=%2F#NoTLS"
        )
        node = scanner.parse_node(uri)
        self.assertEqual(node.outbound["streamSettings"]["security"], "none")
        self.assertEqual(node.outbound["streamSettings"]["network"], "websocket")

    def test_country_detection_from_flag_code_and_full_name(self):
        self.assertEqual(scanner.country_from_name("🇩🇪 | @WhiteDNS | DE33|GPT-US"), "DE")
        self.assertEqual(scanner.country_from_name("undefined HK | server"), "HK")
        self.assertEqual(scanner.country_from_name("Sertraline-Finland-c20"), "FI")
        self.assertEqual(scanner.country_from_name("Premium-Türkiye-01"), "TR")
        self.assertEqual(scanner.country_from_name("Servidor-España-02"), "ES")
        self.assertEqual(scanner.country_from_name("Côte d’Ivoire node"), "CI")
        self.assertEqual(scanner.country_from_name("Papua-New-Guinea-fast"), "PG")
        self.assertIsNone(scanner.country_from_name("Fast Private Server"))

    def test_all_country_aliases_map_to_supported_codes(self):
        self.assertTrue(scanner.COUNTRY_NAME_ALIASES)
        self.assertFalse(
            set(scanner.COUNTRY_NAME_ALIASES.values()) - scanner.ISO_COUNTRY_CODES
        )
        for code in scanner.ISO_COUNTRY_CODES:
            with self.subTest(code=code):
                label = scanner.country_display_name(
                    code, "The Untrusted Provider Country Label"
                )
                self.assertNotEqual(label, code)
                self.assertFalse(label.casefold().startswith("the "))
                self.assertNotIn("(", label)

    def test_preferred_country_labels_use_usa_and_uae(self):
        self.assertEqual(
            scanner.country_display_name("US", "United States"), "USA"
        )
        self.assertEqual(
            scanner.country_display_name("AE", "United Arab Emirates"), "UAE"
        )
        self.assertEqual(scanner.country_display_name("us"), "USA")
        self.assertEqual(scanner.country_display_name("ae"), "UAE")
        self.assertEqual(
            scanner.country_display_name("NL", "The Netherlands"), "Netherlands"
        )

    def test_exit_country_reads_cloudflare_trace(self):
        completed = mock.Mock(
            returncode=0,
            stdout="fl=1\nip=203.0.113.1\nloc=JP\ncolo=NRT\ntls=TLSv1.3\n",
        )
        with mock.patch.object(scanner.subprocess, "run", return_value=completed):
            self.assertEqual(scanner.detect_exit_country(19080, 5.0), "JP")
            trace = scanner.detect_exit_trace(19080, 5.0)
        self.assertEqual(trace, scanner.ExitTrace("203.0.113.1", "JP", "NRT"))

    def test_exit_ip_falls_back_through_same_proxy_when_trace_fails(self):
        failed_trace = mock.Mock(returncode=22, stdout="")
        ipify = mock.Mock(returncode=0, stdout="198.51.100.24\n")
        with mock.patch.object(
            scanner.subprocess, "run", side_effect=[failed_trace, ipify]
        ) as run:
            trace = scanner.detect_exit_trace(19080, 5.0)
        self.assertEqual(trace, scanner.ExitTrace("198.51.100.24", None, None))
        self.assertIn("socks5h://127.0.0.1:19080", run.call_args_list[1].args[0])
        self.assertIn("https://api64.ipify.org", run.call_args_list[1].args[0])

    def test_geo_city_requires_country_and_distance_corroboration(self):
        trace = scanner.ExitTrace("203.0.113.8", "DE", "FRA")
        record = {
            "country": {"iso_code": "DE", "names": {"en": "Germany"}},
            "city": {"names": {"en": "Frankfurt"}},
            "location": {"latitude": 50.1109, "longitude": 8.6821},
        }
        airport = {
            "country": "DE",
            "lat": 50.0379,
            "lon": 8.5622,
        }
        geo = scanner.corroborate_exit_geo(trace, record, airport, 80.0)
        self.assertEqual(geo.country_name, "Germany")
        self.assertEqual(geo.city, "Frankfurt")
        self.assertTrue(geo.city_confident)

        mismatch = scanner.corroborate_exit_geo(
            trace,
            dict(record, country={"iso_code": "NL", "names": {"en": "Netherlands"}}),
            airport,
            80.0,
        )
        self.assertEqual(mismatch.country_code, "DE")
        self.assertIsNone(mismatch.city)
        self.assertFalse(mismatch.city_confident)

    def test_geonames_recovers_only_a_missing_nearby_city(self):
        trace = scanner.ExitTrace("203.0.113.8", "DE", "FRA")
        record = {
            "country": {"iso_code": "DE", "names": {"en": "Germany"}},
            "city": {"names": {}},
            "location": {"latitude": 50.1109, "longitude": 8.6821},
        }
        airport = {"country": "DE", "lat": 50.0379, "lon": 8.5622}
        nearby = scanner.GeoCity("Frankfurt am Main", "DE", 50.1109, 8.6821)
        geo = scanner.corroborate_exit_geo(
            trace, record, airport, 80.0, nearby, 0.0, 25.0
        )
        self.assertEqual(geo.city, "Frankfurt")
        self.assertTrue(geo.city_confident)
        self.assertEqual(geo.city_source, "geonames_nearest")

        too_far = scanner.corroborate_exit_geo(
            trace, record, airport, 80.0, nearby, 25.1, 25.0
        )
        self.assertIsNone(too_far.city)
        self.assertFalse(too_far.city_confident)

    def test_existing_dbip_city_is_never_replaced_by_geonames(self):
        trace = scanner.ExitTrace("203.0.113.8", "DE", "FRA")
        record = {
            "country": {"iso_code": "DE", "names": {"en": "Germany"}},
            "city": {"names": {"en": "Frankfurt"}},
            "location": {"latitude": 50.1109, "longitude": 8.6821},
        }
        airport = {"country": "DE", "lat": 50.0379, "lon": 8.5622}
        different = scanner.GeoCity("Wiesbaden", "DE", 50.0826, 8.2493)
        geo = scanner.corroborate_exit_geo(
            trace, record, airport, 80.0, different, 10.0, 25.0
        )
        self.assertEqual(geo.city, "Frankfurt")
        self.assertEqual(geo.city_source, "dbip")

    def test_geonames_local_dump_finds_nearest_city_within_same_country(self):
        def row(
            geoname_id,
            name,
            latitude,
            longitude,
            country,
            population,
            feature_code="PPL",
        ):
            fields = [""] * 19
            fields[0] = str(geoname_id)
            fields[1] = name
            fields[2] = name
            fields[4] = str(latitude)
            fields[5] = str(longitude)
            fields[7] = feature_code
            fields[8] = country
            fields[14] = str(population)
            return "\t".join(fields)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cities15000.txt"
            path.write_text(
                "\n".join(
                    (
                        row(1, "Frankfurt am Main", 50.1109, 8.6821, "DE", 650000),
                        row(2, "Berlin", 52.52, 13.405, "DE", 3600000),
                        row(3, "Strasbourg", 48.5734, 7.7521, "FR", 290000),
                        row(4, "Frankfurt District", 50.12, 8.69, "DE", 900000, "PPLX"),
                    )
                ),
                encoding="utf-8",
            )
            city, distance = scanner.nearest_geonames_city(
                str(path), "DE", 50.12, 8.69, 25.0
            )
            self.assertIsNotNone(city)
            self.assertEqual(city.name, "Frankfurt")
            self.assertLess(distance, 2.0)
            absent, _ = scanner.nearest_geonames_city(
                str(path), "DE", 51.0, 10.0, 25.0
            )
            self.assertIsNone(absent)

    def test_geonames_prefers_a_dominant_city_over_a_nearby_small_district(self):
        def row(geoname_id, name, latitude, population, feature_code):
            fields = [""] * 19
            fields[0] = str(geoname_id)
            fields[1] = name
            fields[2] = name
            fields[4] = str(latitude)
            fields[5] = "139.65"
            fields[7] = feature_code
            fields[8] = "JP"
            fields[14] = str(population)
            return "\t".join(fields)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cities15000.txt"
            path.write_text(
                "\n".join(
                    (
                        row(1, "Small Locality", 35.6762, 19000, "PPL"),
                        row(2, "Tokyo", 35.7000, 9733276, "PPLC"),
                    )
                ),
                encoding="utf-8",
            )
            city, distance = scanner.nearest_geonames_city(
                str(path), "JP", 35.6762, 139.65, 25.0
            )
            self.assertIsNotNone(city)
            self.assertEqual(city.name, "Tokyo")
            self.assertLess(distance, 5.0)

    def test_city_display_name_uses_familiar_stable_labels(self):
        self.assertEqual(scanner.city_display_name("Frankfurt am Main"), "Frankfurt")
        self.assertEqual(scanner.city_display_name("New York City"), "New York")
        self.assertEqual(
            scanner.city_display_name("Amsterdam (Amsterdam-Zuidoost)", "NL"),
            "Amsterdam",
        )
        self.assertEqual(
            scanner.city_display_name("Paris (7th Arrondissement)", "FR"),
            "Paris",
        )
        self.assertEqual(
            scanner.city_display_name(
                "Frankfurt am Main (Innenstadt I)", "DE"
            ),
            "Frankfurt",
        )
        self.assertEqual(
            scanner.city_display_name(
                "Los Angeles (Downtown Los Angeles)", "US"
            ),
            "Los Angeles",
        )
        self.assertEqual(
            scanner.city_display_name("Singapore (Pioneer)", "SG"),
            "Singapore",
        )
        self.assertEqual(scanner.city_display_name("Shibuya City", "JP"), "Tokyo")
        self.assertEqual(scanner.city_display_name("Chiyoda", "JP"), "Tokyo")
        self.assertIsNone(scanner.city_display_name("District 7", "XX"))
        self.assertIsNone(
            scanner.city_display_name("An Implausibly Long Administrative Place Name")
        )
        self.assertIsNone(scanner.city_display_name(""))

    def test_source_city_hint_requires_matching_country_and_clean_pattern(self):
        self.assertEqual(
            scanner.source_city_from_name(
                "🇳🇱 The Netherlands, Amsterdam | [BL]", "NL"
            ),
            "Amsterdam",
        )
        self.assertEqual(
            scanner.source_city_from_name(
                "🇩🇪 Germany, Frankfurt am Main | [BL]", "DE"
            ),
            "Frankfurt",
        )
        self.assertIsNone(
            scanner.source_city_from_name(
                "🇹🇷 Turkey, Istanbul | [BL]", "RO"
            )
        )
        self.assertIsNone(scanner.source_city_from_name("France | [BL]", "FR"))

    def test_provider_tag_is_not_mistaken_for_country(self):
        record = {
            "name": "Unlocated server | [BL]",
            "source_names": ["Unlocated server | [BL]"],
        }
        self.assertIsNone(scanner.record_country_code(record, None))

    def test_duplicate_source_city_hints_must_agree(self):
        matching = {
            "name": "Netherlands source",
            "source_names": [
                "🇳🇱 Netherlands, Amsterdam | [BL]",
                "🇳🇱 The Netherlands, Amsterdam | another source",
            ],
        }
        conflicting = {
            "name": "Netherlands source",
            "source_names": [
                "🇳🇱 Netherlands, Amsterdam | [BL]",
                "🇳🇱 Netherlands, Rotterdam | another source",
            ],
        }
        self.assertEqual(
            scanner.source_city_from_record(matching, "NL"), "Amsterdam"
        )
        self.assertIsNone(scanner.source_city_from_record(conflicting, "NL"))

    def test_matching_source_city_fills_only_missing_geoip_city(self):
        uri = f"vless://{UUID}@se.example:443#Old"
        parsed = scanner.parse_node(uri)
        records = [
            {
                "fingerprint": parsed.fingerprint,
                "name": "🇸🇪 Sweden, Stockholm | [BL]",
                "source_names": ["🇸🇪 Sweden, Stockholm | [BL]"],
                "uri": uri,
            }
        ]
        results = {
            parsed.fingerprint: scanner.TestResult(
                parsed.fingerprint,
                True,
                3,
                3,
                100,
                10,
                1.0,
                "ok",
                exit_country="SE",
                exit_country_name="Sweden",
                exit_city=None,
                geo_city_confident=False,
            )
        }
        scanner.normalize_published_names(records, results, {})
        self.assertRegex(records[0]["name"], r"^Sweden · Stockholm #\d{4,5}$")
        self.assertEqual(records[0]["city_source"], "subscription_name")

    def test_geoip_city_wins_over_source_name_hint(self):
        uri = f"vless://{UUID}@se.example:443#Old"
        parsed = scanner.parse_node(uri)
        records = [
            {
                "fingerprint": parsed.fingerprint,
                "name": "🇸🇪 Sweden, Stockholm | [BL]",
                "source_names": ["🇸🇪 Sweden, Stockholm | [BL]"],
                "uri": uri,
            }
        ]
        results = {
            parsed.fingerprint: scanner.TestResult(
                parsed.fingerprint,
                True,
                3,
                3,
                100,
                10,
                1.0,
                "ok",
                exit_country="SE",
                exit_country_name="Sweden",
                exit_city="Gothenburg",
                geo_city_confident=True,
            )
        }
        scanner.normalize_published_names(records, results, {})
        self.assertRegex(records[0]["name"], r"^Sweden · Gothenburg #\d{4,5}$")
        self.assertEqual(records[0]["city_source"], "geoip")

    def test_preserved_names_are_resanitized_before_publication(self):
        uri = f"vless://{UUID}@nl.example:443#Old"
        parsed = scanner.parse_node(uri)
        records = [
            {
                "fingerprint": parsed.fingerprint,
                "name": "The Netherlands source",
                "uri": uri,
                "country": "NL",
                "country_name": "The Netherlands",
                "city": "Amsterdam (Amsterdam-Zuidoost)",
                "city_confident": True,
                "status": "preserved",
            }
        ]
        scanner.normalize_published_names(records, {}, {})
        self.assertRegex(
            records[0]["name"], r"^Netherlands · Amsterdam #\d{4,5}$"
        )
        self.assertEqual(scanner.parse_node(records[0]["uri"]).name, records[0]["name"])

    def test_city_equal_to_country_is_omitted_from_published_name(self):
        uri = f"vless://{UUID}@sg.example:443#Old"
        parsed = scanner.parse_node(uri)
        records = [
            {"fingerprint": parsed.fingerprint, "name": "Singapore", "uri": uri}
        ]
        results = {
            parsed.fingerprint: scanner.TestResult(
                parsed.fingerprint,
                True,
                3,
                3,
                100,
                10,
                1.0,
                "ok",
                exit_country="SG",
                exit_country_name="Singapore",
                exit_city="Singapore",
                geo_city_confident=True,
            )
        }
        counts = scanner.normalize_published_names(records, results, {})
        self.assertEqual(counts, (1, 0, 0, 1))
        self.assertRegex(records[0]["name"], r"^Singapore #\d{4,5}$")
        self.assertNotIn("Singapore · Singapore", records[0]["name"])

    def test_equivalent_macau_spelling_is_recognized_as_duplicate(self):
        self.assertEqual(scanner.city_display_name("Macao", "MO"), "Macau")
        self.assertEqual(
            scanner.location_label_key("Macau"),
            scanner.location_label_key(scanner.city_display_name("Macao", "MO")),
        )

    def test_geo_city_is_omitted_when_colo_is_too_far_away(self):
        geo = scanner.corroborate_exit_geo(
            scanner.ExitTrace("203.0.113.8", "DE", "FRA"),
            {
                "country": {"iso_code": "DE", "names": {"en": "Germany"}},
                "city": {"names": {"en": "Berlin"}},
                "location": {"latitude": 52.52, "longitude": 13.405},
            },
            {"country": "DE", "lat": 50.0379, "lon": 8.5622},
            80.0,
        )
        self.assertIsNone(geo.city)
        self.assertFalse(geo.city_confident)

    def test_display_name_rewrite_preserves_vless_fingerprint(self):
        uri = f"vless://{UUID}@example.com:443?security=tls&type=tcp#Old"
        before = scanner.parse_node(uri)
        rewritten = scanner.set_uri_display_name(uri, "🇺🇸 US | Server 1")
        after = scanner.parse_node(rewritten)
        self.assertEqual(after.name, "🇺🇸 US | Server 1")
        self.assertEqual(after.fingerprint, before.fingerprint)

    def test_display_name_rewrite_preserves_vmess_fingerprint(self):
        payload = {
            "v": "2", "ps": "Old", "add": "example.com", "port": "443",
            "id": UUID, "aid": "0", "net": "ws", "path": "/", "tls": "tls",
        }
        uri = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
        before = scanner.parse_node(uri)
        rewritten = scanner.set_uri_display_name(uri, "🇨🇦 CA | Server 1")
        after = scanner.parse_node(rewritten)
        self.assertEqual(after.name, "🇨🇦 CA | Server 1")
        self.assertEqual(after.fingerprint, before.fingerprint)

    def test_display_name_rewrite_supports_trojan_and_shadowsocks(self):
        ss_user = base64.urlsafe_b64encode(b"aes-256-gcm:password").decode().rstrip("=")
        uris = [
            "trojan://secret@example.com:443?security=tls#Old",
            f"ss://{ss_user}@example.com:8388#Old",
        ]
        for uri in uris:
            with self.subTest(uri=uri):
                before = scanner.parse_node(uri)
                rewritten = scanner.set_uri_display_name(uri, "🇳🇱 NL | Server 1")
                after = scanner.parse_node(rewritten)
                self.assertEqual(after.name, "🇳🇱 NL | Server 1")
                self.assertEqual(after.fingerprint, before.fingerprint)

    def test_published_names_use_stable_ids_and_confident_city(self):
        records = [
            {"fingerprint": "a", "name": "🇺🇸 source", "uri": f"vless://{UUID}@a.example:443#x"},
            {"fingerprint": "b", "name": "United States node", "uri": f"vless://{UUID}@b.example:443#x"},
            {"fingerprint": "c", "name": "Canada", "uri": f"vless://{UUID}@c.example:443#x"},
            {"fingerprint": "d", "name": "mystery", "uri": f"vless://{UUID}@d.example:443#x"},
        ]
        results = {
            "a": scanner.TestResult(
                "a", True, 3, 3, 100, 10, 1.0, "ok",
                exit_country="US", exit_country_name="USA",
                exit_city="New York", geo_city_confident=True,
            )
        }
        registry = {}
        counts = scanner.normalize_published_names(records, results, registry)
        self.assertEqual(counts, (3, 1, 1, 2))
        self.assertEqual(len(records), 3)
        self.assertRegex(records[0]["name"], r"^USA · New York #\d{4,5}$")
        self.assertRegex(records[1]["name"], r"^USA #\d{4,5}$")
        self.assertRegex(records[2]["name"], r"^Canada #\d{4,5}$")
        self.assertTrue(all("Unknown" not in record["name"] for record in records))
        self.assertEqual(len(set(registry.values())), 3)

        original_ids = dict(registry)
        returning = [
            {"fingerprint": "c", "name": "Canada", "uri": f"vless://{UUID}@c.example:443#x"},
            {"fingerprint": "a", "name": "US", "uri": f"vless://{UUID}@a.example:443#x"},
        ]
        scanner.normalize_published_names(returning, results, registry)
        self.assertEqual(
            [record["server_id"] for record in returning],
            [original_ids["c"], original_ids["a"]],
        )

    def test_stable_id_collision_never_reuses_an_existing_number(self):
        registry = {"old": 1042}
        with mock.patch.object(scanner.hashlib, "sha256") as digest:
            digest.return_value.digest.return_value = (
                (1042 - scanner.SERVER_ID_MIN).to_bytes(8, "big") + b"x" * 24
            )
            allocated = scanner.allocate_stable_server_id("new", registry)
        self.assertNotEqual(allocated, 1042)
        self.assertEqual(registry["old"], 1042)

    def test_stable_ids_prefer_four_digits_and_never_exceed_five(self):
        registry = {}
        for index in range(500):
            allocated = scanner.allocate_stable_server_id(
                f"fingerprint-{index}", registry
            )
            self.assertGreaterEqual(allocated, 1000)
            self.assertLessEqual(allocated, 9999)
            self.assertLessEqual(len(str(allocated)), 5)
        self.assertEqual(len(set(registry.values())), 500)

    def test_stable_id_uses_five_digits_only_when_four_digit_space_is_full(self):
        registry = {
            f"occupied-{server_id}": server_id
            for server_id in range(
                scanner.SERVER_ID_MIN,
                scanner.SERVER_ID_FOUR_DIGIT_MAX + 1,
            )
        }
        allocated = scanner.allocate_stable_server_id("new", registry)
        self.assertGreaterEqual(allocated, 10000)
        self.assertLessEqual(allocated, 99999)

    def test_existing_four_or_five_digit_id_is_preserved(self):
        for existing in (1042, 42081):
            with self.subTest(existing=existing):
                registry = {"same": existing}
                self.assertEqual(
                    scanner.allocate_stable_server_id("same", registry), existing
                )

    def test_legacy_six_digit_id_is_replaced_once(self):
        registry = {"same": 602881}
        replacement = scanner.allocate_stable_server_id("same", registry)
        self.assertGreaterEqual(replacement, 1000)
        self.assertLessEqual(replacement, 9999)
        self.assertEqual(registry["same"], replacement)
        self.assertEqual(
            scanner.allocate_stable_server_id("same", registry), replacement
        )

    def test_settings_defaults(self):
        settings = scanner.Settings.from_env()
        self.assertEqual(settings.max_latency_ms, 3000.0)
        self.assertEqual(settings.elite_latency_ms, 800.0)
        self.assertEqual(settings.max_jitter_ms, 600.0)
        self.assertEqual(settings.max_output, 450)
        self.assertEqual(settings.min_speed_mbps, 1.1)
        self.assertEqual(settings.good_speed_mbps, 1.5)
        self.assertEqual(settings.strong_speed_mbps, 2.5)
        self.assertEqual(settings.speed_budget_bytes, 160 * 1024 * 1024)
        self.assertEqual(settings.speed_retry_reserve_bytes, 24 * 1024 * 1024)
        self.assertGreaterEqual(settings.max_configs, 6000)
        self.assertTrue(settings.tcp_prefilter)
        self.assertEqual(settings.geo_city_max_distance_km, 80.0)
        self.assertEqual(
            settings.geonames_cities_path, ".cache/geoip/cities15000.txt"
        )
        self.assertEqual(settings.geonames_nearest_city_km, 25.0)
        self.assertEqual(
            settings.speed_retry_url, "https://proof.ovh.net/files/1Mb.dat"
        )

    def test_health_probes_do_not_depend_on_cloudflare_hosted_urls(self):
        # Workers/proxyip nodes cannot reach Cloudflare-hosted sites by design.
        for url in scanner.Settings().probe_urls:
            self.assertNotIn("cloudflare", url)
        self.assertGreaterEqual(len(scanner.Settings().probe_urls), 5)

    def test_stream_reliability_dominates_small_latency_difference(self):
        settings = scanner.Settings.from_env()
        low_latency = {
            "latency_ms": 200.0,
            "jitter_ms": 20.0,
            "success_rate": 1.0,
            "speed_mbps": None,
            "stream_quality": "unverified",
            "stream_reliability": 0.0,
            "stream_verified": False,
            "status": "healthy",
        }
        streamed = {
            "latency_ms": 450.0,
            "jitter_ms": 20.0,
            "success_rate": 1.0,
            "stream_floor_mbps": 2.5,
            "stream_quality": "strong",
            "stream_reliability": 1.0,
            "stream_verified": True,
            "status": "healthy",
        }
        self.assertLess(
            scanner.record_score(low_latency, settings),
            scanner.record_score(streamed, settings),
        )

    def test_stream_quality_accepts_sustained_good_transfer(self):
        quality, confirmed, reason = scanner.assess_stream_quality(
            [3.2, 2.8], 2, 2, 0, True, scanner.Settings()
        )
        self.assertEqual((quality, confirmed, reason), ("strong", False, "ok"))

    def test_stream_quality_rejects_two_confirmed_slow_transfers(self):
        quality, confirmed, reason = scanner.assess_stream_quality(
            [0.8, 0.9], 2, 2, 0, True, scanner.Settings()
        )
        self.assertEqual((quality, confirmed, reason), ("poor", True, "confirmed_slow"))

    def test_stream_quality_detects_burst_then_stall(self):
        quality, confirmed, reason = scanner.assess_stream_quality(
            [4.0], 2, 1, 1, True, scanner.Settings()
        )
        self.assertEqual((quality, confirmed, reason), ("unstable", False, "stream_stall"))

    def test_one_slow_sample_is_not_called_confirmed(self):
        quality, confirmed, reason = scanner.assess_stream_quality(
            [0.9], 1, 1, 0, False, scanner.Settings()
        )
        self.assertEqual((quality, confirmed, reason), ("poor", False, "stream_below_target"))

    def test_unverified_transfer_keeps_previously_good_healthy_node(self):
        result = scanner.TestResult("abc", True, 3, 3, 200.0, 20.0, 1.0, "ok")
        scanner.apply_stream_result(
            result,
            scanner.StreamTestResult(
                None, [], None, 1, 0, 0, 0, False,
                "unverified", False, "stream_unverified", None,
            ),
            {"stream_quality": "good", "speed_mbps": 1.8},
            scanner.Settings(),
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.stream_quality, "unverified")

    def test_untested_healthy_node_is_published_provisionally(self):
        # A node that passed the real HTTPS health probes must not be rejected
        # merely because the transfer-test budget ran out before its turn.
        result = scanner.TestResult("abc", True, 3, 3, 200.0, 20.0, 1.0, "ok")
        scanner.apply_stream_result(result, None, None, scanner.Settings())
        self.assertTrue(result.passed)
        self.assertEqual(result.stream_quality, "unverified")

    def test_inconclusive_transfer_is_provisional_for_a_limited_time(self):
        inconclusive = scanner.StreamTestResult(
            None, [], None, 1, 0, 0, 0, False,
            "unverified", False, "stream_unverified", None,
        )
        for streak in range(scanner.INCONCLUSIVE_STREAM_LIMIT):
            result = scanner.TestResult("abc", True, 3, 3, 200.0, 20.0, 1.0, "ok")
            scanner.apply_stream_result(
                result, inconclusive, {"stream_uncertain_streak": streak},
                scanner.Settings(),
            )
            self.assertTrue(result.passed, streak)

        result = scanner.TestResult("abc", True, 3, 3, 200.0, 20.0, 1.0, "ok")
        scanner.apply_stream_result(
            result,
            inconclusive,
            {
                "stream_quality": "strong",
                "stream_verified": True,
                "stream_uncertain_streak": scanner.INCONCLUSIVE_STREAM_LIMIT,
            },
            scanner.Settings(),
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "stream_unverified")

    def test_stream_geo_does_not_erase_health_phase_geo(self):
        result = scanner.TestResult(
            "abc", True, 3, 3, 200.0, 20.0, 1.0, "ok",
            exit_country="DE", exit_ip="203.0.113.9",
        )
        scanner.apply_stream_result(
            result,
            scanner.StreamTestResult(
                3.0, [3.0], 3.0, 1, 1, 0, 262144, False,
                "strong", False, "ok", None,
            ),
            None,
            scanner.Settings(),
        )
        self.assertEqual(result.exit_country, "DE")
        self.assertEqual(result.exit_ip, "203.0.113.9")

    def test_uncertain_streak_counts_only_attempted_transfers(self):
        settings = scanner.Settings()
        node = scanner.parse_node(
            f"vless://{UUID}@example.com:443?security=tls&type=tcp#streak"
        )
        skipped = scanner.TestResult(node.fingerprint, True, 3, 3, 200.0, 20.0, 1.0, "ok")
        record = scanner.make_record(
            node, skipped, "2026-07-26T12:00:00Z",
            {"stream_uncertain_streak": 2}, settings,
        )
        self.assertEqual(record["stream_uncertain_streak"], 2)
        tried = dataclasses.replace(skipped, stream_attempts=1)
        record = scanner.make_record(
            node, tried, "2026-07-26T12:00:00Z",
            {"stream_uncertain_streak": 2}, settings,
        )
        self.assertEqual(record["stream_uncertain_streak"], 3)

    def test_one_weak_sample_gets_one_chance_but_not_indefinitely(self):
        stream = scanner.StreamTestResult(
            0.9, [0.9], 0.9, 2, 1, 0, 262144, False,
            "poor", False, "stream_below_target", None,
        )
        first = scanner.TestResult(
            "abc", True, 3, 3, 200.0, 20.0, 1.0, "ok"
        )
        scanner.apply_stream_result(
            first,
            stream,
            {"stream_quality": "strong", "stream_verified": True},
            scanner.Settings(),
        )
        self.assertTrue(first.passed)

        repeated = scanner.TestResult(
            "abc", True, 3, 3, 200.0, 20.0, 1.0, "ok"
        )
        scanner.apply_stream_result(
            repeated,
            stream,
            {
                "stream_quality": "strong",
                "stream_verified": True,
                "stream_failure_streak": 1,
            },
            scanner.Settings(),
        )
        self.assertFalse(repeated.passed)
        self.assertEqual(repeated.reason, "stream_below_target")

    def test_previous_good_does_not_override_current_stream_stall(self):
        result = scanner.TestResult("abc", True, 3, 3, 200.0, 20.0, 1.0, "ok")
        scanner.apply_stream_result(
            result,
            scanner.StreamTestResult(
                4.0, [4.0], 4.0, 2, 1, 1, 300000, True,
                "unstable", False, "stream_stall", None,
            ),
            {"stream_quality": "strong", "stream_verified": True},
            scanner.Settings(),
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "stream_stall")
        self.assertIn(result.reason, scanner.HARD_REJECTION_REASONS)

    def test_deep_good_result_marks_history_verified(self):
        settings = scanner.Settings()
        node = scanner.parse_node(
            f"vless://{UUID}@example.com:443?security=tls&type=tcp#history"
        )
        result = scanner.TestResult(
            node.fingerprint, True, 3, 3, 220.0, 15.0, 1.0, "ok",
            speed_mbps=2.8,
            speed_samples=[3.0, 2.6],
            speed_floor_mbps=2.6,
            stream_attempts=2,
            stream_completed=2,
            stream_deep_tested=True,
            stream_quality="strong",
        )
        record = scanner.make_record(node, result, "2026-07-26T12:00:00Z", None, settings)
        self.assertTrue(record["stream_verified"])
        self.assertEqual(record["stream_quality"], "strong")
        self.assertEqual(len(record["stream_history"]), 1)

    def test_curl_low_speed_guard_is_enabled(self):
        completed = mock.Mock(
            returncode=0,
            stdout=(
                "__MEZA_METRICS__200\t0.1\t1.0\t262144\t262144\n"
            ),
            stderr="",
        )
        with mock.patch.object(scanner.subprocess, "run", return_value=completed) as run:
            ok, _, _ = scanner.curl_measure(
                19080,
                "https://example.com/file",
                10.0,
                expected_min_bytes=200000,
                maximum_bytes=262144,
                byte_range="0-262143",
                low_speed_limit_bps=137500,
                low_speed_seconds=3,
            )
        self.assertTrue(ok)
        command = run.call_args.args[0]
        self.assertIn("--speed-limit", command)
        self.assertEqual(command[command.index("--speed-limit") + 1], "137500")
        self.assertIn("--speed-time", command)
        self.assertIn("--max-filesize", command)
        self.assertIn("--range", command)
        self.assertEqual(command[command.index("--range") + 1], "0-262143")
        self.assertIn("Cache-Control: no-cache", command)

    def test_stream_plan_never_exceeds_network_budget(self):
        settings = scanner.Settings()
        for candidates in (0, 1, 100, 214, 450, 5000):
            primary = scanner.initial_stream_test_count(candidates, settings)
            for retry_needed in (0, primary // 5, primary):
                with self.subTest(
                    candidates=candidates, retry_needed=retry_needed
                ):
                    retry, deep, planned = scanner.followup_stream_test_plan(
                        primary, retry_needed, settings
                    )
                    self.assertLessEqual(planned, settings.speed_budget_bytes)
                    self.assertLessEqual(retry, retry_needed)
                    self.assertLessEqual(deep, primary)
                    self.assertLessEqual(primary, settings.speed_test_max)

    def test_independent_retry_can_recover_an_unverified_primary(self):
        settings = scanner.Settings()
        primary = scanner.StreamTestResult(
            None, [], None, 1, 0, 0, 0, False,
            "unverified", False, "stream_unverified", None,
        )
        fallback = scanner.StreamTestResult(
            2.0, [2.0], 2.0, 1, 1, 0, 262144, False,
            "good", False, "ok", "DE",
        )
        combined = scanner.combine_stream_results(
            primary, fallback, settings, multi_endpoint_retry=True
        )
        self.assertEqual(combined.quality, "good")
        self.assertEqual(combined.reason, "ok")
        self.assertEqual(combined.exit_country, "DE")

    def test_combined_geo_omits_disagreeing_cities(self):
        settings = scanner.Settings()
        primary = scanner.StreamTestResult(
            3.0, [3.0], 3.0, 1, 1, 0, 262144, False,
            "strong", False, "ok", "DE", "203.0.113.1",
            "Germany", "Frankfurt", True,
        )
        secondary = scanner.StreamTestResult(
            3.1, [3.1], 3.1, 1, 1, 0, 1048576, True,
            "strong", False, "ok", "DE", "203.0.113.2",
            "Germany", "Berlin", True,
        )
        combined = scanner.combine_stream_results(primary, secondary, settings)
        self.assertIsNone(combined.exit_city)
        self.assertFalse(combined.geo_city_confident)

    def test_combined_geo_keeps_two_matching_confident_cities(self):
        settings = scanner.Settings()
        primary = scanner.StreamTestResult(
            3.0, [3.0], 3.0, 1, 1, 0, 262144, False,
            "strong", False, "ok", "DE", "203.0.113.1",
            "Germany", "Frankfurt", True,
        )
        secondary = dataclasses.replace(
            primary,
            speed_mbps=3.1,
            speed_samples=[3.1],
            exit_ip="203.0.113.2",
        )
        combined = scanner.combine_stream_results(primary, secondary, settings)
        self.assertEqual(combined.exit_city, "Frankfurt")
        self.assertTrue(combined.geo_city_confident)

    def test_two_independent_failures_are_hard_rejection(self):
        settings = scanner.Settings()
        failed = scanner.StreamTestResult(
            None, [], None, 1, 0, 0, 0, False,
            "unverified", False, "stream_unverified", None,
        )
        combined = scanner.combine_stream_results(
            failed, failed, settings, multi_endpoint_retry=True
        )
        self.assertEqual(combined.reason, "stream_multi_endpoint_failed")
        self.assertIn(combined.reason, scanner.HARD_REJECTION_REASONS)

        result = scanner.TestResult(
            "abc", True, 3, 3, 200.0, 20.0, 1.0, "ok"
        )
        scanner.apply_stream_result(
            result,
            combined,
            {"stream_quality": "strong", "stream_verified": True},
            settings,
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "stream_multi_endpoint_failed")

    def test_three_samples_ignore_one_low_outlier(self):
        settings = scanner.Settings()
        primary = scanner.StreamTestResult(
            0.9, [0.9], 0.9, 1, 1, 0, 262144, False,
            "poor", False, "stream_below_target", None,
        )
        fallback = scanner.StreamTestResult(
            2.55, [2.5, 2.6], 2.5, 2, 2, 0, 1310720, True,
            "strong", False, "ok", None,
        )
        combined = scanner.combine_stream_results(
            primary, fallback, settings, multi_endpoint_retry=True
        )
        self.assertEqual(combined.quality, "strong")
        self.assertEqual(combined.speed_floor_mbps, 2.5)

    def test_two_conflicting_endpoints_remain_unverified(self):
        quality, confirmed, reason = scanner.assess_stream_quality(
            [0.9, 2.4], 2, 2, 0, False, scanner.Settings()
        )
        self.assertEqual(
            (quality, confirmed, reason),
            ("unverified", False, "stream_inconsistent"),
        )

    def test_one_stall_with_two_good_transfers_is_capped_at_good(self):
        quality, confirmed, reason = scanner.assess_stream_quality(
            [3.0, 2.8], 3, 2, 1, True, scanner.Settings()
        )
        self.assertEqual((quality, confirmed, reason), ("good", False, "ok"))

    def test_ovh_measurement_uses_exact_http_range(self):
        completed = mock.Mock(
            returncode=0,
            stdout="__MEZA_METRICS__206\t0.1\t0.5\t262144\t524288\n",
            stderr="",
        )
        with mock.patch.object(scanner.subprocess, "run", return_value=completed) as run:
            ok, _, downloaded, _ = scanner._stream_measurement(
                19080,
                262144,
                scanner.Settings(),
                endpoint_url="https://proof.ovh.net/files/1Mb.dat",
                use_range=True,
            )
        self.assertTrue(ok)
        self.assertEqual(downloaded, 262144)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--range") + 1], "0-262143")

    def test_stream_speed_excludes_connection_startup_time(self):
        metrics = {
            "http_code": 200,
            "size_download": 1_000_000,
            "speed_download": 500_000.0,
            "ttfb_seconds": 0.5,
            "total_seconds": 1.5,
        }
        with mock.patch.object(
            scanner, "curl_measure", return_value=(True, metrics, "")
        ):
            ok, speed, downloaded, stalled = scanner._stream_measurement(
                19080, 1_000_000, scanner.Settings()
            )
        self.assertTrue(ok)
        self.assertEqual(downloaded, 1_000_000)
        self.assertFalse(stalled)
        self.assertAlmostEqual(speed, 8.0)

    def test_single_high_latency_outlier_is_ignored_after_retests(self):
        samples = [
            scanner.ProbeSample(True, latency_ms=value)
            for value in (200.0, 210.0, 900.0, 220.0, 230.0)
        ]
        success_count, median, jitter, success_rate = scanner.summarize_samples(samples)
        self.assertEqual(success_count, 5)
        self.assertEqual(median, 220.0)
        self.assertEqual(jitter, 30.0)
        self.assertEqual(success_rate, 1.0)

    def test_health_filter_marks_zero_responses_unreachable(self):
        result = self._test_result_for_samples(
            [scanner.ProbeSample(False, reason="timeout") for _ in range(5)]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "confirmed_unreachable")

    def test_health_filter_keeps_stable_viable_node(self):
        result = self._test_result_for_samples(
            [scanner.ProbeSample(True, latency_ms=value) for value in (900, 950, 1000, 920, 980)]
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.reason, "ok")

    def test_health_filter_rejects_consistently_extreme_latency(self):
        result = self._test_result_for_samples(
            [scanner.ProbeSample(True, latency_ms=value) for value in (3200, 3300, 3400, 3250, 3350)]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "consistently_high_latency")

    def test_health_filter_rejects_repeated_large_jitter(self):
        result = self._test_result_for_samples(
            [scanner.ProbeSample(True, latency_ms=value) for value in (100, 900, 1000, 1100, 1200)]
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "unstable_jitter")

    def test_trojan_without_security_parameter_uses_tls(self):
        node = scanner.parse_node(
            "trojan://pw@example.com:443?sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fa#t"
        )
        stream = node.outbound["streamSettings"]
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(stream["tlsSettings"]["serverName"], "cdn.example.com")
        # An explicit value still wins, and VLESS keeps its plaintext default.
        explicit = scanner.parse_node("trojan://pw@example.com:443?security=none&type=tcp#t")
        self.assertEqual(explicit.outbound["streamSettings"]["security"], "none")
        vless = scanner.parse_node(f"vless://{UUID}@example.com:443?type=tcp#v")
        self.assertEqual(vless.outbound["streamSettings"]["security"], "none")
        blank = scanner.parse_node("trojan://pw@example.com:443?security=&sni=a.example#t")
        self.assertEqual(blank.outbound["streamSettings"]["security"], "tls")

    def test_allow_insecure_is_replaced_by_a_pinned_certificate_for_probes(self):
        node = scanner.parse_node(
            "trojan://pw@example.com:443?allowInsecure=1&sni=self.example#t"
        )
        before = json.dumps(node.outbound, sort_keys=True)
        with mock.patch.object(
            scanner, "fetch_peer_cert_sha256", return_value="cd" * 32
        ) as fetch:
            config = scanner.build_xray_config(node, 19080)
        tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
        self.assertNotIn("allowInsecure", tls)
        self.assertEqual(tls["pinnedPeerCertSha256"], "cd" * 32)
        fetch.assert_called_once_with("example.com", 443, "self.example")
        # The node itself (and so its fingerprint and published link) is untouched.
        self.assertEqual(json.dumps(node.outbound, sort_keys=True), before)
        self.assertTrue(node.outbound["streamSettings"]["tlsSettings"]["allowInsecure"])

    def test_verified_tls_nodes_never_fetch_a_pin_and_drop_the_removed_key(self):
        node = scanner.parse_node(
            "trojan://pw@example.com:443?security=tls&sni=ok.example#t"
        )
        with mock.patch.object(scanner, "fetch_peer_cert_sha256") as fetch:
            config = scanner.build_xray_config(node, 19080)
        fetch.assert_not_called()
        tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
        self.assertNotIn("allowInsecure", tls)
        self.assertNotIn("pinnedPeerCertSha256", tls)

    def test_unreachable_insecure_node_is_reported_with_a_clear_error(self):
        node = scanner.parse_node(
            "trojan://pw@127.0.0.1:1?allowInsecure=1&sni=x.example#t"
        )
        with mock.patch.object(
            scanner, "fetch_peer_cert_sha256",
            side_effect=scanner.ScannerError("insecure TLS node: certificate unavailable (OSError)"),
        ):
            result = scanner.test_node(node, "xray", scanner.Settings())
        self.assertFalse(result.passed)
        self.assertIn("certificate unavailable", result.error)

    def _patient(self, samples, previous=None):
        settings = scanner.Settings()
        node = scanner.parse_node(
            f"vless://{UUID}@example.com:443?security=tls&type=tcp#patient"
        )
        previous = previous or scanner.TestResult(
            node.fingerprint, False, 1, 3, None, None, 0.33,
            "insufficient_successes", error="curl: (28) timed out",
        )
        session = mock.MagicMock()
        session.__enter__.return_value = 19080
        session.__exit__.return_value = None
        with mock.patch.object(scanner, "XraySession", return_value=session), mock.patch.object(
            scanner, "probe_once", side_effect=samples
        ) as probe, mock.patch.object(
            scanner, "detect_exit_trace", return_value=scanner.ExitTrace(None, "NL", None)
        ):
            result = scanner.patient_test_node(node, "xray", settings, previous)
        self.patient_probe_calls = probe.call_count
        return result, previous

    def test_patient_stage_accepts_a_slow_node_that_answers_three_destinations(self):
        ok = scanner.ProbeSample(True, latency_ms=5200.0)
        bad = scanner.ProbeSample(False, reason="timed out")
        result, previous = self._patient([bad, ok, ok, ok, ok])
        self.assertTrue(result.passed)
        self.assertTrue(result.patient)
        self.assertEqual(result.reason, "ok")
        self.assertEqual(result.exit_country, "NL")
        self.assertEqual(self.patient_probe_calls, 4)  # stops once three answered

    def test_patient_stage_still_rejects_a_node_that_stays_silent(self):
        bad = scanner.ProbeSample(False, reason="curl: (28) timed out")
        ok = scanner.ProbeSample(True, latency_ms=900.0)
        result, previous = self._patient([ok, bad, bad, bad, bad])
        self.assertIs(result, previous)
        self.assertFalse(result.passed)
        self.assertEqual(self.patient_probe_calls, 4)  # gave up once 3 could not happen

    def test_patient_stage_rejects_beyond_the_slow_latency_limit(self):
        slow = scanner.ProbeSample(True, latency_ms=scanner.Settings().patient_max_latency_ms + 1)
        result, previous = self._patient([slow, slow, slow])
        self.assertIs(result, previous)

    def test_patient_stage_failure_to_start_keeps_the_original_failure(self):
        settings = scanner.Settings()
        node = scanner.parse_node(f"vless://{UUID}@example.com:443?security=tls&type=tcp#p")
        previous = scanner.TestResult(
            node.fingerprint, False, 0, 2, None, None, 0.0, "confirmed_unreachable"
        )
        with mock.patch.object(scanner, "XraySession", side_effect=scanner.ScannerError("x")):
            self.assertIs(
                scanner.patient_test_node(node, "xray", settings, previous), previous
            )

    def test_only_nodes_with_signs_of_life_get_the_patient_stage(self):
        def failed(reason, error="", successes=0):
            return scanner.TestResult(
                "abc", False, successes, 3, None, None, 0.0, reason, error=error
            )

        self.assertTrue(scanner.needs_patient_retest(failed("confirmed_unreachable", "curl: (28) Connection timed out")))
        self.assertTrue(scanner.needs_patient_retest(failed("insufficient_successes", "curl: (35) reset", successes=1)))
        self.assertTrue(scanner.needs_patient_retest(failed("unstable_jitter", successes=4)))
        self.assertFalse(scanner.needs_patient_retest(failed("confirmed_unreachable", "curl: (35) wrong version number")))
        self.assertFalse(scanner.needs_patient_retest(failed("confirmed_unreachable", "ScannerError: xray failed to start")))
        self.assertFalse(scanner.needs_patient_retest(failed("confirmed_unreachable", "tcp connect failed: TimeoutError")))
        self.assertFalse(scanner.needs_patient_retest(failed("stream_stall", "timed out")))
        self.assertFalse(scanner.needs_patient_retest(scanner.TestResult("a", True, 3, 3, 1.0, 1.0, 1.0, "ok")))

    def test_two_failed_probes_stop_the_health_test_early(self):
        samples = [scanner.ProbeSample(False, reason="curl: (28) timeout")] * 2 + [
            scanner.ProbeSample(True, latency_ms=100.0)
        ] * 3
        result = self._test_result_for_samples(samples)
        self.assertFalse(result.passed)
        self.assertEqual(self.probe_calls, 2)
        self.assertEqual(result.reason, "confirmed_unreachable")
        self.assertIn("timeout", result.error)

    def test_one_failed_probe_is_still_recovered_by_retest(self):
        samples = [
            scanner.ProbeSample(False, reason="curl: (28) timeout"),
            *[scanner.ProbeSample(True, latency_ms=100.0)] * 4,
        ]
        result = self._test_result_for_samples(samples)
        self.assertTrue(result.passed)
        self.assertEqual(self.probe_calls, 5)

    def test_health_pass_records_egress_country_for_naming(self):
        result = self._test_result_for_samples(
            [scanner.ProbeSample(True, latency_ms=100.0)] * 3
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.exit_country, "DE")  # country from the trace alone
        with mock.patch.object(
            scanner,
            "resolve_exit_geo",
            return_value=scanner.ExitGeo("203.0.113.5", "NL", "Netherlands", None, False),
        ):
            result = self._test_result_for_samples(
                [scanner.ProbeSample(True, latency_ms=100.0)] * 3
            )
        self.assertEqual(result.exit_country, "NL")
        self.assertEqual(result.exit_ip, "203.0.113.5")

    def test_percent_encoded_query_value_does_not_corrupt_the_link(self):
        # ``ech=...%2Budp%3A%2F%2F...`` contains an encoded "://" inside a
        # query value. The link itself must be kept byte-for-byte.
        link = (
            f"vless://{UUID}@188.114.97.6:443?encryption=none&security=tls"
            "&sni=a.example&fp=chrome&alpn=http%2F1.1"
            "&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&type=ws&host=a.example"
            "&path=%2Fcart%2Fproxyip%3D1.2.3.4%3Fed%23Telegram---tag#NAME"
        )
        links = scanner.extract_links(link)
        self.assertEqual(links, [link])
        path = scanner.parse_node(links[0]).outbound["streamSettings"]["wsSettings"]["path"]
        self.assertEqual(path, "/cart/proxyip=1.2.3.4?ed#Telegram---tag")

    def test_fully_encoded_embedded_link_is_still_decoded(self):
        inner = f"vless://{UUID}@example.com:443?security=tls&type=tcp#E"
        wrapped = "https://t.me/proxy?url=" + inner.replace(":", "%3A").replace("/", "%2F")
        self.assertEqual(scanner.extract_links(wrapped), [inner])
        self.assertEqual(
            scanner.extract_links(inner.replace(":", "%3A").replace("/", "%2F")),
            [inner],
        )

    def test_links_differing_only_in_path_stay_distinct(self):
        base = (
            f"vless://{UUID}@188.114.97.6:443?security=tls&sni=a.example"
            "&ech=x.example%2Budp%3A%2F%2F1.1.1.1&type=ws&host=a.example&path="
        )
        first = scanner.extract_links(base + "%2Fp%3Fed%23one#A")[0]
        second = scanner.extract_links(base + "%2Fp%3Fed%23two#B")[0]
        self.assertNotEqual(
            scanner.parse_node(first).fingerprint,
            scanner.parse_node(second).fingerprint,
        )

    def test_rotation_changes_between_windows_and_is_stable_inside_one(self):
        fingerprints = [f"{index:04x}" for index in range(200)]
        first = sorted(fingerprints, key=lambda item: scanner.rotation_key(item, 1))
        again = sorted(fingerprints, key=lambda item: scanner.rotation_key(item, 1))
        later = sorted(fingerprints, key=lambda item: scanner.rotation_key(item, 2))
        self.assertEqual(first, again)
        self.assertNotEqual(first, later)
        # Over a few windows every node reaches the first quarter at least once.
        seen = set()
        for salt in range(40):
            ordered = sorted(fingerprints, key=lambda item: scanner.rotation_key(item, salt))
            seen.update(ordered[:50])
        self.assertEqual(seen, set(fingerprints))
        self.assertEqual(scanner.rotation_salt(0), 0)
        self.assertEqual(
            scanner.rotation_salt(scanner.ROTATION_WINDOW_SECONDS * 3 + 1), 3
        )

    def test_retry_plan_uses_actual_primary_bytes(self):
        settings = scanner.Settings()
        primary = scanner.initial_stream_test_count(1000, settings)
        planned_retry, _, _ = scanner.followup_stream_test_plan(primary, 1000, settings)
        used_retry, deep, planned = scanner.followup_stream_test_plan(
            primary, 1000, settings, primary_used_bytes=primary * 40_000
        )
        self.assertGreater(used_retry, planned_retry)
        self.assertLessEqual(planned, settings.speed_budget_bytes)
        self.assertLessEqual(
            primary * settings.speed_test_bytes, settings.speed_budget_bytes
        )
        # Reported actual bytes can never raise the plan above the cap.
        capped_retry, _, capped_planned = scanner.followup_stream_test_plan(
            primary, 1000, settings, primary_used_bytes=10**12
        )
        self.assertEqual(capped_retry, planned_retry)
        self.assertLessEqual(capped_planned, settings.speed_budget_bytes)

    def test_node_uses_tcp_detection(self):
        tcp = scanner.parse_node(f"vless://{UUID}@example.com:443?security=tls&type=ws&path=%2F#a")
        kcp = scanner.parse_node(f"vless://{UUID}@example.com:443?security=none&type=kcp#b")
        h3 = scanner.parse_node(
            f"vless://{UUID}@example.com:443?security=tls&type=xhttp&alpn=h3&path=%2F#c"
        )
        ss = scanner.parse_node(
            "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
            + "@example.com:8388#d"
        )
        self.assertTrue(scanner.node_uses_tcp(tcp))
        self.assertFalse(scanner.node_uses_tcp(kcp))
        self.assertFalse(scanner.node_uses_tcp(h3))
        self.assertTrue(scanner.node_uses_tcp(ss))

    def test_tcp_prefilter_rejects_only_confirmed_dead_endpoints(self):
        import socket

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        live_port = server.getsockname()[1]
        dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()  # nothing listens here any more
        try:
            def make(port, tag):
                return scanner.parse_node(
                    f"vless://{UUID}@127.0.0.1:{port}?security=tls&type=ws&path=%2F{tag}#{tag}"
                )

            alive_node = make(live_port, "alive")
            dead_node = make(dead_port, "dead")
            protected_node = make(dead_port, "protected")
            udp_node = scanner.parse_node(
                f"vless://{UUID}@127.0.0.1:{dead_port}?security=none&type=kcp#udp"
            )
            settings = dataclasses.replace(
                scanner.Settings(),
                tcp_connect_timeout_seconds=1.0,
                tcp_retry_timeout_seconds=1.0,
            )
            failed, checked = scanner.tcp_prefilter(
                [alive_node, dead_node, protected_node, udp_node],
                {protected_node.fingerprint},
                settings,
            )
        finally:
            server.close()
        self.assertEqual(set(failed), {dead_node.fingerprint})
        self.assertEqual(checked, 2)


class FullRunTests(unittest.TestCase):
    """Drive run() end to end with the network and Xray replaced by fakes."""

    def _run(self, node_count, env, health=None, patient=None):
        import argparse
        import os

        links = []
        for index in range(node_count):
            links.append(
                f"vless://{UUID}@10.0.{index // 250}.{index % 250 + 1}:{4000 + index}"
                f"?security=tls&type=ws&sni=a.example&host=a.example"
                f"&ech=x.example%2Budp%3A%2F%2F1.1.1.1&path=%2Fp{index}%3Fed%23tag{index}"
                f"#raw-{index}"
            )

        def fake_test_node(node, xray_bin, settings):
            number = int(node.fingerprint[:6], 16)
            if number % 3 == 0:
                return scanner.TestResult(
                    node.fingerprint, False, 0, 2, None, None, 0.0,
                    "confirmed_unreachable", error="curl: (28) timed out",
                )
            return scanner.TestResult(
                node.fingerprint, True, 3, 3, 250.0, 30.0, 1.0, "ok",
                exit_country="DE", exit_ip="203.0.113.7",
                exit_country_name="Germany",
            )

        calls = {"primary": 0, "retry": 0}

        def fake_speed(node, xray_bin, settings, deep_test=False,
                       endpoint_url=None, use_range=False, include_quick=True):
            if endpoint_url:  # independent OVH retry always succeeds
                calls["retry"] += 1
                return scanner.StreamTestResult(
                    3.0, [3.0], 3.0, 1, 1, 0, 262144, False, "strong", False, "ok",
                    "DE", "203.0.113.7", "Germany",
                )
            calls["primary"] += 1
            number = int(node.fingerprint[6:12], 16)
            if number % 2 == 0:  # primary Cloudflare endpoint unreachable
                return scanner.StreamTestResult(
                    None, [], None, 1, 0, 0, 0, False, "unverified", False,
                    "stream_unverified", None,
                )
            return scanner.StreamTestResult(
                3.0, [3.0], 3.0, 1, 1, 0, 262144, False, "strong", False, "ok",
                "DE", "203.0.113.7", "Germany",
            )

        def fake_tcp(host, port, timeout):
            return "TimeoutError" if port % 5 == 0 else ""

        with tempfile.TemporaryDirectory() as directory:
            fake_xray = Path(directory) / "xray"
            fake_xray.write_text("#!/bin/sh\n")
            fake_xray.chmod(0o755)
            output = Path(directory) / "public"
            args = argparse.Namespace(
                xray=str(fake_xray), output_dir=str(output), previous_state_url=None
            )
            environment = {"SUB_URLS": "https://feed.example/list", **env}
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                scanner, "fetch_source",
                return_value=scanner.SourceResult("feed", True, links),
            ), mock.patch.object(scanner, "test_node", health or fake_test_node), mock.patch.object(
                scanner, "speed_test_node", fake_speed
            ), mock.patch.object(scanner, "tcp_connect_check", fake_tcp), mock.patch.object(
                scanner, "patient_test_node",
                patient or (lambda node, xray, settings, previous: previous),
            ):
                self.assertEqual(scanner.run(args), 0)
            status = json.loads((output / "status.json").read_text(encoding="utf-8"))
            published = (output / "sub-raw.txt").read_text(encoding="utf-8").split()
            state = json.loads((output / "state.json").read_text(encoding="utf-8"))
        return status, published, state, calls

    def test_every_candidate_is_tested_and_healthy_nodes_are_not_dropped(self):
        status, published, state, calls = self._run(
            400, {"MAX_OUTPUT": "450", "MAX_CONFIGS": "6000"}
        )
        configs = status["configs"]
        self.assertEqual(configs["unique_supported"], 400)
        self.assertEqual(configs["tested"], 400)
        self.assertGreater(configs["tcp_prefilter_rejected"], 0)
        self.assertEqual(configs["health_not_tested"], 0)
        # Healthy nodes are published whether or not the first endpoint worked.
        self.assertEqual(configs["published"], configs["passed_current"])
        self.assertEqual(len(published), configs["published"])
        self.assertGreater(calls["retry"], 0)
        self.assertLessEqual(
            status["stream_test"]["planned_bytes"],
            status["stream_test"]["budget_bytes"],
        )
        self.assertEqual(status["broken"]["stream_unverified"], 0)
        self.assertTrue(status["broken"]["top_errors"])
        self.assertTrue(all("%23" in link for link in published[:5]))
        self.assertTrue(all(" " not in link for link in published))
        self.assertEqual(state["scanner_version"], scanner.SCANNER_VERSION)

    def test_nodes_beyond_the_transfer_budget_are_published_provisionally(self):
        status, published, _state, calls = self._run(
            400, {"SPEED_TEST_MAX": "40", "MAX_OUTPUT": "450"}
        )
        configs = status["configs"]
        self.assertLessEqual(calls["primary"], 40)
        self.assertGreater(configs["passed_current"], 40)
        self.assertEqual(configs["published"], configs["passed_current"])
        self.assertGreater(configs["provisional_published"], 0)
        self.assertEqual(status["broken"]["stream_unverified"], 0)

    def test_second_chance_recovers_a_node_that_failed_once(self):
        attempts = {}

        def flaky(node, xray_bin, settings):
            count = attempts[node.fingerprint] = attempts.get(node.fingerprint, 0) + 1
            number = int(node.fingerprint[:6], 16)
            if number % 4 == 0 or (number % 4 == 1 and count == 1):
                return scanner.TestResult(
                    node.fingerprint, False, 1, 3, None, None, 0.33,
                    "insufficient_successes", error="curl: (28) timed out",
                )
            return scanner.TestResult(
                node.fingerprint, True, 3, 3, 250.0, 30.0, 1.0, "ok",
                exit_country="DE", exit_ip="203.0.113.7", exit_country_name="Germany",
            )

        status, _published, _state, _calls = self._run(
            300, {"MAX_OUTPUT": "450"}, health=flaky
        )
        configs = status["configs"]
        self.assertGreater(configs["second_chance_tested"], 0)
        self.assertGreater(configs["second_chance_recovered"], 0)
        # A node that fails twice is still rejected.
        self.assertLess(
            configs["second_chance_recovered"], configs["second_chance_tested"]
        )
        self.assertEqual(configs["published"], configs["passed_current"])

    def test_patient_stage_recovers_slow_nodes_and_they_are_published(self):
        def timing_out(node, xray_bin, settings):
            number = int(node.fingerprint[:6], 16)
            if number % 5 == 0:
                return scanner.TestResult(
                    node.fingerprint, False, 0, 2, None, None, 0.0,
                    "confirmed_unreachable", error="curl: (28) Connection timed out",
                )
            return scanner.TestResult(
                node.fingerprint, True, 3, 3, 250.0, 30.0, 1.0, "ok",
                exit_country="DE", exit_ip="203.0.113.7", exit_country_name="Germany",
            )

        def slow_but_alive(node, xray_bin, settings, previous):
            if int(node.fingerprint[6:12], 16) % 2 == 0:
                return scanner.TestResult(
                    node.fingerprint, True, 3, 4, 5200.0, 800.0, 0.75, "ok",
                    patient=True, exit_country="DE", exit_ip="203.0.113.7",
                    exit_country_name="Germany",
                )
            return previous

        status, published, state, _calls = self._run(
            300, {"MAX_OUTPUT": "450"}, health=timing_out, patient=slow_but_alive
        )
        configs = status["configs"]
        self.assertGreater(configs["patient_tested"], 0)
        self.assertGreater(configs["patient_recovered"], 0)
        self.assertLess(configs["patient_recovered"], configs["patient_tested"])
        slow_records = [r for r in state["nodes"].values() if r.get("patient")]
        self.assertTrue(slow_records)
        # A 5.2 s node is below the normal 3 s ceiling but still published,
        # because it was judged by the patient stage.
        self.assertTrue(all(r["latency_ms"] > 3000 for r in slow_records))
        self.assertEqual(configs["published"], configs["passed_current"])

    def test_candidate_cap_rotates_but_keeps_running(self):
        status, _published, _state, _calls = self._run(
            400, {"MAX_CONFIGS": "100", "MAX_OUTPUT": "450"}
        )
        self.assertTrue(status["configs"]["candidate_limit_reached"])
        self.assertEqual(status["configs"]["unique_supported"], 100)


if __name__ == "__main__":
    unittest.main()
