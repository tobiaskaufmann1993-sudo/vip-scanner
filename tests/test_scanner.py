import base64
import dataclasses
import json
import unittest
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
        ):
            return scanner.test_node(node, "xray", settings)

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
        public = (
            "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/"
            "refs/heads/main/xray_final.txt"
        )
        with mock.patch.dict(
            scanner.os.environ,
            {
                "SUB_URLS": f"{first}\n{second}\n{public}",
                "ADDITIONAL_SUB_URLS": public,
            },
            clear=False,
        ):
            self.assertEqual(
                scanner.configured_source_urls(),
                [first, second, public],
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

    def test_preferred_country_labels_use_usa_and_uae(self):
        self.assertEqual(
            scanner.country_display_name("US", "United States"), "USA"
        )
        self.assertEqual(
            scanner.country_display_name("AE", "United Arab Emirates"), "UAE"
        )
        self.assertEqual(scanner.country_display_name("us"), "USA")
        self.assertEqual(scanner.country_display_name("ae"), "UAE")

    def test_exit_country_reads_cloudflare_trace(self):
        completed = mock.Mock(
            returncode=0,
            stdout="fl=1\nip=203.0.113.1\nloc=JP\ncolo=NRT\ntls=TLSv1.3\n",
        )
        with mock.patch.object(scanner.subprocess, "run", return_value=completed):
            self.assertEqual(scanner.detect_exit_country(19080, 5.0), "JP")
            trace = scanner.detect_exit_trace(19080, 5.0)
        self.assertEqual(trace, scanner.ExitTrace("203.0.113.1", "JP", "NRT"))

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

    def test_city_display_name_uses_familiar_stable_labels(self):
        self.assertEqual(scanner.city_display_name("Frankfurt am Main"), "Frankfurt")
        self.assertEqual(scanner.city_display_name("New York City"), "New York")
        self.assertIsNone(scanner.city_display_name(""))

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
        self.assertEqual(counts, (3, 1, 1, 3))
        self.assertRegex(records[0]["name"], r"^USA · New York #\d{4,5}$")
        self.assertRegex(records[1]["name"], r"^USA #\d{4,5}$")
        self.assertRegex(records[2]["name"], r"^Canada #\d{4,5}$")
        self.assertRegex(records[3]["name"], r"^Unknown #\d{4,5}$")
        self.assertEqual(len(set(registry.values())), 4)

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
        self.assertEqual(settings.speed_budget_bytes, 96 * 1024 * 1024)
        self.assertEqual(settings.speed_retry_reserve_bytes, 12 * 1024 * 1024)
        self.assertEqual(settings.geo_city_max_distance_km, 80.0)
        self.assertEqual(
            settings.speed_retry_url, "https://proof.ovh.net/files/1Mb.dat"
        )

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

    def test_unverified_new_node_is_not_published(self):
        result = scanner.TestResult("abc", True, 3, 3, 200.0, 20.0, 1.0, "ok")
        scanner.apply_stream_result(result, None, None, scanner.Settings())
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "stream_unverified")

    def test_unverified_previous_node_gets_only_one_provisional_scan(self):
        result = scanner.TestResult("abc", True, 3, 3, 200.0, 20.0, 1.0, "ok")
        scanner.apply_stream_result(
            result,
            scanner.StreamTestResult(
                None, [], None, 1, 0, 0, 0, False,
                "unverified", False, "stream_unverified", None,
            ),
            {
                "stream_quality": "strong",
                "stream_verified": True,
                "stream_uncertain_streak": 1,
            },
            scanner.Settings(),
        )
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, "stream_unverified")

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


if __name__ == "__main__":
    unittest.main()
