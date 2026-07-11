import base64
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

    def test_exit_country_reads_cloudflare_trace(self):
        completed = mock.Mock(returncode=0, stdout="fl=1\nip=203.0.113.1\nloc=JP\ntls=TLSv1.3\n")
        with mock.patch.object(scanner.subprocess, "run", return_value=completed):
            self.assertEqual(scanner.detect_exit_country(19080, 5.0), "JP")

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

    def test_published_names_are_numbered_per_country(self):
        records = [
            {"fingerprint": "a", "name": "🇺🇸 source", "uri": f"vless://{UUID}@a.example:443#x"},
            {"fingerprint": "b", "name": "United States node", "uri": f"vless://{UUID}@b.example:443#x"},
            {"fingerprint": "c", "name": "Canada", "uri": f"vless://{UUID}@c.example:443#x"},
            {"fingerprint": "d", "name": "mystery", "uri": f"vless://{UUID}@d.example:443#x"},
        ]
        detected, unknown = scanner.normalize_published_names(records, {})
        self.assertEqual((detected, unknown), (3, 1))
        self.assertEqual(
            [record["name"] for record in records],
            [
                "🇺🇸 US | Server 1", "🇺🇸 US | Server 2",
                "🇨🇦 CA | Server 1", "🌐 UN | Server 1",
            ],
        )

    def test_settings_defaults(self):
        settings = scanner.Settings.from_env()
        self.assertEqual(settings.max_latency_ms, 3000.0)
        self.assertEqual(settings.elite_latency_ms, 800.0)
        self.assertEqual(settings.max_jitter_ms, 600.0)
        self.assertEqual(settings.max_output, 450)

    def test_latency_dominates_speed_in_ranking(self):
        settings = scanner.Settings.from_env()
        low_latency = {
            "latency_ms": 200.0,
            "jitter_ms": 20.0,
            "success_rate": 1.0,
            "speed_mbps": None,
            "status": "healthy",
        }
        slower_but_fast = {
            "latency_ms": 450.0,
            "jitter_ms": 20.0,
            "success_rate": 1.0,
            "speed_mbps": 100.0,
            "status": "healthy",
        }
        self.assertGreater(
            scanner.record_score(low_latency, settings),
            scanner.record_score(slower_but_fast, settings),
        )

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
