import gzip
import threading
import unittest
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import brotli
import requests

from nvai import teste as proxy


ITEM_URL = "https://produto.mercadolivre.com.br/MLB-6203834422"
PRODUCT = b'<html><script>{"pageState":{"startTime":"2026-01-22T00:00:00Z"}}</script></html>'
# Minimal reproduction of the marker in the captured HTTP-200 verification page.
CHALLENGE = b'<html><script>const path="/security/bot_challenge";</script>Continuar</html>'


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                status, headers, body = self.server.replies.pop(0)
                self.server.received_headers.append(dict(self.headers))
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_HEAD = do_GET

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.replies = []
        self.server.received_headers = []
        self.transport = requests.Session()
        self.transport.trust_env = False
        self.addCleanup(self.transport.close)
        for name, value in (("JIT_MAX", 0), ("SP_GATE_RETRY", False),
                            ("SP_CANONICALIZE_ITEM", False), ("SP_SECOND_CHANCE_5XX", False)):
            p = patch.object(proxy, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(proxy, "pick_sticky_endpoint", return_value=(None, None, 0))
        p.start()
        self.addCleanup(p.stop)

        def local_request(**kwargs):
            requested_url = kwargs["url"]
            kwargs["url"] = f"http://127.0.0.1:{self.server.server_port}/"
            result = self.transport.request(**kwargs)
            result.url = requested_url
            return result

        p = patch.object(proxy.session, "request", side_effect=local_request)
        self.upstream_request = p.start()
        self.addCleanup(p.stop)
        self.client = proxy.app.test_client()

    def queue(self, body=PRODUCT, status=200, encoding=None, content_type="text/html"):
        headers = {"Content-Type": content_type}
        if encoding:
            body = {"gzip": gzip.compress, "deflate": zlib.compress, "br": brotli.compress}[encoding](body)
            headers["Content-Encoding"] = encoding
        self.server.replies.append((status, headers, body))

    def get(self):
        return self.client.get("/" + ITEM_URL, headers={"Origin": "https://www.mercadolivre.com.br"})

    def test_product_is_decoded_once_with_correct_length(self):
        for encoding in (None, "gzip", "deflate", "br"):
            with self.subTest(encoding=encoding):
                self.queue(encoding=encoding)
                result = self.get()
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.data, PRODUCT)
                self.assertNotIn("Content-Encoding", result.headers)
                self.assertEqual(int(result.headers["Content-Length"]), len(PRODUCT))

    def test_http_200_challenge_is_explicit_error_even_when_compressed(self):
        for encoding in (None, "gzip", "deflate", "br"):
            with self.subTest(encoding=encoding):
                self.queue(CHALLENGE, encoding=encoding)
                result = self.get()
                self.assertEqual(result.status_code, 502)
                self.assertEqual(result.json["error"], "upstream_challenge")
                self.assertEqual(result.json["reason"], "bot_challenge")
                self.assertEqual(result.json["upstream_status"], 200)
                self.assertEqual(result.headers["Cache-Control"], "no-store")
                self.assertEqual(result.headers["X-Proxy-Error"], "upstream_challenge")
                self.assertEqual(result.headers["Access-Control-Allow-Origin"], "https://www.mercadolivre.com.br")
                self.assertNotIn("Content-Encoding", result.headers)

    def test_marker_after_old_40kb_limit(self):
        self.queue(b"<html>" + b" " * 45000 + CHALLENGE, content_type="Text/HTML; charset=UTF-8")
        self.assertEqual(self.get().status_code, 502)

    def test_legacy_verification_page(self):
        self.queue(b'<html><a href="/account-verification">Continuar</a></html>')
        self.assertEqual(self.get().json["reason"], "account-verification")

    def test_json_is_not_misclassified_as_challenge(self):
        body = b'{"message":"/security/bot_challenge"}'
        self.queue(body, content_type="application/json")
        result = self.get()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data, body)

    def test_api_permission_error_is_preserved(self):
        self.queue(b'{"error":"forbidden"}', status=403, content_type="application/json")
        result = self.get()
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.json, {"error": "forbidden"})

    def test_existing_retry_can_recover(self):
        self.queue(CHALLENGE, encoding="br")
        self.queue(PRODUCT, encoding="gzip")
        with patch.object(proxy, "SP_GATE_RETRY", True):
            result = self.get()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data, PRODUCT)
        self.assertEqual(self.upstream_request.call_count, 2)

    def test_persistent_challenge_stops_after_existing_retry(self):
        self.queue(CHALLENGE)
        self.queue(CHALLENGE)
        with patch.object(proxy, "SP_GATE_RETRY", True), patch.object(proxy, "SP_CANONICALIZE_ITEM", True):
            result = self.get()
        self.assertEqual(result.status_code, 502)
        self.assertEqual(result.json["error"], "upstream_challenge")
        self.assertEqual(self.upstream_request.call_count, 2)

    def test_head_preserves_representation_encoding(self):
        self.queue(encoding="gzip")
        result = self.client.head("/" + ITEM_URL)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data, b"")
        self.assertEqual(result.headers["Content-Encoding"], "gzip")

    def test_corrupted_encoding_does_not_return_success(self):
        self.server.replies.append((200, {"Content-Type": "text/html", "Content-Encoding": "gzip"}, b"invalid gzip"))
        result = self.get()
        self.assertEqual(result.status_code, 502)
        self.assertIn("error", result.json)


if __name__ == "__main__":
    unittest.main()
