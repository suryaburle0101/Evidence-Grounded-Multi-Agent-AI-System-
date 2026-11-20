import unittest

from pipeline.request_limits import RequestBodyLimitMiddleware


class RequestBodyLimitTests(unittest.IsolatedAsyncioTestCase):
    async def _invoke(self, messages, limit=5, headers=()):
        received = iter(messages)
        sent = []
        downstream_body = []

        async def receive():
            return next(received)

        async def send(message):
            sent.append(message)

        async def app(scope, downstream_receive, downstream_send):
            message = await downstream_receive()
            downstream_body.append(message.get("body", b""))
            await downstream_send({"type": "http.response.start", "status": 200, "headers": []})
            await downstream_send({"type": "http.response.body", "body": b"ok"})

        middleware = RequestBodyLimitMiddleware(app, max_bytes=limit)
        await middleware({"type": "http", "method": "POST", "headers": list(headers)}, receive, send)
        return sent, downstream_body

    async def test_chunked_body_over_limit_is_rejected(self):
        sent, downstream = await self._invoke([
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456", "more_body": False},
        ])
        self.assertEqual(sent[0]["status"], 413)
        self.assertEqual(downstream, [])

    async def test_body_within_limit_is_replayed_unchanged(self):
        sent, downstream = await self._invoke([
            {"type": "http.request", "body": b"12", "more_body": True},
            {"type": "http.request", "body": b"345", "more_body": False},
        ])
        self.assertEqual(sent[0]["status"], 200)
        self.assertEqual(downstream, [b"12345"])

    async def test_oversized_content_length_is_rejected_without_reading_body(self):
        sent, downstream = await self._invoke([], headers=[(b"content-length", b"6")])
        self.assertEqual(sent[0]["status"], 413)
        self.assertEqual(downstream, [])


if __name__ == "__main__":
    unittest.main()
