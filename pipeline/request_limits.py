"""Small ASGI middleware for bounded request bodies."""


class RequestBodyLimitMiddleware:
    """Bound mutating request bodies even when clients use chunked transfer."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        raw_length = next((value for key, value in scope.get("headers", [])
                           if key.lower() == b"content-length"), None)
        if raw_length is not None:
            try:
                declared_length = int(raw_length)
            except (TypeError, ValueError):
                declared_length = self.max_bytes + 1
            if declared_length < 0 or declared_length > self.max_bytes:
                await self._reject(send)
                return

        chunks = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await self._reject(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _reject(self, send):
        body = b'{"detail":"Request body exceeds the configured limit"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode("ascii"))]})
        await send({"type": "http.response.body", "body": body})
