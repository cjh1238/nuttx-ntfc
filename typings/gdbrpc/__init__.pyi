"""Minimal type stubs for gdbrpc."""

from typing import Any, Dict, Optional

class Request:
    def __call__(self, q: Any) -> None: ...

class PostRequest:
    def __call__(self, result: Any) -> None: ...

class Client:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 20819,
        log_level: int = ...,
    ) -> None: ...
    def connect(self) -> bool: ...
    def disconnect(self) -> None: ...
    def call(
        self,
        request: Request,
        post_request: Optional[PostRequest] = None,
        timeout: float = 30,
    ) -> Dict[str, Any]: ...
    _pending_requests: Dict[str, Any]
