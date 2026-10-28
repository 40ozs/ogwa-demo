"""State-changing HTTP client. Every request is gated by an injected MutationPolicy.

Only reviewed executor modules may import this; tests/test_mutation_safety.py enforces
an allowlist. Discovery code must use ``app.core.http_client.ReadOnlyHttpClient``.
"""

import logging
from collections.abc import Iterable, Mapping

from app.core.http_client import HttpPolicy, Transport, _BaseHttpClient
from app.core.safety import MutationCapableService, MutationOutcome, MutationPolicy, MutationRequest

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class MutatingHttpClient(MutationCapableService, _BaseHttpClient):
    """Sends POST/PUT/PATCH/DELETE only when the mutation policy says EXECUTE. Never retries."""

    _allows_unsafe_methods = True

    def __init__(
        self,
        *,
        mutation_policy: MutationPolicy,
        http_policy: HttpPolicy,
        allowed_hosts: Iterable[str],
        transport: Transport | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        MutationCapableService.__init__(self, mutation_policy=mutation_policy)
        _BaseHttpClient.__init__(
            self,
            mode=self.mutation_policy.mode,
            http_policy=http_policy,
            allowed_hosts=allowed_hosts,
            transport=transport,
            logger=logger,
        )

    def send_mutation(
        self,
        request: MutationRequest,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> MutationOutcome:
        method = method.upper()
        if method not in UNSAFE_METHODS:
            raise ValueError(f"{method} is not a mutating method; use ReadOnlyHttpClient for reads")
        self._check_destination(url)
        return self._perform(request, lambda: self._send_once(method, url, headers, body, attempt=1))
