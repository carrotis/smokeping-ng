"""Lightweight API-key authentication.

Deliberately not OAuth.  Agents are long-lived machines with a config file, so
a shared secret in a header is the right weight of mechanism -- as long as the
details are right:

* keys are compared as SHA-256 digests with :func:`hmac.compare_digest`, so a
  timing side channel cannot be used to recover a key byte by byte;
* *every* configured key is checked even after a match, so the response time
  does not leak which key matched or how many keys exist;
* a key may be bound to specific ``agent_ids``, which stops a compromised edge
  agent from writing measurements attributed to another location -- the whole
  value of the data is that you trust where it came from.

Keys can be stored as plaintext (from an env var) or as ``key_sha256`` so a
committed config file holds no live secret.

Run this behind TLS.  A shared secret in a header is only as private as the
transport.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from smokecommon.logging import get_logger
from smokeserver.config import ApiKeyConfig, AuthConfig

log = get_logger(__name__)

ANY_AGENT = "*"


def hash_key(key: str) -> str:
    """SHA-256 hex digest of an API key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_key(nbytes: int = 32) -> str:
    """Generate a fresh API key.  Backs ``smoke-server genkey``."""
    return secrets.token_urlsafe(nbytes)


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    label: str
    agent_ids: tuple[str, ...]
    anonymous: bool = False

    def may_write_as(self, agent_id: str) -> bool:
        return ANY_AGENT in self.agent_ids or agent_id in self.agent_ids


class AuthError(Exception):
    """Authentication or authorisation failure, with an HTTP status attached."""

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class _Credential:
    digest: str
    label: str
    agent_ids: tuple[str, ...]


class Authenticator:
    """Validates API keys and the agent ids they are allowed to write as."""

    def __init__(self, config: AuthConfig) -> None:
        self.header_name = config.header_name
        self.allow_anonymous = config.allow_anonymous
        self._credentials = [
            _to_credential(entry) for entry in config.keys if entry.enabled
        ]
        if self.allow_anonymous:
            log.warning(
                "anonymous ingest is enabled -- anyone who can reach this port "
                "can write measurements"
            )

    def authenticate(self, presented_key: str | None) -> Principal:
        """Resolve a presented key to a :class:`Principal`.

        Raises :class:`AuthError` when the key is missing or unknown.
        """
        if not presented_key:
            if self.allow_anonymous:
                return Principal(label="anonymous", agent_ids=(ANY_AGENT,), anonymous=True)
            raise AuthError(f"missing {self.header_name} header")

        digest = hash_key(presented_key)
        matched: _Credential | None = None
        # Scan every credential regardless of an early match: bailing out early
        # would make the response time depend on the key's position.
        for credential in self._credentials:
            if hmac.compare_digest(credential.digest, digest):
                matched = credential

        if matched is None:
            if self.allow_anonymous:
                return Principal(label="anonymous", agent_ids=(ANY_AGENT,), anonymous=True)
            raise AuthError("invalid API key")

        return Principal(label=matched.label, agent_ids=matched.agent_ids)

    def authorize_agent(self, principal: Principal, agent_id: str) -> None:
        """Check that ``principal`` may submit data for ``agent_id``."""
        if not principal.may_write_as(agent_id):
            raise AuthError(
                f"API key {principal.label!r} is not allowed to write as agent {agent_id!r}",
                status_code=403,
            )

    def __len__(self) -> int:
        return len(self._credentials)


def _to_credential(entry: ApiKeyConfig) -> _Credential:
    if entry.key_sha256:
        digest = entry.key_sha256.strip().lower()
        if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
            raise ValueError(
                f"auth key {entry.label!r}: key_sha256 must be a 64-character hex digest"
            )
    elif entry.key:
        digest = hash_key(entry.key)
    else:  # pragma: no cover - config validation catches this first
        raise ValueError(f"auth key {entry.label!r} has neither `key` nor `key_sha256`")

    return _Credential(
        digest=digest,
        label=entry.label,
        agent_ids=tuple(entry.agent_ids or (ANY_AGENT,)),
    )
