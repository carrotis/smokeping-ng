"""API key authentication and agent-id binding."""

from __future__ import annotations

import pytest

from smokeserver.auth import ANY_AGENT, Authenticator, AuthError, generate_key, hash_key
from smokeserver.config import ApiKeyConfig, AuthConfig


def auth(*keys: ApiKeyConfig, allow_anonymous: bool = False) -> Authenticator:
    return Authenticator(AuthConfig(keys=list(keys), allow_anonymous=allow_anonymous))


class TestKeyMatching:
    def test_plaintext_key_authenticates(self):
        a = auth(ApiKeyConfig(key="s3cret", label="edge"))
        assert a.authenticate("s3cret").label == "edge"

    def test_hashed_key_authenticates_without_the_plaintext_in_config(self):
        # So a committed config file never holds a live secret.
        a = auth(ApiKeyConfig(key_sha256=hash_key("s3cret"), label="edge"))
        assert a.authenticate("s3cret").label == "edge"

    def test_wrong_key_is_rejected(self):
        a = auth(ApiKeyConfig(key="s3cret"))
        with pytest.raises(AuthError) as exc:
            a.authenticate("wrong")
        assert exc.value.status_code == 401

    def test_missing_key_is_rejected(self):
        a = auth(ApiKeyConfig(key="s3cret"))
        with pytest.raises(AuthError, match="missing"):
            a.authenticate(None)

    def test_empty_key_is_rejected(self):
        a = auth(ApiKeyConfig(key="s3cret"))
        with pytest.raises(AuthError):
            a.authenticate("")

    def test_the_right_key_wins_among_several(self):
        a = auth(
            ApiKeyConfig(key="key-a", label="seoul"),
            ApiKeyConfig(key="key-b", label="tokyo"),
            ApiKeyConfig(key="key-c", label="berlin"),
        )
        assert a.authenticate("key-b").label == "tokyo"
        assert a.authenticate("key-c").label == "berlin"

    def test_disabled_keys_are_ignored(self):
        a = auth(ApiKeyConfig(key="revoked", label="old", enabled=False))
        with pytest.raises(AuthError):
            a.authenticate("revoked")

    def test_malformed_digest_is_rejected_at_construction(self):
        with pytest.raises(ValueError, match="64-character hex"):
            auth(ApiKeyConfig(key_sha256="not-a-digest", label="bad"))

    def test_case_insensitive_digest_in_config(self):
        a = auth(ApiKeyConfig(key_sha256=hash_key("s3cret").upper()))
        assert a.authenticate("s3cret")


class TestAgentBinding:
    def test_wildcard_allows_any_agent(self):
        a = auth(ApiKeyConfig(key="k", agent_ids=[ANY_AGENT]))
        principal = a.authenticate("k")
        a.authorize_agent(principal, "anything-at-all")

    def test_bound_key_accepts_its_own_agents(self):
        a = auth(ApiKeyConfig(key="k", label="seoul", agent_ids=["seoul-1", "seoul-2"]))
        principal = a.authenticate("k")
        a.authorize_agent(principal, "seoul-2")

    def test_bound_key_rejects_another_agents_id(self):
        # A compromised edge agent must not be able to forge measurements that
        # look like they came from a different location.
        a = auth(ApiKeyConfig(key="k", label="seoul", agent_ids=["seoul-1"]))
        principal = a.authenticate("k")
        with pytest.raises(AuthError) as exc:
            a.authorize_agent(principal, "frankfurt-1")
        assert exc.value.status_code == 403
        assert "seoul" in str(exc.value)


class TestAnonymous:
    def test_anonymous_mode_accepts_no_key(self):
        a = auth(allow_anonymous=True)
        principal = a.authenticate(None)
        assert principal.anonymous is True
        a.authorize_agent(principal, "whatever")

    def test_anonymous_mode_also_accepts_an_unknown_key(self):
        a = auth(ApiKeyConfig(key="k"), allow_anonymous=True)
        assert a.authenticate("not-the-key").anonymous is True

    def test_a_valid_key_still_gets_its_own_identity(self):
        a = auth(ApiKeyConfig(key="k", label="named"), allow_anonymous=True)
        principal = a.authenticate("k")
        assert principal.anonymous is False
        assert principal.label == "named"


class TestKeyGeneration:
    def test_generated_keys_are_unique_and_long(self):
        keys = {generate_key() for _ in range(50)}
        assert len(keys) == 50
        assert all(len(k) >= 32 for k in keys)

    def test_hash_is_stable_and_hex(self):
        digest = hash_key("hello")
        assert digest == hash_key("hello")
        assert len(digest) == 64
        assert int(digest, 16) >= 0
