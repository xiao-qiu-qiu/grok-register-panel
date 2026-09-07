# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import cloudflare


class FakeResponse:
    def __init__(self, status_code, *, body="", data=None, reason=""):
        self.status_code = status_code
        self.text = body
        self._data = data
        self.reason = reason or "test response"

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code} for test request")


def _without_sleep(callback):
    previous = cloudflare.time.sleep
    cloudflare.time.sleep = lambda _seconds: None
    try:
        return callback()
    finally:
        cloudflare.time.sleep = previous


def test_address_collision_retries_with_admin_payload():
    calls = []
    responses = [
        FakeResponse(400, body="Address already exists"),
        FakeResponse(200, data={"address": "user@mail.example", "jwt": "test-jwt"}),
    ]

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return responses.pop(0)

    result = _without_sleep(
        lambda: cloudflare.create_temp_address(
            fake_post,
            "https://mail.example",
            accounts_path="/admin/new_address",
            domain="mail.example",
            randomize_subdomain=False,
            name="fixed-name",
        )
    )
    assert result == ("user@mail.example", "test-jwt")
    assert len(calls) == 2
    assert calls[0][1]["json"] == {
        "name": "fixed-name",
        "enablePrefix": True,
        "domain": "mail.example",
    }
    assert calls[1][1]["json"]["name"] != "fixed-name"
    assert "password" not in calls[0][1]["json"]


def test_random_subdomain_is_sent_as_worker_flag():
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(
            200,
            data={"address": "user@abcd1234.mail.example", "jwt": "test-jwt"},
        )

    result = cloudflare.create_temp_address(
        fake_post,
        "https://mail.example",
        accounts_path="/api/new_address",
        domain="mail.example",
        randomize_subdomain=True,
    )

    assert result == ("user@abcd1234.mail.example", "test-jwt")
    assert calls[0][1]["json"] == {
        "domain": "mail.example",
        "enableRandomSubdomain": True,
    }
    assert calls[0][1]["headers"] == {"Content-Type": "application/json"}


def test_nonretryable_400_is_not_retried_or_echoed():
    calls = []
    secret = "response-secret-value-123456"

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(400, body=f"Required field token={secret}")

    try:
        _without_sleep(
            lambda: cloudflare.create_temp_address(
                fake_post,
                "https://mail.example",
                domain="mail.example",
                randomize_subdomain=False,
            )
        )
    except RuntimeError as exc:
        assert secret not in str(exc)
    else:
        raise AssertionError("non-retryable HTTP 400 must fail")
    assert len(calls) == 1


def test_admin_fallback_respects_random_subdomain_opt_out():
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(
            200,
            data={"address": "user@mail.example", "jwt": "test-jwt"},
        )

    result = cloudflare.create_mailbox_fallback(
        lambda *_args, **_kwargs: None,
        fake_post,
        "https://mail.example",
        domains_path="/domains",
        accounts_path="/admin/new_address",
        token_path="/token",
        domain="mail.example",
        randomize_subdomain=False,
    )
    assert result == ("user@mail.example", "test-jwt")
    assert calls[0][1]["json"]["domain"] == "mail.example"


if __name__ == "__main__":
    test_address_collision_retries_with_admin_payload()
    test_nonretryable_400_is_not_retried_or_echoed()
    test_admin_fallback_respects_random_subdomain_opt_out()
    print("OK cloudflare provider")
