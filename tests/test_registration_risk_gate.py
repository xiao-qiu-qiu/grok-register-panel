# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register


def test_registration_risk_policy_classifier_still_parses():
    """The historical classifier stays for the deprecated SSO panel."""
    blocked_cases = (
        ({"denied": True}, "policy=deny,event=$registration"),
        ({"bot_flag_source": 1}, "botFlagSource=1"),
        ({"bot_flag_source": 2}, "botFlagSource=2"),
        (
            {"policy": "deny", "event": "$login"},
            "policy=deny,event=$login",
        ),
    )
    for state, expected_detail in blocked_cases:
        blocked, detail = register._registration_risk_should_block(state)
        assert blocked is True
        assert detail == expected_detail

    for state in (
        {"found": True, "bot_flag_source": 0},
        {"found": False},
        {},
        None,
    ):
        assert register._registration_risk_should_block(state) == (False, "")


def test_oauth_gate_no_longer_inspects_sso_botflag():
    previous_auto_add = register.config.get("cpa_auto_add")
    previous_functions = (
        register.inspect_sso_registration_state_via_browser,
        register._append_sso_risk_rejected,
        register.record_register_result,
    )
    inspected = []
    quarantined = []
    recorded = []
    register.config["cpa_auto_add"] = False
    register.inspect_sso_registration_state_via_browser = (
        lambda sso, **_kwargs: inspected.append(sso)
        or {
            "found": True,
            "bot_flag_source": 2,
            "bot_flag_details": "risk=0.95,policy=allow,event=$registration",
            "policy": "allow",
            "event": "$registration",
            "denied": False,
        }
    )
    register._append_sso_risk_rejected = (
        lambda email, sso, details, **_kwargs: quarantined.append(
            (email, sso, details)
        )
    )
    register.record_register_result = (
        lambda status, email, **kwargs: recorded.append((status, email, kwargs))
    )
    try:
        state = register.ensure_sso_oauth_eligible(
            "sso=quarantined-token",
            email="risk@example.test",
        )
    finally:
        (
            register.inspect_sso_registration_state_via_browser,
            register._append_sso_risk_rejected,
            register.record_register_result,
        ) = previous_functions
        if previous_auto_add is None:
            register.config.pop("cpa_auto_add", None)
        else:
            register.config["cpa_auto_add"] = previous_auto_add

    assert state.get("skipped") is True
    assert state.get("error") == "sso_botflag_deprecated"
    assert inspected == []
    assert quarantined == []
    assert recorded == []


def test_unavailable_risk_check_does_not_quarantine_or_block():
    previous_functions = (
        register.inspect_sso_registration_state_via_browser,
        register._append_sso_risk_rejected,
        register.record_register_result,
    )
    previous_excluded = dict(register._startup_excluded_proxies)
    previous_proxy = register.get_thread_proxy()
    quarantined = []
    recorded = []
    register._startup_excluded_proxies.clear()
    register.set_thread_proxy("http://127.0.0.1:8003")
    register.inspect_sso_registration_state_via_browser = lambda *_args, **_kwargs: {
        "found": False,
        "bot_flag_source": None,
        "error": "grok.com 浏览器仍停在 Cloudflare 挑战页",
        "denied": False,
    }
    register._append_sso_risk_rejected = (
        lambda email, sso, details, **_kwargs: quarantined.append((email, sso, details))
    )
    register.record_register_result = (
        lambda status, email, **kwargs: recorded.append((status, email, kwargs))
    )
    try:
        state = register.ensure_sso_oauth_eligible(
            "clean-or-unknown-token", email="unknown@example.test"
        )
    finally:
        (
            register.inspect_sso_registration_state_via_browser,
            register._append_sso_risk_rejected,
            register.record_register_result,
        ) = previous_functions
        register._startup_excluded_proxies.clear()
        register._startup_excluded_proxies.update(previous_excluded)
        register.set_thread_proxy(previous_proxy)

    assert state.get("skipped") is True
    assert state.get("error") == "sso_botflag_deprecated"
    assert quarantined == []
    assert recorded == []


class _FakeRiskPage:
    def __init__(self, html, url="https://grok.com/"):
        self.html = html
        self.url = url
        self.cookie_values = []
        self.opened_url = ""
        self.set = self
        self.wait = self

    def get(self, url):
        self.opened_url = url

    def doc_loaded(self):
        return None

    def run_js(self, script, *_args):
        if "document.documentElement.outerHTML" in script:
            return self.html
        if "document.title" in script:
            return "Grok"
        if "document.body" in script:
            return self.html
        return ""

    def cookies(self, values):
        self.cookie_values = values


def test_browser_risk_inspector_reads_bot_flag_from_live_html():
    previous_page = register._active_page
    fake_page = _FakeRiskPage(
        '<script>{"botFlagSource":1,"botFlagDetails":"policy=deny,event=$registration"}</script>'
    )
    register._active_page = lambda: fake_page
    try:
        state = register.inspect_sso_registration_state_via_browser(
            "sso=browser-token", timeout=0
        )
    finally:
        register._active_page = previous_page

    assert state["found"] is True
    assert state["bot_flag_source"] == 1
    assert state["policy"] == "deny"
    assert state["denied"] is True
    assert fake_page.opened_url.startswith("https://grok.com/?risk_check=")
    assert len(fake_page.cookie_values) == 4


def test_browser_risk_inspector_accepts_clean_state():
    previous_page = register._active_page
    fake_page = _FakeRiskPage(
        '<script>{"botFlagSource":0,"botFlagDetails":"policy=allow,event=$registration"}</script>'
    )
    register._active_page = lambda: fake_page
    try:
        state = register.inspect_sso_registration_state_via_browser(
            "browser-token", timeout=0
        )
    finally:
        register._active_page = previous_page

    assert state["found"] is True
    assert state["bot_flag_source"] == 0
    assert state["denied"] is False


def test_browser_risk_inspector_rejects_cloudflare_without_state():
    previous_page = register._active_page
    fake_page = _FakeRiskPage("<title>Just a moment...</title>Checking your browser")
    register._active_page = lambda: fake_page
    try:
        state = register.inspect_sso_registration_state_via_browser(
            "browser-token", timeout=0
        )
    finally:
        register._active_page = previous_page

    assert state["found"] is False
    assert "Cloudflare" in state["error"]
    assert register._registration_risk_check_is_unavailable(state) is True
    assert register._registration_risk_should_block(state) == (False, "")


class _AbortThenOkRiskPage(_FakeRiskPage):
    def __init__(self, html):
        super().__init__(html)
        self.gets = 0

    def get(self, url):
        self.gets += 1
        if self.gets == 1:
            raise RuntimeError("Page.goto: NS_BINDING_ABORTED; maybe frame was detached?")
        super().get(url)


def test_browser_risk_inspector_retries_navigation_abort():
    previous_page = register._active_page
    previous_sleep = register.time.sleep
    fake_page = _AbortThenOkRiskPage(
        '<script>{"botFlagSource":0,"botFlagDetails":"policy=allow,event=$registration"}</script>'
    )
    register._active_page = lambda: fake_page
    register.time.sleep = lambda *_args, **_kwargs: None
    try:
        state = register.inspect_sso_registration_state_via_browser(
            "browser-token", timeout=0
        )
    finally:
        register._active_page = previous_page
        register.time.sleep = previous_sleep

    assert fake_page.gets == 2
    assert state["found"] is True
    assert state["bot_flag_source"] == 0


if __name__ == "__main__":
    test_registration_risk_policy_classifier_still_parses()
    test_oauth_gate_no_longer_inspects_sso_botflag()
    test_unavailable_risk_check_does_not_quarantine_or_block()
    test_browser_risk_inspector_reads_bot_flag_from_live_html()
    test_browser_risk_inspector_accepts_clean_state()
    test_browser_risk_inspector_rejects_cloudflare_without_state()
    test_browser_risk_inspector_retries_navigation_abort()
    print("OK registration risk gate")
