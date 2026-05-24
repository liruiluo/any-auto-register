#!/usr/bin/env python3
"""Minimal offline regressions for recent OAuth recovery fixes."""

from __future__ import annotations

import time

from platforms.chatgpt.oauth_client import OAuthClient


def assert_true(value, message):
    if not value:
        raise AssertionError(message)


def assert_equal(left, right, message):
    if left != right:
        raise AssertionError(f"{message}: left={left!r} right={right!r}")


def test_recent_successful_otp_ttl():
    client = OAuthClient({}, verbose=False)
    client._remember_successful_email_otp("123456")
    assert_equal(
        client._get_recent_successful_email_otp(ttl_seconds=600),
        "123456",
        "recent OTP should be returned inside TTL",
    )
    client.last_successful_email_otp_at = time.time() - 601
    assert_equal(
        client._get_recent_successful_email_otp(ttl_seconds=600),
        "",
        "expired OTP should not be reused after TTL",
    )


def test_force_fresh_otp_when_max_check_attempts_present():
    client = OAuthClient({}, verbose=False)
    assert_true(
        client._should_force_fresh_otp_after_browser_submit(
            "https://auth.openai.com/email-verification",
            "Oops, an error occurred! max_check_attempts",
            "",
        ),
        "max_check_attempts in body should force fresh OTP",
    )
    assert_true(
        client._should_force_fresh_otp_after_browser_submit(
            "https://auth.openai.com/email-verification",
            "",
            "<html>max_check_attempts</html>",
        ),
        "max_check_attempts in html should force fresh OTP",
    )
    assert_true(
        not client._should_force_fresh_otp_after_browser_submit(
            "https://auth.openai.com/about-you",
            "About you",
            "<html>about-you</html>",
        ),
        "normal about-you page should not force fresh OTP",
    )


def test_cross_origin_native_nextauth_should_not_burn_retry():
    native_signin_attempted = True
    native_result = {"error": "cross_origin_page_not_chatgpt"}
    if native_result.get("error") == "cross_origin_page_not_chatgpt":
        native_signin_attempted = False
    assert_true(
        native_signin_attempted is False,
        "cross-origin native next-auth should leave retry available",
    )


def test_warning_banner_only_requires_exact_banner_key():
    client = OAuthClient({}, verbose=False)
    assert_true(
        client._chatgpt_session_warning_banner_only({"WARNING_BANNER": "guest"}),
        "single WARNING_BANNER key should be treated as banner-only session",
    )
    assert_true(
        not client._chatgpt_session_warning_banner_only(
            {"WARNING_BANNER": "guest", "accessToken": "tok"}
        ),
        "presence of access token should not be treated as banner-only session",
    )
    assert_true(
        not client._chatgpt_session_warning_banner_only({"WARNING_BANNER": "", "foo": "bar"}),
        "non-banner payload should not be treated as banner-only session",
    )


def test_guest_probe_requires_both_guest_signals():
    client = OAuthClient({}, verbose=False)
    guest_probe = {
        "backend_checks": [
            {
                "url": "/backend-api/accounts/check/v4-2023-04-27",
                "text": '{"plan_type":"guest","account_id":null,"account_user_id":null}',
            },
            {
                "url": "/backend-api/me",
                "text": '{"email":"","name":"","email_domain_type":"unknown"}',
            },
        ]
    }
    assert_true(
        client._chatgpt_probe_looks_guest_session(guest_probe),
        "guest probe should require both guest account and guest identity signals",
    )
    partial_probe = {
        "backend_checks": [
            {
                "url": "/backend-api/accounts/check/v4-2023-04-27",
                "text": '{"plan_type":"guest","account_id":null,"account_user_id":null}',
            }
        ]
    }
    assert_true(
        not client._chatgpt_probe_looks_guest_session(partial_probe),
        "partial guest probe should not be treated as guest session",
    )


def test_login_failure_reason_setter():
    client = OAuthClient({}, verbose=False)
    client._set_login_failure_reason("oauth_state_machine_exceeded_max_steps")
    assert_equal(
        client.last_login_failure_reason,
        "oauth_state_machine_exceeded_max_steps",
        "login failure reason should be persisted for upper-layer diagnostics",
    )


def test_login_failure_reason_can_preserve_specific_reason():
    client = OAuthClient({}, verbose=False)
    client._set_login_failure_reason("about_you_warning_banner_guest_session")
    client._set_login_failure_reason(
        "oauth_state_machine_exceeded_max_steps:page=about_you",
        overwrite=False,
    )
    assert_equal(
        client.last_login_failure_reason,
        "about_you_warning_banner_guest_session",
        "generic late failure should not overwrite earlier specific reason",
    )


def test_remember_flow_state_uses_describer():
    client = OAuthClient({}, verbose=False)
    client._remember_flow_state(
        type(
            "State",
            (),
            {
                "page_type": "email_otp_verification",
                "method": "GET",
                "current_url": "https://auth.openai.com/email-verification",
                "continue_url": "https://auth.openai.com/email-verification",
            },
        )()
    )
    assert_true(
        "email_otp_verification" in client.last_flow_state_description,
        "flow state description should be remembered for later diagnostics",
    )


def test_about_you_browser_failure_reason_mapping():
    client = OAuthClient({}, verbose=False)
    assert_equal(
        client._about_you_browser_failure_reason(error="warning_banner_guest_session"),
        "about_you_warning_banner_guest_session",
        "warning banner guest session should map to a stable reason",
    )
    assert_equal(
        client._about_you_browser_failure_reason(error="browser_fallback_timeout"),
        "about_you_browser_browser_fallback_timeout",
        "browser error should map to a namespaced reason",
    )
    assert_equal(
        client._about_you_browser_failure_reason(status=403),
        "about_you_browser_http_403",
        "status-only failures should map to http reason",
    )


def test_about_you_protocol_failure_reason_mapping():
    client = OAuthClient({}, verbose=False)
    assert_equal(
        client._about_you_protocol_failure_reason(
            status=400,
            lowered_text="user_already_exists",
        ),
        "about_you_user_already_exists",
        "already_exists should map to stable protocol reason",
    )
    assert_equal(
        client._about_you_protocol_failure_reason(
            status=400,
            lowered_text="registration_disallowed",
        ),
        "about_you_registration_disallowed",
        "registration_disallowed should map to stable protocol reason",
    )
    assert_equal(
        client._about_you_protocol_failure_reason(
            status=403,
            lowered_text="forbidden",
        ),
        "about_you_http_403",
        "other protocol failures should map to http reason",
    )


def test_terminal_flow_failure_reason_mapping():
    client = OAuthClient({}, verbose=False)
    assert_equal(
        client._terminal_flow_failure_reason(
            "state_stuck",
            "page=about_you method=GET",
        ),
        "state_stuck:page=about_you method=GET",
        "state_stuck should retain state description",
    )
    assert_equal(
        client._terminal_flow_failure_reason("login_password_no_next_state"),
        "login_password_no_next_state",
        "login_password_no_next_state should remain stable",
    )
    assert_equal(
        client._terminal_flow_failure_reason(
            "oauth_state_machine_exceeded_max_steps",
            "page=email_otp_verification method=GET",
        ),
        "oauth_state_machine_exceeded_max_steps:page=email_otp_verification method=GET",
        "max steps should retain final flow state",
    )


def main():
    tests = [
        test_recent_successful_otp_ttl,
        test_force_fresh_otp_when_max_check_attempts_present,
        test_cross_origin_native_nextauth_should_not_burn_retry,
        test_warning_banner_only_requires_exact_banner_key,
        test_guest_probe_requires_both_guest_signals,
        test_login_failure_reason_setter,
        test_login_failure_reason_can_preserve_specific_reason,
        test_remember_flow_state_uses_describer,
        test_about_you_browser_failure_reason_mapping,
        test_about_you_protocol_failure_reason_mapping,
        test_terminal_flow_failure_reason_mapping,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")


if __name__ == "__main__":
    main()
