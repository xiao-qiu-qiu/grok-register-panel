# -*- coding: utf-8 -*-
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from email_providers.common import decode_raw_message, extract_verification_code


def test_reject_per100():
    assert extract_verification_code("width per-100 class footer", "") is None
    assert extract_verification_code(
        "class=per-100 style and real code later QO7-TUD near xAI",
        "",
    ) == "QO7-TUD"
    assert extract_verification_code(
        "CloudMail template per-100 max-100\nYour code",
        "CXX-PC2 xAI verify",
    ) == "CXX-PC2"


def test_subject_wins():
    assert extract_verification_code("per-100 junk", "B2R-9QB xAI sign-up") == "B2R-9QB"


def test_mixed_real_codes():
    assert extract_verification_code("please use XSB-802 to continue with xAI", "") == "XSB-802"
    assert extract_verification_code("code A99-698", "A99-698 xAI") == "A99-698"
    assert extract_verification_code(
        "Please use the code below.", "SpaceXAI confirmation code: 050-278"
    ) == "050-278"
    assert extract_verification_code(
        "SpaceXAI header 050-278 body 050-278", ""
    ) == "050-278"
    assert extract_verification_code("layout spacer 100-200", "") is None
    assert extract_verification_code("only max-100 in mail chrome", "") is None


def test_spacexai_numeric_confirmation_code():
    """2026-08 起 xAI 主题改成 SpaceXAI confirmation code: 427-599（两侧全数字）。"""
    subject = "SpaceXAI confirmation code: 427-599"
    preview = (
        "Validate your email\r \r Hi,\r \r Thank you for creating a SpaceXAI "
        "account. Please use the code below to validate your email"
    )
    assert extract_verification_code(preview, subject) == "427-599"
    assert extract_verification_code(
        "from=noreply@x.ai\nSpaceXAI confirmation code: 021-135\nValidate your email",
        "",
    ) == "021-135"
    # 无 SpaceXAI/confirmation 上下文时，仍拒绝裸 3-3 数字，避免 HTML 100-200
    assert extract_verification_code("margin 100-200 padding 12px", "") is None


def test_decode_raw_mime_before_code_extraction():
    message = MIMEMultipart("alternative")
    message["Subject"] = "SpaceXAI confirmation code: 050-278"
    message.attach(MIMEText("Please use the code below to validate your email.", "plain"))
    decoded = decode_raw_message(message.as_string())
    assert "validate your email" in decoded
    assert extract_verification_code(decoded, message["Subject"]) == "050-278"


if __name__ == "__main__":
    test_reject_per100()
    test_subject_wins()
    test_mixed_real_codes()
    test_spacexai_numeric_confirmation_code()
    test_decode_raw_mime_before_code_extraction()
    print("OK extract_code")
