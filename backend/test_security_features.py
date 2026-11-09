"""Regression tests for CatchPhish's security detection features."""

from io import BytesIO

import pytest
from PIL import Image

from backend.main import analyze_content, analyze_image_bytes


def indicator_names(result):
    return {item["name"] for item in result["indicators"]}


def test_sql_injection_payload_is_critical():
    result = analyze_content("/products?id=1' OR 1=1 --")

    assert "SQL injection payload" in indicator_names(result)
    assert result["risk_level"] == "CRITICAL"


def test_xss_payload_is_critical():
    result = analyze_content('<img src=x onerror=alert(1)>')

    assert "Cross-site scripting payload" in indicator_names(result)
    assert result["risk_level"] == "CRITICAL"


def test_whatsapp_reward_chain_is_detected():
    result = analyze_content(
        "WhatsApp support: forward this message to 10 friends to claim your reward"
    )

    assert "WhatsApp scam pattern" in indicator_names(result)
    assert "whatsapp_scam" in result["detected_features"]


def test_phone_number_with_otp_pressure_is_detected():
    result = analyze_content(
        "Call +91 98765 43210 immediately and share your OTP for bank KYC verification"
    )

    names = indicator_names(result)
    assert "Phone number detected" in names
    assert "Phone-based scam pressure" in names


def test_multilingual_script_is_reported():
    result = analyze_content("आपका बैंक खाता बंद हो जाएगा, OTP साझा करें")

    assert "Multilingual content detected" in indicator_names(result)
    assert "Hindi" in result["detected_languages"]


def test_brand_impersonation_and_risky_url_are_detected():
    result = analyze_content(
        "https://paypal-login.verify-account.top/redirect?url=http://evil.example"
    )

    names = indicator_names(result)
    assert "Possible brand impersonation" in names
    assert "High-risk domain ending" in names
    assert "Potential redirect parameter" in names


def test_qr_payment_text_is_detected():
    result = analyze_content("Scan this QR code to receive your refund through UPI")

    assert "QR payment pressure" in indicator_names(result)
    assert "QR or UPI payment content" in indicator_names(result)


def test_safe_text_has_no_known_indicators():
    result = analyze_content("Please review the meeting notes tomorrow afternoon.")

    assert result["risk_score"] == 0
    assert result["indicators"] == []


def test_screenshot_pipeline_accepts_valid_image():
    buffer = BytesIO()
    Image.new("RGB", (120, 80), "white").save(buffer, format="PNG")

    result = analyze_image_bytes(buffer.getvalue(), "test.png")

    assert result["input_type"] == "screenshot"
    assert result["image"]["width"] == 120
    assert result["image"]["height"] == 80
    assert result["qr_contents"] == []


def test_image_pipeline_rejects_invalid_image():
    with pytest.raises(Exception):
        analyze_image_bytes(b"not an image", "bad.png")
