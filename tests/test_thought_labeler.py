import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from fetih_desktop_bridge.thought_labeler import ThoughtLabeler, sanitize_label


def test_sanitize_label_valid():
    assert sanitize_label("Yetkilendirme mekanizması inceleniyor") == "Yetkilendirme mekanizması inceleniyor"
    assert sanitize_label('"Kimlik doğrulama kodu analiz ediliyor."') == "Kimlik doğrulama kodu analiz ediliyor"
    assert sanitize_label("  **Analyzing authentication tokens** ... ") == "Analyzing authentication tokens"


def test_sanitize_label_leaks_rejected():
    assert sanitize_label("The user wants to check the login page") is None
    assert sanitize_label("kullanıcı bizden şunu yapmamızı istedi") is None
    assert sanitize_label("Okay, let's see what is inside the file") is None
    assert sanitize_label("I should check the database configuration") is None
    assert sanitize_label("Önce dosyaları okuyalım") is None
    assert sanitize_label("kullanıcı istiyor") is None


def test_sanitize_label_empty_and_short():
    assert sanitize_label("") is None
    assert sanitize_label("   ") is None
    assert sanitize_label("ab") is None


@pytest.mark.asyncio
async def test_thought_labeler_fake_model_fallback():
    labels = []

    def on_label(sid, lbl):
        labels.append((sid, lbl))

    labeler = ThoughtLabeler(session_id="s123", on_label=on_label, fake_model=True)
    labeler.start_segment()

    # Stream short chunk < 120
    labeler.on_chunk("Bu modüldeki güvenlik açıkları taranıyor.")
    assert len(labels) == 0

    # Close segment - triggers final call
    labeler.on_close()
    await asyncio.sleep(0.05)

    assert len(labels) == 1
    assert labels[0][0] == "s123"
    assert "güvenlik açıkları" in labels[0][1]


@pytest.mark.asyncio
async def test_thought_labeler_provisional_at_120_chars():
    labels = []

    labeler = ThoughtLabeler(session_id="s456", on_label=lambda s, l: labels.append(l), fake_model=True)
    labeler.start_segment()

    chunk = "Sistem yapılandırma dosyaları ve çevre değişkenleri içindeki API anahtarları ile gizli kimlik doğrulama parametreleri detaylı olarak taranıyor."
    assert len(chunk) >= 120
    labeler.on_chunk(chunk)

    await asyncio.sleep(0.05)
    assert len(labels) == 1

    # Closing without doubling chars should NOT trigger a second call
    labeler.on_close()
    await asyncio.sleep(0.05)
    assert len(labels) == 1


@pytest.mark.asyncio
async def test_thought_labeler_max_two_calls():
    calls = []

    labeler = ThoughtLabeler(session_id="s789", on_label=lambda s, l: calls.append(l), fake_model=True)
    labeler.start_segment()

    # 1. Provisional trigger
    labeler.on_chunk("A" * 125)
    await asyncio.sleep(0.05)
    assert len(calls) == 1

    # 2. Add more than 2x characters
    labeler.on_chunk("B" * 200)
    labeler.on_close()
    await asyncio.sleep(0.05)
    assert len(calls) == 2

    # Extra close call does nothing
    labeler.on_close()
    await asyncio.sleep(0.05)
    assert len(calls) == 2
