"""ThoughtLabeler: Generates concise, Claude-style activity labels for thought streams.

Emits dynamic present-tense labels (e.g. 'Yetkilendirme mekanizması inceleniyor',
'Analyzing authentication tokens') via an async, non-blocking background task.
Limits LLM invocations to at most 2 calls per thought segment:
  1. Provisional call: at 120 characters or after 2.0s (if >= 30 characters).
  2. Final call: at segment close (if chars >= 2x provisional or provisional never fired).
"""

import asyncio
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

RAW_LEAK_PATTERNS = [
    re.compile(r"^\s*(?:the\s+user|user\s+|kullanıcı\s+|kullanıcının\s+)", re.IGNORECASE),
    re.compile(r"^\s*(?:okay|ok|sure|let\s*me|let\'?s|i\s+need|i\s+should|i\s+will|i\s+must|i\s+have\s+to|i\'?m\s+going\s+to|i\s+am\s+going\s+to)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:önce|ilk\s+olarak|şimdi\s+ben|ben\s+)\b", re.IGNORECASE),
    re.compile(r"(?:the\s+user\s+wants|the\s+user\s+is\s+asking|kullanıcı\s+istiyor|kullanıcı\s+benden)", re.IGNORECASE),
]

PROMPT_SYSTEM = (
    "You are an activity summarizer for an AI coding and security agent. "
    "Given a reasoning excerpt from the agent, produce a single, concise, subjectless present-tense action phrase "
    "describing what the agent is currently analyzing or figuring out.\n"
    "Rules:\n"
    "- Match language: In Turkish if the thought is Turkish, in English if the thought is English.\n"
    "- Maximum 5 to 8 words (strictly under 50 characters).\n"
    "- NEVER use pronouns or conversational fillers ('I', 'we', 'ben', 'kullanıcı', 'the user', 'okay', 'let me').\n"
    "- Use present continuous / gerund / action style (e.g. 'Yetkilendirme mekanizması inceleniyor', "
    "'Kimlik doğrulama kodu analiz ediliyor', 'Searching configuration files', 'Analyzing auth tokens').\n"
    "- Output ONLY the clean action phrase with NO quotes, NO markdown, and NO ending punctuation."
)


def sanitize_label(text: str) -> Optional[str]:
    """Sanitize and validate an LLM-generated thought label."""
    if not text:
        return None
    cleaned = text.strip()
    # Strip markdown headers/formatting, quotes, bullet points
    cleaned = re.sub(r"[*_`]+", "", cleaned)
    cleaned = re.sub(r"^[\s#\->]+", "", cleaned)
    cleaned = re.sub(r'["\']+', "", cleaned).strip()
    # Strip ending punctuation
    cleaned = re.sub(r"[\s.,;:\-–—…!]+$", "", cleaned).strip()

    if not cleaned or len(cleaned) < 3:
        return None

    # Check for raw thought leaks
    for pattern in RAW_LEAK_PATTERNS:
        if pattern.search(cleaned):
            return None

    # Truncate to 60 characters at word boundary
    if len(cleaned) > 60:
        words = cleaned[:60].rsplit(" ", 1)
        cleaned = words[0] if len(words) > 1 else cleaned[:60]
        cleaned = cleaned.rstrip(" .,;:-")

    return cleaned or None


class ThoughtLabeler:
    """Manages label generation for thought segments in a session.
    
    Thread-safe: can be called from worker threads running the agent.
    Schedules timers and async LLM tasks on the provided asyncio loop.
    """

    def __init__(
        self,
        session_id: str,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        on_label: Optional[Callable[[str, str], None]] = None,
        fake_model: bool = False,
    ):
        self.session_id = session_id
        try:
            self.loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self.loop = loop or asyncio.get_event_loop()
        self.on_label = on_label
        self.fake_model = fake_model

        # Current segment state
        self._text_chunks: List[str] = []
        self._total_chars = 0
        self._call_count = 0
        self._provisional_fired = False
        self._char_count_at_provisional = 0
        self._start_time = 0.0
        self._timer_handle: Optional[asyncio.TimerHandle] = None
        self._latest_label: Optional[str] = None

    @property
    def latest_label(self) -> Optional[str]:
        return self._latest_label

    def start_segment(self) -> None:
        """Called when a new thought segment begins."""
        self._cancel_timer()
        self._text_chunks = []
        self._total_chars = 0
        self._call_count = 0
        self._provisional_fired = False
        self._char_count_at_provisional = 0
        self._start_time = time.time()
        self._latest_label = None

        if self.loop and not self.loop.is_closed():
            self._timer_handle = self.loop.call_later(2.0, self._on_timer_tick)

    def on_chunk(self, chunk: str) -> None:
        """Called as new thought text streams in (from worker thread or main loop)."""
        if not chunk:
            return
        if not self._start_time:
            self.start_segment()

        self._text_chunks.append(chunk)
        self._total_chars += len(chunk)

        # Trigger 1: provisional at >= 120 chars
        if not self._provisional_fired and self._total_chars >= 120 and self._call_count == 0:
            self._cancel_timer()
            self._dispatch_call(is_final=False)

    def _on_timer_tick(self) -> None:
        """Fires 2.0s after segment start if provisional has not fired yet."""
        if not self._provisional_fired and self._call_count == 0 and self._total_chars >= 30:
            self._dispatch_call(is_final=False)

    def on_close(self) -> None:
        """Called when the current thought segment ends."""
        self._cancel_timer()
        if self._call_count == 0:
            # Provisional never fired; if text is non-trivial, run final
            if self._total_chars >= 20:
                self._dispatch_call(is_final=True)
        elif self._call_count == 1:
            # Provisional fired; if chars doubled since provisional, fire final
            if self._total_chars >= 2 * self._char_count_at_provisional and self._total_chars > self._char_count_at_provisional + 30:
                self._dispatch_call(is_final=True)

    def _cancel_timer(self) -> None:
        if self._timer_handle:
            try:
                self._timer_handle.cancel()
            except Exception:
                pass
            self._timer_handle = None

    def _dispatch_call(self, is_final: bool) -> None:
        if self._call_count >= 2:
            return

        self._call_count += 1
        if not is_final:
            self._provisional_fired = True
            self._char_count_at_provisional = self._total_chars

        full_text = "".join(self._text_chunks)
        if self.loop and not self.loop.is_closed():
            try:
                # If we are in the loop's thread
                try:
                    running_loop = asyncio.get_running_loop()
                except RuntimeError:
                    running_loop = None

                if running_loop is self.loop:
                    self.loop.create_task(self._generate_label_async(full_text))
                else:
                    asyncio.run_coroutine_threadsafe(self._generate_label_async(full_text), self.loop)
            except Exception as ex:
                logger.debug("Failed to dispatch ThoughtLabeler task: %s", ex)

    async def _generate_label_async(self, thought_text: str) -> None:
        if not thought_text:
            return

        label: Optional[str] = None

        if self.fake_model:
            label = self._deterministic_fallback(thought_text)
        else:
            try:
                from agent.auxiliary_client import async_call_llm

                excerpt = thought_text[:600]
                messages = [
                    {"role": "system", "content": PROMPT_SYSTEM},
                    {"role": "user", "content": excerpt},
                ]
                resp = await async_call_llm(
                    task="auxiliary",
                    messages=messages,
                    max_tokens=30,
                    temperature=0.0,
                    timeout=3.5,
                )
                raw_text = ""
                if isinstance(resp, str):
                    raw_text = resp
                elif hasattr(resp, "choices") and resp.choices:
                    c = resp.choices[0]
                    raw_text = getattr(c.message, "content", "") or ""
                elif isinstance(resp, dict):
                    choices = resp.get("choices") or []
                    if choices:
                        raw_text = choices[0].get("message", {}).get("content", "")

                label = sanitize_label(raw_text)
            except Exception as ex:
                logger.debug("ThoughtLabeler LLM call failed, using fallback: %s", ex)
                label = self._deterministic_fallback(thought_text)

        if label:
            self._latest_label = label
            if self.on_label:
                try:
                    self.on_label(self.session_id, label)
                except Exception as ex:
                    logger.warning("Error in ThoughtLabeler on_label callback: %s", ex)

    def _deterministic_fallback(self, thought_text: str) -> Optional[str]:
        """Pure deterministic fallback when offline, fake-model, or on LLM error."""
        clean = thought_text.strip()
        # Find first sentence
        m = re.search(r"([^.!?\r\n]+[.!?]?)", clean)
        first_sentence = m.group(1).strip() if m else clean
        first_sentence = re.sub(r"^[\s#*\->`]+", "", first_sentence).strip()

        # Filter out leaks
        for pattern in RAW_LEAK_PATTERNS:
            if pattern.search(first_sentence):
                return None

        # Truncate
        if len(first_sentence) > 50:
            first_sentence = first_sentence[:48].rsplit(" ", 1)[0]

        first_sentence = first_sentence.rstrip(" .,;:-")
        return first_sentence if len(first_sentence) >= 5 else None
