"""
gateway.py
==========
Runtime LLM Application Firewall & Governance Gateway

An OpenAI-compatible reverse proxy that sits in front of a local Ollama
model (default: llama3.2). Every request is scanned for prompt-injection /
jailbreak attempts and leaked secrets before it reaches the model, and every
response is scanned again before it goes back to the caller.

Point any OpenAI-client-compatible app at this server
(base_url=http://localhost:8000/v1) and it works as a drop-in proxy.

Run it with:
    python gateway.py
or:
    uvicorn gateway:app --reload --port 8000
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ============================================================================
# CONFIGURATION
# ============================================================================

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.2"
OLLAMA_TIMEOUT_SECONDS = 60.0

# ============================================================================
# AUDIT LOGGING (structured, color-coded console output)
# ============================================================================

_COLOR_RESET = "\033[0m"
_COLOR_GREEN = "\033[92m"   # ALLOWED
_COLOR_YELLOW = "\033[93m"  # SANITIZED
_COLOR_RED = "\033[91m"     # BLOCKED

_VERDICT_COLORS = {
    "ALLOWED": _COLOR_GREEN,
    "SANITIZED": _COLOR_YELLOW,
    "BLOCKED": _COLOR_RED,
}


def audit_log(verdict: str, category: str, detail: str = "") -> None:
    """Print one structured, color-coded audit line per transaction stage."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    color = _VERDICT_COLORS.get(verdict, _COLOR_RESET)
    line = (
        f"{color}[{timestamp}] "
        f"VERDICT={verdict:<10} "
        f"CATEGORY={category:<20}"
        f"{_COLOR_RESET} {detail}"
    )
    print(line)


# ============================================================================
# INPUT GUARDRAIL: PROMPT INJECTION / JAILBREAK DETECTION
# ============================================================================
# Heuristic regex matching for common instruction-override / jailbreak
# phrasing. This is intentionally simple and fast (no model call needed on
# the hot path) — for higher-recall detection in production, pair this with
# an embedding-similarity check or a dedicated classifier such as
# Meta's Llama Guard or NVIDIA NeMo Guardrails.

INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(the\s+)?previous\s+instructions", re.I),
    re.compile(r"ignore\s+(all\s+)?(the\s+)?above", re.I),
    re.compile(
        r"disregard\s+(the\s+)?(system|safety)\s+"
        r"(rules|filters|instructions|prompt)",
        re.I,
    ),
    re.compile(r"you\s+are\s+now\s+in\s+(developer|debug|god)\s+mode", re.I),
    re.compile(
        r"pretend\s+(that\s+)?you\s+(have\s+no|don't\s+have)\s+"
        r"(restrictions|rules|filters|limits)",
        re.I,
    ),
    re.compile(
        r"bypass\s+(your\s+)?(safety|content)\s+"
        r"(filters|guidelines|restrictions)",
        re.I,
    ),
    re.compile(
        r"reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions)", re.I
    ),
    re.compile(r"\bjailbreak\b", re.I),
    re.compile(r"\bDAN\s+mode\b", re.I),
    re.compile(r"act\s+as\s+if\s+you\s+have\s+no\s+guidelines", re.I),
    re.compile(
        r"override\s+(your\s+)?(system|safety)\s+(settings|controls)", re.I
    ),
    re.compile(r"you\s+have\s+no\s+restrictions\s+or\s+filters", re.I),
]


def detect_injection(text: str) -> Optional[str]:
    """Return the matched pattern (as a string) if text looks like a
    prompt-injection / jailbreak attempt, otherwise None."""
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


# ============================================================================
# SECRET / PII SCRUBBING (applied to both inbound and outbound text)
# ============================================================================

SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "AWS_ACCESS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS_SECRET_KEY": re.compile(
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?"
        r"[A-Za-z0-9/+=]{40}['\"]?"
    ),
    "GITHUB_TOKEN": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    "PRIVATE_KEY_BLOCK": re.compile(
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "GENERIC_API_KEY": re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9\-_]{16,}['\"]?"
    ),
    "EMAIL_ADDRESS": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    ),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}


def scrub_secrets(text: str) -> Tuple[str, List[str]]:
    """Redact any recognized secret/PII patterns in text.

    Returns (sanitized_text, list_of_categories_found).
    """
    found: List[str] = []
    sanitized = text
    for category, pattern in SECRET_PATTERNS.items():
        if pattern.search(sanitized):
            found.append(category)
            sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized, found


# ============================================================================
# OUTPUT GUARDRAIL: DEGENERATE / RECURSIVE LOOP DETECTION
# ============================================================================


def detect_repetition(
    text: str, chunk_size: int = 40, min_repeats: int = 3
) -> bool:
    """Heuristic check for degenerate repeated output — a common local-model
    failure mode where generation gets stuck looping the same text."""
    if len(text) < chunk_size * min_repeats:
        return False
    chunk = text[:chunk_size]
    return text.count(chunk) >= min_repeats


# ============================================================================
# OUTPUT GUARDRAIL: TOXICITY CHECK (pluggable stub)
# ============================================================================


def check_toxicity(text: str) -> bool:
    """Placeholder heuristic toxicity gate.

    In production, swap this out for a real moderation call — e.g. OpenAI's
    /v1/moderations endpoint, Google's Perspective API, or a local
    classifier such as Detoxify. The function signature (str -> bool) is
    the integration point, so callers below never need to change.
    """
    lowered = text.lower()
    flagged_phrases = [
        "kill yourself",
        "i will hurt you",
        "i hope you die",
    ]
    return any(phrase in lowered for phrase in flagged_phrases)


# ============================================================================
# OPENAI-COMPATIBLE SCHEMA (subset needed for /v1/chat/completions)
# ============================================================================


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = OLLAMA_MODEL
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False


class ChatCompletionChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str = "stop"


class UsageInfo(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[ChatCompletionChoice]
    usage: UsageInfo


def safety_violation_response(category: str, detail: str) -> JSONResponse:
    """Build an OpenAI-style structured error body for a blocked request."""
    payload = {
        "error": {
            "message": "Request blocked by input guardrail.",
            "type": "safety_violation",
            "category": category,
            "detail": detail,
        }
    }
    return JSONResponse(status_code=400, content=payload)


# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Runtime LLM Application Firewall & Governance Gateway",
    description=(
        "Inline reverse proxy that inspects prompts for jailbreaks and "
        "secrets, forwards clean traffic to a local Ollama model, and "
        "scans the response before it reaches the client."
    ),
    version="1.0.0",
)


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Simple liveness/readiness probe."""
    return {"status": "ok", "upstream": OLLAMA_URL, "model": OLLAMA_MODEL}


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest) -> JSONResponse:
    """
    OpenAI-compatible chat endpoint, wrapped in input/output guardrails.

    Flow:
        1. Scan every user message for injection/jailbreak patterns -> block.
        2. Scrub secrets/PII from user messages -> sanitize + continue.
        3. Forward sanitized messages to Ollama.
        4. Scrub secrets/PII, check for repetition loops, and check
           toxicity on the model's response before returning it.
    """
    sanitized_messages: List[ChatMessage] = []
    overall_verdict = "ALLOWED"

    # ---- 1 & 2: INPUT GUARDRAILS -----------------------------------------
    for msg in req.messages:
        if msg.role != "user":
            sanitized_messages.append(msg)
            continue

        injection_hit = detect_injection(msg.content)
        if injection_hit:
            audit_log(
                "BLOCKED", "PROMPT_INJECTION", f"pattern={injection_hit!r}"
            )
            return safety_violation_response(
                "PROMPT_INJECTION",
                "The request contains a pattern resembling a jailbreak "
                "or instruction-override attempt and was blocked.",
            )

        clean_content, secret_hits = scrub_secrets(msg.content)
        if secret_hits:
            overall_verdict = "SANITIZED"
            audit_log(
                "SANITIZED", ",".join(secret_hits), "input message redacted"
            )
        sanitized_messages.append(
            ChatMessage(role=msg.role, content=clean_content)
        )

    if overall_verdict == "ALLOWED":
        audit_log("ALLOWED", "NONE", "input passed all guardrails")

    # ---- 3: UPSTREAM FORWARD (async httpx call to Ollama) ----------------
    ollama_payload = {
        "model": OLLAMA_MODEL,
        "messages": [m.model_dump() for m in sanitized_messages],
        "stream": False,
        "options": {"temperature": req.temperature or 0.7},
    }

    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_SECONDS) as client:
            upstream_resp = await client.post(OLLAMA_URL, json=ollama_payload)
            upstream_resp.raise_for_status()
            upstream_data = upstream_resp.json()
    except httpx.ConnectError:
        audit_log("BLOCKED", "UPSTREAM_UNREACHABLE", OLLAMA_URL)
        raise HTTPException(
            status_code=502,
            detail=(
                "Could not reach the upstream Ollama server at "
                f"{OLLAMA_URL}. Is `ollama serve` running?"
            ),
        )
    except httpx.HTTPStatusError as exc:
        audit_log("BLOCKED", "UPSTREAM_ERROR", str(exc))
        raise HTTPException(
            status_code=502, detail=f"Upstream model error: {exc}"
        )
    except httpx.TimeoutException:
        audit_log("BLOCKED", "UPSTREAM_TIMEOUT", OLLAMA_URL)
        raise HTTPException(
            status_code=504, detail="Upstream model timed out."
        )

    raw_output = upstream_data.get("message", {}).get("content", "")

    # ---- 4: OUTPUT GUARDRAILS ---------------------------------------------
    clean_output, out_secret_hits = scrub_secrets(raw_output)
    if out_secret_hits:
        overall_verdict = "SANITIZED"
        audit_log(
            "SANITIZED", ",".join(out_secret_hits), "output message redacted"
        )

    if detect_repetition(clean_output):
        overall_verdict = "SANITIZED"
        audit_log(
            "SANITIZED",
            "RECURSIVE_LOOP",
            "degenerate repetition detected, output truncated",
        )
        clean_output = (
            clean_output[:400] + "\n[TRUNCATED: repetitive output detected]"
        )

    if check_toxicity(clean_output):
        audit_log("BLOCKED", "TOXIC_CONTENT", "output withheld from client")
        raise HTTPException(
            status_code=502,
            detail="Upstream response failed the output safety check.",
        )

    if overall_verdict == "ALLOWED":
        audit_log("ALLOWED", "NONE", "output passed all guardrails")

    # ---- BUILD OPENAI-COMPATIBLE RESPONSE ---------------------------------
    prompt_tokens = sum(len(m.content.split()) for m in sanitized_messages)
    completion_tokens = len(clean_output.split())

    response_payload = ChatCompletionResponse(
        id=f"chatcmpl-{uuid.uuid4().hex[:24]}",
        created=int(time.time()),
        model=req.model,
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role="assistant", content=clean_output),
                finish_reason="stop",
            )
        ],
        usage=UsageInfo(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
    )

    return JSONResponse(status_code=200, content=response_payload.model_dump())


# ============================================================================
# ENTRYPOINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("gateway:app", host="0.0.0.0", port=8000, reload=True)
