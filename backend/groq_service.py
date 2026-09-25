"""Groq-backed AI remediation helpers for CryptoAPI-Safe."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from groq import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    BadRequestError,
    Groq,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)

from analyzer.scanner import auto_fix_code


_ENV_LOADED = False
_DEFAULT_MODEL = "openai/gpt-oss-20b"
_KEY_PATTERN = re.compile(r"^gsk_[A-Za-z0-9_-]{20,}$")


class GroqServiceError(Exception):
    """Safe, non-secret Groq failure with a machine-readable reason code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _load_backend_env() -> None:
    """Load backend/.env into process env without overriding existing values."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    env_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=env_path, override=False)
    _ENV_LOADED = True


def reload_env_for_tests() -> None:
    """Allow unit tests to force a fresh dotenv load decision."""
    global _ENV_LOADED
    _ENV_LOADED = False
    _load_backend_env()


_load_backend_env()


def get_groq_model() -> str:
    _load_backend_env()
    model = (os.getenv("GROQ_MODEL") or "").strip()
    return model or _DEFAULT_MODEL


def get_groq_api_key() -> Optional[str]:
    _load_backend_env()
    key = os.getenv("GROQ_API_KEY")
    if key is None:
        return None
    key = key.strip().strip('"').strip("'")
    return key or None


def is_key_format_valid(api_key: Optional[str]) -> bool:
    if not api_key:
        return False
    return bool(_KEY_PATTERN.match(api_key))


def _safe_error_message(exc: Exception) -> str:
    """Extract a short, non-secret message from a Groq SDK exception."""
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msg = err.get("message")
            if isinstance(msg, str) and msg.strip():
                return _redact_secrets(msg.strip())
        msg = body.get("message")
        if isinstance(msg, str) and msg.strip():
            return _redact_secrets(msg.strip())
    text = str(exc).strip()
    return _redact_secrets(text) if text else type(exc).__name__


def _redact_secrets(text: str) -> str:
    """Remove accidental key-like substrings from error text."""
    return re.sub(r"gsk_[A-Za-z0-9_-]+", "gsk_[REDACTED]", text)


def _classify_sdk_error(exc: Exception) -> GroqServiceError:
    if isinstance(exc, GroqServiceError):
        return exc

    if isinstance(exc, AuthenticationError):
        return GroqServiceError(
            "auth_failure",
            "Groq rejected the API key (HTTP 401). Create a new key in the Groq console.",
        )
    if isinstance(exc, PermissionDeniedError):
        return GroqServiceError(
            "auth_failure",
            "Groq rejected the API key (HTTP 403). The key may be invalid, revoked, or unauthorized.",
        )
    if isinstance(exc, RateLimitError):
        return GroqServiceError(
            "rate_limit",
            "Groq rate limit reached. Retry after a short wait.",
        )
    if isinstance(exc, NotFoundError):
        model = get_groq_model()
        return GroqServiceError(
            "invalid_model",
            f"Groq rejected model '{model}'. Set GROQ_MODEL in backend/.env to a currently available model.",
        )
    if isinstance(exc, BadRequestError):
        detail = _safe_error_message(exc)
        lower = detail.lower()
        model = get_groq_model()
        if "model" in lower:
            return GroqServiceError(
                "invalid_model",
                f"Groq rejected model '{model}': {detail}",
            )
        return GroqServiceError("bad_request", f"Groq rejected the request: {detail}")
    if isinstance(exc, APIConnectionError):
        return GroqServiceError(
            "network_failure",
            "Could not reach the Groq API (network/DNS failure).",
        )
    if isinstance(exc, APIStatusError):
        status = getattr(exc, "status_code", None)
        if status in (401, 403):
            return GroqServiceError(
                "auth_failure",
                f"Groq authentication failed (HTTP {status}). Replace GROQ_API_KEY in the Groq console.",
            )
        if status == 429:
            return GroqServiceError(
                "rate_limit",
                "Groq rate limit reached. Retry after a short wait.",
            )
        detail = _safe_error_message(exc)
        return GroqServiceError(
            "http_error",
            f"Groq returned HTTP {status}: {detail}" if status else f"Groq API error: {detail}",
        )

    return GroqServiceError(
        "unknown_error",
        f"Groq request failed: {_redact_secrets(type(exc).__name__)}.",
    )


def _build_client(api_key: str) -> Groq:
    return Groq(api_key=api_key)


def _chat_completion(
    client: Groq,
    *,
    model: str,
    messages: List[Dict[str, str]],
    max_tokens: int,
    temperature: float = 0.2,
    structured: bool = True,
) -> Any:
    request_args: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if structured:
        request_args["response_format"] = {"type": "json_object"}
    return client.chat.completions.create(**request_args)


def probe_groq_connection() -> Dict[str, Any]:
    """
    Diagnose Groq configuration with a minimal authenticated request.
    Never returns the API key.
    """
    api_key = get_groq_api_key()
    model = get_groq_model()
    configured = bool(api_key)
    key_format_valid = is_key_format_valid(api_key)
    key_length = len(api_key) if api_key else 0

    status: Dict[str, Any] = {
        "configured": configured,
        "key_format_valid": key_format_valid,
        "key_length": key_length,
        "model": model,
        "api_reachable": False,
        "authenticated": False,
        "error": "",
    }

    if not configured:
        status["error"] = "GROQ_API_KEY is missing."
        return status

    if not key_format_valid:
        status["error"] = "GROQ_API_KEY format is invalid. Expected a key starting with gsk_."
        return status

    try:
        client = _build_client(api_key)
        client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": "Reply with the word OK."},
            ],
            max_tokens=8,
            temperature=0,
        )
        status["api_reachable"] = True
        status["authenticated"] = True
        status["error"] = ""
        return status
    except Exception as exc:
        classified = _classify_sdk_error(exc)
        if classified.code == "network_failure":
            status["api_reachable"] = False
            status["authenticated"] = False
        elif classified.code == "auth_failure":
            status["api_reachable"] = True
            status["authenticated"] = False
        elif classified.code in ("invalid_model", "rate_limit", "bad_request", "http_error"):
            # Reaching an HTTP error response means the API host was reachable.
            status["api_reachable"] = True
            status["authenticated"] = classified.code != "auth_failure"
            if classified.code in ("invalid_model", "rate_limit", "bad_request"):
                # Auth succeeded enough for Groq to evaluate the request.
                status["authenticated"] = True
        else:
            status["api_reachable"] = False
            status["authenticated"] = False
        status["error"] = classified.message
        return status


def _build_ai_prompt(code: str, findings: Optional[List[Dict[str, Any]]] = None) -> str:
    findings_block = json.dumps(findings or [], indent=2)
    return f"""
You are a cryptographic security remediation assistant for a Python post-quantum code analyzer.

Your job:
- analyze the code and findings
- determine if the issue is confirmed, ambiguous, or likely false positive
- explain the issue in simple developer-friendly language
- suggest a secure fix using modern PQC-safe practices
- return strict JSON only

Inputs:
- code: {code}
- findings: {findings_block}

Rules:
1. Do not invent runtime facts.
2. Prefer evidence from the code and findings.
3. If uncertain, say "ambiguous" and explain why.
4. Recommend realistic secure fixes.
5. Keep every text field concise. Keep secure_code under 20 lines.
6. Output only valid JSON with this structure:
{{
  "status": "confirmed | ambiguous | false_positive",
  "overall_severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "summary": "short explanation",
  "fix_recommendation": "plain English recommendation",
  "secure_code": "corrected code snippet",
  "why_it_is_wrong": "reason",
  "confidence": 0.0-1.0
}}
""".strip()


def _fallback_ai_fix(
    code: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    reason: str = "Groq API key is not configured.",
) -> Dict[str, Any]:
    fix_result = auto_fix_code(code)
    return {
        "success": True,
        "source": "fallback",
        "fallback_reason": reason,
        "status": "ambiguous" if not findings else "confirmed",
        "overall_severity": "HIGH" if findings else "MEDIUM",
        "summary": f"{reason} Static remediation fallback generated a best-effort fix.",
        "fix_recommendation": (
            "Use the generated remediation patch as a safe starting point "
            "and validate the result in your environment."
        ),
        "secure_code": fix_result.get("fixed_code", code),
        "why_it_is_wrong": (
            "The AI layer did not return a usable response, "
            "so the backend used the deterministic remediation fallback."
        ),
        "confidence": 0.55,
        "fallback": True,
        "applied_fixes": fix_result.get("applied_fixes", []),
        "diff": fix_result.get("diff", ""),
    }


def _parse_model_json(content: str) -> Dict[str, Any]:
    if not content or not content.strip():
        raise GroqServiceError("invalid_json", "Groq returned an empty response body.")
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE | re.DOTALL).strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        # Some models add a short sentence before/after the JSON object.
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise GroqServiceError("invalid_json", f"Groq returned invalid JSON: {exc.msg}.") from exc
        try:
            parsed = json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError as nested_exc:
            raise GroqServiceError("invalid_json", f"Groq returned invalid JSON: {nested_exc.msg}.") from nested_exc
    if not isinstance(parsed, dict):
        raise GroqServiceError(
            "invalid_json",
            "Groq JSON response must be an object.",
        )
    return parsed


def _normalize_ai_payload(parsed: Dict[str, Any]) -> Dict[str, Any]:
    confidence = parsed.get("confidence", 0.5)
    try:
        confidence_value = float(confidence)
    except (TypeError, ValueError):
        confidence_value = 0.5

    return {
        "success": True,
        "source": "groq",
        "status": str(parsed.get("status", "ambiguous")),
        "overall_severity": str(parsed.get("overall_severity", "MEDIUM")),
        "summary": str(parsed.get("summary", "")),
        "fix_recommendation": str(parsed.get("fix_recommendation", "")),
        "secure_code": str(parsed.get("secure_code", "")),
        "why_it_is_wrong": str(parsed.get("why_it_is_wrong", "")),
        "confidence": confidence_value,
        "fallback": False,
    }


def _call_groq_api(prompt: str) -> Dict[str, Any]:
    api_key = get_groq_api_key()
    if not api_key:
        raise GroqServiceError("missing_key", "GROQ_API_KEY is missing.")
    if not is_key_format_valid(api_key):
        raise GroqServiceError(
            "malformed_key",
            "GROQ_API_KEY format is invalid. Expected a key starting with gsk_.",
        )

    model = get_groq_model()
    client = _build_client(api_key)

    messages = [
        {
            "role": "system",
            "content": (
                "You are a precise cryptography remediation assistant. "
                "Return one valid JSON object only. Do not use Markdown fences."
            ),
        },
        {"role": "user", "content": prompt},
    ]
    try:
        completion = _chat_completion(
            client,
            model=model,
            messages=messages,
            max_tokens=1200,
            temperature=0.2,
        )
    except BadRequestError as exc:
        # Some available Groq models reject strict JSON mode. Retry with the
        # same evidence and an explicit plain-text JSON instruction.
        if "validate JSON" not in _safe_error_message(exc):
            raise _classify_sdk_error(exc) from exc
        completion = _chat_completion(
            client,
            model=model,
            messages=messages,
            max_tokens=1200,
            temperature=0.2,
            structured=False,
        )
    except Exception as exc:
        raise _classify_sdk_error(exc) from exc

    try:
        content = completion.choices[0].message.content or ""
    except (AttributeError, IndexError, TypeError) as exc:
        raise GroqServiceError(
            "invalid_json",
            "Groq response did not contain a usable message payload.",
        ) from exc

    try:
        parsed = _parse_model_json(content)
    except GroqServiceError as exc:
        if exc.code != "invalid_json":
            raise

        # A model can truncate a long JSON response at its token limit. Ask
        # again for a compact response without a full rewritten source file.
        retry_messages = [
            {
                "role": "system",
                "content": "Return one compact valid JSON object only. Do not use Markdown.",
            },
            {
                "role": "user",
                "content": (
                    f"Review this Python crypto code and return JSON with only these keys: "
                    f"status, overall_severity, summary, fix_recommendation, "
                    f"why_it_is_wrong, confidence. Keep each value short.\n\n{prompt}"
                ),
            },
        ]
        try:
            retry_completion = _chat_completion(
                client,
                model=model,
                messages=retry_messages,
                max_tokens=500,
                temperature=0,
                structured=False,
            )
            retry_content = retry_completion.choices[0].message.content or ""
            parsed = _parse_model_json(retry_content)
        except Exception as retry_exc:
            if isinstance(retry_exc, GroqServiceError):
                raise retry_exc from exc
            raise _classify_sdk_error(retry_exc) from retry_exc
    return _normalize_ai_payload(parsed)


def generate_ai_fix(
    code: str,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Generate a secure-code recommendation using Groq if possible; else deterministic fallback."""
    findings = findings or []
    if not code.strip():
        return {"success": False, "error": "No code provided for AI fix."}

    try:
        prompt = _build_ai_prompt(code, findings)
        return _call_groq_api(prompt)
    except GroqServiceError as exc:
        return _fallback_ai_fix(code, findings, exc.message)
    except Exception as exc:
        classified = _classify_sdk_error(exc)
        return _fallback_ai_fix(code, findings, classified.message)
