"""
OpenAI-compatible model client. Stdlib only.

Anything speaking `/v1/chat/completions` works — vLLM, llama.cpp server, Ollama,
Together, Moonshot, Z.ai, DeepSeek. That is the whole portability story: swapping
providers is configuration, not code.

Two things here are not optional decoration:

**Schema validation with repair.** Structured-output adherence varies far more
across models than benchmark scores suggest. Without validation, swapping in a
weaker model doesn't degrade gracefully — it emits plausible-looking garbage that
a later stage happily consumes.

**The preflight probe.** It asks the configured endpoint to do a trivial
structured task *and* to engage with a benign defensive-security question. When
Hugging Face was breached in July 2026, their blue team found commercial frontier
models refusing to analyse attack logs — guardrails cannot tell an attacker
building an exploit from a defender detecting one. Discovering that three hours
into a batch is expensive; discovering it at startup is free.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import ModelConfig

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.+?)\s*```", re.S)


class ModelError(Exception):
    pass


class AuthError(ModelError):
    """Credentials or endpoint configuration are wrong.

    Split from ModelError because it is NOT transient: retrying a 401 three times
    produces three identical 401s, burns the finding's attempts, and buries the
    real cause under a retry count. Callers must abort on this, not retry.
    """


class RefusalError(ModelError):
    """The model declined the request rather than failing technically."""


# Phrases that indicate a refusal rather than a technical failure. Deliberately
# conservative — a false positive here blocks a legitimate run.
_REFUSAL_MARKERS = (
    "i can't help", "i cannot help", "i can't assist", "i cannot assist",
    "i'm not able to help", "i am not able to help", "i won't provide",
    "i will not provide", "against my guidelines", "i can't provide",
    "i cannot provide", "unable to assist with that",
)


def looks_like_refusal(text: str) -> bool:
    t = (text or "").strip().lower()
    if len(t) > 600:          # long answers are engagement, not refusal
        return False
    return any(m in t for m in _REFUSAL_MARKERS)


def _is_anthropic(cfg) -> bool:
    """Anthropic's native Messages API is not OpenAI-shaped; route it separately."""
    return "anthropic.com" in (cfg.endpoint or "").lower()


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class Client:
    def __init__(self, cfg: ModelConfig):
        self.cfg = cfg
        self.usage = Usage()
        self.last_raw_response: str = ""   # set by chat_json for evidence

    # -- transport --------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.cfg.endpoint}{path}"
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json",
                   "User-Agent": "patchwing/0.1"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"

        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_s) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            detail = e.read()[:500].decode("utf-8", "replace")
            if e.code in (401, 403):
                key_hint = (f"set ${self.cfg.api_key_env}" if self.cfg.api_key_env
                            else "no api_key_env configured")
                raise AuthError(
                    f"{self.cfg.role}: HTTP {e.code} from {url} — auth rejected "
                    f"({key_hint}). {detail}") from e
            if e.code == 404:
                raise ModelError(
                    f"{self.cfg.role}: HTTP 404 from {url} — check the endpoint "
                    f"ends in /v1 and that model '{self.cfg.model}' exists. "
                    f"{detail}") from e
            raise ModelError(f"{self.cfg.role}: HTTP {e.code} from {url}: "
                             f"{detail}") from e
        except urllib.error.URLError as e:
            raise ModelError(
                f"{self.cfg.role}: cannot reach {url} — {e.reason}") from e

    # -- completion -------------------------------------------------------

    def chat(self, messages: list[dict], *, max_tokens: int | None = None,
             temperature: float | None = None) -> str:
        if _is_anthropic(self.cfg):
            return self._chat_anthropic(messages, max_tokens=max_tokens,
                                        temperature=temperature)
        # max_tokens <= 0 means "no cap from us" — omit from the payload so the
        # server applies its own default. A reasoning model can spend its budget
        # thinking before answering, and pinning that budget from here is how the
        # last two attempts failed. See models.max_tokens in the run config.
        _mt = max_tokens if max_tokens is not None else self.cfg.max_tokens
        payload = {
            "model": self.cfg.model,
            "messages": messages,
            "temperature": (self.cfg.temperature if temperature is None
                            else temperature),
        }
        if _mt and _mt > 0:
            payload["max_tokens"] = _mt
        if getattr(self.cfg, "extra", None):
            payload.update(self.cfg.extra)
        data = self._post("/chat/completions", payload)

        u = data.get("usage") or {}
        self.usage.prompt_tokens += int(u.get("prompt_tokens", 0) or 0)
        self.usage.completion_tokens += int(u.get("completion_tokens", 0) or 0)

        try:
            choice = data["choices"][0]
        except (KeyError, IndexError) as e:
            raise ModelError(f"{self.cfg.role}: no choices in response: "
                             f"{json.dumps(data)[:300]}") from e

        msg = choice.get("message") or {}
        text = msg.get("content") or ""
        finish = choice.get("finish_reason")

        # Truncation is never acceptable: a half-written diff or a cut-off
        # JSON verdict silently corrupts everything downstream. Raise loudly
        # regardless of whether content came back or not — the caller can
        # decide to retry, but must NEVER treat a truncated response as a
        # normal reply. This is the safety net for Jay's "no token limiting"
        # policy: we omit max_tokens client-side, but if the server's own
        # default clips a big response, we hear about it.
        if finish == "length":
            cap = payload.get("max_tokens", "(server default)")
            raise ModelError(
                f"{self.cfg.role}: response truncated (finish_reason=length, "
                f"max_tokens={cap}, got {u.get('completion_tokens', '?')} "
                f"completion tokens). Model was cut off mid-generation.")
        if not text.strip():
            raise ModelError(f"{self.cfg.role}: empty response content")
        return text

    def _chat_anthropic(self, messages: list[dict], *, max_tokens=None,
                        temperature=None) -> str:
        """Native Anthropic Messages API adapter (system split out, x-api-key)."""
        system = "\n\n".join(m["content"] for m in messages
                              if m.get("role") == "system")
        convo = [{"role": ("assistant" if m["role"] == "assistant" else "user"),
                  "content": m["content"]}
                 for m in messages if m.get("role") in ("user", "assistant")]
        payload = {"model": self.cfg.model,
                   "max_tokens": max_tokens or self.cfg.max_tokens,
                   "messages": convo,
                   "temperature": (self.cfg.temperature if temperature is None
                                   else temperature)}
        if system:
            payload["system"] = system
        url = f"{self.cfg.endpoint}/messages"
        headers = {"content-type": "application/json",
                   "anthropic-version": "2023-06-01",
                   "User-Agent": "patchwing/0.1"}
        if self.cfg.api_key:
            headers["x-api-key"] = self.cfg.api_key
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout_s) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            detail = e.read()[:500].decode("utf-8", "replace")
            raise ModelError(f"{self.cfg.role}: HTTP {e.code} from {url} "
                             f"(anthropic): {detail}") from e
        except urllib.error.URLError as e:
            raise ModelError(f"{self.cfg.role}: cannot reach {url} - "
                             f"{e.reason}") from e
        u = data.get("usage") or {}
        self.usage.prompt_tokens += int(u.get("input_tokens", 0) or 0)
        self.usage.completion_tokens += int(u.get("output_tokens", 0) or 0)
        text = "".join(p.get("text", "") for p in (data.get("content") or [])
                       if p.get("type") == "text")
        if not text.strip():
            raise ModelError(f"{self.cfg.role}: empty anthropic response: "
                             f"{json.dumps(data)[:300]}")
        return text

    def chat_json(self, messages: list[dict], required: tuple[str, ...] = (),
                  *, attempts: int = 3) -> dict:
        """
        Get a JSON object back, repairing on failure.

        `required` names top-level keys that must be present. On mismatch the
        model is told exactly what was wrong and asked again — which is what
        makes a weaker model degrade instead of silently corrupting a stage.

        Also sets `self.last_raw_response` to the model's exact reply text
        (bytes-as-decoded) so the caller can persist it for evidence — the
        parsed `obj` returned here has lost any formatting, prose, or
        pre-JSON preamble the model chose to include.
        """
        convo = list(messages)
        last_err = ""

        for attempt in range(attempts):
            raw = self.chat(convo)
            self.last_raw_response = raw   # persisted-for-evidence side channel
            if looks_like_refusal(raw):
                raise RefusalError(
                    f"{self.cfg.role} ({self.cfg.model}) refused: "
                    f"{raw.strip()[:200]}")

            parsed, err = _extract_json(raw)
            if parsed is not None:
                missing = [k for k in required if k not in parsed]
                if not missing:
                    return parsed
                err = f"missing required key(s): {', '.join(missing)}"

            last_err = err
            convo = convo + [
                {"role": "assistant", "content": raw[:2000]},
                {"role": "user", "content":
                    f"That response could not be used: {err}. "
                    f"Reply with a single valid JSON object and nothing else"
                    + (f", including the keys: {', '.join(required)}."
                       if required else ".")},
            ]

        raise ModelError(
            f"{self.cfg.role} ({self.cfg.model}) did not return usable JSON "
            f"after {attempts} attempts. Last problem: {last_err}")

    # -- preflight --------------------------------------------------------

    def preflight(self) -> dict:
        """
        Fail loudly at startup rather than three hours into a batch.

        Checks reachability, structured-output adherence, and — the one that
        matters for a security tool — whether the endpoint will engage with a
        plainly defensive security question.
        """
        result = {"role": self.cfg.role, "model": self.cfg.model,
                  "endpoint": self.cfg.endpoint, "family": self.cfg.family,
                  "reachable": False, "json_ok": False, "security_ok": False,
                  "latency_s": None, "notes": []}

        started = time.time()
        try:
            obj = self.chat_json(
                [{"role": "user",
                  "content": 'Reply with exactly this JSON: {"ok": true}'}],
                required=("ok",), attempts=2)
            result["reachable"] = True
            result["json_ok"] = obj.get("ok") in (True, "true", 1)
        except RefusalError as e:
            result["notes"].append(f"refused a trivial prompt: {e}")
            return result
        except ModelError as e:
            result["notes"].append(str(e))
            return result
        finally:
            result["latency_s"] = round(time.time() - started, 2)

        # The refusal probe. Unambiguously defensive: explaining why a bounds
        # check prevents an overflow is textbook secure-coding material.
        probe = (
            "You are assisting a defensive security review of code we maintain. "
            "In one or two sentences: why does adding a bounds check before a "
            "memcpy prevent a heap buffer overflow?"
        )
        try:
            answer = self.chat([{"role": "user", "content": probe}],
                               max_tokens=1024)
            if looks_like_refusal(answer):
                result["notes"].append(
                    "REFUSED a benign defensive-security question — this "
                    "endpoint is unsuitable for security work. This is the "
                    "failure mode that forced Hugging Face onto self-hosted "
                    "weights in July 2026.")
            else:
                result["security_ok"] = True
        except RefusalError as e:
            result["notes"].append(f"REFUSED the security probe: {e}")
        except ModelError as e:
            # A reasoning model that spent its token budget thinking still
            # ENGAGED with the question - that is not a refusal.
            if "finish_reason=length" in str(e):
                result["security_ok"] = True
                result["notes"].append("engaged (reasoning model truncated before final text)")
            else:
                result["notes"].append(f"security probe failed: {e}")

        return result


def _extract_json(text: str) -> tuple[dict | None, str]:
    """Parse a JSON object out of a model response. Returns (obj, error)."""
    t = (text or "").strip()

    m = _JSON_BLOCK.search(t)
    if m:
        t = m.group(1).strip()

    try:
        obj = json.loads(t)
        return (obj, "") if isinstance(obj, dict) else (None, "top level was not an object")
    except json.JSONDecodeError:
        pass

    # Fall back to the outermost braces — models like to add a preamble.
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(t[start:end + 1])
            if isinstance(obj, dict):
                return obj, ""
        except json.JSONDecodeError as e:
            return None, f"invalid JSON ({e.msg})"
    return None, "no JSON object found in the response"


def preflight_all(models: dict[str, ModelConfig]) -> list[dict]:
    return [Client(cfg).preflight() for _, cfg in sorted(models.items())]
