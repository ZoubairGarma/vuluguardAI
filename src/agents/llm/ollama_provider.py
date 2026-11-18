import os
import time

import requests
from dotenv import load_dotenv

from src.agents.llm.base import LLMProvider


load_dotenv()

DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_TIMEOUT = 600
# Ollama's built-in default context (2048-4096 tokens depending on the
# version) is too small for vulnerability prompts. When a prompt does not fit,
# Ollama silently drops its beginning, which is where the instructions are.
DEFAULT_NUM_CTX = 8192
DEFAULT_TEMPERATURE = 0.1
DEFAULT_SEED = 42


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return parsed


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number.") from exc


class OllamaProvider(LLMProvider):
    """LLM provider using a locally running Ollama server.

    Every setting can be passed explicitly or configured through ``.env``:
    OLLAMA_MODEL, OLLAMA_BASE_URL, OLLAMA_TIMEOUT, OLLAMA_NUM_CTX,
    OLLAMA_TEMPERATURE and OLLAMA_SEED.
    """

    supports_json_schema = True

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int | None = None,
        num_ctx: int | None = None,
        temperature: float | None = None,
        seed: int | None = None,
    ):
        self.model = model or os.getenv("OLLAMA_MODEL") or DEFAULT_MODEL
        self.base_url = (
            base_url or os.getenv("OLLAMA_BASE_URL") or DEFAULT_BASE_URL
        ).rstrip("/")
        self.timeout = timeout or _env_int("OLLAMA_TIMEOUT", DEFAULT_TIMEOUT)
        self.num_ctx = num_ctx or _env_int("OLLAMA_NUM_CTX", DEFAULT_NUM_CTX)
        self.temperature = (
            temperature
            if temperature is not None
            else _env_float("OLLAMA_TEMPERATURE", DEFAULT_TEMPERATURE)
        )
        self.seed = seed if seed is not None else _env_int("OLLAMA_SEED", DEFAULT_SEED)
        # Token counts and timing of the most recent call, for diagnostics.
        self.last_metadata: dict = {}

    def _payload(self, prompt: str, response_format) -> dict:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
            },
        }
        if response_format is not None:
            payload["format"] = response_format
        return payload

    def _post(self, payload: dict) -> requests.Response:
        response = requests.post(
            f"{self.base_url}/api/generate",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response

    def generate(self, prompt: str, json_schema: dict | None = None) -> str:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        started = time.perf_counter()
        try:
            try:
                response = self._post(self._payload(prompt, json_schema))
            except requests.exceptions.HTTPError as exc:
                # Ollama versions before 0.5 accept only format="json", not a
                # schema object. Retry with plain JSON mode in that case.
                status = getattr(exc.response, "status_code", None)
                if json_schema is None or status != 400:
                    raise
                response = self._post(self._payload(prompt, "json"))

            result = response.json()

        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                "Cannot connect to Ollama. Make sure Ollama is running."
            ) from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError("Ollama request timed out.") from exc

        except requests.exceptions.HTTPError as exc:
            raise RuntimeError(
                f"Ollama HTTP error: {exc}"
            ) from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"Ollama request failed: {exc}"
            ) from exc

        prompt_tokens = result.get("prompt_eval_count")
        self.last_metadata = {
            "model": self.model,
            "num_ctx": self.num_ctx,
            "prompt_tokens": prompt_tokens,
            "output_tokens": result.get("eval_count"),
            "duration_seconds": round(time.perf_counter() - started, 2),
            # Ollama caps the prompt at num_ctx tokens; reaching the cap means
            # part of the prompt was probably dropped.
            "context_may_be_truncated": (
                isinstance(prompt_tokens, int) and prompt_tokens >= self.num_ctx
            ),
        }

        generated_text = (result.get("response") or "").strip()

        if not generated_text:
            raise RuntimeError("Ollama returned an empty response.")

        return generated_text
