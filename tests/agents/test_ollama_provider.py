
from unittest.mock import Mock, patch

import pytest
import requests

from src.agents.llm.ollama_provider import OllamaProvider


def test_generate_returns_response():
    provider = OllamaProvider()

    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "response": "A software vulnerability is a security weakness."
    }

    with patch("src.agents.llm.ollama_provider.requests.post",
               return_value=mock_response) as mock_post:

        result = provider.generate("Explain a vulnerability.")

    assert result == "A software vulnerability is a security weakness."
    mock_post.assert_called_once()


def test_generate_rejects_empty_prompt():
    provider = OllamaProvider()

    with pytest.raises(ValueError):
        provider.generate("")


def test_generate_handles_connection_error():
    provider = OllamaProvider()

    with patch(
        "src.agents.llm.ollama_provider.requests.post",
        side_effect=requests.exceptions.ConnectionError,
    ):
        with pytest.raises(RuntimeError, match="Cannot connect to Ollama"):
            provider.generate("Explain a vulnerability.")


def test_generate_handles_timeout():
    provider = OllamaProvider()

    with patch(
        "src.agents.llm.ollama_provider.requests.post",
        side_effect=requests.exceptions.Timeout,
    ):
        with pytest.raises(RuntimeError, match="timed out"):
            provider.generate("Explain a vulnerability.")


def _ok_response(payload):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def test_payload_sets_context_window_seed_and_schema():
    provider = OllamaProvider(model="m", num_ctx=4096, seed=7, temperature=0.0)
    schema = {"type": "object"}

    with patch(
        "src.agents.llm.ollama_provider.requests.post",
        return_value=_ok_response({"response": "{}", "prompt_eval_count": 100}),
    ) as mock_post:
        provider.generate("Explain.", json_schema=schema)

    payload = mock_post.call_args.kwargs["json"]
    assert payload["model"] == "m"
    assert payload["format"] == schema
    assert payload["options"] == {"temperature": 0.0, "seed": 7, "num_ctx": 4096}


def test_settings_are_read_from_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
    monkeypatch.setenv("OLLAMA_NUM_CTX", "16384")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://other:11434/")

    provider = OllamaProvider()

    assert provider.model == "qwen2.5:3b"
    assert provider.num_ctx == 16384
    assert provider.base_url == "http://other:11434"


def test_invalid_environment_value_is_rejected(monkeypatch):
    monkeypatch.setenv("OLLAMA_NUM_CTX", "large")

    with pytest.raises(ValueError, match="OLLAMA_NUM_CTX"):
        OllamaProvider()


def test_records_metadata_and_flags_possible_truncation():
    provider = OllamaProvider(num_ctx=2048)

    with patch(
        "src.agents.llm.ollama_provider.requests.post",
        return_value=_ok_response(
            {"response": "text", "prompt_eval_count": 2048, "eval_count": 50}
        ),
    ):
        provider.generate("Explain.")

    assert provider.last_metadata["prompt_tokens"] == 2048
    assert provider.last_metadata["output_tokens"] == 50
    assert provider.last_metadata["context_may_be_truncated"] is True


def test_falls_back_to_plain_json_mode_on_old_ollama():
    provider = OllamaProvider()
    rejected = Mock()
    rejected.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=Mock(status_code=400)
    )

    with patch(
        "src.agents.llm.ollama_provider.requests.post",
        side_effect=[rejected, _ok_response({"response": "{}"})],
    ) as mock_post:
        assert provider.generate("Explain.", json_schema={"type": "object"}) == "{}"

    assert mock_post.call_args_list[1].kwargs["json"]["format"] == "json"
