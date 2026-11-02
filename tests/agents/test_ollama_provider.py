
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
