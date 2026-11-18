from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Common interface for all LLM providers."""

    # Providers that can constrain output to a JSON schema set this to True.
    supports_json_schema = False

    @abstractmethod
    def generate(self, prompt: str, json_schema: dict | None = None) -> str:
        """Generate a text response from a prompt.

        When ``json_schema`` is given and the provider supports it, the
        response must be a JSON document matching that schema.
        """
        raise NotImplementedError
