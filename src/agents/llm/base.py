
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Common interface for all LLM providers."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate a text response from a prompt."""
        raise NotImplementedError
