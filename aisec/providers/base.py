"""Interface provider LLM + selection.

Le mode par defaut est *local* (Ollama): aucune donnee ne quitte la machine.
L'utilisateur peut basculer vers une API compatible OpenAI s'il le souhaite.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.config import Config


class LLMError(RuntimeError):
    pass


class Provider(ABC):
    """Un backend LLM capable de repondre a un prompt et de renvoyer du texte."""

    name: str = ""

    def __init__(self, config: Config) -> None:
        self.config = config

    @abstractmethod
    def available(self) -> bool:
        """Le provider est-il joignable/config correct ?"""

    @abstractmethod
    def complete(self, prompt: str, system: str = "") -> str:
        """Renvoie la reponse texte du modele."""


def get_provider(config: Config) -> Provider | None:
    """Instancie le provider configure, ou None si provider == 'none'."""
    provider = (config.provider or "none").lower()
    if provider in {"none", "off", "heuristic", ""}:
        return None
    if provider == "ollama":
        from .ollama import OllamaProvider

        return OllamaProvider(config)
    if provider in {"openai", "groq", "api", "openai-compatible"}:
        from .openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider(config)
    raise LLMError(f"provider inconnu: {provider!r}")
