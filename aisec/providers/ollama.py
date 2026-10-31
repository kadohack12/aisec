"""Provider Ollama (LLM 100% local)."""

from __future__ import annotations

import httpx

from .base import LLMError, Provider


class OllamaProvider(Provider):
    name = "ollama"

    def available(self) -> bool:
        try:
            resp = httpx.get(f"{self.config.ollama_host}/api/tags", timeout=3.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def complete(self, prompt: str, system: str = "") -> str:
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }
        if system:
            payload["system"] = system
        try:
            resp = httpx.post(
                f"{self.config.ollama_host}/api/generate",
                json=payload,
                timeout=self.config.timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama injoignable ({self.config.ollama_host}): {exc}") from exc
        return resp.json().get("response", "")
