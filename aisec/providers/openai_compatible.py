"""Provider compatible OpenAI (OpenAI, Groq, vLLM, LM Studio, ...)."""

from __future__ import annotations

import httpx

from .base import LLMError, Provider


class OpenAICompatibleProvider(Provider):
    name = "openai"

    def available(self) -> bool:
        return bool(self.config.api_key)

    def complete(self, prompt: str, system: str = "") -> str:
        if not self.config.api_key:
            raise LLMError("api_key manquante pour le provider API.")
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
        }
        headers = {"Authorization": f"Bearer {self.config.api_key}"}
        try:
            resp = httpx.post(
                f"{self.config.api_base.rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.config.timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMError(f"API injoignable ({self.config.api_base}): {exc}") from exc
        data = resp.json()
        return data["choices"][0]["message"]["content"]
