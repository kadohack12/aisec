"""Chargement de la configuration aisec.

Ordre de priorite (le dernier gagne):
  1. valeurs par defaut
  2. fichier de config (~/.config/aisec/config.toml ou ./aisec.toml)
  3. variables d'environnement (AISEC_*)
  4. arguments CLI
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

CONFIG_PATHS = [
    Path.cwd() / "aisec.toml",
    Path.home() / ".config" / "aisec" / "config.toml",
]

_ENV_PREFIX = "AISEC_"


@dataclass
class Config:
    # Provider LLM: "ollama" (local, recommande), "openai", "groq", "none"
    provider: str = "ollama"
    model: str = "llama3.1"
    ollama_host: str = "http://localhost:11434"
    # Endpoint compatible OpenAI (utilise si provider = openai/groq)
    api_base: str = "https://api.openai.com/v1"
    api_key: str = ""
    temperature: float = 0.1
    timeout: float = 120.0
    # Si vrai, on n'execute jamais la commande, on l'affiche seulement.
    dry_run: bool = False
    # Confirmation avant les actions sensibles (scan reseau prive, etc.)
    assume_yes: bool = False
    # IA dediee par expert: {"dns": "modele-dns", "web": "modele-web"}
    expert_models: dict[str, str] = field(default_factory=dict)

    def model_for(self, expert_name: str, default: str | None = None) -> str:
        """Modele a utiliser pour un expert (IA dediee) ou le modele global."""
        return self.expert_models.get(expert_name) or default or self.model

    def with_model(self, model: str) -> "Config":
        """Copie de la config avec un modele donne (pour une IA dediee)."""
        clone = Config(**self.to_dict())
        clone.model = model
        return clone

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        data: dict[str, Any] = {}
        candidates = [path] if path else CONFIG_PATHS
        for candidate in candidates:
            if candidate and candidate.is_file():
                with candidate.open("rb") as handle:
                    data.update(tomllib.load(handle))
                break

        known = {f.name for f in fields(cls)}
        for key in known:
            env_key = _ENV_PREFIX + key.upper()
            if env_key in os.environ:
                data[key] = _coerce(os.environ[env_key], key)

        # Alias usuels pour les cles d'API.
        if not data.get("api_key"):
            data["api_key"] = (
                os.environ.get("AISEC_API_KEY")
                or os.environ.get("OPENAI_API_KEY")
                or os.environ.get("GROQ_API_KEY")
                or ""
            )

        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def apply_overrides(self, **overrides: Any) -> "Config":
        for key, value in overrides.items():
            if value is not None and hasattr(self, key):
                setattr(self, key, value)
        return self


def _coerce(value: str, key: str) -> Any:
    if key in {"temperature", "timeout"}:
        try:
            return float(value)
        except ValueError:
            return value
    if key in {"dry_run", "assume_yes"}:
        return value.strip().lower() in {"1", "true", "yes", "on", "oui"}
    return value
