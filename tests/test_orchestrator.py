"""Orchestrateur unique: selection d'expert, routage LLM et agregation.

Le provider LLM est remplace par un stub deterministe (dependance externe) ;
tout le reste est le vrai code de production.
"""

from __future__ import annotations

from aisec.core.config import Config
from aisec.core.orchestrator import Orchestrator
from aisec.experts import select
from aisec.providers.base import Provider


class StubProvider(Provider):
    """Provider deterministe: renvoie une reponse JSON predefinie."""

    name = "stub"

    def __init__(self, response: str, available: bool = True) -> None:
        super().__init__(Config(provider="none"))
        self._response = response
        self._available = available
        self.calls = 0

    def available(self) -> bool:
        return self._available

    def complete(self, prompt: str, system: str = "") -> str:
        self.calls += 1
        return self._response


# ---- Routage LLM --------------------------------------------------------


def test_llm_routing_selects_expert_from_json():
    stub = StubProvider('{"expert": "wireless"}')
    assert select("truc totalement inconnu", provider=stub, routing="llm").name == "wireless"


def test_llm_routing_falls_back_to_heuristic_on_invalid_json():
    stub = StubProvider("je ne sais pas")
    expert = select("casse le wpa de capture.cap avec rockyou.txt", provider=stub, routing="llm")
    assert expert.name == "wireless"


def test_llm_routing_falls_back_when_provider_unavailable():
    stub = StubProvider('{"expert": "wireless"}', available=False)
    expert = select("analyse les ports 22 de la cible", provider=stub, routing="llm")
    assert expert.name == "info"


def test_heuristic_routing_is_default():
    assert select("analyse les ports 22 de la cible").name == "info"


def test_llm_routing_ignores_unknown_expert_name():
    stub = StubProvider('{"expert": "classe-inexistante"}')
    expert = select("casse le wpa de capture.cap", provider=stub, routing="llm")
    assert expert.name == "wireless"


# ---- Orchestrateur ------------------------------------------------------


def test_orchestrator_runs_and_records_dry_run():
    orchestrator = Orchestrator(Config(provider="none", dry_run=True))
    record = orchestrator.run("analyse les ports 22, 80, 8080 de la cible 10.0.0.1")
    assert record.expert == "info"
    assert record.tool == "nmap"
    assert record.executed is False
    assert len(orchestrator.report.records) == 1


def test_orchestrator_imposes_expert():
    orchestrator = Orchestrator(Config(provider="none", dry_run=True))
    record = orchestrator.run("capture le handshake wifi sur wlan0mon", expert_name="wireless")
    assert record.expert == "wireless"
    assert record.tool == "airodump-ng"


def test_orchestrator_run_many_aggregates():
    orchestrator = Orchestrator(Config(provider="none", dry_run=True))
    records = orchestrator.run_many(
        [
            ("analyse les ports 22 de la cible 10.0.0.1", None),
            ("casse le wpa de capture.cap", None),
        ]
    )
    assert [r.expert for r in records] == ["info", "wireless"]
    assert len(orchestrator.report.records) == 2


def test_orchestrator_plan_does_not_execute():
    orchestrator = Orchestrator(Config(provider="none"))
    plan = orchestrator.plan("analyse les ports 22 de la cible 10.0.0.1")
    assert plan.tool == "nmap"
    assert plan.argv[0] == "nmap"


def test_orchestrator_uses_llm_routing_when_configured():
    orchestrator = Orchestrator(Config(provider="none", dry_run=True, routing="llm"))
    orchestrator.provider = StubProvider('{"expert": "automotive"}')
    record = orchestrator.run("fais un truc")
    assert record.expert == "automotive"


def test_orchestrator_dedicated_model_is_applied():
    config = Config(provider="none", dry_run=True, expert_models={"info": "mon-modele"})
    orchestrator = Orchestrator(config)
    expert = orchestrator.select_expert("analyse les ports 22 de la cible 10.0.0.1")
    effective = orchestrator._config_for(expert)
    assert effective.model == "mon-modele"
    # Sans IA dediee, le modele global reste inchange.
    assert orchestrator._config_for(orchestrator.select_expert("resous les MX")).model == config.model


def test_orchestrator_report_is_exportable():
    orchestrator = Orchestrator(Config(provider="none", dry_run=True))
    orchestrator.run("analyse les ports 22 de la cible 10.0.0.1")
    data = orchestrator.report.to_json()
    assert "nmap" in data
