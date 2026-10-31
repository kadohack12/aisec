"""IA generaliste: decomposition, consultation des experts et synthese.

Le provider LLM est remplace par un stub deterministe (dependance externe) ;
tout le reste est le vrai code de production.
"""

from __future__ import annotations

from aisec.core.config import Config
from aisec.core.generalist import Generalist, Step, generalist_user_prompt
from aisec.providers.base import Provider


class StubProvider(Provider):
    """Provider deterministe: renvoie une reponse predefinie (liste indexee)."""

    name = "stub"

    def __init__(self, *responses: str, available: bool = True) -> None:
        super().__init__(Config(provider="none"))
        self._responses = list(responses)
        self._available = available
        self.prompts: list[str] = []
        self.systems: list[str] = []

    def available(self) -> bool:
        return self._available

    def complete(self, prompt: str, system: str = "") -> str:
        self.prompts.append(prompt)
        self.systems.append(system)
        if not self._responses:
            return ""
        return self._responses.pop(0)


def _generalist(**kwargs) -> Generalist:
    config = Config(provider="none", dry_run=True, **kwargs)
    return Generalist(config)


# ---- Decomposition heuristique ------------------------------------------


def test_plan_single_clause_routes_to_one_expert():
    steps = _generalist().plan("analyse les ports 22, 80, 8080 de la cible 10.0.0.1")
    assert len(steps) == 1
    assert steps[0].expert == "info"


def test_plan_splits_on_connector():
    steps = _generalist().plan(
        "analyse les ports 22 de la cible 10.0.0.1 puis casse le wpa de capture.cap"
    )
    assert [s.expert for s in steps] == ["info", "wireless"]
    assert steps[0].request == "analyse les ports 22 de la cible 10.0.0.1"
    assert steps[1].request == "casse le wpa de capture.cap"


def test_plan_splits_on_semicolon():
    steps = _generalist().plan("resous les MX de example.com; scanne 10.0.0.1")
    assert [s.expert for s in steps] == ["dns", "info"]


# ---- Consultation des experts -------------------------------------------


def test_consult_runs_step_and_builds_reply():
    generalist = _generalist()
    step = Step(expert="info", request="analyse les ports 22 de la cible 10.0.0.1")
    consultation = generalist.consult(step)
    assert consultation.record.expert == "info"
    assert consultation.record.tool == "nmap"
    assert "nmap" in consultation.reply


def test_answer_decomposes_consults_and_synthesizes():
    answer = _generalist().answer(
        "analyse les ports 22 de la cible 10.0.0.1 puis casse le wpa de capture.cap"
    )
    assert [s.expert for s in answer.steps] == ["info", "wireless"]
    assert [c.record.tool for c in answer.consultations] == ["nmap", "aircrack-ng"]
    assert answer.source == "heuristic"
    assert "nmap" in answer.synthesis and "aircrack-ng" in answer.synthesis


def test_answer_report_aggregates_all_consultations():
    generalist = _generalist()
    generalist.answer("resous les MX de example.com puis scanne 10.0.0.1")
    assert len(generalist.report.records) == 2
    assert "dig" in generalist.report.to_json()
    assert "nmap" in generalist.report.to_json()


def test_answer_to_dict_shape():
    answer = _generalist().answer("scanne 10.0.0.1")
    payload = answer.to_dict()
    assert set(payload) == {"goal", "source", "steps", "consultations", "synthesis"}
    assert payload["steps"][0]["expert"] == "info"


# ---- Decomposition LLM ---------------------------------------------------


def test_plan_llm_uses_steps_from_json():
    stub = StubProvider(
        '{"steps": [{"expert": "dns", "request": "resous les MX"}, '
        '{"expert": "wireless", "request": "casse le wpa"}]}'
    )
    generalist = _generalist()
    generalist.provider = stub
    steps = generalist.plan("fais un audit complet")
    assert [s.expert for s in steps] == ["dns", "wireless"]
    assert steps[0].request == "resous les MX"
    # Le prompt envoye doit etre celui de production (source unique).
    assert stub.prompts[0] == generalist_user_prompt("fais un audit complet")


def test_plan_llm_falls_back_to_heuristic_on_invalid_json():
    stub = StubProvider("je ne sais pas")
    generalist = _generalist()
    generalist.provider = stub
    steps = generalist.plan("analyse les ports 22 de la cible 10.0.0.1")
    assert [s.expert for s in steps] == ["info"]


def test_plan_llm_ignores_unknown_expert():
    stub = StubProvider('{"steps": [{"expert": "classe-inexistante", "request": "x"}]}')
    generalist = _generalist()
    generalist.provider = stub
    steps = generalist.plan("analyse les ports 22 de la cible 10.0.0.1")
    assert [s.expert for s in steps] == ["info"]


def test_plan_llm_falls_back_when_provider_unavailable():
    stub = StubProvider('{"steps": [{"expert": "dns", "request": "x"}]}', available=False)
    generalist = _generalist()
    generalist.provider = stub
    steps = generalist.plan("resous les MX de example.com")
    assert [s.expert for s in steps] == ["dns"]


# ---- Synthese LLM --------------------------------------------------------


def test_synthesize_llm_uses_provider_text():
    # 1re reponse: la decomposition (invalide -> repli heuristique).
    # 2e reponse: la synthese redigee par le modele.
    stub = StubProvider("je ne sais pas", "Voici la synthese finale.")
    generalist = _generalist()
    generalist.provider = stub
    answer = generalist.answer("scanne 10.0.0.1")
    assert answer.source == "llm"
    assert answer.synthesis == "Voici la synthese finale."


# ---- Place reservee (modele dedie) --------------------------------------


def test_generalist_model_is_applied():
    generalist = _generalist(generalist_model="mon-generaliste")
    assert generalist._config.model == "mon-generaliste"
    # Sans modele dedie, le modele global reste inchange.
    assert _generalist()._config.model == Config().model


# ---- CLI -----------------------------------------------------------------


def test_cli_generalist_dry_run(capsys):
    from aisec.cli import run_cli

    code = run_cli(
        None,
        [
            "--dry-run",
            "--provider",
            "none",
            "generalist",
            "analyse les ports 22 de la cible 10.0.0.1 puis casse le wpa de capture.cap",
        ],
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "generaliste" in out
    assert "nmap" in out and "aircrack-ng" in out
    assert "Synthese" in out


def test_cli_generalist_json(capsys):
    from aisec.cli import run_cli

    code = run_cli(
        None, ["--dry-run", "--provider", "none", "--json", "generalist", "scanne 10.0.0.1"]
    )
    assert code == 0
    import json

    payload = json.loads(capsys.readouterr().out)
    assert payload["steps"][0]["expert"] == "info"
    assert payload["consultations"][0]["command"] == "nmap 10.0.0.1"


def test_cli_consult_runs_named_expert(capsys):
    from aisec.cli import run_cli

    code = run_cli(
        None, ["--dry-run", "--provider", "none", "consult", "wireless", "casse le wpa de capture.cap"]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "[expert: wireless" in out
    assert "aircrack-ng" in out


def test_cli_consult_unknown_expert(capsys):
    from aisec.cli import run_cli

    code = run_cli(None, ["consult", "inexistant", "truc"])
    assert code == 2
    assert "inconnu" in capsys.readouterr().err
