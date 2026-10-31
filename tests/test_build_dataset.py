"""Tests du generateur de jeux d'entrainement (scripts/build_dataset.py)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "build_dataset", ROOT / "scripts" / "build_dataset.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bd = _load()


def test_expert_samples_use_production_prompt():
    rows = bd._expert_samples("openai")
    assert rows, "aucun exemple de routage de classe"
    first = rows[0]["messages"]
    assert first[0]["content"] == bd.EXPERT_ROUTER_SYSTEM
    assert "Classes disponibles:" in first[1]["content"]
    payload = json.loads(first[2]["content"])
    assert set(payload) == {"expert"}


def test_tool_samples_shape_and_params():
    rows = bd._tool_samples("openai")
    assert rows
    for row in rows:
        msgs = row["messages"]
        payload = json.loads(msgs[2]["content"])
        assert set(payload) == {"tool", "params"}
        assert isinstance(payload["params"], dict)
        # le prompt systeme doit etre celui de l'expert, reutilise a l'inference
        assert "expert '" in msgs[0]["content"]


def test_build_writes_all_formats(tmp_path):
    for fmt in ("openai", "chatml", "alpaca"):
        out = tmp_path / fmt
        bd.build(out, fmt, 0.9, seed=1)
        for name in ("expert_routing", "tool_routing", "generalist_routing", "all"):
            train = out / f"{name}.train.jsonl"
            val = out / f"{name}.val.jsonl"
            assert train.is_file() and val.is_file()
            assert train.read_text(encoding="utf-8").strip()


def test_chatml_contains_special_tokens(tmp_path):
    bd.build(tmp_path, "chatml", 0.9, seed=1)
    text = (tmp_path / "tool_routing.train.jsonl").read_text(encoding="utf-8")
    assert "<|im_start|>assistant" in text
    assert "<|im_end|>" in text


def test_modelfiles_one_per_expert(tmp_path):
    from aisec.experts import all_experts

    bd.write_modelfiles(tmp_path, "llama3.1")
    files = sorted(p.name for p in tmp_path.glob("Modelfile.*"))
    expected = sorted([f"Modelfile.{e.name}" for e in all_experts()] + ["Modelfile.generalist"])
    assert files == expected
    content = (tmp_path / "Modelfile.info").read_text(encoding="utf-8")
    assert content.startswith("FROM llama3.1")
    assert 'SYSTEM """' in content
    assert "MESSAGE assistant" in content


def test_generalist_samples_and_modelfile(tmp_path):
    rows = bd._generalist_samples("openai")
    assert rows
    # Le prompt systeme doit etre celui de production (source unique).
    assert rows[0]["messages"][0]["content"] == bd.GENERALIST_SYSTEM
    for row in rows:
        payload = json.loads(row["messages"][2]["content"])
        assert "steps" in payload and payload["steps"]
        for step in payload["steps"]:
            assert set(step) == {"expert", "request"}

    bd.write_modelfiles(tmp_path, "llama3.1")
    generalist = (tmp_path / "Modelfile.generalist").read_text(encoding="utf-8")
    assert generalist.startswith("FROM llama3.1")
    assert bd.GENERALIST_SYSTEM.split(".")[0] in generalist


def test_eval_reports_unavailable_provider(tmp_path, capsys):
    dataset = tmp_path / "d.jsonl"
    dataset.write_text(
        json.dumps({"instruction": "s", "input": "u", "output": "{}"}) + "\n",
        encoding="utf-8",
    )
    assert bd.evaluate(dataset, "none", None) == 2
    assert "indisponible" in capsys.readouterr().out
