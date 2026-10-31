#!/usr/bin/env python3
"""Genere les jeux d'entrainement/eval d'aisec a partir du code.

Le principe : les experts et les outils contiennent deja tout le savoir
(system_prompt, description, parametres, exemples). On en derive deux jeux de
donnees supervises, avec **exactement** les prompts utilises en production
(importes depuis `aisec.experts.base`), pour qu'un modele fine-tune colle au
comportement d'inference.

Deux taches:
  1. routage de CLASSE (expert) : demande libre -> {"expert": "..."}
  2. routage d'OUTIL (par expert) : demande libre -> {"tool": "...", "params": {...}}
  3. planification GENERALISTE : objectif (mono ou multi-etapes) ->
     {"steps": [{"expert": "...", "request": "..."}]}

Formats de sortie:
  - openai : {"messages": [system, user, assistant]}  (Ollama, OpenAI, vLLM...)
  - chatml : {"text": "<|im_start|>system ... <|im_end|>..."}  (HF SFT, Unsloth)
  - alpaca : {"instruction", "input", "output"}

Exemples:
  python scripts/build_dataset.py --out datasets
  python scripts/build_dataset.py --out datasets --format chatml --split 0.9
  python scripts/build_dataset.py --eval datasets/expert_routing.val.jsonl --provider ollama
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aisec.core.config import Config  # noqa: E402
from aisec.core.generalist import GENERALIST_SYSTEM  # noqa: E402
from aisec.core.registry import get as get_tool  # noqa: E402
from aisec.experts import all_experts, router_catalog  # noqa: E402
from aisec.experts.base import EXPERT_ROUTER_SYSTEM, tool_router_system  # noqa: E402
from aisec.providers.base import get_provider  # noqa: E402


def _json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def _format(system: str, user: str, assistant: str, fmt: str) -> dict:
    if fmt == "openai":
        return {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
                {"role": "assistant", "content": assistant},
            ]
        }
    if fmt == "chatml":
        return {
            "text": (
                f"<|im_start|>system\n{system}<|im_end|>\n"
                f"<|im_start|>user\n{user}<|im_end|>\n"
                f"<|im_start|>assistant\n{assistant}<|im_end|>"
            )
        }
    if fmt == "alpaca":
        return {"instruction": system, "input": user, "output": assistant}
    raise ValueError(f"format inconnu: {fmt}")


def _expert_samples(fmt: str) -> list[dict]:
    """Routage de classe: chaque exemple d'outil -> expert proprietaire."""
    catalog = router_catalog()
    samples: list[dict] = []
    for expert in all_experts():
        for tool_name in expert.tool_names:
            tool = get_tool(tool_name)
            for text in tool.examples:
                user = f"Classes disponibles:\n{catalog}\n\nDemande: \"{text}\""
                assistant = _json({"expert": expert.name})
                samples.append(_format(EXPERT_ROUTER_SYSTEM, user, assistant, fmt))
    return samples


def _tool_samples(fmt: str) -> list[dict]:
    """Routage d'outil: par expert, chaque exemple -> outil + params."""
    samples: list[dict] = []
    for expert in all_experts():
        system = tool_router_system(expert)
        for tool_name in expert.tool_names:
            tool = get_tool(tool_name)
            for text in tool.examples:
                params = tool.coerce(tool.parse_intent(text))
                assistant = _json({"tool": tool_name, "params": params})
                samples.append(_format(system, expert.prompt(text), assistant, fmt))
    return samples


def _generalist_samples(fmt: str) -> list[dict]:
    """Planification generaliste: objectif -> etapes (mono et multi-experts).

    Mono-etape: on reutilise chaque exemple d'outil comme objectif d'une seule
    etape (couvre tout le catalogue). Multi-etapes: on combine des exemples de
    deux experts differents via un connecteur, pour apprendre la decomposition.
    """
    from aisec.core.generalist import generalist_user_prompt

    per_expert: dict[str, list[str]] = {}
    for expert in all_experts():
        texts: list[str] = []
        for tool_name in expert.tool_names:
            texts.extend(get_tool(tool_name).examples)
        if texts:
            per_expert[expert.name] = texts

    samples: list[dict] = []

    def _emit(goal: str, steps: list[dict]) -> None:
        user = generalist_user_prompt(goal)
        assistant = _json({"steps": steps})
        samples.append(_format(GENERALIST_SYSTEM, user, assistant, fmt))

    for expert_name, texts in per_expert.items():
        for text in texts:
            _emit(text, [{"expert": expert_name, "request": text}])

    names = sorted(per_expert)
    for index, first in enumerate(names):
        second = names[(index + 1) % len(names)]
        if second == first:
            continue
        goal = f"{per_expert[first][0]} puis {per_expert[second][0]}"
        _emit(
            goal,
            [
                {"expert": first, "request": per_expert[first][0]},
                {"expert": second, "request": per_expert[second][0]},
            ],
        )
    return samples


def _split(rows: list[dict], ratio: float, rng: random.Random) -> tuple[list, list]:
    shuffled = rows[:]
    cut = int(len(shuffled) * ratio)
    return shuffled[:cut], shuffled[cut:]


def _write(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _quote(text: str) -> str:
    """Echappe le delimiteur triple-quote des Modelfiles Ollama."""
    return text.replace('"""', '\\"\\"\\"')


def _modelfile(expert, base: str) -> str:
    """Modelfile Ollama: systeme de l'expert + exemples few-shot (par outil)."""
    lines = [f"FROM {base}", f'SYSTEM """{_quote(tool_router_system(expert))}"""']
    for tool_name in expert.tool_names:
        tool = get_tool(tool_name)
        for text in tool.examples:
            params = tool.coerce(tool.parse_intent(text))
            answer = _json({"tool": tool_name, "params": params})
            lines.append(f'MESSAGE user """{_quote(expert.prompt(text))}"""')
            lines.append(f'MESSAGE assistant """{answer}"""')
    return "\n".join(lines) + "\n"


def _generalist_modelfile(base: str) -> str:
    """Modelfile Ollama de l'IA generaliste: systeme + exemples de decomposition."""
    lines = [f"FROM {base}", f'SYSTEM """{_quote(GENERALIST_SYSTEM)}"""']
    for row in _generalist_samples("openai"):
        user = row["messages"][1]["content"]
        answer = row["messages"][2]["content"]
        lines.append(f'MESSAGE user """{_quote(user)}"""')
        lines.append(f'MESSAGE assistant """{answer}"""')
    return "\n".join(lines) + "\n"


def write_modelfiles(out_dir: Path, base: str) -> None:
    """Ecrit un Modelfile Ollama par expert + un pour l'IA generaliste."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for expert in all_experts():
        path = out_dir / f"Modelfile.{expert.name}"
        path.write_text(_modelfile(expert, base), encoding="utf-8")
    (out_dir / "Modelfile.generalist").write_text(_generalist_modelfile(base), encoding="utf-8")
    print(f"Modelfiles ecrits: {out_dir}/Modelfile.<expert> + Modelfile.generalist  (base={base})")
    print("  creer un modele par classe:")
    print(f"    ollama create aisec-<expert> -f {out_dir}/Modelfile.<expert>")
    print(f"    ollama create aisec-generalist -f {out_dir}/Modelfile.generalist")


def build(out_dir: Path, fmt: str, ratio: float, seed: int) -> None:
    rng = random.Random(seed)
    expert_rows = _expert_samples(fmt)
    tool_rows = _tool_samples(fmt)
    generalist_rows = _generalist_samples(fmt)

    tools = [get_tool(n) for e in all_experts() for n in e.tool_names]
    with_examples = sum(1 for t in tools if t.examples)
    print(f"couverture exemples: {with_examples}/{len(tools)} outils ont des `examples`")

    sets = (
        ("expert_routing", expert_rows),
        ("tool_routing", tool_rows),
        ("generalist_routing", generalist_rows),
    )
    for name, rows in sets:
        train, val = _split(rows, ratio, rng)
        _write(out_dir / f"{name}.train.jsonl", train)
        _write(out_dir / f"{name}.val.jsonl", val)
        print(f"{name:20s} train={len(train):4d}  val={len(val):4d}")

    all_rows = expert_rows + tool_rows + generalist_rows
    train, val = _split(all_rows, ratio, rng)
    _write(out_dir / "all.train.jsonl", train)
    _write(out_dir / "all.val.jsonl", val)
    print(f"{'all':20s} train={len(train):4d}  val={len(val):4d}  (format={fmt})")


def _expected(row: dict) -> str:
    if "messages" in row:
        return row["messages"][-1]["content"]
    if "output" in row:
        return row["output"]
    return row["text"].rsplit("<|im_start|>assistant\n", 1)[-1].split("<|im_end|>")[0]


def _json_equal(a: str, b: str) -> bool:
    try:
        return json.loads(a) == json.loads(b)
    except json.JSONDecodeError:
        return a.strip() == b.strip()


def evaluate(dataset: Path, provider_name: str | None, model: str | None) -> int:
    """Rejoue le dataset contre le provider actif et mesure l'accuracy exacte."""
    config = Config.load()
    if provider_name:
        config.provider = provider_name
    if model:
        config.model = model
    provider = get_provider(config)
    if provider is None or not provider.available():
        print(f"provider indisponible ({config.provider}); rien a evaluer.")
        return 2

    rows = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines() if line]
    ok = 0
    for row in rows:
        if "messages" in row:
            system = row["messages"][0]["content"]
            user = row["messages"][1]["content"]
        else:
            system, user = row.get("instruction", ""), row.get("input", "")
        got = provider.complete(user, system=system).strip()
        if _json_equal(got, _expected(row)):
            ok += 1
    total = len(rows) or 1
    print(f"accuracy: {ok}/{total} = {ok / total:.1%}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", type=Path, default=ROOT / "datasets", help="dossier de sortie")
    parser.add_argument("--format", choices=["openai", "chatml", "alpaca"], default="openai")
    parser.add_argument("--split", type=float, default=0.9, help="part train (reste = val)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--eval", type=Path, help="evaluer un fichier .jsonl au lieu de generer")
    parser.add_argument("--provider", help="provider pour --eval (defaut: config)")
    parser.add_argument("--model", help="modele pour --eval (defaut: config)")
    parser.add_argument("--modelfiles", action="store_true", help="ecrire un Modelfile Ollama par expert")
    parser.add_argument("--base-model", default="llama3.1", help="modele de base des Modelfiles")
    args = parser.parse_args()

    if args.eval:
        return evaluate(args.eval, args.provider, args.model)
    if args.modelfiles:
        write_modelfiles(args.out, args.base_model)
        return 0
    build(args.out, args.format, args.split, args.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
