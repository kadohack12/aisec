"""Execution de commandes, sans shell.

On utilise subprocess avec une liste d'arguments (jamais shell=True) et on
verifie au prealable que le binaire est bien celui attendu et que les
arguments ne contiennent pas de metacaracteres dangereux.
"""

from __future__ import annotations

import shutil
import subprocess
import time

from .models import ExecResult
from .safety import validate_argv


class ExecutionError(RuntimeError):
    pass


def binary_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(
    argv: list[str],
    allowed_binary: str | None = None,
    timeout: float = 120.0,
    dry_run: bool = False,
) -> ExecResult:
    """Lance argv et capture la sortie.

    `allowed_binary` verrouille le premier element de argv (defense en profondeur).
    """
    if allowed_binary is None:
        allowed_binary = argv[0] if argv else ""

    report = validate_argv(argv, allowed_binary)
    if not report.ok:
        raise ExecutionError("; ".join(report.errors))

    if not binary_available(allowed_binary):
        raise ExecutionError(
            f"binaire '{allowed_binary}' introuvable dans le PATH. "
            f"Installe-le puis reessaie."
        )

    if dry_run:
        return ExecResult(argv=argv, returncode=0, stdout="", stderr="", duration_s=0.0)

    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)
        code = -1

    return ExecResult(
        argv=argv,
        returncode=code,
        stdout=stdout,
        stderr=stderr,
        duration_s=round(time.monotonic() - started, 3),
        timed_out=timed_out,
    )


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
