"""STAGE 3: test engine (generate-show-approve-run + diff)."""

from avci.testing.diff import AttemptResult, load_results, summarize
from avci.testing.generator import extract_python
from avci.testing.runner import RunResult, ScriptCheck, check_script, run_script

__all__ = [
    "AttemptResult",
    "RunResult",
    "ScriptCheck",
    "check_script",
    "extract_python",
    "load_results",
    "run_script",
    "summarize",
]
