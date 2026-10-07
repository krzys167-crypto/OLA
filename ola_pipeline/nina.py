"""Nina — execution agent. Executes the task through the configured provider."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .config import ProviderConfig
from .source import SourceAnchor
from .stage import StageResult, run_stage
from .vault import EvidenceVault

NINA_SYSTEM = (
    "You are Nina, the execution agent of an evidence-driven AI operating system. "
    "Carry out the user's task completely and precisely. Return only the deliverable, "
    "without meta commentary. If the task cannot be completed with the information given, "
    "state exactly what is missing instead of inventing facts."
)


def build_messages(task: str, correction: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    if correction is None:
        user = task
    else:
        fixes = "\n".join(f"- {c}" for c in correction["required_corrections"])
        user = (
            f"ORIGINAL TASK:\n{task}\n\n"
            f"YOUR PREVIOUS ANSWER (rejected by independent verification):\n{correction['previous_output']}\n\n"
            f"REQUIRED CORRECTIONS:\n{fixes}\n\n"
            "Produce a corrected, complete answer that resolves every required correction."
        )
    return [{"role": "system", "content": NINA_SYSTEM}, {"role": "user", "content": user}]


class Nina:
    agent_id = "nina"

    def __init__(self, cfg: ProviderConfig):
        self.cfg = cfg

    def execute(self, *, vault: EvidenceVault, anchor: SourceAnchor, session_id: str, run_id: str,
                parent_run_id: Optional[str], iteration: int, task: str,
                correction: Optional[Dict[str, Any]] = None) -> StageResult:
        if correction is None:
            input_obj: Dict[str, Any] = {"task": task}
            refs: Dict[str, Any] = {}
        else:
            input_obj = {
                "task": task, "previous_run_id": correction["previous_run_id"],
                "previous_output_hash": correction["previous_output_hash"],
                "required_corrections": correction["required_corrections"],
                "evaluation_hash": correction["evaluation_hash"],
            }
            refs = {"correction_of_run_id": correction["previous_run_id"],
                    "correction_evaluation_hash": correction["evaluation_hash"]}
        return run_stage(
            vault=vault, anchor=anchor, session_id=session_id, run_id=run_id,
            parent_run_id=parent_run_id, agent_id=self.agent_id, iteration=iteration,
            cfg=self.cfg, messages=build_messages(task, correction), input_obj=input_obj, refs=refs,
        )
