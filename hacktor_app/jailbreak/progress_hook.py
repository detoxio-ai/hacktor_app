from __future__ import annotations

from typing import Any, Dict, Optional
from .state import AdvanceRunState


class StopRequested(RuntimeError):
    """Raised to cooperatively cancel a run."""


def _extract_texts(candidate: Dict[str, Any]) -> tuple[str, str]:
    p = ""
    r = ""
    if not isinstance(candidate, dict):
        return p, r
    for k in ("best_prompt", "prompt", "adversarial_prompt", "input", "user", "root_task", "task", "goal"):
        v = candidate.get(k)
        if isinstance(v, str) and v:
            p = v
            break
    for k in ("best_response", "response", "output", "assistant", "text", "completion"):
        v = candidate.get(k)
        if isinstance(v, str) and v:
            r = v
            break
    if not r:
        inner = candidate.get("result") or candidate.get("data") or {}
        if isinstance(inner, dict):
            for k in ("best_response", "response", "output", "assistant", "text", "completion"):
                v = inner.get(k)
                if isinstance(v, str) and v:
                    r = v
                    break
    return p, r


class GradioStateProgressHook:
    def __init__(self, state: AdvanceRunState):
        self.state = state
        self.global_best: float = 0.0
        self._behaviors_total: Optional[int] = None
        self._strategies_total: Optional[int] = None
        self._turns_total: Optional[int] = None
        self._behaviors_done = 0
        self._strategies_done = 0
        self._turns_done = 0

    def _bail_if_stopping(self):
        if self.state.stop_flag:
            self.state.append_log("Stop requested…")
            raise StopRequested()

    def _update_progress(self):
        total = done = None
        if self._turns_total:
            total, done = self._turns_total, self._turns_done
        elif self._strategies_total:
            total, done = self._strategies_total, self._strategies_done
        elif self._behaviors_total:
            total, done = self._behaviors_total, self._behaviors_done
        if total and total > 0:
            self.state.set(progress=max(0.0, min(1.0, done / total)))

    def on_total_behaviors(self, n: int):
        self._behaviors_total = int(n)
        self._update_progress()

    def on_total_strategies(self, n: int):
        self._strategies_total = int(n)
        self._update_progress()

    def on_total_turns(self, n: int):
        self._turns_total = int(n)
        self._update_progress()

    def on_behavior_start(self, *_, **__):
        self._bail_if_stopping()
        self.state.set(status="In Progress")
        self.state.append_log("Behavior start…")

    def on_behavior_end(self, *_, **__):
        self._behaviors_done += 1
        self._update_progress()

    def on_strategy_start(self, *_, **__):
        self._bail_if_stopping()

    def on_strategy_end(self, *_, **__):
        self._strategies_done += 1
        self._update_progress()

    def on_turn_start(self, *_, **__):
        self._bail_if_stopping()

    def on_turn_end(self, *_, **__):
        self._turns_done += 1
        self._update_progress()

    def on_strategy_end_summary(self, stats: Any):
        self.state.append_log(f"[Strategy Summary] {stats!s}")

    def on_success(self, depth: int, score: float, prompt: str):
        if score > self.global_best:
            self.global_best = float(score)
            self.state.set(best_score=self.global_best)
            if isinstance(prompt, str) and prompt:
                self.state.set(best_prompt=prompt)
        self.state.append_log(f"[SUCCESS] depth={depth} score={score:.2f}")

    def on_new_global_best(self, technique: str, score: float, prev_best: float, candidate: Dict[str, Any]):
        if score > self.global_best:
            self.global_best = float(score)
            p, r = _extract_texts(candidate)
            updates = {"best_score": self.global_best}
            if p:
                updates["best_prompt"] = p
            if r:
                updates["best_response"] = r
            self.state.set(**updates)
        self.state.append_log(f"[{technique}] new global best {score:.2f} (prev {prev_best:.2f})")

    def on_best_score_update(self, technique: str, score: float, candidate: Dict[str, Any]):
        if score > self.global_best:
            self.global_best = float(score)
            p, r = _extract_texts(candidate)
            updates = {"best_score": self.global_best}
            if p:
                updates["best_prompt"] = p
            if r:
                updates["best_response"] = r
            self.state.set(**updates)

    def on_structure_progress(self, technique: str, structure_type: str, data: Dict[str, Any]):
        self.state.append_log(f"[{technique}] {structure_type}: {data!s}")

    def on_behavior_error(self, exception: Exception, friendly_message: str, behavior_number: int):
        self.state.set(status="Error")
        self.state.append_log(f"[Behavior {behavior_number}] ERROR: {friendly_message} ({exception})")

    def on_strategy_error(self, exception: Exception, friendly_message: str, behavior_number: int, strategy_idx: int):
        self.state.set(status="Error")
        self.state.append_log(f"[B{behavior_number}|S{strategy_idx}] ERROR: {friendly_message} ({exception})")

    def on_turn_error(self, exception: Exception, friendly_message: str, behavior_number: int, strategy_idx: int, turn_idx: int):
        self.state.set(status="Error")
        self.state.append_log(f"[B{behavior_number}|S{strategy_idx}|T{turn_idx}] ERROR: {friendly_message} ({exception})")
