from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import List, Literal, Dict, Any

RunStatus = Literal["Idle", "In Progress", "Stopped", "Error", "Completed"]


@dataclass
class AdvanceRunState:
    status: RunStatus = "Idle"
    best_score: float = 0.0
    progress: float | None = None  # 0..1, None => indeterminate
    logs: List[str] = field(default_factory=list)
    running: bool = False
    stop_flag: bool = False

    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def set(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, v)

    def append_log(self, msg: str) -> None:
        with self._lock:
            self.logs.append(str(msg))

    def clear_logs(self) -> None:
        with self._lock:
            self.logs.clear()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status": self.status,
                "best_score": self.best_score,
                "progress": self.progress,
                "logs": list(self.logs),
                "running": self.running,
                "stop_flag": self.stop_flag,
            }
