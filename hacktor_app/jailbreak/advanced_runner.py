from __future__ import annotations

import inspect
import os
from typing import Iterable, Optional, Any, Tuple

from .state import AdvanceRunState
from .progress_hook import GradioStateProgressHook, StopRequested

try:
    from dtx_attacks.models.openai_model import OpenAIModel
    from dtx_attacks.attacks.attackers.pair.runner import PAIRRunner, PAIRConfig
    from dtx_attacks.attacks.attackers.tap.runner import TAPRunner, TAPConfig
    from dtx_attacks.attacks.targets.base import GenerationConfig
    from dtx_attacks.attacks.targets.openai import OpenAITarget
except Exception as e:  # pragma: no cover
    raise ImportError(
        "dtx_attacks is not installed. Run: poetry add git+https://github.com/detoxio-ai/dtx_attacks.git"
    ) from e


def _filter_kwargs_by_signature(cls: type, kwargs: dict) -> dict:
    try:
        sig = inspect.signature(cls.__init__)
    except Exception:
        return {}
    allowed = {
        p.name
        for p in sig.parameters.values()
        if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
    }
    return {k: v for k, v in kwargs.items() if k in allowed}


def _resolve_base_url(provider: str) -> Optional[str]:
    p = (provider or "").strip().lower()
    if p == "openai":
        if os.getenv("OPENAI_API_BASE"):
            return os.getenv("OPENAI_API_BASE")
        dtx = os.getenv("DETOXIO_API_HOST")
        if dtx:
            return f"https://{dtx}/dtx.services.llms.v1.LlmPlatformProxyService/openai/v1/"
        return "https://api.openai.com/v1"
    if p == "groq":
        return os.getenv("GROQ_API_BASE") or "https://api.groq.com/openai/v1"
    return None


def _build_openai_model(
    model_name: str,
    api_key: str,
    temperature: float,
    max_tokens: int,
    base_url: str | None,
):
    return OpenAIModel(
        model_name=model_name,
        api_key=api_key,
        base_url=base_url,
        generation_config={"temperature": float(temperature), "max_tokens": int(max_tokens)},
    )


def _runner_run_compat(runner: Any, goal_text: str) -> Any:
    sig = inspect.signature(runner.run)
    names = list(sig.parameters.keys())
    if "root_task" in names:
        kwargs = {"root_task": goal_text}
        if "judge_goal" in names:
            kwargs["judge_goal"] = goal_text
        return runner.run(**kwargs)
    if "goal" in names:
        return runner.run(goal=goal_text)
    if "task" in names:
        return runner.run(task=goal_text)
    return runner.run(goal_text)


def _unpack_best_score(result: Any) -> Tuple[float, str]:
    if isinstance(result, tuple):
        if len(result) >= 3 and isinstance(result[-1], (int, float)):
            return float(result[-1]), "tuple[3]"
        if len(result) >= 2 and isinstance(result[-1], (int, float)):
            return float(result[-1]), "tuple[2]"
    if isinstance(result, dict):
        for k in ("best_score", "score", "global_best", "best"):
            if k in result and isinstance(result[k], (int, float)):
                return float(result[k]), f"dict[{k}]"
    for k in ("best_score", "score", "global_best", "best"):
        if hasattr(result, k) and isinstance(getattr(result, k), (int, float)):
            return float(getattr(result, k)), f"obj.{k}"
    return 0.0, "default"


def _extract_best_texts(result: Any) -> Tuple[str, str]:
    best_prompt, best_response = "", ""
    if isinstance(result, (tuple, list)):
        if len(result) >= 1 and isinstance(result[0], str):
            best_prompt = result[0]
        if len(result) >= 2:
            if isinstance(result[1], str):
                best_response = result[1]
            elif isinstance(result[1], dict):
                for k in ("response", "output", "assistant", "text"):
                    v = result[1].get(k)
                    if isinstance(v, str):
                        best_response = v
                        break
    elif isinstance(result, dict):
        for k in ("best_prompt", "prompt", "input"):
            v = result.get(k)
            if isinstance(v, str):
                best_prompt = v
                break
        for k in ("best_response", "response", "output", "assistant", "text"):
            v = result.get(k)
            if isinstance(v, str):
                best_response = v
                break
        if not best_response:
            inner = result.get("result") or result.get("data") or {}
            if isinstance(inner, dict):
                for k in ("best_response", "response", "output", "assistant", "text"):
                    v = inner.get(k)
                    if isinstance(v, str):
                        best_response = v
                        break
    return best_prompt, best_response


def run_pair_with_hook(
    state: AdvanceRunState,
    *,
    goal: str,
    target_model: str,
    api_key: str,
    attacker_model: Optional[str] = None,
    eval_model: Optional[str] = None,
    temperature: float = 0.2,
    max_new_tokens: int = 200,
    base_url: Optional[str] = None,
) -> None:
    state.clear_logs()
    state.set(status="In Progress", running=True, best_score=0.0, progress=None, best_prompt="", best_response="")
    attacker_llm = _build_openai_model(attacker_model or target_model, api_key, 0.7, 512, base_url)
    judge_llm = _build_openai_model(eval_model or target_model, api_key, 0.0, 256, base_url)
    target_llm = _build_openai_model(target_model, api_key, temperature, max_new_tokens, base_url)
    target = OpenAITarget(target_llm)
    desired_cfg = dict(
        attack_model=attacker_llm,
        eval_model=judge_llm,
        n_streams=3,
        n_iterations=3,
        max_attempts=3,
        gen_cfg=GenerationConfig(max_new_tokens=max_new_tokens, temperature=temperature),
        success_threshold=10.0,
        judge_template="chao2023pair",
        judge_generation_kwargs={"temperature": 0.0, "max_tokens": 256},
    )
    cfg = PAIRConfig(**_filter_kwargs_by_signature(PAIRConfig, desired_cfg))
    hook = GradioStateProgressHook(state)
    try:
        runner = PAIRRunner(target=target, config=cfg, progress_hook=hook)
        raw = _runner_run_compat(runner, goal or "No goal specified.")
        best_score, note = _unpack_best_score(raw)
        bp, br = _extract_best_texts(raw)
        snap = state.snapshot()
        bp = snap.get("best_prompt") or bp
        br = snap.get("best_response") or br
        state.append_log(f"PAIR complete. Best Score={best_score:.2f} ({note})")
        state.set(best_score=best_score, best_prompt=bp, best_response=br, status="Completed", running=False)
    except StopRequested:
        state.append_log("PAIR stopped by user.")
        state.set(status="Stopped", running=False)
    except Exception as e:
        state.append_log(f"PAIR fatal error: {e!r}")
        state.set(status="Error", running=False)


def run_tap_with_hook(
    state: AdvanceRunState,
    *,
    goal: str,
    target_model: str,
    api_key: str,
    temperature: float = 0.2,
    max_new_tokens: int = 200,
    base_url: Optional[str] = None,
) -> None:
    state.clear_logs()
    state.set(status="In Progress", running=True, best_score=0.0, progress=None, best_prompt="", best_response="")
    attacker_llm = _build_openai_model(target_model, api_key, 0.7, 512, base_url)
    judge_llm = _build_openai_model(target_model, api_key, 0.0, 256, base_url)
    target_llm = _build_openai_model(target_model, api_key, temperature, max_new_tokens, base_url)
    target = OpenAITarget(target_llm)
    desired_cfg = dict(
        attack_model=attacker_llm,
        eval_model=judge_llm,
        n_streams=3,
        n_iterations=3,
        gen_cfg=GenerationConfig(max_new_tokens=max_new_tokens, temperature=temperature),
        success_threshold=10.0,
        judge_template="chao2023pair",
        judge_generation_kwargs={"temperature": 0.0, "max_tokens": 256},
    )
    cfg = TAPConfig(**_filter_kwargs_by_signature(TAPConfig, desired_cfg))
    hook = GradioStateProgressHook(state)
    try:
        runner = TAPRunner(target=target, config=cfg, progress_hook=hook)
        raw = _runner_run_compat(runner, goal or "No goal specified.")
        best_score, note = _unpack_best_score(raw)
        bp, br = _extract_best_texts(raw)
        snap = state.snapshot()
        bp = snap.get("best_prompt") or bp
        br = snap.get("best_response") or br
        state.append_log(f"TAP complete. Best Score={best_score:.2f} ({note})")
        state.set(best_score=best_score, best_prompt=bp, best_response=br, status="Completed", running=False)
    except StopRequested:
        state.append_log("TAP stopped by user.")
        state.set(status="Stopped", running=False)
    except Exception as e:
        state.append_log(f"TAP fatal error: {e!r}")
        state.set(status="Error", running=False)


def run_advanced(
    *,
    state: AdvanceRunState,
    provider: str,
    model_name: str,
    api_key: str,
    goal: str,
    techniques: Iterable[str],
) -> None:
    base_url = _resolve_base_url(provider)
    if not base_url:
        state.append_log(f"Provider '{provider}' not supported yet.")
        state.set(status="Error", running=False)
        return
    for tech in techniques:
        if state.stop_flag:
            state.append_log("Stop requested before starting next technique.")
            state.set(status="Stopped", running=False)
            return
        t = (tech or "").strip().upper()
        state.append_log(f"Starting technique: {t} (provider={provider}, base_url={base_url})")
        if t == "PAIR":
            run_pair_with_hook(state, goal=goal, target_model=model_name, api_key=api_key, base_url=base_url)
        elif t == "TAP":
            run_tap_with_hook(state, goal=goal, target_model=model_name, api_key=api_key, base_url=base_url)
        else:
            state.append_log(f"Technique '{t}' is not implemented.")
            state.set(status="Error", running=False)
            return
        if state.status in ("Stopped", "Error"):
            return
