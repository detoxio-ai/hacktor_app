from __future__ import annotations

import base64
import logging
import os
import re
import time
from pathlib import Path
from typing import List, Tuple
from threading import Thread

import gradio as gr
from dotenv import load_dotenv

from hacktor_app.hacktor import HacktorClient
from hacktor_app.threat_model.openai_analysis import AppRiskAnalysis

from hacktor_app.jailbreak.state import AdvanceRunState
from hacktor_app.jailbreak.advanced_runner import run_advanced


# -----------------------------------------------------------------------------
# Environment & setup
# -----------------------------------------------------------------------------
load_dotenv()  # read .env from project root

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("gradio_app")

# Constants
MAX_USER_CLICK = 10
click_count = 0
last_prompt = "NA"
technique_used = ""

# Shared state for Advance Jailbreaks
adv_state = AdvanceRunState()

# Providers & validation (regex permissive to avoid false negatives with proxies)
PROVIDERS = {
    "OpenAI": {
        "models": [
            "gpt-4o-mini",
            "gpt-4o",
            "o4-mini",
            "gpt-4.1-mini",
            "gpt-4.1",
            "gpt-3.5-turbo",
        ],
        "key_hint": "sk-… (or proxy token)",
        # normal OpenAI sk-* OR long proxy tokens
        "key_regex": r"^(sk-[A-Za-z0-9_-]{10,}|[A-Za-z0-9._=\-]{20,})$",
    },
    "Groq": {
        "models": [
            "llama-3.3-70b-versatile",
            "llama-3.3-70b-specdec",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
        ],
        "key_hint": "gsk_…",
        "key_regex": r"^gsk_[A-Za-z0-9]{20,}$",
    },
}

# Core env vars
default_api_key = os.getenv("DETOXIO_API_KEY", "")
dtx_hostname = os.getenv("DETOXIO_API_HOST", "api.detoxio.ai")
CONCURRENCY_LIMIT = int(os.getenv("CONCURRENCY_LIMIT", 2))

# Dump paths (ensure directories exist; provide sane defaults)
prompt_conversion_dump_path = os.getenv("PROMPT_CONVERSATION_DUMP_PATH") or "./data/prompt_conversion_dump.json"
threat_model_dump_path = os.getenv("THREAT_MODEL_DUMP_PATH") or "./data/threat_model_dump.json"

for p in (prompt_conversion_dump_path, threat_model_dump_path):
    try:
        Path(p).expanduser().parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log.warning("Could not ensure directory for %s: %r", p, e)

if not default_api_key:
    raise ValueError("Missing Detoxio API Key")

app_title = os.getenv("TITLE", "AI Red Teaming Companion")
custom_api_key: str | None = None

# Initialize clients
client = HacktorClient(
    default_api_key,
    dtx_hostname,
    dump_file=prompt_conversion_dump_path,
)

risk_analyzer = AppRiskAnalysis(
    model="gpt-4o",
    temperature=0.2,
    dump_file=threat_model_dump_path,
)

log.info("Detoxio host: %s", dtx_hostname)
log.info("App title: %s", app_title)


# -----------------------------------------------------------------------------
# Existing app functions
# -----------------------------------------------------------------------------
def set_api_key(api_key: str) -> str:
    """Set a custom API key from user input."""
    global client, custom_api_key
    custom_api_key = api_key.strip() if api_key else None
    client = HacktorClient(
        custom_api_key or default_api_key,
        dtx_hostname,
        dump_file=prompt_conversion_dump_path,
    )
    return "Custom Key in Use" if custom_api_key else "System Default Key in Use"


def generate_prompt(attack_module: str, goal: str) -> Tuple[str, str]:
    """Generate a prompt based on the selected attack module and user goal."""
    global click_count, last_prompt, technique_used
    click_count += 1
    last_prompt, technique_used = client.generate(attack_module, goal=goal)
    return last_prompt, technique_used


def evaluate_text(prompt: str, response: str):
    """Evaluate the response based on the last generated prompt."""
    global click_count
    click_count += 1
    if not prompt:
        return {"Error": "No prompt provided for evaluation."}
    return client.evaluate(prompt, response)


def generate_threat_model(agent_description: str):
    """Analyze the AI agent and return an AppRiskProfile in a formatted table."""
    global click_count
    click_count += 1
    analysis_result = risk_analyzer.analyze(agent_description)

    app_name = analysis_result.profile.app.name
    app_capabilities = "\n".join(f"- {cap}" for cap in analysis_result.profile.app.capabilities)

    risks_table = [
        [
            risk.risk,
            risk.risk_score,
            risk.threat_level,
            risk.rationale,
            "\n".join(f"- {strategy}" for strategy in risk.attack_strategies),
        ]
        for risk in analysis_result.profile.risks
    ]

    return app_name, app_capabilities, analysis_result.think, risks_table


# -----------------------------------------------------------------------------
# Helpers for new tabs
# -----------------------------------------------------------------------------
def _adv_validate(provider: str, model_name: str, api_key: str, technique: str, key_ok: bool) -> bool:
    # goal is optional now; only require provider, model, 1 technique, and a key that matches regex
    return bool(provider and model_name and technique and api_key and key_ok)


def _mask_key(k: str) -> str:
    if not k:
        return ""
    if len(k) <= 6:
        return "*" * len(k)
    return f"{k[:3]}***{k[-3:]}"


def _validate_key(provider: str, key: str) -> tuple[str, bool]:
    """Regex-only key format validation per provider."""
    if not key:
        return "Enter an API key.", False
    cfg = PROVIDERS.get(provider or "")
    if not cfg:
        return "Unknown provider.", False
    ok = re.match(cfg["key_regex"], key) is not None
    if ok:
        if provider == "OpenAI":
            return "✓ Looks like a valid OpenAI key or proxy token.", True
        return f"✓ Looks like a valid {provider} key format.", True
    hint = cfg["key_hint"]
    return f"✗ Key format doesn't match {provider} (e.g., {hint})", False


def _simple_transform(prompt: str, techniques: List[str]) -> str:
    """Apply lightweight obfuscations in a fixed order."""
    out = prompt
    if "Base64" in techniques:
        out = base64.b64encode(out.encode("utf-8")).decode("utf-8")
    if "Cipher" in techniques:
        # ROT13
        def rot13(s: str) -> str:
            res = []
            for ch in s:
                if "a" <= ch <= "z":
                    res.append(chr((ord(ch) - 97 + 13) % 26 + 97))
                elif "A" <= ch <= "Z":
                    res.append(chr((ord(ch) - 65 + 13) % 26 + 65))
                else:
                    res.append(ch)
            return "".join(res)

        out = rot13(out)
    return out


# -----------------------------------------------------------------------------
# UI
# -----------------------------------------------------------------------------
my_theme = gr.Theme.from_hub("Taithrah/Minimal")

with gr.Blocks(theme=my_theme, title=app_title, fill_height=True) as demo:
    # a light global CSS polish
    gr.HTML(
        """
        <style>
          .gradio-container { max-width: 100% !important; width: 100% !important; margin: 0; padding: 0 18px; }
          .gr-box, .gr-input, textarea, input, .gr-button { border-radius: 12px !important; }
          .gr-button { padding: 0.6rem 0.9rem; }
          .label-wrap .wrap > label { font-weight: 600; }
          .gr-row { gap: 14px !important; }
        </style>
        """
    )

    # --------------------- Generate Prompt ---------------------
    with gr.Tab("Generate Prompt"):
        gr.Markdown("## Generate a Text Prompt")
        attack_module = gr.Dropdown(
            label="Offensive Prompt Dataset",
            choices=[""] + list(HacktorClient.ATTACK_MODULES_MAP.keys()),
            value="",
            info="Select an attack module to generate a prompt.",
        )
        goal_input = gr.Textbox(label="Goal (Optional)", placeholder="Enter a goal to refine the prompt.", lines=2)
        generate_btn = gr.Button("Generate Prompt", variant="primary", scale=0)
        generated_prompt = gr.Textbox(label="Generated Prompt", lines=8, interactive=False, show_copy_button=True)
        with gr.Accordion("Techniques Used", open=False):
            technique_display = gr.Markdown(visible=True)

        generate_btn.click(
            fn=generate_prompt,
            inputs=[attack_module, goal_input],
            outputs=[generated_prompt, technique_display],
        )

    # --------------------- Evaluate Text ---------------------
    with gr.Tab("Evaluate Text"):
        gr.Markdown("## Evaluate Your Text")
        response = gr.Textbox(label="Enter Response for Evaluation", lines=8)
        evaluate_btn = gr.Button("Evaluate Text", variant="primary", scale=0)
        evaluation_result = gr.JSON(label="Evaluation Results")

        evaluate_btn.click(
            fn=evaluate_text,
            inputs=[generated_prompt, response],
            outputs=[evaluation_result],
        )

    # --------------------- Threat Modelling ---------------------
    with gr.Tab("Threat Modelling"):
        gr.Markdown("## Threat Modelling for AI Agents")
        agent_description = gr.Textbox(
            label="Provide Agent Description",
            placeholder="Describe the AI agent: name, functionality, purpose...",
            lines=6,
        )
        generate_threat_btn = gr.Button("Generate Threat Model", variant="primary", scale=0)

        gr.Markdown("#### AI Agent Information")
        app_name_display = gr.Markdown("Nothing Yet", label="AI App Name")
        gr.Markdown("#### Capabilities")
        app_capabilities_display = gr.Markdown("Nothing Yet", label="Capabilities")

        gr.Markdown("#### Analysis Summary")
        think_result = gr.Markdown("Nothing Yet", label="Security Analyst's Thought Process")

        gr.Markdown("#### Threat Model")
        threat_table = gr.Dataframe(
            headers=["Risk", "Risk Score", "Threat Level", "Rationale", "Attack Strategies"],
            interactive=False,
            show_copy_button=True,
        )

        generate_threat_btn.click(
            fn=generate_threat_model,
            inputs=[agent_description],
            outputs=[app_name_display, app_capabilities_display, think_result, threat_table],
            show_progress=True,
        )

    # --------------------- [2] Advance Jailbreaks ---------------------
    with gr.Tab("[2] Advance Jailbreaks"):
        gr.Markdown("## Select Target")
        adv_provider = gr.Dropdown(
            label="Provider",
            choices=list(PROVIDERS.keys()),  # OpenAI & Groq
            value="OpenAI",
            info="Choose the target provider.",
        )
        adv_model = gr.Dropdown(
            label="Model Name",
            choices=PROVIDERS["OpenAI"]["models"],
            allow_custom_value=True,
            value=PROVIDERS["OpenAI"]["models"][0],  # visible + selectable + editable
            info="Select or type a model name…",
        )
        adv_key = gr.Textbox(
            label="API Key",
            placeholder="Enter an API key (sk-… / proxy token / gsk_…)",
            type="password",
            lines=1,
        )
        adv_key_msg = gr.Markdown("")  # inline validation message
        adv_goal = gr.Textbox(label="Goal (optional)", placeholder="What are you trying to achieve?", lines=2)

        gr.Markdown("## Select Techniques")
        adv_technique = gr.Radio(choices=["TAP", "PAIR"], label="Choose one technique.")

        gr.Markdown("## Controls")
        adv_run_btn = gr.Button("Run", variant="primary", interactive=False)
        adv_stop_btn = gr.Button("Stop", variant="secondary", interactive=False)

        gr.Markdown("## Progress")
        adv_progress = gr.Slider(label="Progress", minimum=0, maximum=100, value=0, step=1, interactive=False)
        # NEW: score+status directly under bar
        adv_status_md = gr.Markdown("No run yet.")
        # NEW: best prompt/response just below status
        adv_best_prompt = gr.Textbox(
            label="Best Prompt",
            lines=4,
            max_lines=999999,
            interactive=False,
            show_copy_button=True,
            elem_id="best-prompt",
        )
        adv_best_response = gr.Textbox(
            label="Best Response",
            lines=6,
            max_lines=999999,
            interactive=False,
            show_copy_button=True,
            elem_id="best-response",
        )

        # Auto-resize the two textareas to fit full content
        gr.HTML(
            """
            <script>
              (function(){
                function autoResize(ta){
                  if(!ta) return;
                  ta.style.overflowY = 'hidden';
                  ta.style.height = 'auto';
                  ta.style.height = (ta.scrollHeight + 2) + 'px';
                }
                function bindAutoResize(rootId){
                  const root = document.getElementById(rootId);
                  const tryBind = () => {
                    const ta = root?.querySelector('textarea');
                    if(!ta){ setTimeout(tryBind, 300); return; }
                    autoResize(ta);
                    ta.addEventListener('input', () => autoResize(ta));
                    const obs = new MutationObserver(() => autoResize(ta));
                    obs.observe(ta, {subtree:true, childList:true, characterData:true});
                    setInterval(() => autoResize(ta), 500);
                  };
                  tryBind();
                }
                bindAutoResize('best-prompt');
                bindAutoResize('best-response');
              })();
            </script>
            """
        )

        gr.Markdown("## Progress Logs")
        adv_logs = gr.Textbox(value="No logs yet.", lines=12, show_copy_button=True, interactive=False, elem_id="adv-logs")

        # --- Dynamic behavior helpers ---
        def _on_provider_change(provider: str):
            cfg = PROVIDERS.get(provider, PROVIDERS["OpenAI"])
            first = cfg["models"][0] if cfg["models"] else None
            # switch model list + default, refresh key placeholder, clear validation and disable run
            return (
                gr.update(choices=cfg["models"], value=first),  # adv_model
                gr.update(placeholder=f"Enter an API key ({cfg['key_hint']})"),  # adv_key
                gr.update(value=""),  # adv_key_msg (clear)
                gr.update(interactive=False),  # adv_run_btn
            )

        adv_provider.change(
            _on_provider_change,
            inputs=[adv_provider],
            outputs=[adv_model, adv_key, adv_key_msg, adv_run_btn],
        )

        def _form_validate(provider: str, model: str, key: str, technique: str):
            msg, ok = _validate_key(provider, key) if key else ("Enter an API key.", False)
            can_run = _adv_validate(provider, model, key, technique, ok)
            return msg, gr.update(interactive=can_run)

        # validate on any relevant change
        for c in (adv_provider, adv_model, adv_key, adv_technique):
            c.change(
                _form_validate,
                inputs=[adv_provider, adv_model, adv_key, adv_technique],
                outputs=[adv_key_msg, adv_run_btn],
            )

        # Run button (real runner in background thread; stream updates)
        def _adv_on_run(provider, model, key, goal, technique):
            msg, ok = _validate_key(provider, key)
            if not _adv_validate(provider, model, key, technique, ok):
                # keep disabled state & surface the message
                yield (
                    gr.update(), gr.update(), gr.update(), gr.update(value=msg),
                    gr.update(interactive=False),  # goal
                    gr.update(interactive=False),  # run
                    gr.update(interactive=False),  # stop
                    gr.update(value=0),            # progress
                    "Best Score: 0 | Status: Idle",  # status
                    "", "",                         # best prompt/resp
                    "No run yet.",                  # logs
                )
                return

            # reset state & lock inputs
            adv_state.set(status="In Progress", running=True, stop_flag=False, best_score=0.0, progress=None)
            adv_state.clear_logs()
            adv_state.set(best_prompt="", best_response="")
            adv_state.append_log(f"Target: {provider} | Model: {model} | Key: {_mask_key(key)}")

            worker = Thread(
                target=run_advanced,
                kwargs=dict(
                    state=adv_state,
                    provider=provider,
                    model_name=model,
                    api_key=key,
                    goal=goal or "",           # goal optional
                    techniques=[technique] if technique else [],
                ),
                daemon=True,
            )
            worker.start()

            # lock inputs, enable Stop
            yield (
                gr.update(interactive=False),  # provider
                gr.update(interactive=False),  # model
                gr.update(interactive=False),  # key
                gr.update(),                   # key_msg
                gr.update(interactive=False),  # goal
                gr.update(interactive=False),  # run
                gr.update(interactive=True),   # stop
                gr.update(value=0),            # progress
                "Best Score: 0 | Status: In Progress",  # status
                "", "",                         # best prompt/resp
                "Starting…",                    # logs
            )

            # stream updates
            while True:
                snap = adv_state.snapshot()
                status = f"Best Score: {snap['best_score']:.2f} | Status: {snap['status']}"
                prog = int(round((snap["progress"] or 0.0) * 100))
                logs = "\n".join(snap["logs"]) if snap["logs"] else "No logs yet."
                best_p = snap.get("best_prompt", "")
                best_r = snap.get("best_response", "")
                yield (
                    gr.update(), gr.update(), gr.update(), gr.update(),
                    gr.update(), gr.update(interactive=False), gr.update(interactive=True),
                    gr.update(value=prog), status, best_p, best_r, logs
                )
                if not snap["running"]:
                    break
                time.sleep(0.4)

            # unlock inputs and finalize
            final = adv_state.snapshot()
            status = f"Best Score: {final['best_score']:.2f} | Status: {final['status']}"
            prog = int(round((final["progress"] or (1.0 if final["status"] == "Completed" else 0.0)) * 100))
            logs = "\n".join(final["logs"]) if final["logs"] else "No logs yet."
            best_p = final.get("best_prompt", "")
            best_r = final.get("best_response", "")
            yield (
                gr.update(interactive=True),
                gr.update(interactive=True),
                gr.update(interactive=True),
                gr.update(),                   # key_msg
                gr.update(interactive=True),   # goal
                gr.update(interactive=True),   # Run
                gr.update(interactive=False),  # Stop
                gr.update(value=prog),
                status,
                best_p,
                best_r,
                logs,
            )

        adv_run_btn.click(
            _adv_on_run,
            inputs=[adv_provider, adv_model, adv_key, adv_goal, adv_technique],
            outputs=[
                adv_provider, adv_model, adv_key, adv_key_msg,
                adv_goal, adv_run_btn, adv_stop_btn,
                adv_progress, adv_status_md, adv_best_prompt, adv_best_response, adv_logs
            ],
            show_progress=True,
        )

        # Stop button (cooperative)
        def _adv_stop():
            adv_state.set(stop_flag=True)
            return gr.update(interactive=True), gr.update(interactive=False)

        adv_stop_btn.click(_adv_stop, inputs=[], outputs=[adv_run_btn, adv_stop_btn])

        # Auto-scroll logs to bottom
        gr.HTML(
            """
            <script>
              (function(){
                const wrap = document.getElementById('adv-logs');
                const start = () => {
                  const ta = wrap?.querySelector('textarea');
                  if (!ta) { setTimeout(start, 300); return; }
                  let last = ta.value.length;
                  setInterval(()=>{
                    if (ta.value.length !== last) {
                      last = ta.value.length;
                      ta.scrollTop = ta.scrollHeight;
                    }
                  }, 400);
                };
                start();
              })();
            </script>
            """
        )

    # --------------------- [3] Simple Jailbreaks ---------------------
    with gr.Tab("[3] Simple Jailbreaks"):
        gr.Markdown("## Input Prompt")
        sj_input = gr.Textbox(lines=8, placeholder="Paste or write the base prompt here…", elem_id="sj-input")

        gr.Markdown("## Goal (optional)")
        sj_goal = gr.Textbox(placeholder="Describe the goal to subtly influence the transformation (optional).", lines=2)

        gr.Markdown("## Select Technique")
        # Single-choice now
        sj_technique = gr.Radio(choices=["Base64", "Cipher"], label="Choose one technique.")

        sj_generate = gr.Button("Generate", variant="primary", interactive=False, elem_id="sj-generate")

        gr.Markdown("## Output Prompt")
        sj_output = gr.Textbox(lines=10, interactive=False, show_copy_button=True)

        def _sj_can_generate(inp, tech):
            return gr.update(interactive=bool(inp and tech))

        sj_input.change(_sj_can_generate, inputs=[sj_input, sj_technique], outputs=[sj_generate])
        sj_technique.change(_sj_can_generate, inputs=[sj_input, sj_technique], outputs=[sj_generate])

        def _sj_generate(inp, goal, tech, progress=gr.Progress(track_tqdm=False)):
            progress(0, desc="Working…")
            time.sleep(0.05)
            prompt = inp if not goal else f"{goal}\n\n{inp}"
            out = _simple_transform(prompt, [tech] if tech else [])
            progress(100)
            return out

        sj_generate.click(_sj_generate, inputs=[sj_input, sj_goal, sj_technique], outputs=[sj_output], show_progress=True)

        # Keyboard shortcut: Ctrl/Cmd+Enter triggers Generate
        gr.HTML(
            """
            <script>
              (function(){
                const wrap = document.getElementById('sj-input');
                const btnWrap = document.getElementById('sj-generate');
                const hook = () => {
                  const ta = wrap?.querySelector('textarea');
                  const btn = btnWrap?.querySelector('button');
                  if (!ta || !btn) { setTimeout(hook, 300); return; }
                  ta.addEventListener('keydown', (e)=>{
                    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                      e.preventDefault();
                      btn.click();
                    }
                  });
                };
                hook();
              })();
            </script>
            """
        )

    # --------------------- How it Works? ---------------------
    with gr.Tab("How it Works?"):
        gr.Markdown(
            """
            ## How to Use This App

            **Step 1:** Generate a prompt by going to the **Generate Prompt** tab.

            **Step 2:** Optionally, provide a **goal** to refine the prompt.

            **Step 3:** Copy the generated prompt and try it on an LLM of your choice.

            **Step 4:** Copy the response generated by the LLM, go to the **Evaluate Text** tab.

            **Step 5:** Paste the LLM's response into the input box and hit **Evaluate Text**.

            **Step 6:** Review whether the response is classified as **SAFE** or **UNSAFE**.

            **Step 7:** For AI security analysis, go to the **Threat Modelling** tab and input an AI agent description.

            **Optional:** Use your own Detoxio API Key by going to **Advanced Settings** and entering your key.
            """
        )


# -----------------------------------------------------------------------------
# Launch
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    demo.queue(default_concurrency_limit=CONCURRENCY_LIMIT)
    demo.launch(
        server_name="0.0.0.0",
        server_port=int(os.getenv("SERVER_PORT", 7860)),
        show_error=True,
        show_api=False,
    )
