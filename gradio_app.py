from __future__ import annotations

import base64
import logging
import os
import time
from pathlib import Path
from typing import List, Tuple

import gradio as gr
from dotenv import load_dotenv

from hacktor_app.hacktor import HacktorClient
from hacktor_app.threat_model.openai_analysis import AppRiskAnalysis


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
_adv_should_stop = False  # stop flag for Advance Jailbreaks

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
def _adv_validate(provider: str, model_name: str, api_key: str, techniques: List[str]) -> bool:
    return bool(provider and model_name and api_key and techniques)


def _mask_key(k: str) -> str:
    if not k:
        return ""
    if len(k) <= 6:
        return "*" * len(k)
    return f"{k[:3]}***{k[-3:]}"


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


def _run_advance_job(provider: str, model_name: str, api_key: str, goal: str, techniques: List[str]):
    """
    Simulate a multi-step run, using HacktorClient.generate when a technique
    matches one of its modules. Yields:
      (status_text, progress_value(0-100), best_score, logs_text)
    """
    global _adv_should_stop
    _adv_should_stop = False

    logs: List[str] = []
    best_score = 0
    total_steps = max(6, 2 + len(techniques) * 2)
    step = 0

    logs.append(f"Target: {provider} | Model: {model_name} | Key: {_mask_key(api_key)}")
    yield f"Best Score: {best_score} | Status: In Progress", 3, best_score, "\n".join(logs)

    for tech in techniques:
        if _adv_should_stop:
            yield f"Best Score: {best_score} | Status: Stopped", (step * 100) // total_steps, best_score, "\n".join(logs)
            return

        step += 1
        logs.append(f"[{tech}] Preparing attack…")
        yield f"Best Score: {best_score} | Status: In Progress", (step * 100) // total_steps, best_score, "\n".join(logs)
        time.sleep(0.15)

        try:
            if hasattr(HacktorClient, "ATTACK_MODULES_MAP") and tech in HacktorClient.ATTACK_MODULES_MAP:
                prompt, used = client.generate(tech, goal=goal or "")
                sample = (prompt or "")[:140].replace("\n", " ")
                logs.append(f"[{tech}] Prompt generated via HacktorClient: {sample}…")
                best_score = max(best_score, min(10, max(1, len(prompt) // 160)))
            else:
                logs.append(f"[{tech}] (No built-in module) – step recorded.")
                best_score = max(best_score, 1)
        except Exception as e:
            logs.append(f"[{tech}] Error: {e!r}")
            yield f"Best Score: {best_score} | Status: Error", (step * 100) // total_steps, best_score, "\n".join(logs)
            return

        step += 1
        yield f"Best Score: {best_score} | Status: In Progress", (step * 100) // total_steps, best_score, "\n".join(logs)
        time.sleep(0.15)

    while step < total_steps:
        if _adv_should_stop:
            yield f"Best Score: {best_score} | Status: Stopped", (step * 100) // total_steps, best_score, "\n".join(logs)
            return
        step += 1
        yield f"Best Score: {best_score} | Status: In Progress", (step * 100) // total_steps, best_score, "\n".join(logs)
        time.sleep(0.08)

    yield f"Best Score: {best_score} | Status: Completed", 100, best_score, "\n".join(logs)


# -----------------------------------------------------------------------------
# UI
# -----------------------------------------------------------------------------
my_theme = gr.Theme.from_hub("Taithrah/Minimal")

with gr.Blocks(theme=my_theme, title=app_title) as demo:
    # --------------------- Generate Prompt ---------------------
    with gr.Tab("Generate Prompt"):
        gr.Markdown("## Generate a Text Prompt")
        attack_module = gr.Dropdown(
            label="Offensive Prompt Dataset",
            choices=[""] + list(HacktorClient.ATTACK_MODULES_MAP.keys()),
            value="",
            info="Select an attack module to generate a prompt.",
        )
        goal_input = gr.Textbox(label="Goal (Optional)", placeholder="Enter a goal to refine the prompt.")
        generate_btn = gr.Button("Generate Prompt", scale=0)
        generated_prompt = gr.Textbox(label="Generated Prompt", lines=5, interactive=False, show_copy_button=True)
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
        response = gr.Textbox(label="Enter Response for Evaluation", lines=5)
        evaluate_btn = gr.Button("Evaluate Text", scale=0)
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
        )
        generate_threat_btn = gr.Button("Generate Threat Model", scale=0)

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
            choices=["OpenAI", "Anthropic", "Groq", "Custom"],
            value="OpenAI",
            info="Choose the target provider.",
        )
        adv_model = gr.Textbox(label="Model Name", placeholder="e.g., gpt-4o-mini")
        adv_key = gr.Textbox(label="API Key", placeholder="Enter an API key", type="password")
        adv_goal = gr.Textbox(label="Goal (optional)", placeholder="What are you trying to achieve?")

        gr.Markdown("## Select Techniques")
        adv_techniques = gr.CheckboxGroup(choices=["TAP", "PAIR"], label="Choose one or more techniques.")

        gr.Markdown("## Controls")
        adv_run_btn = gr.Button("Run", variant="primary", interactive=False)
        adv_stop_btn = gr.Button("Stop", variant="secondary", interactive=False)

        gr.Markdown("## Progress")
        adv_readout = gr.Markdown("No run yet.")
        adv_progress = gr.Slider(label="Progress", minimum=0, maximum=100, value=0, step=1, interactive=False)

        gr.Markdown("## Progress Logs")
        adv_logs = gr.Textbox(value="No logs yet.", lines=12, show_copy_button=True, interactive=False, elem_id="adv-logs")

        # Enable Run when form is valid
        def _adv_can_run(provider, model, key, techs):
            return gr.update(interactive=_adv_validate(provider, model, key, techs))

        for c in (adv_provider, adv_model, adv_key, adv_techniques):
            c.change(_adv_can_run, inputs=[adv_provider, adv_model, adv_key, adv_techniques], outputs=[adv_run_btn])

        # Run button (stream updates)
        def _adv_on_run(provider, model, key, goal, techs):
            # lock inputs, enable Stop
            yield (
                gr.update(interactive=False),
                gr.update(interactive=False),
                gr.update(interactive=False),
                gr.update(interactive=False),
                gr.update(interactive=False),  # Run
                gr.update(interactive=True),   # Stop
                "Best Score: 0 | Status: In Progress",
                gr.update(value=0),
                "Starting…",
            )
            for status, prog, best, logs in _run_advance_job(provider, model, key, goal, techs):
                yield (
                    gr.update(), gr.update(), gr.update(), gr.update(),
                    gr.update(interactive=False),
                    gr.update(interactive=True),
                    status,
                    gr.update(value=prog),
                    logs or "No logs yet.",
                )
            # unlock inputs and reset Stop
            yield (
                gr.update(interactive=True),
                gr.update(interactive=True),
                gr.update(interactive=True),
                gr.update(interactive=True),
                gr.update(interactive=True),
                gr.update(interactive=False),
                status,
                gr.update(value=100),
                logs or "No logs yet.",
            )

        adv_run_btn.click(
            _adv_on_run,
            inputs=[adv_provider, adv_model, adv_key, adv_goal, adv_techniques],
            outputs=[adv_provider, adv_model, adv_key, adv_goal, adv_run_btn, adv_stop_btn, adv_readout, adv_progress, adv_logs],
            show_progress=True,
        )

        # Stop button
        def _adv_stop():
            global _adv_should_stop
            _adv_should_stop = True
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
        sj_goal = gr.Textbox(placeholder="Describe the goal to subtly influence the transformation (optional).")

        gr.Markdown("## Select Techniques")
        sj_techniques = gr.CheckboxGroup(choices=["Base64", "Cipher"], label="Choose one or more techniques.")

        sj_generate = gr.Button("Generate", variant="primary", interactive=False, elem_id="sj-generate")

        gr.Markdown("## Output Prompt")
        sj_output = gr.Textbox(lines=10, interactive=False, show_copy_button=True)

        def _sj_can_generate(inp, techs):
            return gr.update(interactive=bool(inp and techs))

        sj_input.change(_sj_can_generate, inputs=[sj_input, sj_techniques], outputs=[sj_generate])
        sj_techniques.change(_sj_can_generate, inputs=[sj_input, sj_techniques], outputs=[sj_generate])

        def _sj_generate(inp, goal, techs, progress=gr.Progress(track_tqdm=False)):
            progress(0, desc="Working…")
            time.sleep(0.05)
            prompt = inp if not goal else f"{goal}\n\n{inp}"
            out = _simple_transform(prompt, techs)
            progress(100)
            return out

        sj_generate.click(_sj_generate, inputs=[sj_input, sj_goal, sj_techniques], outputs=[sj_output], show_progress=True)

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
        # prevent_thread_lock defaults to False (blocking run, suitable for production)
    )
