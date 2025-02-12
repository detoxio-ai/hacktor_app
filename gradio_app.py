import gradio as gr
from dotenv import load_dotenv
from hacktor_app.hacktor import HacktorClient
from hacktor_app.threat_model.openai_analysis import AppRiskAnalysis, AnalysisResult
import os
import logging

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

# Constants
MAX_USER_CLICK = 10
click_count = 0  # Track user actions
last_prompt = "NA"  # Keep track of the last generated prompt
technique_used = ""

# Load API keys
default_api_key = os.getenv("DETOXIO_API_KEY", "")
dtx_hostname = os.getenv("DETOXIO_API_HOST", "api.detoxio.ai")

prompt_conversion_dump_path = os.getenv("PROMPT_CONVERSATION_DUMP_PATH", "")
threat_model_dump_path = os.getenv("THREAT_MODEL_DUMP_PATH", "")

if not default_api_key:
    raise ValueError("Missing Detoxio API Key")

app_title = os.getenv("TITLE", "AI Red Teaming Companion")
custom_api_key = None  # User-provided API key

# Initialize Hacktor Client
client = HacktorClient(default_api_key, dtx_hostname, dump_file=prompt_conversion_dump_path)

# Initialize AppRiskAnalysis
risk_analyzer = AppRiskAnalysis(model="gpt-4o", temperature=0.2, dump_file=threat_model_dump_path)


# ------------------------
# Function Definitions
# ------------------------

def set_api_key(api_key):
    """Set the custom API key from user input."""
    global client, custom_api_key
    custom_api_key = api_key.strip() if api_key else None
    client = HacktorClient(custom_api_key or default_api_key)
    return "Custom Key in Use" if custom_api_key else "System Default Key in Use"


def generate_prompt(attack_module, goal):
    """Generate a prompt based on the selected attack module and user goal."""
    global click_count, last_prompt, technique_used
    click_count += 1
    last_prompt, technique_used = client.generate(attack_module, goal=goal)
    return last_prompt, technique_used


def evaluate_text(prompt, response):
    """Evaluate the response based on the last generated prompt."""
    global click_count
    click_count += 1
    if not prompt:
        return {"Error": "No prompt provided for evaluation."}
    return client.evaluate(prompt, response)


def generate_threat_model(agent_description):
    """Analyze the AI agent and return an AppRiskProfile in a formatted table."""
    global click_count
    click_count += 1
    analysis_result = risk_analyzer.analyze(agent_description)

    # Extract application info
    app_name = analysis_result.profile.app.name
    app_capabilities = "\n".join(f"- {cap}" for cap in analysis_result.profile.app.capabilities)

    # Format risk details into a table
    risks_table = [
        [risk.risk, risk.risk_score, risk.threat_level, risk.rationale, "\n".join(f"- {strategy}" for strategy in risk.attack_strategies)]
        for risk in analysis_result.profile.risks
    ]
    
    return app_name, app_capabilities, analysis_result.think, risks_table


# ------------------------
# Gradio Interface
# ------------------------

with gr.Blocks(theme=gr.themes.Ocean()) as demo:
    # Title Section
    gr.HTML(
        f"""
        <h1 style="text-align: center; background: -webkit-linear-gradient(#ff7f50, #1e90ff, #32cd32); -webkit-background-clip: text; color: transparent; font-size: 3.5em;">
            {app_title}
        </h1>
        <div style="font-size: small; color: gray; text-align: center;">
            Try Command Line Tool: <a href="https://github.com/detoxio-ai/hacktor" target="_blank">https://github.com/detoxio-ai/hacktor</a>
        </div>
        """
    )

    with gr.Tab("Generate Prompt"):
        gr.Markdown("## Generate a Text Prompt")
        attack_module = gr.Dropdown(
            label="Attack Module",
            choices=[""] + list(HacktorClient.ATTACK_MODULES_MAP.keys()),
            value="",
            info="Select an attack module to generate a prompt."
        )
        goal_input = gr.Textbox(label="Goal (Optional)", placeholder="Enter a goal to refine the prompt.")
        generate_btn = gr.Button("Generate Prompt", scale=0)
        generated_prompt = gr.Textbox(label="Generated Prompt", lines=5, interactive=False, show_copy_button=True)
        with gr.Accordion("Techniques Used", open=False):
            technique_display = gr.Markdown(visible=True)

        # Generate button interaction
        generate_btn.click(
            fn=generate_prompt,
            inputs=[attack_module, goal_input],
            outputs=[generated_prompt, technique_display]
        )

    with gr.Tab("Evaluate Text"):
        gr.Markdown("## Evaluate Your Text")
        response = gr.Textbox(label="Enter Response for Evaluation", lines=5)
        evaluate_btn = gr.Button("Evaluate Text", scale=0)
        evaluation_result = gr.JSON(label="Evaluation Results")

        # Evaluate button interaction
        evaluate_btn.click(
            fn=evaluate_text,
            inputs=[generated_prompt, response],
            outputs=[evaluation_result]
        )

    with gr.Tab("Threat Modelling"):
        gr.Markdown("## Threat Modelling for AI Agents")
        agent_description = gr.Textbox(
            label="Provide Agent Description",
            placeholder="Describe the AI agent: name, functionality, purpose..."
        )
        

        generate_threat_btn = gr.Button("Generate Threat Model", scale=0)

        # Display AI App Info
        gr.Markdown("#### AI Agent Information")
        app_name_display = gr.Markdown("Nothing Yet", label="AI App Name")
        gr.Markdown("#### Capabilities")
        app_capabilities_display = gr.Markdown("Nothing Yet", label="Capabilities")

    
        # Display Thought Process
        gr.Markdown("#### Analysis Summary")
        think_result = gr.Markdown("Nothing Yet", label="Security Analyst's Thought Process")

        gr.Markdown("#### Threat Model") 
        # Display Threat Model Table
        threat_table = gr.Dataframe(
            headers=["Risk", "Risk Score", "Threat Level", "Rationale", "Attack Strategies"],
            interactive=False, show_copy_button=True
        )

        # Generate Threat Model interaction
        generate_threat_btn.click(
            fn=generate_threat_model,
            inputs=[agent_description],
            outputs=[app_name_display, app_capabilities_display, think_result, threat_table],
            show_progress=True
        )


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

    # Footer Section
    gr.HTML(
        """
        <hr>
        <div style="text-align: center; font-size: 14px;">
            Powered by <a href="https://detoxio.ai" target="_blank" style="color: #007BFF;">Detoxio AI</a>
        </div>
        <div style="text-align: center; font-size: 12px;">
            Send us feedback at hello@detoxio.ai
        </div>
        """
    )

# Launch the app
if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=int(os.getenv("SERVER_PORT", 7860)))
