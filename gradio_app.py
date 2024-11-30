import gradio as gr
from dotenv import load_dotenv
from hacktor_app.hacktor import HacktorClient
import os
import logging

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

# Constants
MAX_USER_CLICK = 10
click_count = 0  # Track the number of user actions

# Determine DETOXIO_API_KEY
detoxio_api_key = os.getenv("DETOXIO_API_KEY", "")
if not detoxio_api_key:
    detoxio_api_key = "YOUR_DEFAULT_API_KEY"  # Replace with a default API key or user-provided key

# Initialize Hacktor Client
client = HacktorClient(detoxio_api_key)


# Functions
def generate_prompt(attack_module):
    """
    Generate a prompt based on the selected attack module.
    """
    global click_count
    if click_count >= MAX_USER_CLICK:
        return "Error: You have reached the maximum number of actions. Please refresh the session."
    click_count += 1
    return client.generate(attack_module)


def evaluate_text(prompt, response):
    """
    Evaluate the response based on the last generated prompt.
    """
    global click_count
    if click_count >= MAX_USER_CLICK:
        return {"Error": "You have reached the maximum number of actions. Please refresh the session."}
    click_count += 1
    return client.evaluate(prompt, response)


# Gradio App with Blocks
with gr.Blocks() as demo:
    # Title
    gr.HTML(
        """
        <h1 style="text-align: center; background: -webkit-linear-gradient(#ff7f50, #1e90ff, #32cd32); -webkit-background-clip: text; color: transparent; font-size: 3.5em;">
            Detoxio AI Demo
        </h1>
        <div style="font-size: small; color: gray; text-align: center;">
            Try Hacktor Tool: <a href="https://github.com/detoxio-ai/hacktor" target="_blank">https://github.com/detoxio-ai/hacktor</a>
        </div>
        """
    )

    # Tabs for Generate and Evaluate
    with gr.Tab("Generate Prompt"):
        gr.Markdown("## Generate a Text Prompt")
        attack_module = gr.Dropdown(
            label="Attack Module",
            choices=list(HacktorClient.ATTACK_MODULES_MAP.keys()),
            value="JAILBREAK-BENCH",
        )
        generate_btn = gr.Button("Generate Prompt")
        generated_prompt = gr.Textbox(label="Generated Prompt", lines=5)
        generate_btn.click(
            fn=generate_prompt,
            inputs=[attack_module],
            outputs=[generated_prompt],
        )

    with gr.Tab("Evaluate Text"):
        gr.Markdown("## Evaluate Your Text")
        last_prompt = gr.Textbox(label="Last Generated Prompt", lines=5)
        response = gr.Textbox(label="Enter Response for Evaluation", lines=5)
        evaluate_btn = gr.Button("Evaluate Text")
        evaluation_result = gr.JSON(label="Evaluation Results")
        evaluate_btn.click(
            fn=evaluate_text,
            inputs=[last_prompt, response],
            outputs=[evaluation_result],
        )

    # Footer
    gr.HTML(
        """
        <hr>
        <div style="text-align: center; font-size: 14px;">
            Powered by <a href="https://detoxio.ai" target="_blank" style="color: #007BFF;">Detoxio AI</a>
        </div>
        """
    )

# Launch the app
if __name__ == "__main__":
    demo.launch()
