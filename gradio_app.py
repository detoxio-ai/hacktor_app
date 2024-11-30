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
last_prompt = ""  # Keep track of the last generated prompt

# Determine DETOXIO_API_KEY
default_api_key = os.getenv("DETOXIO_API_KEY", "")
custom_api_key = None  # User-provided API key

# Initialize Hacktor Client
client = HacktorClient(default_api_key)


# Functions
def set_api_key(api_key):
    """
    Set the custom API key from user input in advanced settings.
    """
    global client, custom_api_key
    custom_api_key = api_key
    client = HacktorClient(custom_api_key or default_api_key)
    return f"{'Custom Key in Use' if custom_api_key else 'System Default Key in Use'}"


def generate_prompt(attack_module):
    """
    Generate a prompt based on the selected attack module.
    """
    global click_count, last_prompt
    if click_count >= MAX_USER_CLICK:
        return "Error: You have reached the maximum number of actions. Please refresh the session."
    click_count += 1
    last_prompt = client.generate(attack_module)
    return last_prompt


def evaluate_text(prompt, response):
    """
    Evaluate the response based on the last generated prompt.
    """
    global click_count
    if click_count >= MAX_USER_CLICK:
        return {"Error": "You have reached the maximum number of actions. Please refresh the session."}
    click_count += 1
    if not prompt:
        return {"Error": "No prompt provided for evaluation."}
    return client.evaluate(prompt, response)


# Gradio App with Blocks
with gr.Blocks(theme=gr.themes.Ocean()) as demo:
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
            choices=[""] + list(HacktorClient.ATTACK_MODULES_MAP.keys()),  # Default to empty
            value="",
            info="Select an attack module to generate a prompt.",
        )
        generate_btn = gr.Button("Generate Prompt", elem_classes=["small-button"])
        generated_prompt = gr.Textbox(label="Generated Prompt", lines=5, interactive=False)
        
        # Generate button interaction
        generate_btn.click(
            fn=generate_prompt,
            inputs=[attack_module],
            outputs=[generated_prompt],
        )

    with gr.Tab("Evaluate Text"):
        gr.Markdown("## Evaluate Your Text")
        response = gr.Textbox(label="Enter Response for Evaluation", lines=5, info="Enter the response you want to evaluate.")
        evaluate_btn = gr.Button("Evaluate Text", elem_classes=["small-button"])
        evaluation_result = gr.JSON(label="Evaluation Results")

        # Evaluate button interaction
        evaluate_btn.click(
            fn=evaluate_text,
            inputs=[generated_prompt, response],
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

    # Advanced Settings at the Bottom
    with gr.Accordion("Advanced Settings", open=False):
        gr.Markdown("### Add or Update DETOXIO_API_KEY")
        api_key_input = gr.Textbox(
            label="DETOXIO_API_KEY (Optional)",
            placeholder="Enter your DETOXIO_API_KEY here",
            type="password",
            info="Provide your DETOXIO_API_KEY for advanced features.",
        )
        update_api_key_btn = gr.Button("Update API Key", elem_classes=["small-button"])
        api_key_status = gr.Textbox(label="API Key Status", value="Using System Default Key", interactive=False)

        # API Key update interaction
        update_api_key_btn.click(
            fn=set_api_key,
            inputs=[api_key_input],
            outputs=[api_key_status]
        )

        gr.Markdown(
            """
            <div style="font-size: small; color: gray;">
                Apply for the API Key: <a href="https://detoxio.ai/contact_us" target="_blank">https://detoxio.ai/contact_us</a>
            </div>
            """
        )

    # Custom CSS for Button Sizing
    demo.css = """
    .small-button {
        width: 200px !important;
        padding: 8px 16px !important;
        font-size: 16px !important;
    }
    """

# Launch the app
if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=int(os.getenv("SERVER_PORT", 7860)))
