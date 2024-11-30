import streamlit as st
import requests
import base64
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

import logging
logging.basicConfig(level=logging.DEBUG)

# Hacktor Client
class HacktorClient:
    THREAT_CLASS = {}

    THREAT_CATEGORY = {}

    ATTACK_MODULES_MAP = {
        "OWASP-LLM-APP": "DETOXIO.ATTACKIO",
        "LLM-RISKS": "DETOXIO",
        "JAILBREAK-BENCH": "DETOXIO.JAILBREAKBENCH",
        "ADVBENCH": "DETOXIO.ADVBENCH",
    }

    def __init__(self, api_key):
        self.api_key = api_key
        self.generate_url = "https://api.detoxio.ai/dtx.services.prompts.v1.PromptService/GeneratePrompts"
        self.evaluate_url = "https://api.detoxio.ai/dtx.services.prompts.v1.PromptService/EvaluateModelInteraction"

    def generate(self, attack_module, count=1):
        payload = {
            "count": str(count),
            "filter": {"labels": {}},
        }

        if attack_module:
            lineage = self.ATTACK_MODULES_MAP.get(attack_module, "DETOXIO").lower()
            payload["filter"]["labels"]["lineage"] = lineage

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        try:
            response = requests.post(self.generate_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

            if "prompts" in data and len(data["prompts"]) > 0:
                prompt_data = data["prompts"][0]
                prompt_content = prompt_data["data"]["content"]

                # Decode if base64 encoded
                if "_prompt_encoding" in prompt_data.get("sourceLabels", {}) and prompt_data["sourceLabels"]["_prompt_encoding"] == "base64":
                    prompt_content = base64.b64decode(prompt_content).decode("utf-8")

                return prompt_content
            else:
                return "No prompt generated."
        except requests.exceptions.RequestException as e:
            logging.error(f"Error generating prompt: {e}")
            return f"Error generating prompt: {e}"

    def evaluate(self, prompt, response):
        payload = {
            "prompt": {"data": {"content": prompt if prompt else ""}},
            "responses": [{"message": {"content": response}}],
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        try:
            response = requests.post(self.evaluate_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

            # Parse response for any "UNSAFE" threat evaluation statuses
            results = data.get("responses", [])[0].get("results", [])
            unsafe_findings = []

            for result in results:
                threat_class = result["threat"]["threatClass"]
                threat_category = result["threat"]["threatCategory"]
                status = result["status"]
                if "UNSAFE" in status:
                    unsafe_findings.append(
                        {
                            "threatClass": threat_class,
                            "threatCategory": threat_category,
                            "status": status,
                        }
                    )

            if unsafe_findings:
                return {
                    "evaluation": "UNSAFE",
                    "details": unsafe_findings,
                }
            else:
                return {
                    "evaluation": "SAFE",
                    "details": results,
                }

        except requests.exceptions.RequestException as e:
            logging.error(f"Error evaluating interaction: {e}")
            return {"error": f"Error evaluating interaction: {e}"}



# Streamlit App
st.set_page_config(layout="wide", initial_sidebar_state="collapsed")
st.title("Hacktor App")
st.markdown(
    """
    <div style="font-size: small; color: gray;">
        Try Hacktor: <a href="https://github.com/detoxio-ai/hacktor" target="_blank">https://github.com/detoxio-ai/hacktor</a>
    </div>
    """,
    unsafe_allow_html=True
)

# Sidebar for optional DETOXIO_API_KEY
with st.sidebar:
    st.title("Settings")
    detoxio_api_key_input = st.text_input(
        "DETOXIO_API_KEY (Optional)", 
        value="",  # Default to environment variable
        type="password"
    )
    st.markdown(
        """
        <div style="font-size: small; color: gray;">
            Apply for the API Key: <a href="https://detoxio.ai/contact_us" target="_blank">https://detoxio.ai/contact_us</a>
        </div>
        """,
        unsafe_allow_html=True
    )

# Determine DETOXIO_API_KEY
detoxio_api_key = detoxio_api_key_input if detoxio_api_key_input else os.getenv("DETOXIO_API_KEY", "")


# Initialize Hacktor Client
client = HacktorClient(detoxio_api_key)

# Initialize session state variables
if "generated_prompt" not in st.session_state:
    st.session_state.generated_prompt = ""
if "attack_module" not in st.session_state:
    st.session_state.attack_module = "JAILBREAK-BENCH"
if "threat_class" not in st.session_state:
    st.session_state.threat_class = "Toxicity"

# Main app layout
col1, col2 = st.columns(2)

# Left section: Generate Prompt
with col1:
    st.subheader("Generate a Text Prompt")
    
    # Generate button
    generate_clicked = st.button("Generate Prompt", key="generate_button")
    
    if generate_clicked:
        st.session_state.generated_prompt = client.generate(st.session_state.attack_module)
    
    # Display the generated prompt in a long text area
    generated_prompt = st.text_area(
        "Generated Prompt",
        value=st.session_state.generated_prompt,
        height=200
    )
    
    # Collapsible Advanced Options
    with st.expander("Advanced Options", expanded=False):
        st.session_state.attack_module = st.selectbox(
            "Attack Module", 
            list(HacktorClient.ATTACK_MODULES_MAP.keys()), 
            index=None,
        )
        st.session_state.threat_class = st.selectbox(
            "Threat Class", 
            ["Toxicity", "Misuse"], 
            index=["Toxicity", "Misuse"].index(st.session_state.threat_class)
        )

# Right section: Evaluate Text
with col2:
    st.subheader("Evaluate Your Text")
    text_to_evaluate = st.text_area("Enter text for evaluation:")

    if st.button("Evaluate Text", key="evaluate_button"):
        if text_to_evaluate.strip():
            last_prompt = st.session_state.generated_prompt if st.session_state.generated_prompt else ""
            evaluation_result = client.evaluate(last_prompt, text_to_evaluate)
            st.write("Evaluation Results:")
            st.json(evaluation_result)
        else:
            st.warning("Please enter some text to evaluate.")


# Footer
st.markdown(
    """
    <hr>
    <div style="text-align: center; font-size: 14px;">
        Powered by <a href="https://detoxio.ai" target="_blank" style="color: #007BFF;">Detoxio AI</a>
    </div>
    """,
    unsafe_allow_html=True
)
