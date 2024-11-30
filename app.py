import streamlit as st
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Function to generate a text prompt
def generate_prompt(attack_module, threat_class):
    return f"This is an AI-generated text prompt using Attack Module: {attack_module} and Threat Class: {threat_class}."

# Function to evaluate a given text
def evaluate_text(text):
    # Placeholder for evaluation logic
    evaluation_result = {
        "Length": len(text),
        "Word Count": len(text.split()),
        "Sentiment": "Neutral",  # Placeholder
        "Feedback": "Your text is well-structured."  # Placeholder
    }
    return evaluation_result

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
        value=os.getenv("DETOXIO_API_KEY", ""),  # Default to environment variable
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

if detoxio_api_key:
    st.sidebar.success("DETOXIO_API_KEY is set!")
else:
    st.sidebar.warning("DETOXIO_API_KEY is not set!")

# Initialize session state variables
if "generated_prompt" not in st.session_state:
    st.session_state.generated_prompt = ""
if "attack_module" not in st.session_state:
    st.session_state.attack_module = "jailbreak-bench"
if "threat_class" not in st.session_state:
    st.session_state.threat_class = "Toxicity"

# Custom button styles
button_styles = """
    <style>
        .blue-button button {
            background-color: #007BFF;
            color: white;
            font-weight: bold;
            border: none;
            padding: 0.5em 1em;
            margin: 0.5em 0;
            border-radius: 4px;
            cursor: pointer;
        }
        .blue-button button:hover {
            background-color: #0056b3;
        }
        .orange-button button {
            background-color: #FF5722;
            color: white;
            font-weight: bold;
            border: none;
            padding: 0.5em 1em;
            margin: 0.5em 0;
            border-radius: 4px;
            cursor: pointer;
        }
        .orange-button button:hover {
            background-color: #e64a19;
        }
    </style>
"""
st.markdown(button_styles, unsafe_allow_html=True)

# Main app layout
col1, col2 = st.columns(2)

# Left section: Generate Prompt
with col1:
    st.subheader("Generate a Text Prompt")
    
    # Generate button with blue styling
    generate_clicked = st.button("Generate Prompt", key="generate_button")
    
    if generate_clicked:
        st.session_state.generated_prompt = generate_prompt(
            st.session_state.attack_module,
            st.session_state.threat_class
        )
    
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
            ["jailbreak-bench", "advbench"], 
            index=["jailbreak-bench", "advbench"].index(st.session_state.attack_module)
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
    
    # Evaluate button with orange styling
    if st.button("Evaluate Text", key="evaluate_button"):
        if text_to_evaluate.strip():
            evaluation = evaluate_text(text_to_evaluate)
            st.write("Evaluation Results:")
            st.json(evaluation)
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
