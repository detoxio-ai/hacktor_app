import streamlit as st
from dotenv import load_dotenv
from hacktor_app.hacktor import HacktorClient
import os
import logging

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

MAX_USER_CLICK=10


# Streamlit App
st.set_page_config(layout="wide", initial_sidebar_state="collapsed")

# Colorful Title
st.markdown(
    """
    <h1 style="text-align: center; background: -webkit-linear-gradient(#ff7f50, #1e90ff, #32cd32); -webkit-background-clip: text; color: transparent; font-size: 3.5em;">
        Detoxio AI Demo
    </h1>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div style="font-size: small; color: gray; text-align: center;">
        Try Hacktor Tool: <a href="https://github.com/detoxio-ai/hacktor" target="_blank">https://github.com/detoxio-ai/hacktor</a>
    </div>
    """,
    unsafe_allow_html=True,
)


# Sidebar for optional DETOXIO_API_KEY
with st.sidebar:
    st.title("Settings")
    detoxio_api_key_input = st.text_input(
        "DETOXIO_API_KEY (Optional)",
        value="",
        type="password",
    )
    st.markdown(
        """
        <div style="font-size: small; color: gray;">
            Apply for the API Key: <a href="https://detoxio.ai/contact_us" target="_blank">https://detoxio.ai/contact_us</a>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Determine DETOXIO_API_KEY
detoxio_api_key = detoxio_api_key_input if detoxio_api_key_input else os.getenv("DETOXIO_API_KEY", "")

if detoxio_api_key:
    st.sidebar.warning("Using System DETOXIO_API_KEY Key, with default Restrictions")

# Initialize Hacktor Client
client = HacktorClient(detoxio_api_key)

# Initialize session state variables
if "generated_prompt" not in st.session_state:
    st.session_state.generated_prompt = ""
if "attack_module" not in st.session_state:
    st.session_state.attack_module = "JAILBREAK-BENCH"
if "threat_class" not in st.session_state:
    st.session_state.threat_class = "Toxicity"
if "click_count" not in st.session_state:
    st.session_state.click_count = 0  # Track number of clicks

# Restrict to 10 clicks
if st.session_state.click_count >= MAX_USER_CLICK:
    st.error("You have reached the maximum number of actions. Please refresh the page.")
    st.stop()

# Main app layout
col1, col2 = st.columns(2)

# Left section: Generate Prompt
with col1:
    st.subheader("Generate a Text Prompt")

    # Generate button
    generate_clicked = st.button("Generate Prompt", key="generate_button")

    if generate_clicked:
        st.session_state.click_count += 1
        st.session_state.generated_prompt = client.generate(st.session_state.attack_module)

    # Display the generated prompt in a long text area
    generated_prompt = st.text_area(
        "Generated Prompt",
        value=st.session_state.generated_prompt,
        height=200,
    )

    # Collapsible Advanced Options
    with st.expander("Advanced Options", expanded=False):
        st.session_state.attack_module = st.selectbox(
            "Attack Module",
            list(HacktorClient.ATTACK_MODULES_MAP.keys()),
            index=list(HacktorClient.ATTACK_MODULES_MAP.keys()).index(st.session_state.attack_module),
        )
        st.session_state.threat_class = st.selectbox(
            "Threat Class",
            ["Toxicity", "Misuse"],
            index=["Toxicity", "Misuse"].index(st.session_state.threat_class),
        )

# Right section: Evaluate Text
with col2:
    st.subheader("Evaluate Your Text")
    text_to_evaluate = st.text_area("Enter text for evaluation:")

    if st.button("Evaluate Text", key="evaluate_button"):
        st.session_state.click_count += 1
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
    unsafe_allow_html=True,
)
