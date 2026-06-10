
# app.py
import streamlit as st
from sample_logs import SAMPLE_LOGS
def format_response(response_text):
    """
    Scan the response for threat level keywords and
    prepend a coloured badge so it is easy to read at a glance.
    """
    text_lower = response_text.lower()

    if "threat level: critical" in text_lower:
        badge = "🔴 **CRITICAL THREAT**"
    elif "threat level: high" in text_lower:
        badge = "🟠 **HIGH THREAT**"
    elif "threat level: medium" in text_lower:
        badge = "🟡 **MEDIUM THREAT**"
    elif "threat level: low" in text_lower:
        badge = "🟢 **LOW THREAT**"
    elif "threat level: none" in text_lower:
        badge = "✅ **NO THREAT**"
    else:
        badge = "🔵 **ANALYSIS COMPLETE**"

    return f"{badge}\n\n---\n\n{response_text}"

# --- Page configuration ---
st.set_page_config(
    page_title="Security Log Analyst",
    page_icon="🔐",
    layout="wide",
)

# --- Header ---
st.title("🔐 Security Log Analyst")
st.caption("Powered by Ollama · Local LLM · No data leaves your machine")

# --- Sidebar ---
with st.sidebar:
    st.header("⚙️ Settings")

    model_name = st.selectbox(
        "Ollama model",
        ["llama3.2", "mistral", "llama3"],
        help="Must be pulled in Ollama first"
    )

    temperature = st.slider(
        "Temperature",
        min_value=0.0,
        max_value=1.0,
        value=0.3,
        step=0.1,
        help="Lower = more consistent. Higher = more creative."
    )

    st.divider()
    st.header("📋 Load sample log")
    selected_sample = st.selectbox("Choose a sample", list(SAMPLE_LOGS.keys()))

    if st.button("Load sample", use_container_width=True):
        if SAMPLE_LOGS[selected_sample]:
            st.session_state["prefill"] = SAMPLE_LOGS[selected_sample]

    st.divider()
    if st.button("🗑️ Clear conversation", use_container_width=True):
        st.session_state["messages"] = []
        st.rerun()

    st.divider()
    st.markdown("**About this app**")
    st.markdown(
        "Paste a network connection log or describe "
        "suspicious activity. The AI analyst will assess "
        "the threat level and recommend next steps."
    )

# --- Initialise session state ---
if "messages" not in st.session_state:
    st.session_state["messages"] = []

# --- Display conversation history ---
for msg in st.session_state["messages"]:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# --- Placeholder for chat input (we add LLM logic tomorrow) ---
# --- Chat input ---
# Check if a sample was loaded from the sidebar
prefill_value = st.session_state.pop("prefill", "")

user_input = st.chat_input(
    "Paste a network log or ask a security question...",
)

# If a sample was loaded, use it as the input automatically
if prefill_value and not user_input:
    user_input = prefill_value

# --- Process input and get LLM response ---
if user_input:
    # Show user message immediately
    with st.chat_message("user"):
        st.markdown(user_input)

    # Add to history
    st.session_state["messages"].append({
        "role": "user",
        "content": user_input
    })

    # Build messages for Ollama
    from prompts import build_messages
    messages = build_messages(
        st.session_state["messages"][:-1],  # history without current message
        user_input
    )

    # Call Ollama and stream the response
    import ollama

    with st.chat_message("assistant"):
        response_placeholder = st.empty()
        full_response = ""

        try:
            stream = ollama.chat(
                model=model_name,
                messages=messages,
                options={"temperature": temperature},
                stream=True,
            )

            for chunk in stream:
                token = chunk["message"]["content"]
                full_response += token
                response_placeholder.markdown(full_response + "▌")

            # Final response without cursor
            response_placeholder.markdown(format_response(full_response))

        except Exception as e:
            full_response = f"⚠️ Error connecting to Ollama: {e}\n\nMake sure Ollama is running and the model '{model_name}' is pulled."
            response_placeholder.markdown(full_response)

    # Save assistant response to history
    st.session_state["messages"].append({
        "role": "assistant",
        "content": full_response
    })
    