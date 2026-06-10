# Security Log Analyst Chatbot

## What this app does

[Write 2–3 sentences in your own words describing what the app does]

## The problem it solves

Security teams receive thousands of alerts per day. Most tools give a
verdict (malicious / not malicious) but no explanation. Junior analysts
cannot act on a flag alone — they need to understand *why* something was
flagged before they can decide what to do.

This chatbot provides plain-English analysis of network connection logs,
connecting directly to the work of the Port Scanner Anomaly Detector project.

## How to run it

### Requirements
- Windows 11
- Python 3.11
- uv package manager
- Ollama installed and running

### Setup

```powershell
git clone https://github.com/MJoshi982/security-log-analyst
cd security-log-analyst
uv venv
.venv\Scripts\activate
uv sync
```

Pull the model:

```powershell
ollama pull llama3.2
```

Run the app:

```powershell
uv run streamlit run app.py
```

Open your browser to http://localhost:8501

## How to use it

1. Select a sample log from the sidebar dropdown
2. Click **Load sample**
3. Press Enter in the chat box
4. Read the threat analysis

Or type your own network log or security question directly.

## Tools used

| Tool | Purpose |
|---|---|
| Ollama | Run LLM locally (no internet required) |
| Llama 3.2 | Open-source language model |
| Streamlit | Web UI |
| Python 3.11 | Language |
| uv | Package manager |

## Workflow

User input → Streamlit UI → System prompt + history → Ollama (Llama 3.2)
→ Streamed response → Displayed with threat badge

## Project connection

This chatbot is the explanation layer for the Port Scanner Anomaly Detector.
The ML model flags connections. This LLM explains why they are suspicious.
Together they form a complete detection + explanation pipeline.

## Sample inputs included

- Port scan — suspicious (high RF confidence attack)
- Normal web traffic (cleared by both models)
- DoS attack pattern (critical threat)
- Ambiguous connection (needs human review)