# Application Workflow Diagram

## CAP 942 — Security Log Analyst Chatbot

---

## System flow

```
┌─────────────────────────────────────────────────────┐
│                    USER                             │
│  Pastes network log or types security question      │
└────────────────────┬────────────────────────────────┘
                     │ user_input (text)
                     ▼
┌─────────────────────────────────────────────────────┐
│              STREAMLIT UI (app.py)                  │
│  - Chat input box                                   │
│  - Sample log loader (sidebar)                      │
│  - Model selector (sidebar)                         │
│  - Conversation history display                     │
│  - Streaming response display                       │
└────────────────────┬────────────────────────────────┘
                     │ messages list
                     ▼
┌─────────────────────────────────────────────────────┐
│           PROMPT BUILDER (prompts.py)               │
│  Combines:                                          │
│    1. System prompt (security analyst persona)      │
│    2. Conversation history (multi-turn memory)      │
│    3. New user message                              │
└────────────────────┬────────────────────────────────┘
                     │ structured messages []
                     ▼
┌─────────────────────────────────────────────────────┐
│            OLLAMA (local LLM runner)                │
│  Model: Llama 3.2 (3B parameters)                  │
│  Running: locally on Windows 11                     │
│  No internet required                               │
│  No paid API                                        │
└────────────────────┬────────────────────────────────┘
                     │ streamed tokens
                     ▼
┌─────────────────────────────────────────────────────┐
│           RESPONSE FORMATTER (app.py)               │
│  - Adds threat level badge (🔴🟠🟡🟢✅)             │
│  - Streams tokens live to UI                        │
│  - Saves to conversation history                    │
└────────────────────┬────────────────────────────────┘
                     │ formatted analysis
                     ▼
┌─────────────────────────────────────────────────────┐
│                    USER                             │
│  Reads: Threat level + Explanation + Recommendation │
└─────────────────────────────────────────────────────┘
```

---

## Components

### app.py
Main application file. Handles UI layout, session state, user input,
Ollama API call, response streaming, and conversation history.

### prompts.py
Contains the system prompt that defines the LLM's persona as a
cybersecurity analyst. Also contains `build_messages()` which assembles
the full message list for each API call, including conversation history
for multi-turn memory.

### sample_logs.py
Pre-written test inputs covering normal traffic, port scans, DoS attacks,
and ambiguous cases. Used in the demo to show the app handling different
threat levels.

---

## Data flow

1. User types or pastes a network connection log into the chat input
2. Streamlit stores it in `st.session_state["messages"]`
3. `build_messages()` prepends the security analyst system prompt and
   appends the full conversation history for context
4. `ollama.chat()` sends the messages to the local Llama 3.2 model
5. The model streams tokens back one at a time
6. Each token is appended to the display in real time
7. When streaming completes, `format_response()` adds a threat badge
8. The complete response is saved to conversation history for next turn

---

## Tools and libraries

| Component | Tool | Version |
|---|---|---|
| LLM runner | Ollama | Latest |
| Language model | Llama 3.2 (3B) | Meta open-source |
| Web UI | Streamlit | Latest |
| LLM client | ollama (Python) | Latest |
| Language | Python | 3.11 |
| Package manager | uv | Latest |