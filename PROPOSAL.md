# Project Proposal
## CAP 942 — Capstone Project: AI Application Development
**Project Title:** Security Log Analyst Chatbot
**Student Name:** [Your Full Name]
**Date:** [Today's Date]
**Course:** CAP 942

---

## 1. Problem Statement

Security Operations Centre (SOC) analysts are overwhelmed by alerts generated
by network intrusion detection systems every day. Most automated tools produce
a binary verdict — malicious or not malicious — with no explanation of why a
connection was flagged. This forces analysts, especially junior ones, to make
critical decisions without fully understanding the underlying threat.

The core problem has two parts. First, alert fatigue — at 1 million network
connections per day, even a 2% false positive rate generates 20,000 false
alarms that analysts must manually investigate. Second, the explainability
gap — when a machine learning model flags a connection, it does not tell the
analyst which specific features triggered the alert or what the analyst should
do next.

This project addresses the explainability gap by building an AI-powered
chatbot that analyses raw network connection logs and explains them in plain
English — giving analysts the context they need to act quickly and confidently.

---

## 2. Why This Project Matters

Port scanning is step zero of almost every cyberattack. Before an attacker
can exploit anything on a network, they first map which ports are open, which
services are running, and which versions are exposed. Detecting this
reconnaissance phase early is the difference between stopping an attack
before it starts and responding to a breach after the damage is done.

Traditional rule-based detection tools — such as flagging any connection
that scans more than 100 ports in 10 seconds — are well known to attackers,
who deliberately work around them. Machine learning-based detection learns
from patterns in real traffic and can catch slow, careful scans that rules
miss entirely. However, ML models still produce results that are difficult
for non-specialists to interpret.

This chatbot solves a real operational problem by bridging the gap between
automated detection and human understanding. A junior analyst who receives
a flagged connection log can paste it directly into the chatbot and receive
a structured, plain-English analysis within seconds — including the threat
level, an explanation of which values look suspicious, and a recommended
next action. This reduces investigation time, supports better decision-making,
and directly addresses the alert fatigue problem at scale.

The project is also directly connected to the Port Scanner Anomaly Detector
ML project, where Random Forest and Isolation Forest models were trained on
494,000 real network connections from the KDD Cup 1999 dataset. That project
demonstrated that false positive rate matters more than accuracy at production
scale. This chatbot is the explanation layer that makes those model outputs
actionable.

---

## 3. Tools and Frameworks Chosen

| Tool | Category | Reason for choosing |
|---|---|---|
| Ollama | LLM runner | Runs models locally on Windows 11 — no internet, no paid API required |
| Llama 3.2 (3B) | Language model | Fast performance on 16GB RAM, strong reasoning, fully open-source |
| Streamlit | Web UI framework | Beginner-friendly, zero frontend code needed, native chat support |
| ollama (Python library) | LLM client | Official Python client for Ollama, supports streaming responses |
| Python 3.11 | Programming language | Required by all libraries, industry standard for AI applications |
| uv | Package manager | Fast, modern dependency management for Python projects |
| Git + GitHub | Version control | Required for submission, enables collaboration and reproducibility |

All tools are free and open-source. No paid APIs are used at any point.
The entire application runs locally on the student's Windows 11 machine.

---

## 4. How the LLM Is Used

The application uses Llama 3.2, a 3-billion parameter open-source language
model from Meta, running locally through Ollama. The model is accessed via
the official Python `ollama` library using the `ollama.chat()` function.

The LLM is not trained or fine-tuned. It is used as a pre-trained model and
guided entirely through prompt engineering. The system prompt is the core of
the prompt engineering work — it instructs the model to behave as an expert
cybersecurity analyst and to always structure its response in three sections:

**Threat Assessment** — Is the connection suspicious? What is the threat level
(Critical / High / Medium / Low / None)? What type of attack does it represent?

**Explanation** — What specific values in the log look suspicious? Why do
these patterns indicate an attack or confirm normal traffic? This is written
in plain English so junior analysts can follow the reasoning.

**Recommendation** — What should the analyst do next? Should the connection
be blocked, monitored, or cleared? Are there any immediate actions required?

The model also maintains multi-turn conversation memory. Each message includes
the full conversation history so the analyst can ask follow-up questions about
the same log without repeating context. Responses are streamed token by token
so the user sees output immediately rather than waiting for the full response.

---

## 5. Expected Output and User Interaction

The application runs as a Streamlit web app at `http://localhost:8501`.

**User interaction flow:**

1. The user opens the app in their browser
2. The user either selects a pre-loaded sample log from the sidebar dropdown
   or pastes their own network connection log into the chat input box
3. The user sends the message
4. The app displays a coloured threat badge immediately as the response begins
   streaming (🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low / ✅ None)
5. The full structured analysis streams in real time — Threat Assessment,
   Explanation, and Recommendation
6. The user can ask follow-up questions in the same conversation window
7. The user can clear the conversation and start a new analysis at any time

**Sample output for a port scan log:**

```
🔴 CRITICAL THREAT

THREAT ASSESSMENT
- Suspicious: Yes
- Threat level: High
- Attack type: Port scan / reconnaissance

EXPLANATION
The connection shows several strong indicators of a port scan attack.
The src_bytes value of 0 means no data was sent from the source — typical
of a SYN scan where the attacker only sends connection requests without
completing the handshake. The same_srv_rate of 0.06 and diff_srv_rate of
0.06 indicate the source is connecting to many different services, which
is the signature pattern of a horizontal port sweep. The dst_host_count
of 255 confirms the scanner has been probing a large number of hosts.

RECOMMENDATION
Block the source IP immediately and investigate other connections from
the same address in the last 24 hours. Escalate to a senior analyst if
the scanning pattern continues after blocking.
```

---

## 6. Application Workflow

```
User pastes network log or types security question
                    ↓
           Streamlit UI (app.py)
     Chat input · Sidebar · Session state
                    ↓
         Prompt Builder (prompts.py)
   System prompt + conversation history + user input
                    ↓
      Ollama local server (llama3.2 model)
         Running on Windows 11 · No internet
                    ↓
        Response streamed token by token
                    ↓
       Response Formatter (app.py)
      Threat badge added · Saved to history
                    ↓
         Displayed to user in chat window
```

---

## 7. Project Files

| File | Purpose |
|---|---|
| `app.py` | Main Streamlit application — UI, Ollama call, streaming, session state |
| `prompts.py` | System prompt and message builder — core prompt engineering |
| `sample_logs.py` | Pre-written test logs for demo — port scan, normal, DoS, ambiguous |
| `README.md` | Installation and usage instructions |
| `DOCUMENTATION.md` | Final project documentation for submission |
| `docs/workflow_diagram.md` | Visual workflow diagram |

---

## 8. Scope and Limitations

**In scope for this MVP:**
- Analysing individual network connection logs pasted as text
- Answering general cybersecurity questions about port scanning and attacks
- Multi-turn conversation within a single session
- Four pre-loaded sample logs for demonstration

**Out of scope (future work):**
- Direct integration with the ML anomaly detector model output
- Automatic CSV batch processing
- Persistent conversation history across sessions
- Real-time packet capture and analysis
- SHAP-style feature importance highlighting

The scope is intentionally kept small. Functionality and clarity take
priority over complexity, as recommended by the course guidelines.

---

## 9. Connection to Course Requirements

| Course requirement | How this project meets it |
|---|---|
| Use one open-source LLM | Llama 3.2 via Ollama — fully open-source |
| Accept user input | Streamlit chat input box |
| Produce LLM-generated output | Structured threat analysis streamed to UI |
| Run as small web app | Streamlit at localhost:8501 |
| No paid APIs | 100% local — Ollama runs on student machine |
| No ML training required | Uses pre-trained Llama 3.2 as-is |
| Prompt engineering | Custom security analyst system prompt in prompts.py |
| Workflow diagram | Included in docs/workflow_diagram.md |
| GitHub deployment | Public repository with README and setup instructions |

---

*Submitted for CAP 942 — Capstone Project: AI Application Development*
*Naming convention: FirstName_LastName_CapstoneAI*
