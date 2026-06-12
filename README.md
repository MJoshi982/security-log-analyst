# Security Log Analyst Chatbot 

---

A Security Log Analyst Chatbot is an AI assistant that reads network
connection logs and explains them in plain English. You paste in a
suspicious connection, and it tells you what it means, how dangerous
it is, and what to do about it.

---

## What problem it solves

Every time someone connects to a network, a log entry is created. A busy
network generates millions of these per day. Security tools scan them and
raise alerts — but the alert just says **"suspicious"** with no explanation.

The analyst then has to figure out:
- Is this actually dangerous or a false alarm?
- Which part of the log triggered it?
- What should I do right now?

That takes time, expertise, and energy. At scale it causes **alert fatigue**
— analysts get so many unexplained alerts they start ignoring them. That is
when real attacks slip through.

The chatbot solves this by turning a raw log like this:

```
duration=0, src_bytes=0, dst_bytes=0,
same_srv_rate=0.06, diff_srv_rate=0.94,
dst_host_count=255
```

Into this:

> 🔴 **HIGH THREAT — Port Scan Detected**
>
> The source sent zero bytes, meaning it never completed a real connection
> — classic SYN scan behaviour. It probed 94% different services across
> 255 hosts, which is the signature of an attacker mapping your network
> before an attack. **Recommend: block the source IP immediately.**

---

## How it works — step by step

```
You paste a network log
        ↓
Streamlit web page receives it
        ↓
System prompt turns the AI into a security analyst
        ↓
Ollama runs Llama 3.2 locally on your machine
        ↓
AI analyses the log numbers and writes an explanation
        ↓
Response streams back to your screen in real time
        ↓
You get: threat level + explanation + recommendation
```

Three things make it work together:

**Ollama** runs the AI model locally — no internet, no paid API, nothing
leaves your computer.

**Llama 3.2** is the open-source language model that does the actual
reasoning — it understands what combinations of log values mean in a
security context.

**The system prompt** is the instructions that tell the AI to behave like
a cybersecurity analyst and always structure its answer the same way —
threat level first, then explanation, then recommendation.

---

## How it differs from other security tools

Most security tools are built for one thing — **detection**. They tell you
something is wrong. They do not tell you why or what to do.

| Tool | What it does | The gap it leaves |
|---|---|---|
| Snort / Suricata | Matches traffic against fixed rules | Misses slow or novel attacks, no explanation |
| Wireshark | Shows raw packet data | Requires expert knowledge to read |
| Splunk | Collects and dashboards logs | Still produces unexplained alerts, very expensive |
| CrowdStrike | Blocks known threats automatically | Black box — no reasoning shown to the analyst |
| **Your chatbot** | Explains what was flagged and why | Not a detector — it is the explanation layer |

The simplest way to put it:

> Snort says **"alert."** Wireshark shows you **raw data.**
> Your chatbot says **"here is what this means, here is why it is
> dangerous, and here is what you should do right now."**

---

## Who it is built for

Built for security analysts who spend too much time manually investigating
false positives. Instead of reading through raw log numbers to decide if
an alert is real or not, the chatbot explains it instantly — so analysts
spend less time on dead ends and more time on actual threats.


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
