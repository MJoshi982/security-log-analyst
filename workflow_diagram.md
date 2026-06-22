# Application Workflow Diagram
## CAP 942 — Security Log Analyst Chatbot

---

## System Flow

```mermaid
flowchart TD
    USER(["👤 USER\nPastes network log or types security question"])

    UI["🖥️ STREAMLIT UI\napp.py\n─────────────────\n• Chat input box\n• Sample log loader sidebar\n• Model selector sidebar\n• Conversation history display\n• Streaming response display\n• Threat intel panel"]

    PROMPT["⚙️ PROMPT BUILDER\nprompts.py\n─────────────────\n• System prompt — security analyst persona\n• Conversation history — multi-turn memory\n• New user message"]

    OLLAMA["🤖 OLLAMA — Local LLM Runner\nModel: Llama 3.2 · 3B parameters\n─────────────────\n• Runs on Windows 11 locally\n• No internet required\n• No paid API\n• Streams tokens back in real time"]

    FORMATTER["🔍 RESPONSE FORMATTER\napp.py\n─────────────────\n• Adds threat level badge 🔴🟠🟡🟢✅\n• Streams tokens live to UI\n• Saves response to conversation history\n• Detects attack type for threat intel"]

    INTEL["🛡️ THREAT INTELLIGENCE ENGINE\napp.py — THREAT_INTEL database\n─────────────────\n• CVE references from NVD\n• Threat actor profiles\n• Remediation playbook\n• Export to .txt report"]

    OUTPUT(["📋 USER RECEIVES\nThreat level + Explanation\n+ Recommendation + Threat Intel"])

    USER      -->|"user_input text"| UI
    UI        -->|"messages list"| PROMPT
    PROMPT    -->|"structured messages"| OLLAMA
    OLLAMA    -->|"streamed tokens"| FORMATTER
    FORMATTER -->|"formatted analysis"| UI
    FORMATTER -->|"attack type + score"| INTEL
    UI        -->|"final display"| OUTPUT
    INTEL     -->|"CVEs + actors + playbook"| OUTPUT

    style USER      fill:#4f46e5,color:#fff,stroke:#3730a3
    style UI        fill:#1e1b30,color:#e8e6f0,stroke:#3d3668
    style PROMPT    fill:#1e1b30,color:#e8e6f0,stroke:#3d3668
    style OLLAMA    fill:#7c3aed,color:#fff,stroke:#5b21b6
    style FORMATTER fill:#1e1b30,color:#e8e6f0,stroke:#3d3668
    style INTEL     fill:#ef4444,color:#fff,stroke:#b91c1c
    style OUTPUT    fill:#16a34a,color:#fff,stroke:#15803d
```

---

## Component Breakdown

```mermaid
flowchart LR
    subgraph FILES["📁 Project Files"]
        APP["app.py\nMain application"]
        PROMPTS["prompts.py\nSystem prompt + builder"]
        SAMPLES["sample_logs.py\nTest inputs"]
    end

    subgraph RUNTIME["⚙️ Runtime"]
        STREAMLIT["Streamlit\nWeb UI framework"]
        OLLAMA_RT["Ollama\nLLM runner"]
        LLAMA["Llama 3.2\n3B parameter model"]
    end

    subgraph OUTPUT_T["📤 Output Types"]
        CHAT["Chat analysis\nStreamed response"]
        BADGE["Threat badge\n🔴🟠🟡🟢✅"]
        INTEL_OUT["Threat intel panel\nCVEs + actors + playbook"]
        EXPORT["Exported report\n.txt download"]
    end

    APP      --> STREAMLIT
    APP      --> OLLAMA_RT
    PROMPTS  --> APP
    SAMPLES  --> APP
    OLLAMA_RT --> LLAMA
    LLAMA    --> CHAT
    LLAMA    --> BADGE
    APP      --> INTEL_OUT
    APP      --> EXPORT

    style FILES    fill:#1e1b30,color:#e8e6f0,stroke:#3d3668
    style RUNTIME  fill:#2d1f6e,color:#e8e6f0,stroke:#4c1d95
    style OUTPUT_T fill:#14532d,color:#e8e6f0,stroke:#166534
```

---

## Data Flow — Step by Step

```mermaid
sequenceDiagram
    actor User
    participant UI      as Streamlit UI
    participant Builder as Prompt Builder
    participant Ollama  as Ollama LLM
    participant Intel   as Threat Intel Engine

    User->>UI: Pastes network connection log
    UI->>UI: Stores input in session_state
    UI->>Builder: Sends conversation history + new message
    Builder->>Builder: Prepends system prompt
    Builder->>Ollama: Sends structured messages []
    Ollama-->>UI: Streams tokens one by one
    UI-->>User: Displays streaming response in real time
    Ollama->>UI: Stream complete — full response ready
    UI->>UI: format_response() adds threat badge
    UI->>Intel: detect_attack_type() → port_scan / dos / brute_force
    Intel->>UI: Returns CVEs + threat actors + playbook
    UI-->>User: Displays full analysis + threat intel panel
    User->>UI: Asks follow-up question
    UI->>Builder: Includes previous exchange in history
    Note over Builder,Ollama: Multi-turn memory — full context preserved
```

---

## Threat Intelligence Flow

```mermaid
flowchart TD
    LOG["Raw network log input\ne.g. src_bytes=0, dst_host_count=255"]

    DETECT{"Attack type\ndetection"}

    PS["Port Scan Profile\nTA0043 · T1046"]
    DOS["DoS Profile\nTA0040 · T1498"]
    BF["Brute Force Profile\nTA0006 · T1110"]
    NORM["Normal Traffic\nNo threat profile"]

    CVE["CVE References\nLinked to NVD database"]
    ACTOR["Threat Actor Profiles\nAPT28 · Lazarus · FIN7 etc."]
    PLAY["Remediation Playbook\nImmediate · Short-term · Long-term"]
    EXPORT_TI["Downloadable Report\n.txt export"]

    LOG    --> DETECT
    DETECT -->|"src_bytes=0\ndst_host_count=255"| PS
    DETECT -->|"serror_rate=1\nSYN flood"| DOS
    DETECT -->|"num_failed_logins\ncredential attack"| BF
    DETECT -->|"threat level: none"| NORM

    PS  --> CVE
    DOS --> CVE
    BF  --> CVE

    PS  --> ACTOR
    DOS --> ACTOR
    BF  --> ACTOR

    CVE   --> PLAY
    ACTOR --> PLAY
    PLAY  --> EXPORT_TI

    style LOG       fill:#1e1b30,color:#e8e6f0,stroke:#3d3668
    style DETECT    fill:#7c3aed,color:#fff,stroke:#5b21b6
    style PS        fill:#ef4444,color:#fff,stroke:#b91c1c
    style DOS       fill:#ea580c,color:#fff,stroke:#c2410c
    style BF        fill:#d97706,color:#fff,stroke:#b45309
    style NORM      fill:#16a34a,color:#fff,stroke:#15803d
    style CVE       fill:#1e3a5f,color:#93c5fd,stroke:#1d4ed8
    style ACTOR     fill:#4c1d00,color:#fed7aa,stroke:#c2410c
    style PLAY      fill:#2d1f6e,color:#ddd6fe,stroke:#4c1d95
    style EXPORT_TI fill:#14532d,color:#bbf7d0,stroke:#166534
```

---

## Tools and Libraries

| Component | Tool | Version | Purpose |
|---|---|---|---|
| LLM runner | Ollama | Latest | Run Llama 3.2 locally on Windows 11 |
| Language model | Llama 3.2 (3B) | Meta open-source | AI security analysis |
| Web UI | Streamlit | Latest | Chat interface and threat intel panel |
| LLM client | ollama (Python) | Latest | API calls to local Ollama server |
| Language | Python | 3.11 | Application code |
| Package manager | uv | Latest | Fast dependency management |

---

#