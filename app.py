# app.py — Security Log Analyst
# Original simple chat interface + enhanced threat intelligence recommendation panel
# CAP 942 Capstone · Ollama + Streamlit

import streamlit as st
import ollama
import re
import datetime
from prompts import build_messages
from sample_logs import SAMPLE_LOGS

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecAI Assistant",
    page_icon="🔐",
    layout="wide",
)

# ── CSS — minimal, just improves the threat intel cards ───────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

[data-testid="stChatMessage"] { font-family: 'Inter', sans-serif !important; }

.ti-card {
    background: #ffffff;
    border: 1.5px solid #e8eaf2;
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 10px;
}
.ti-card-red   { border-left: 4px solid #ef4444; }
.ti-card-orange{ border-left: 4px solid #f97316; }
.ti-card-purple{ border-left: 4px solid #7c3aed; }
.ti-card-blue  { border-left: 4px solid #3b82f6; }
.ti-card-green { border-left: 4px solid #22c55e; }

.ti-label {
    font-size: 0.62rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 5px;
    font-family: 'JetBrains Mono', monospace;
}
.ti-title {
    font-size: 0.88rem;
    font-weight: 600;
    color: #0f1230;
    margin-bottom: 4px;
    font-family: 'Inter', sans-serif;
}
.ti-body {
    font-size: 0.78rem;
    color: #44485e;
    line-height: 1.6;
    font-family: 'Inter', sans-serif;
}
.ti-tag {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 500;
    padding: 2px 8px;
    border-radius: 10px;
    margin: 3px 3px 0 0;
    font-family: 'JetBrains Mono', monospace;
}
.playbook-step {
    display: flex;
    gap: 10px;
    padding: 8px 10px;
    background: #f7f8fc;
    border: 1px solid #e8eaf2;
    border-radius: 6px;
    margin-bottom: 6px;
    font-size: 0.78rem;
    color: #44485e;
    align-items: flex-start;
    font-family: 'Inter', sans-serif;
}
.step-num {
    background: #7c3aed;
    color: #fff;
    font-weight: 700;
    font-size: 0.65rem;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    margin-top: 1px;
    font-family: 'JetBrains Mono', monospace;
}
</style>
""", unsafe_allow_html=True)


# ── Threat intelligence database ───────────────────────────────────────────────
# Maps attack patterns to CVEs, threat actors, and remediation playbooks.
# This is the core of the threat intel enhancement.

THREAT_INTEL = {
    "port_scan": {
        "attack_type":   "Port Scan / Reconnaissance",
        "mitre_tactic":  "TA0043 — Reconnaissance",
        "mitre_technique": "T1046 — Network Service Discovery",
        "mitre_url":     "https://attack.mitre.org/techniques/T1046/",
        "cves": [
            {
                "id":   "CVE-2021-44228",
                "name": "Log4Shell",
                "desc": "Commonly exploited after port scan reveals exposed Log4j services. CVSS 10.0.",
                "url":  "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            },
            {
                "id":   "CVE-2022-30190",
                "name": "Follina (MSDT RCE)",
                "desc": "Attackers scan for exposed MSDT endpoints before exploiting. CVSS 7.8.",
                "url":  "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
            },
        ],
        "threat_actors": [
            {
                "name":     "APT28 (Fancy Bear)",
                "origin":   "Russia — GRU Unit 26165",
                "campaigns": ["Olympic Destroyer", "DNC Breach 2016"],
                "desc":     "Known for extensive port scanning before targeted intrusions against government and military networks.",
                "tags":     ["Nation-state", "Espionage", "Russia"],
            },
            {
                "name":     "Lazarus Group",
                "origin":   "North Korea — RGB",
                "campaigns": ["Operation Dream Job", "WannaCry"],
                "desc":     "Uses automated port scanning tools to identify vulnerable SMB and RDP services before deploying ransomware.",
                "tags":     ["Nation-state", "Financial", "North Korea"],
            },
        ],
        "playbook": [
            ("Immediate",    "Block the source IP at the perimeter firewall immediately."),
            ("Immediate",    "Check firewall logs for other connections from the same /24 subnet in the last 24 hours."),
            ("Short-term",   "Enable geo-blocking if the source IP is from an unexpected country."),
            ("Short-term",   "Verify all exposed services are patched — prioritise CVE-2021-44228 and CVE-2022-30190."),
            ("Short-term",   "Enable port scan detection in your IDS/IPS (Snort rule SID 1228 covers Nmap scans)."),
            ("Long-term",    "Implement network segmentation to limit blast radius of a successful intrusion."),
            ("Long-term",    "Deploy a honeypot to attract and monitor future reconnaissance attempts."),
        ],
        "severity_tags": ["HIGH", "RECONNAISSANCE", "NETWORK"],
    },

    "dos": {
        "attack_type":   "Denial of Service / DoS",
        "mitre_tactic":  "TA0040 — Impact",
        "mitre_technique": "T1498 — Network Denial of Service",
        "mitre_url":     "https://attack.mitre.org/techniques/T1498/",
        "cves": [
            {
                "id":   "CVE-2023-44487",
                "name": "HTTP/2 Rapid Reset (CVSS 7.5)",
                "desc": "Allows attackers to send and cancel HTTP/2 requests rapidly, exhausting server resources.",
                "url":  "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
            },
            {
                "id":   "CVE-2016-6515",
                "name": "OpenSSH DoS",
                "desc": "Allows unauthenticated clients to exhaust server resources via password authentication requests.",
                "url":  "https://nvd.nist.gov/vuln/detail/CVE-2016-6515",
            },
        ],
        "threat_actors": [
            {
                "name":     "Killnet",
                "origin":   "Russia — hacktivist group",
                "campaigns": ["EU Parliament DDoS 2022", "US Healthcare DDoS 2023"],
                "desc":     "Politically motivated DDoS attacks against Western government and critical infrastructure targets.",
                "tags":     ["Hacktivist", "DDoS", "Russia"],
            },
            {
                "name":     "Anonymous Sudan",
                "origin":   "Sudan — hacktivist",
                "campaigns": ["Microsoft DDoS 2023", "Scandinavian Government DDoS"],
                "desc":     "Deploys layer 7 HTTP flood attacks. Has targeted banks, airports, and hospitals.",
                "tags":     ["Hacktivist", "DDoS", "HTTP Flood"],
            },
        ],
        "playbook": [
            ("Immediate",    "Rate-limit inbound connections at the network edge — max 100 connections/second per IP."),
            ("Immediate",    "Enable SYN cookies on the affected server to handle SYN flood traffic."),
            ("Immediate",    "Contact your ISP to request upstream traffic scrubbing if volume exceeds 1Gbps."),
            ("Short-term",   "Deploy a WAF with DDoS protection rules (Cloudflare, AWS Shield, or open-source ModSecurity)."),
            ("Short-term",   "Patch CVE-2023-44487 — update nginx/Apache to versions with HTTP/2 Rapid Reset fix."),
            ("Long-term",    "Implement Anycast routing to distribute attack traffic across multiple PoPs."),
            ("Long-term",    "Create an incident response runbook for future DoS events with escalation paths."),
        ],
        "severity_tags": ["CRITICAL", "AVAILABILITY", "NETWORK"],
    },

    "brute_force": {
        "attack_type":   "Brute Force / Credential Attack",
        "mitre_tactic":  "TA0006 — Credential Access",
        "mitre_technique": "T1110 — Brute Force",
        "mitre_url":     "https://attack.mitre.org/techniques/T1110/",
        "cves": [
            {
                "id":   "CVE-2022-1388",
                "name": "F5 BIG-IP Auth Bypass (CVSS 9.8)",
                "desc": "Unauthenticated remote code execution via iControl REST API — frequently targeted after credential attacks.",
                "url":  "https://nvd.nist.gov/vuln/detail/CVE-2022-1388",
            },
            {
                "id":   "CVE-2019-0708",
                "name": "BlueKeep — RDP RCE (CVSS 9.8)",
                "desc": "Pre-authentication RDP exploit. Brute-forced RDP credentials are often followed by BlueKeep exploitation.",
                "url":  "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
            },
        ],
        "threat_actors": [
            {
                "name":     "FIN7",
                "origin":   "Eastern Europe — cybercrime",
                "campaigns": ["Carbanak Banking Malware", "REVIL Ransomware"],
                "desc":     "Uses credential stuffing and brute-force attacks against RDP and VPN endpoints before deploying ransomware.",
                "tags":     ["Cybercrime", "Ransomware", "Financial"],
            },
            {
                "name":     "Scattered Spider",
                "origin":   "English-speaking — social engineering",
                "campaigns": ["MGM Resorts Breach 2023", "Caesars Entertainment 2023"],
                "desc":     "Combines brute force with social engineering to bypass MFA and gain initial access.",
                "tags":     ["Cybercrime", "Social Engineering", "MFA Bypass"],
            },
        ],
        "playbook": [
            ("Immediate",    "Lock the targeted account after 5 failed login attempts — enforce account lockout policy."),
            ("Immediate",    "Block the source IP and any IPs in the same /24 range at the firewall."),
            ("Immediate",    "Reset credentials for all accounts targeted in the brute-force attempt."),
            ("Short-term",   "Enable MFA on all externally-facing services — RDP, VPN, SSH, and web portals."),
            ("Short-term",   "Audit all accounts with failed login attempts in the last 7 days for signs of compromise."),
            ("Short-term",   "Patch CVE-2019-0708 (BlueKeep) and disable RDP if not required."),
            ("Long-term",    "Implement a SIEM alert for >5 failed logins from the same IP within 60 seconds."),
            ("Long-term",    "Deploy a password manager policy to prevent credential reuse across services."),
        ],
        "severity_tags": ["HIGH", "CREDENTIAL", "AUTHENTICATION"],
    },

    "normal": {
        "attack_type":   "Normal Traffic",
        "mitre_tactic":  "N/A",
        "mitre_technique": "N/A",
        "mitre_url":     "https://attack.mitre.org/",
        "cves":          [],
        "threat_actors": [],
        "playbook": [
            ("Routine",  "No action required — this connection appears normal."),
            ("Routine",  "Continue standard monitoring and log retention policies."),
            ("Routine",  "Review this log again if other suspicious activity is detected from the same source."),
        ],
        "severity_tags": ["SAFE", "NORMAL"],
    },
}


def detect_attack_type(response_text: str, log_input: str) -> str:
    """
    Determine which threat intel profile to show based on
    the LLM response and the raw log input.
    """
    combined = (response_text + " " + log_input).lower()

    if any(w in combined for w in
           ["denial of service", "dos", "syn flood", "serror_rate=1",
            "dst_host_serror_rate=1", "flood"]):
        return "dos"

    if any(w in combined for w in
           ["brute force", "failed login", "num_failed_logins",
            "credential", "password spray", "authentication fail"]):
        return "brute_force"

    if any(w in combined for w in
           ["port scan", "reconnaissance", "probe", "sweep",
            "same_srv_rate=0.0", "diff_srv_rate=0.9",
            "dst_host_count=255", "src_bytes=0"]):
        return "port_scan"

    if any(w in combined for w in
           ["threat level: none", "normal traffic", "no threat",
            "legitimate", "safe"]):
        return "normal"

    return "port_scan"   # default to port scan for security logs


def render_threat_intel(attack_key: str, score: int):
    """Render the full threat intelligence panel for a given attack type."""
    ti = THREAT_INTEL.get(attack_key, THREAT_INTEL["port_scan"])

    # ── Score + attack type header ──
    if score >= 90:   score_color = "#ef4444"
    elif score >= 65: score_color = "#f97316"
    elif score >= 35: score_color = "#eab308"
    elif score >= 10: score_color = "#22c55e"
    else:             score_color = "#06b6d4"

    st.markdown(f"""
    <div class="ti-card ti-card-{'red' if score>=65 else 'green' if score<35 else 'orange'}">
        <div class="ti-label" style="color:{score_color};">
            Threat Intelligence Report
        </div>
        <div class="ti-title">{ti['attack_type']}</div>
        <div class="ti-body" style="margin-bottom:8px;">
            <b>MITRE ATT&CK:</b> {ti['mitre_tactic']}<br>
            <b>Technique:</b> {ti['mitre_technique']}
            &nbsp;·&nbsp;
            <a href="{ti['mitre_url']}" target="_blank"
               style="color:#7c3aed;font-size:0.72rem;">
               View on MITRE ↗
            </a>
        </div>
        <div>
            {''.join([
                f'<span class="ti-tag" '
                f'style="background:{"#fef2f2" if t in ["HIGH","CRITICAL"] else "#f0f9ff" if t=="SAFE" else "#f5f3ff"};'
                f'color:{"#ef4444" if t in ["HIGH","CRITICAL"] else "#06b6d4" if t=="SAFE" else "#7c3aed"};">'
                f'{t}</span>'
                for t in ti["severity_tags"]
            ])}
        </div>
    </div>
    """, unsafe_allow_html=True)

    if attack_key == "normal":
        st.markdown("""
        <div class="ti-card ti-card-green">
            <div class="ti-label" style="color:#22c55e;">Status</div>
            <div class="ti-body">
                ✅ This connection matches normal traffic patterns.
                No threat intelligence entries apply.
                Continue standard monitoring.
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # ── CVE References ──
    if ti["cves"]:
        st.markdown("""
        <div class="ti-label" style="color:#ef4444;
            font-family:'JetBrains Mono',monospace;
            font-size:0.62rem;letter-spacing:0.1em;
            margin:14px 0 8px;">
            ⚠ CVE References — Known Vulnerabilities
        </div>
        """, unsafe_allow_html=True)

        for cve in ti["cves"]:
            st.markdown(f"""
            <div class="ti-card ti-card-red">
                <div class="ti-label" style="color:#ef4444;">
                    {cve['id']}
                </div>
                <div class="ti-title">{cve['name']}</div>
                <div class="ti-body">{cve['desc']}</div>
                <div style="margin-top:6px;">
                    <a href="{cve['url']}" target="_blank"
                       style="font-size:0.7rem;color:#7c3aed;
                              font-family:'JetBrains Mono',monospace;">
                        View on NVD ↗
                    </a>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # ── Threat Actor Profiles ──
    if ti["threat_actors"]:
        st.markdown("""
        <div class="ti-label" style="color:#f97316;
            font-family:'JetBrains Mono',monospace;
            font-size:0.62rem;letter-spacing:0.1em;
            margin:14px 0 8px;">
            👤 Known Threat Actors — This Attack Pattern
        </div>
        """, unsafe_allow_html=True)

        for actor in ti["threat_actors"]:
            tags_html = "".join([
                f'<span class="ti-tag" '
                f'style="background:#fff7ed;color:#f97316;">'
                f'{t}</span>'
                for t in actor["tags"]
            ])
            campaigns_html = " · ".join(actor["campaigns"])
            st.markdown(f"""
            <div class="ti-card ti-card-orange">
                <div class="ti-label" style="color:#f97316;">
                    Threat Actor Profile
                </div>
                <div class="ti-title">{actor['name']}</div>
                <div class="ti-body" style="margin-bottom:6px;">
                    <b>Origin:</b> {actor['origin']}<br>
                    <b>Known campaigns:</b> {campaigns_html}<br>
                    {actor['desc']}
                </div>
                <div>{tags_html}</div>
            </div>
            """, unsafe_allow_html=True)

    # ── Remediation Playbook ──
    st.markdown("""
    <div class="ti-label" style="color:#7c3aed;
        font-family:'JetBrains Mono',monospace;
        font-size:0.62rem;letter-spacing:0.1em;
        margin:14px 0 8px;">
        📋 Remediation Playbook — Step-by-Step
    </div>
    """, unsafe_allow_html=True)

    urgency_colors = {
        "Immediate":  ("#ef4444", "#fef2f2"),
        "Short-term": ("#f97316", "#fff7ed"),
        "Long-term":  ("#7c3aed", "#f5f3ff"),
        "Routine":    ("#22c55e", "#f0fdf4"),
    }

    for i, (urgency, step) in enumerate(ti["playbook"], 1):
        uc, ubg = urgency_colors.get(urgency, ("#7c3aed", "#f5f3ff"))
        st.markdown(f"""
        <div class="playbook-step">
            <div class="step-num"
                 style="background:{uc};">{i}</div>
            <div style="flex:1;">
                <span style="font-size:0.65rem;font-weight:600;
                    color:{uc};font-family:'JetBrains Mono',monospace;
                    text-transform:uppercase;letter-spacing:0.08em;
                    background:{ubg};padding:1px 7px;border-radius:8px;
                    margin-right:6px;">{urgency}</span>
                {step}
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Export threat intel ──
    export_lines = [
        f"THREAT INTELLIGENCE REPORT",
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"{'='*55}",
        f"Attack type:  {ti['attack_type']}",
        f"MITRE Tactic: {ti['mitre_tactic']}",
        f"Technique:    {ti['mitre_technique']}",
        f"",
        f"CVE REFERENCES",
        f"-"*30,
    ]
    for cve in ti["cves"]:
        export_lines += [f"{cve['id']} — {cve['name']}", f"  {cve['desc']}", ""]
    export_lines += ["THREAT ACTORS", "-"*30]
    for actor in ti["threat_actors"]:
        export_lines += [
            f"{actor['name']} ({actor['origin']})",
            f"  Campaigns: {', '.join(actor['campaigns'])}",
            f"  {actor['desc']}", "",
        ]
    export_lines += ["REMEDIATION PLAYBOOK", "-"*30]
    for i, (urg, step) in enumerate(ti["playbook"], 1):
        export_lines.append(f"Step {i} [{urg}]: {step}")

    st.markdown("<div style='margin-top:12px;'>", unsafe_allow_html=True)
    st.download_button(
        "⬇  Download threat intel report",
        "\n".join(export_lines),
        f"threat_intel_{attack_key}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.txt",
        "text/plain",
        use_container_width=True,
        key=f"ti_export_{attack_key}_{score}",
    )
    st.markdown("</div>", unsafe_allow_html=True)


def extract_risk_score(text: str) -> int:
    t = text.lower()
    if "threat level: critical" in t: return 95
    if "threat level: high"     in t: return 78
    if "threat level: medium"   in t: return 45
    if "threat level: low"      in t: return 18
    if "threat level: none"     in t: return 4
    return 50

def format_response(response_text: str) -> str:
    t = response_text.lower()
    if "threat level: critical" in t: badge = "🔴 **CRITICAL THREAT**"
    elif "threat level: high"   in t: badge = "🟠 **HIGH THREAT**"
    elif "threat level: medium" in t: badge = "🟡 **MEDIUM THREAT**"
    elif "threat level: low"    in t: badge = "🟢 **LOW THREAT**"
    elif "threat level: none"   in t: badge = "✅ **NO THREAT**"
    else:                              badge = "🔵 **ANALYSIS COMPLETE**"
    return f"{badge}\n\n---\n\n{response_text}"


# ── Session state ──────────────────────────────────────────────────────────────
if "messages"    not in st.session_state: st.session_state["messages"]    = []
if "last_attack" not in st.session_state: st.session_state["last_attack"] = None
if "last_score"  not in st.session_state: st.session_state["last_score"]  = None
if "last_input"  not in st.session_state: st.session_state["last_input"]  = ""


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")

    model_name = st.selectbox(
        "Ollama model",
        ["llama3.2", "mistral", "llama3"],
        help="Must be pulled in Ollama first",
    )
    temperature = st.slider(
        "Temperature",
        min_value=0.0, max_value=1.0,
        value=0.3, step=0.1,
        help="Lower = more consistent. Higher = more creative.",
    )

    st.divider()
    st.header("📋 Load sample log")
    selected_sample = st.selectbox("Choose a sample", list(SAMPLE_LOGS.keys()))
    if st.button("Load sample", use_container_width=True):
        if SAMPLE_LOGS[selected_sample]:
            st.session_state["prefill"] = SAMPLE_LOGS[selected_sample]

    st.divider()
    if st.button("🗑️ Clear conversation", use_container_width=True):
        st.session_state["messages"]    = []
        st.session_state["last_attack"] = None
        st.session_state["last_score"]  = None
        st.rerun()

    st.divider()
    st.markdown("**About this app**")
    st.markdown(
        "Paste a network connection log or describe "
        "suspicious activity. The AI analyst will assess "
        "the threat level, explain the findings, and provide "
        "a full threat intelligence report."
    )
    st.divider()
    st.markdown("**🔗 Project context**")
    st.markdown(
        "This chatbot is the **explanation layer** for the "
        "Port Scanner Anomaly Detector project.\n\n"
        "The ML models flag suspicious connections. "
        "This chatbot explains **why** they are flagged "
        "and provides **threat intelligence** — CVEs, "
        "threat actors, and remediation playbooks."
    )


# ── Main layout: chat left, threat intel right ────────────────────────────────
st.title("🔐 SecAI Assistant")
st.caption("Powered by Ollama · Local LLM · No data leaves your machine")

chat_col, intel_col = st.columns([1.1, 1], gap="large")

# ══════════════════════════════════════════════════════════════════════════════
# LEFT: Chat (original interface, unchanged)
# ══════════════════════════════════════════════════════════════════════════════
with chat_col:

    # Display conversation history
    for msg in st.session_state["messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat input
    prefill_value = st.session_state.pop("prefill", "") \
                    if st.session_state.get("prefill") else ""

    user_input = st.chat_input(
        "Paste a network log or ask a security question..."
    )

    if prefill_value and not user_input:
        user_input = prefill_value

    if user_input:
        # Show user message
        with st.chat_message("user"):
            st.markdown(user_input)
        st.session_state["messages"].append(
            {"role": "user", "content": user_input}
        )
        st.session_state["last_input"] = user_input

        # Build messages for Ollama
        messages_for_llm = build_messages(
            st.session_state["messages"][:-1],
            user_input,
        )

        # Call Ollama and stream
        with st.chat_message("assistant"):
            placeholder   = st.empty()
            full_response = ""

            try:
                stream = ollama.chat(
                    model=model_name,
                    messages=messages_for_llm,
                    options={"temperature": temperature},
                    stream=True,
                )
                for chunk in stream:
                    full_response += chunk["message"]["content"]
                    placeholder.markdown(full_response + "▌")

                formatted = format_response(full_response)
                placeholder.markdown(formatted)

                # Store attack type + score for threat intel panel
                score       = extract_risk_score(full_response)
                attack_key  = detect_attack_type(full_response, user_input)
                st.session_state["last_attack"] = attack_key
                st.session_state["last_score"]  = score

            except Exception as e:
                full_response = (
                    f"⚠️ Error connecting to Ollama: {e}\n\n"
                    f"Make sure Ollama is running and the model "
                    f"'{model_name}' is pulled:\n\n"
                    f"```powershell\nollama pull {model_name}\n```"
                )
                formatted = full_response
                placeholder.markdown(formatted)

        st.session_state["messages"].append(
            {"role": "assistant", "content": formatted}
        )
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# RIGHT: Threat Intelligence Panel
# ══════════════════════════════════════════════════════════════════════════════
with intel_col:

    st.markdown("### 🛡️ Threat Intelligence")
    st.caption("Auto-populated after each analysis")

    if st.session_state.get("last_attack"):
        render_threat_intel(
            st.session_state["last_attack"],
            st.session_state["last_score"] or 50,
        )
    else:
        # Empty state
        st.markdown("""
        <div style="border:1.5px dashed #e8eaf2;border-radius:10px;
          padding:32px 20px;text-align:center;">
          <div style="font-size:2rem;margin-bottom:10px;">🛡️</div>
          <div style="font-weight:600;font-size:0.88rem;color:#0f1230;
            margin-bottom:8px;">Threat intel standing by</div>
          <div style="font-size:0.78rem;color:#8890aa;line-height:1.7;
            max-width:280px;margin:0 auto;">
            Run a log analysis on the left. This panel will automatically
            populate with relevant CVEs, threat actor profiles, and a
            step-by-step remediation playbook.
          </div>
          <div style="margin-top:20px;display:flex;flex-direction:column;
            gap:8px;text-align:left;max-width:280px;margin:16px auto 0;">
            <div style="background:#fef2f2;border:1px solid #fecaca;
              border-radius:6px;padding:8px 12px;font-size:0.75rem;color:#991b1b;">
              ⚠ CVE references from NVD database
            </div>
            <div style="background:#fff7ed;border:1px solid #fed7aa;
              border-radius:6px;padding:8px 12px;font-size:0.75rem;color:#92400e;">
              👤 Known threat actor profiles
            </div>
            <div style="background:#f5f3ff;border:1px solid #ddd6fe;
              border-radius:6px;padding:8px 12px;font-size:0.75rem;color:#5b21b6;">
              📋 Step-by-step remediation playbook
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)