
# sample_logs.py
# Pre-written test inputs for the demo.
# Each entry has a label (shown in the UI dropdown) and the log text.

SAMPLE_LOGS = {
    "Select a sample...": "",

    "Port scan — suspicious": """
Connection log:
duration=0, protocol=tcp, service=private, flag=S0,
src_bytes=0, dst_bytes=0, wrong_fragment=0,
same_srv_rate=0.06, diff_srv_rate=0.06,
dst_host_count=255, dst_host_srv_count=6,
dst_host_same_srv_rate=0.02, dst_host_diff_srv_rate=0.06
Label from detector: ATTACK (RF confidence: 0.94)
""",

    "Normal web traffic": """
Connection log:
duration=2, protocol=tcp, service=http, flag=SF,
src_bytes=2840, dst_bytes=14560, wrong_fragment=0,
same_srv_rate=1.0, diff_srv_rate=0.0,
dst_host_count=12, dst_host_srv_count=12,
dst_host_same_srv_rate=1.0, dst_host_diff_srv_rate=0.0
Label from detector: NORMAL (RF confidence: 0.02)
""",

    "DoS attack pattern": """
Connection log:
duration=0, protocol=tcp, service=http, flag=S0,
src_bytes=0, dst_bytes=0, wrong_fragment=0,
same_srv_rate=1.0, diff_srv_rate=0.0,
dst_host_count=255, dst_host_srv_count=255,
dst_host_same_srv_rate=1.0, dst_host_serror_rate=1.0
Label from detector: ATTACK (RF confidence: 0.99)
""",

    "Ambiguous — needs analysis": """
Connection log:
duration=1, protocol=tcp, service=ftp, flag=SF,
src_bytes=480, dst_bytes=2390, wrong_fragment=0,
num_failed_logins=3, logged_in=0,
same_srv_rate=0.5, diff_srv_rate=0.5
Label from detector: POSSIBLE ATTACK (RF confidence: 0.61)
""",
}
