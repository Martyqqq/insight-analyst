import json
import pandas as pd
import streamlit as st
from openai import OpenAI


# LM Studio / model config
LM_BASE_URL = "http://localhost:1234/v1"      # LM Studio server
LM_MODEL    = "mistral-7b-instruct"           # model
API_KEY     = "lm-studio"

TEMP        = 0.2
MAX_TOKENS  = 550
MAX_ROWS_TO_MODEL = 200                       # cap rows sent
MAX_CHARS_PER_FIELD = 300                     # cap characters sent


# Streamlit page setup
st.set_page_config(
    page_title="Insight Analyst — Log Summarizer",
    layout="wide"
)

st.title("Insight Analyst — Log Sumarizer")
st.caption(
    "Upload a CSV from Windows Event Viewer or Splunk."
    " The app shows a small preview, generates an incident-style AI summary, "
    "and suggests further investigation steps using a local model."
)

# UI fixes
st.markdown(
    """
<style>
/* Keep content nicely centered with max width */
.block-container {
    max-width: 1200px;
    margin: auto;
}

/* Center headers and cells in tables/dataframes */
table, th, td { text-align: center !important; }
[data-testid="stDataFrame"] td, [data-testid="stDataFrame"] th {
    text-align: center !important;
}

/* Hide toolbar buttons (fullscreen/search/download) on dataframes */
[data-testid="stDataFrame"] [data-testid="stElementToolbar"] {
    display: none !important;
}

/* Hide column menu (hide/pin/etc.) */
[data-testid="stDataFrame"] [role="button"] {
    display: none !important;
}
</style>
""",
    unsafe_allow_html=True,
)

# fix Windows Event Viewer logs
def fix_windows_event_viewer_csv(df: pd.DataFrame) -> pd.DataFrame:
    """
    Windows Security CSV (like the one you uploaded) has:
      headers: Keywords,Date and Time,Source,Event ID,Task Category
      rows:   Audit Success,11/13...,Microsoft...,4624,Logon,<Message>

    That means there are 6 values for 5 headers, and pandas shifts everything
    left and uses 'Audit Success' as the index. We fix that here and produce:

      Keywords | Date and Time | Source | Event ID | Task Category | Message
    """
    expected_cols = ["Keywords", "Date and Time", "Source", "Event ID", "Task Category"]

    if list(df.columns) == expected_cols and df.index.dtype == object:
        # Reconstruct the correct columns using index + shifted columns
        fixed = pd.DataFrame({
            "Keywords": df.index,
            "Date and Time": df["Keywords"].values,
            "Source": df["Date and Time"].values,
            "Event ID": df["Source"].values,
            "Task Category": df["Event ID"].values,
            "Message": df["Task Category"].values,
        })
        fixed.reset_index(drop=True, inplace=True)
        return fixed

    # Otherwise, leave as-is
    return df.reset_index(drop=True)


# extracting time content
def add_time_for_ai(df: pd.DataFrame) -> pd.DataFrame:
    """
    For the AI-only copy: if there's a time-like column, copy it to _time
    WITHOUT renaming or removing the original column.
    """
    if "_time" in df.columns:
        return df

    candidates = [
        "Date and Time",
        "TimeCreated",
        "Time Generated",
        "Timestamp",
        "Time",
        "Created",
        "EventTime",
        "@timestamp",
    ]
    lower_map = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower_map:
            df["_time"] = df[lower_map[cand.lower()]]
            return df

    df["_time"] = None
    return df


# need to list columns that AI should look at
def pick_useful_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Keep only fields that are usually interesting for incident summaries."""
    useful_names = {
        "_time",
        "time",
        "timestamp",
        "eventcode",
        "event id",
        "event_id",
        "computername",
        "machine",
        "hostname",
        "targetusername",
        "subjectusername",
        "user",
        "account name",
        "ipaddress",
        "source_network_address",
        "ip",
        "image",
        "process",
        "commandline",
        "command line",
        "message",
        "task category",
        "keywords",
        "source",
        "provider name",
        "logon type",
        "date and time",
    }
    keep = []
    for c in df.columns:
        if str(c).lower() in useful_names:
            keep.append(c)
    return df[keep] if keep else df


# preview table
def build_preview_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Preview:
      If we have standard fixed Windows Security columns, show exactly:
        Source | Event ID | Task Category | Date and Time
      otherwise show the first few raw columns.
    """
    cols = df.columns
    if all(c in cols for c in ["Source", "Event ID", "Task Category", "Date and Time"]):
        return df[["Source", "Event ID", "Task Category", "Date and Time"]].head(25).copy()

    return df.head(25).copy()


# send data off in chunks that can be accepted
def compress_df_for_model(df_small: pd.DataFrame) -> pd.DataFrame:
    """
    Reduce the size of the data we send to the model:
    - Limit number of rows (sample evenly across the file)
    - Truncate very long text fields
    """
    df = df_small.copy().astype(str)

    # limit rows
    if len(df) > MAX_ROWS_TO_MODEL:
        step = max(1, len(df) // MAX_ROWS_TO_MODEL)
        df = df.iloc[::step].head(MAX_ROWS_TO_MODEL)

    # shorten long text in each column
    for c in df.columns:
        df[c] = df[c].str.slice(0, MAX_CHARS_PER_FIELD)

    return df


# local LLM (LM Studio)
client = OpenAI(base_url=LM_BASE_URL, api_key=API_KEY)


# main prompt for output
def ai_global_summary(df_small: pd.DataFrame) -> str:
    """
    Summarize the uploaded log into a single incident-style narrative.
    """
    sample = compress_df_for_model(df_small).to_dict(orient="records")
    messages = [
        {
            "role": "system",
            "content": (
                "You are a professional SOC analyst with over 20 years of experience. You will be given Windows/Splunk CSV logs.\n"
                "Write a concise incident-style summary with 6–10 sentences that includes:\n"
                "- Time window of activity\n"
                "- Main users, hosts, and IPs involved\n"
                "- Notable events and Event IDs (e.g., 4625, 4624, Sysmon IDs)\n"
                "- Likely scenario (e.g., normal sign-in, brute force attempt, suspicious admin action)\n"
                "- MITRE ATT&CK techniques (name and ID) when clearly applicable\n"
                "- Overall risk level and a conclusion.\n"
                "Use a neutral, professional tone and refer to concrete indicators from the data."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(sample, ensure_ascii=False),
        },
    ]
    resp = client.chat.completions.create(
        model=LM_MODEL,
        messages=messages,
        temperature=TEMP,
        max_tokens=MAX_TOKENS,
    )
    return resp.choices[0].message.content


# further investigation (different section) prompt
def ai_further_investigation(df_small: pd.DataFrame) -> str:
    """
    Suggest follow-up investigation steps and hardening actions based on the data.
    """
    sample = compress_df_for_model(df_small).to_dict(orient="records")
    messages = [
        {
            "role": "system",
            "content": (
                "You are advising a blue-team responder. Based on these log rows, output a practical checklist "
                "with clear format using Markdown:\n\n"
                "Create a checklist header titled Further Investigation:\n\n"
                "## Related Event IDs\n"
                "- List specific Windows / Sysmon Event IDs that should be checked in more detail.\n\n"
                "## Potentially Related Sources\n"
                "- Suggest log sources to correlate (e.g., AD, Defender, firewall, proxy, DNS, EDR).\n\n"
                "## Containment & Removal\n"
                "- If this activity could be malicious, list concrete containment/eradication steps.\n\n"
                "## Hardening & Future Prevention\n"
                "- Recommend configuration changes (GPO, logging, Defender, PS logging, MFA, etc.) to reduce risk.\n\n"
                "## Verify System Integrity\n"
                "- List what should be verified after fixes (e.g., no new admin accounts, no unusual logons).\n\n"
                "Be specific, short, and practical. Reference concrete Event IDs or fields when possible."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(sample, ensure_ascii=False),
        },
    ]
    resp = client.chat.completions.create(
        model=LM_MODEL,
        messages=messages,
        temperature=TEMP,
        max_tokens=MAX_TOKENS,
    )
    return resp.choices[0].message.content


# file upload
uploaded = st.file_uploader(
    "Upload a CSV from Windows Event Viewer or Splunk",
    type=["csv"],
)

if not uploaded:
    st.info("Upload a CSV file to begin.")
else:
    try:
        # read CSV file
        df_raw = pd.read_csv(uploaded, low_memory=False)

        # Windows Event Viewer errors when displaying columns
        df_fixed = fix_windows_event_viewer_csv(df_raw)

        st.success(f"Loaded {len(df_fixed)} rows from {uploaded.name}")

        # Preview section
        st.header("Preview")
        preview = build_preview_table(df_fixed)
        st.dataframe(
            preview,
            use_container_width=True,
            hide_index=True,
        )

        # view for AI
        df_ai = df_fixed.copy()
        df_ai = add_time_for_ai(df_ai)
        df_ai_small = pick_useful_columns(df_ai)

        st.divider()

        # File-Level AI Summary 
        st.header("File-Level AI Summary")
        with st.spinner("Asking local model for an incident-style summary..."):
            try:
                summary_text = ai_global_summary(df_ai_small)
                st.markdown(summary_text)
            except Exception as e:
                st.error(f"AI summary failed: {e}")
                summary_text = ""

        # Further Investigation
        st.markdown("---")
        with st.spinner("Asking local model for follow-up recommendations..."):
            try:
                further_text = ai_further_investigation(df_ai_small)
                st.markdown(further_text)
            except Exception as e:
                st.error(f"Further Investigation failed: {e}")
                further_text = ""

        # Download Markdown File
        if summary_text or further_text:
            combined_md = f"""# Incident Summary

{summary_text}

---

# Further Investigation

{further_text}

---

*Generated by Insight Analyst*
"""
            st.markdown("## Report Download")
            st.download_button(
                "Download the Full Markdown Report",
                data=combined_md.encode(),
                file_name="insight_analyst_report.md",
                mime="text/markdown",
            )

    except Exception as e:
        st.error(f"Failed to read CSV: {e}")
