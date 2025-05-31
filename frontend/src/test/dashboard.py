import streamlit as st
import pandas as pd
import requests
import hashlib
import os
import magic
import plotly.express as px
from datetime import datetime

# ---------------------- CONFIGURATION ---------------------- #
st.set_page_config(page_title="ScaniFY - Cyber Dashboard", layout="wide")

# Custom CSS for futuristic neon UI
st.markdown(
    """
    <style>
        body { background-color: #0D1117; color: white; }
        .stApp { background-color: #0D1117; }
        .block-container { padding: 1.5rem; border-radius: 15px; }
        .stTabs { border-radius: 15px; }
        .stDataFrame { border-radius: 10px; }
        .stButton>button {
            background: linear-gradient(135deg, #00d4ff, #0077b6);
            border: none;
            color: white;
            border-radius: 12px;
            font-size: 16px;
            font-weight: bold;
            padding: 10px 25px;
            transition: 0.3s;
            box-shadow: 0px 0px 10px rgba(0, 255, 255, 0.6);
        }
        .stButton>button:hover {
            box-shadow: 0px 0px 20px rgba(0, 255, 255, 1);
            transform: scale(1.05);
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------- STORAGE ---------------------- #
SCAN_HISTORY_FILE = "scan_history.csv"

# Load scan history
def load_scan_history():
    if os.path.exists(SCAN_HISTORY_FILE):
        df = pd.read_csv(SCAN_HISTORY_FILE)

        # ✅ Ensure "Details" column exists
        if "Details" not in df.columns:
            df["Details"] = "N/A"

        return df
    else:
        return pd.DataFrame(columns=["Date", "Type", "Input", "Result", "Details"])

# Save scan result
def save_scan_history(scan_type, input_value, result, details="N/A"):
    df = load_scan_history()
    new_entry = pd.DataFrame([{
        "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Type": scan_type,
        "Input": input_value,
        "Result": result,
        "Details": details
    }])
    df = pd.concat([new_entry, df], ignore_index=True)
    df.to_csv(SCAN_HISTORY_FILE, index=False)

# ---------------------- UI DESIGN ---------------------- #
st.markdown("<h1 style='text-align: center;'>⚡ ScaniFY - Cybersecurity Dashboard</h1>", unsafe_allow_html=True)

# Sidebar Options
st.sidebar.markdown("### 🔧 Options")
show_scan_trends = st.sidebar.checkbox("📈 Show Scan Trends")

# ---------------------- DASHBOARD OVERVIEW ---------------------- #
st.subheader("📊 Overview")
col1, col2, col3 = st.columns(3)

history_df = load_scan_history()

with col1:
    st.metric("🔍 Total Scans", len(history_df))

with col2:
    file_scans = history_df[history_df["Type"] == "File"]
    st.metric("📂 Files Scanned", len(file_scans))

with col3:
    url_scans = history_df[history_df["Type"] == "URL"]
    st.metric("🔗 URLs Scanned", len(url_scans))

# Show trends only if checkbox is checked
if show_scan_trends and not history_df.empty:
    st.subheader("📈 Scan Trends")
    history_df["Date"] = pd.to_datetime(history_df["Date"])
    scan_count = history_df.groupby(history_df["Date"].dt.date).count()
    fig = px.line(scan_count, x=scan_count.index, y="Type", title="Scans Per Day", color_discrete_sequence=["#00d4ff"])
    st.plotly_chart(fig, use_container_width=True)

# ---------------------- MAIN TABS ---------------------- #
tab1, tab2, tab3 = st.tabs(["🔗 Scan URL", "📂 Scan File", "📜 Scan History"])

# ------------- URL SCANNING SECTION ------------- #
with tab1:
    st.subheader("🔗 Scan a URL")
    url = st.text_input("Enter a URL to scan:")
    if st.button("Scan URL"):
        if url:
            st.success(f"✅ Scanned {url} successfully!")
        else:
            st.error("⚠️ Please enter a valid URL.")

# ------------- FILE SCANNING SECTION ------------- #
with tab2:
    st.subheader("📂 Upload a File for Analysis")
    uploaded_file = st.file_uploader("Choose a file to scan", type=["exe", "pdf", "doc", "docx", "zip", "rar", "jpg", "png"])
    if uploaded_file:
        file_size = len(uploaded_file.getvalue())
        file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
        file_type = magic.from_buffer(uploaded_file.getvalue(), mime=True)
        st.json({
            "Filename": uploaded_file.name,
            "Size (bytes)": file_size,
            "SHA256": file_hash,
            "File Type": file_type,
        })
        save_scan_history("File", uploaded_file.name, "Scanned", f"SHA256: {file_hash}")

# ------------- SCAN HISTORY SECTION ------------- #
with tab3:
    st.subheader("📜 Scan History")
    if not history_df.empty:
        search_query = st.text_input("🔍 Search in History:")
        filtered_df = history_df[
            history_df.apply(lambda row: search_query.lower() in row.to_string().lower(), axis=1)
        ] if search_query else history_df
        st.dataframe(filtered_df[["Date", "Type", "Input", "Result", "Details"]])
    else:
        st.info("No scans have been performed yet.")

