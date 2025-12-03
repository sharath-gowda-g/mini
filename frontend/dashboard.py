import streamlit as st
import requests
import time

st.set_page_config(page_title="DNS Detection Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ DNS Tunneling Detection Dashboard")

token = st.session_state.get("token")
backend_url = st.session_state.get("backend_url", "http://127.0.0.1:8000")

if not token:
    st.error("Not authenticated. Please go to auth page.")
    st.stop()

st.success("Authenticated.")

status_col, action_col, logout_col = st.columns([1,1,1])

with status_col:
    try:
        r = requests.get(f"{backend_url}/capture_status", timeout=5)
        running = r.json().get("running", False) if r.status_code == 200 else False
    except Exception:
        running = False
    st.info(f"Capture running: {running}")

with action_col:
    if st.button("Start Capturing & Analyzing"):
        try:
            resp = requests.post(f"{backend_url}/start_capture", headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if resp.status_code == 200:
                st.success(f"Start result: {resp.json().get('status')}")
            else:
                st.error(f"Failed start: {resp.status_code} {resp.text}")
        except requests.exceptions.RequestException as e:
            st.error(f"Backend unreachable: {e}")
    if st.button("Stop Capture"):
        try:
            resp = requests.post(f"{backend_url}/stop_capture", headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if resp.status_code == 200:
                st.info(f"Stop result: {resp.json().get('status')}")
            else:
                st.error(f"Failed stop: {resp.status_code} {resp.text}")
        except requests.exceptions.RequestException as e:
            st.error(f"Backend unreachable: {e}")

with logout_col:
    if st.button("Logout"):
        st.session_state.clear()
        st.success("Logged out.")
        try:
            st.switch_page("frontend/auth_app.py")
        except Exception:
            st.experimental_set_query_params(page="auth")
            st.info("Navigate back to auth page manually if not redirected.")

st.subheader("Live Suspicious Queries")
auto_refresh = st.checkbox("Auto-refresh (2s)", value=True)
placeholder_table = st.empty()

def load_table():
    try:
        resp = requests.get(f"{backend_url}/user/suspicious", headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                placeholder_table.dataframe(data)
            else:
                placeholder_table.info("No suspicious queries logged yet.")
        else:
            placeholder_table.error(f"Fetch failed: {resp.status_code} {resp.text}")
    except requests.exceptions.RequestException as e:
        placeholder_table.error(f"Backend unreachable: {e}")

load_table()

if auto_refresh:
    # Use dummy loop for one short polling cycle in Streamlit rerun context
    time.sleep(2)
    load_table()

st.divider()
st.caption("Dashboard uses token in session state. Ensure backend running. Start capture to auto-analyze new DNS log lines into suspicious entries.")
