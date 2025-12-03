import streamlit as st
import requests
from typing import Optional

st.set_page_config(page_title="DNS Detection Auth", page_icon="🔐", layout="centered")

BACKEND_URL_DEFAULT = "http://127.0.0.1:8000"

if "token" not in st.session_state:
    st.session_state["token"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None

st.title("🔐 DNS Tunneling Detection - Auth")

backend_url = st.text_input("Backend URL", value=BACKEND_URL_DEFAULT, help="Base URL of FastAPI backend.")

mode = st.radio("Action", ["Login", "Register"], horizontal=True)

email = st.text_input("Email")
password = st.text_input("Password", type="password")

status_placeholder = st.empty()

def register(email: str, password: str) -> Optional[dict]:
    try:
        resp = requests.post(f"{backend_url}/register", json={"email": email, "password": password}, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        status_placeholder.error(f"Register failed: {resp.status_code} {resp.text}")
    except requests.exceptions.RequestException as e:
        status_placeholder.error(f"Backend unreachable: {e}")
    return None

def login(email: str, password: str) -> Optional[str]:
    # FastAPI OAuth2PasswordRequestForm expects form-urlencoded with 'username' and 'password'
    try:
        resp = requests.post(f"{backend_url}/login", data={"username": email, "password": password}, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("access_token")
        status_placeholder.error(f"Login failed: {resp.status_code} {resp.text}")
    except requests.exceptions.RequestException as e:
        status_placeholder.error(f"Backend unreachable: {e}")
    return None

submit = st.button("Submit")

if submit:
    if not email or not password:
        status_placeholder.warning("Please fill email and password.")
    else:
        if mode == "Register":
            user = register(email, password)
            if user:
                status_placeholder.success("Registered successfully. You can now login.")
        else:  # Login
            token = login(email, password)
            if token:
                st.session_state["token"] = token
                # Decode token locally to extract role if needed (optional)
                status_placeholder.success("Login successful. Redirecting...")
                # Attempt Streamlit page switch (requires multipage setup)
                try:
                    st.switch_page("frontend/dashboard.py")
                except Exception:
                    st.experimental_set_query_params(page="dashboard")
                    st.info("If not redirected, open dashboard page manually.")

st.divider()

if st.session_state.get("token"):
    st.success("You are logged in.")
    st.code(st.session_state["token"], language="text")
    if st.button("Go to Dashboard"):
        try:
            st.switch_page("frontend/dashboard.py")
        except Exception:
            st.experimental_set_query_params(page="dashboard")
            st.info("If not redirected, open dashboard page manually.")
else:
    st.caption("No active session.")

st.caption("Errors will display above. Ensure backend is running with: uvicorn backend.main:app --reload")
