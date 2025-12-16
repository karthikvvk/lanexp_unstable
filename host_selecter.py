# pages/1_Select_Host.py
import streamlit as st
import requests
import json
from pathlib import Path
import os
from dotenv import load_dotenv, set_key
from startsetup import *

st.set_page_config(page_title="Select Host", layout="centered")

env = load_env_vars()
host_ip, user, certi, sys, interface, outdir, srcdir, port = (
    env["host"],
    env["user"],
    env["certi"],
    env["system"],
    env["interface"],
    env["out_dir"],
    env["src"],
    env["port"],
)
# Build backend base url strictly from HOST + port
BACKEND = f"http://{host_ip}:5000"

# ---------- UI ----------
st.title("🌐 Select Network Host")
st.write("This page reads values directly from your `.env` file. It will not auto-detect or guess addresses.")
st.caption("When you Connect, only DEST_HOST in `.env` is updated (no other keys).")

with st.expander("📄 Loaded Environment Values", expanded=False):
    st.json({
        "HOST": host_ip,
        "BACKEND_PORT": port,
        "OUTDIR": outdir,
        "SRCDIR": srcdir,
        "USER": user,
        "SYSTEM": sys,
        "INTERFACE": interface,
    })

# ---------- Fetch hosts from backend (exact endpoint /listhost) ----------
@st.cache_data(show_spinner=True)
def fetch_hosts():
    """
    Calls the backend discovery endpoint at /listhost.
    Returns a list of host entries (or empty list on error).
    Each host entry is expected to be a dict with keys like "host", "user", "os".
    """
    try:
        url = f"{BACKEND.rstrip('/')}/listhost"
        r = requests.get(url)
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and isinstance(data.get("hosts"), list):
                    return data.get("hosts")
                return []
            except Exception:
                return []
        return []
    except Exception:
        return []

if st.button("🔄 Scan Network Hosts"):
    fetch_hosts.clear()
    st.rerun()

hosts = fetch_hosts()

if not hosts:
    st.warning("No hosts returned by backend at /listhost. You may add a manual host below.")
else:
    st.success(f"{len(hosts)} host(s) found.")

# allow manual add if backend empty
manual_ip = ""
manual_user = ""
if not hosts:
    manual_ip = st.text_input("Manual host IP (e.g. 192.168.0.55)", value="")
    manual_user = st.text_input("Manual username (optional)", value="")

# ---------- Host grid + selection ----------
display_hosts = hosts if hosts else ([{"host": manual_ip, "user": manual_user or "unknown", "os": "unknown"}] if manual_ip else [])

cols = st.columns(3)
for i, h in enumerate(display_hosts):
    h_ip = h.get("host")
    if not h_ip:
        continue
    h_os = h.get("os", "unknown")
    h_user = h.get("user", "unknown")
    btn_label = f"{h_user}@{h_ip} ({h_os})"
    if cols[i % 3].button(btn_label, key=f"host_{i}_{h_ip}"):
        # Immediately select host + user (no password)
        sel_ip = h_ip
        sel_user = h_user
        sel_os = h_os

        # save to host_list.json for quick reuse (password omitted)
        save_file = Path("host_list.json")
        all_data = []
        if save_file.exists():
            try:
                with open(save_file, "r") as f:
                    all_data = json.load(f)
            except Exception:
                all_data = []
        new_entry = {"ip": sel_ip, "username": sel_user, "password": "", "os_type": sel_os}
        found = False
        for e in all_data:
            if e.get("ip") == sel_ip:
                e.update(new_entry)
                found = True
                break
        if not found:
            all_data.append(new_entry)
        try:
            with open(save_file, "w") as f:
                json.dump(all_data, f, indent=4)
        except Exception:
            # ignore file write errors (best-effort)
            pass

        # update .env: ONLY DEST_HOST
        try:
            set_key(".env", "DEST_HOST", sel_ip)
        except Exception:
            # fallback: append/overwrite manually
            try:
                envp = Path(".env")
                lines = []
                if envp.exists():
                    lines = envp.read_text().splitlines()
                out = {}
                for line in lines:
                    if "=" in line:
                        k, v = line.split("=", 1)
                        out[k.strip()] = v.strip()
                out.update({"DEST_HOST": sel_ip})
                with open(envp, "w") as f:
                    for k, v in out.items():
                        f.write(f"{k}={v}\n")
            except Exception:
                pass

        # set runtime env so other pages can pick it up immediately
        os.environ["DEST_HOST"] = sel_ip

        # immediate override for File Manager page (session-only)
        st.session_state["REMOTE_HOST"] = sel_ip
        st.session_state["REMOTE_USER"] = sel_user
        st.session_state["REMOTE_PASS"] = ""  # no password required
        st.session_state["remote_override_api"] = f"http://{sel_ip}:5000"
        st.session_state["REMOTE_OS"] = sel_os

        st.success(f"Selected host {sel_user}@{sel_ip} — DEST_HOST updated.")

        # navigate to file manager (try switch_page, fallback to goto flag)
        try:
            st.switch_page("pages/fs_ui.py")
        except Exception:
            st.session_state["goto_page"] = "file_manager"
            st.rerun()

