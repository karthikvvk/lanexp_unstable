#!/usr/bin/env python3
import asyncio
import os
import sys
from elevate import elevate
from startsetup import load_env_vars
from receiver_api_functions import start_receiver, stop_receiver
# elevate()

def on_file_received(filepath: str, filesize: int) -> None:
    """
    Callback invoked for each fully received file.
    """
    print(f"[receiver] Received file: {filepath} ({filesize} bytes)")


async def main() -> None:
    # Load env variables from .env via your helper
    env = load_env_vars()

    recivhost = env.get("recivhost") or "0.0.0.0"
    port = env.get("port") or 4433
    cert_path = env.get("certi") or "cert.pem"
    key_path = env.get("key") or "key.pem"
    ca_cert = "/home/muruga/workspace/quic_explorer/stable_v2/lanfxplorer/pkica_export/ca.pem"#env.get("ca_cert") or env.get("CA_CERT")# or None
    out_dir = env.get("out_dir") or os.getcwd()

    # Basic checks
    if not os.path.isfile(cert_path):
        print(f"[receiver] ERROR: certificate file not found: {cert_path}")
        sys.exit(1)

    if not os.path.isfile(key_path):
        print(f"[receiver] ERROR: key file not found: {key_path}")
        sys.exit(1)

    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    print(f"[receiver] Loaded from env:")
    print(f"          RECIVHOST={recivhost}")
    print(f"          PORT={port}")
    print(f"          CERTI={cert_path}")
    print(f"          KEY={key_path}")
    print(f"          OUTDIR={out_dir}")

    # Initialize CA Manager to handle CA duties if we are the CA
    from pki.ca_service import CAManager
    
    # We use current directory as cert directory, same as startsetup.py
    # CAManager needs the actual IP to advertise itself, not 0.0.0.0
    ca_ip = env.get("host") or recivhost
    ca_mgr = CAManager(ca_ip, os.getcwd())
    
    # Check if we are CA and start service if so
    if ca_mgr.check_ca_status():
        print(f"[receiver] CA keys found in {os.getcwd()}. Starting CA Service (Signing + Discovery)...")
        print(f"[receiver] CA will be advertised at {ca_ip}")
        await ca_mgr.start_ca_service()
    else:
        print("[receiver] No CA keys found locally. Running as standard peer.")

    # Start the QUIC receiver using the API
    server = await start_receiver(
        host=recivhost,
        port=port,
        certificate=cert_path,
        private_key=key_path,
        ca_cert=ca_cert,
        require_client_cert=True,
        on_file_received=on_file_received,
        save_dir=out_dir,
    )

    print(f"[receiver] Listening on {recivhost}:{port}")
    print("[receiver] Press Ctrl+C to stop.")

    try:
        await asyncio.Future()  # run forever
    finally:
        await stop_receiver(server)
        print("[receiver] Server stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[receiver] KeyboardInterrupt, exiting.")
