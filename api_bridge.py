from datetime import datetime
from flask import Flask, request, jsonify
import os
import json
import requests
from startsetup import *
from scanner import *
from flask_cors import CORS
import platform
import getpass
import asyncio  # NEW
from sender_api_functions import quic_connect, send_file, close_connection  # NEW
from pki.store import PeerStore
from pki.utils import fingerprint_pem, load_cert_pem


app = Flask(__name__)

CHUNK_SIZE = 64 * 1024
ENV_FILE = ".env"
CORS(app, resources={r"/*": {"origins":"*"}})


# ----------------- Peer Discovery Responder ----------------- #
import threading

class PeerDiscoveryResponder(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.discovery_port = 4434
        self.discovery_msg = b"WHO_IS_PEER"
        self.response_prefix = b"I_AM_PEER"
        env = load_env_vars()
        self.host_ip = env.get("host", "0.0.0.0")

    def run(self):
        print(f"[*] Starting Peer Discovery Responder on UDP {self.discovery_port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # On Linux, SO_REUSEPORT allows multiple processes to bind to the same port
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass # Not available on all platforms
                
            try:
                sock.bind(('0.0.0.0', self.discovery_port))
            except Exception as e:
                print(f"[!] Peer Discovery Bind Failed: {e}")
                return

            while self.running:
                try:
                    data, addr = sock.recvfrom(1024)
                    if data == self.discovery_msg:
                        # Respond with I_AM_PEER <HOST_IP>
                        response = f"{self.response_prefix.decode()} {self.host_ip}".encode()
                        sock.sendto(response, addr)
                except Exception as e:
                    print(f"[!] Peer Discovery Error: {e}")

def start_peer_discovery():
    try:
        t = PeerDiscoveryResponder()
        t.start()
    except Exception as e:
        print(f"[-] Failed to start peer discovery: {e}")

# ----------------- Peer Discovery Responder ----------------- #



















@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200


@app.route("/listhost", methods=["GET"])
def listhost():
    """List available hosts in subnet"""
    env = load_env_vars()
    host = env["host"]
    
    host_list = gethostlist()
    
    # print(host_list)
    

    return jsonify(host_list)


@app.route("/osinfo", methods=["POST"])
def osinfo():
    """Return OS and user info for this peer"""
    try:
        os_name = platform.system().lower()
        user_name = getpass.getuser()
        print(f"OS Info Requested: OS={os_name}, User={user_name}")
        return jsonify({"os": os_name, "user": user_name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/listdir', methods=['POST'])
def list_directory():
    """
    List directory contents on THIS peer
    POST body: {"path": "/absolute/path"}
    """
    try:
        data = request.get_json(silent=True) or {}
        path = data.get("path")

        if not path:
            return jsonify({"status": "error", "message": "path is required"}), 400

        path = os.path.normpath(path)

        if not os.path.exists(path):
            return jsonify({
                "status": "error",
                "message": f"Path does not exist: {path}"
            }), 404

        # ---------------- FILE ----------------
        if os.path.isfile(path):
            st = os.stat(path)
            info = {
                "name": os.path.basename(path),
                "path": path,
                "is_directory": False,
                "size": st.st_size,
                "mtime": datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z",
            }
            return jsonify({
                "status": "success",
                "type": "file",
                "info": info
            }), 200

        # --------------- DIRECTORY ---------------
        if os.path.isdir(path):
            files = []

            try:
                entries = sorted(os.listdir(path))
            except PermissionError:
                return jsonify({
                    "status": "error",
                    "message": "Permission denied"
                }), 403

            for name in entries:
                full_path = os.path.join(path, name)

                try:
                    st = os.stat(full_path)
                    is_dir = os.path.isdir(full_path)

                    files.append({
                        "name": name,
                        "path": full_path,
                        "is_directory": is_dir,
                        "size": None if is_dir else st.st_size,
                        "mtime": datetime.utcfromtimestamp(
                            st.st_mtime
                        ).isoformat() + "Z",
                    })
                except PermissionError:
                    # Skip unreadable entries silently
                    continue
                except FileNotFoundError:
                    # Race condition (deleted between list/stat)
                    continue

            return jsonify({
                "status": "success",
                "type": "directory",
                "files": files
            }), 200

        return jsonify({
            "status": "error",
            "message": f"Unknown filesystem object: {path}"
        }), 400

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500



# ---------- NEW: trigger non-interactive QUIC send ----------
@app.route("/send_files", methods=["POST"])
def send_files():#ip=None):
    """
    Trigger a QUIC file send to a remote peer.

    JSON body:
    {
      "remote_host": "192.168.0.100",   # optional, uses DEST_HOST/HOST if missing
      "files": ["/abs/path/1", "/abs/path/2"]
    }
    """
    try:
        data = request.get_json() or {}
        files = data.get("files", [])
        remote_host = data.get("remote_host")
        # if ip:
        #     remote_host = ip
        if not isinstance(files, list) or not files:
            return jsonify({"status": "error", "message": "files must be a non-empty list"}), 400

        env = load_env_vars()
        if not remote_host:
            remote_host = env.get("dest_host") or env.get("recivhost") or env.get("host")

        if not remote_host:
            return jsonify({"status": "error", "message": "remote_host or DEST_HOST/HOST not set"}), 400

        port = env.get("port") or 4433

        # verify files exist
        valid_files = []
        missing = []
        for f in files:
            if os.path.isfile(f):
                valid_files.append(f)
            else:
                missing.append(f)

        if not valid_files:
            return jsonify({"status": "error", "message": "no valid files to send", "missing": missing}), 400

        async def _do_send():
            # For now read client cert & key (optional) and ca (required)
            env = load_env_vars()
            client_cert = env.get("CLIENT_CERT")
            client_key = env.get("CLIENT_KEY")
            ca_cert = env.get("CA_CERT")

            # SECURITY FIX: Enforce TLS verification
            if not ca_cert:
                raise ValueError(
                    "CA_CERT environment variable not set. "
                    "Cannot verify server certificate. "
                    "Set CA_CERT to enable secure connections."
                )

            conn = await quic_connect(
                host=remote_host,
                port=port,
                insecure=False,  # ALWAYS verify server certificate
                server_name=os.environ.get("SERVER_NAME"),
                client_cert=client_cert,
                client_key=client_key,
                ca_cert=ca_cert,
            )
            try:
                for path in valid_files:
                    await send_file(conn, path)
            finally:
                await close_connection(conn)

        asyncio.run(_do_send())

        return jsonify({
            "status": "success",
            "remote_host": remote_host,
            "port": port,
            "sent": valid_files,
            "missing": missing
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/pki/info", methods=["GET"])
def pki_info():
    ca_path = os.environ.get("CA_CERT")
    if ca_path and os.path.exists(ca_path):
        pem = open(ca_path).read()
        return {
            "has_ca": True,
            "fingerprint": fingerprint_pem(pem)
        }, 200
    return {"has_ca": False}, 200




@app.route("/receive_files", methods=["POST"])
def receive_files():
    """
    Request files from a remote peer (pull operation).
    This tells the REMOTE peer to send files to US.
    
    JSON body:
    {
      "remote_host": "192.168.0.100",  # The peer that HAS the files
      "files": ["/remote/path/1"],      # File paths on REMOTE peer
      "local_dest": "/local/path"       # Not used, but kept for clarity
    }
    """
    try:
        data = request.get_json() or {}
        remote_host = data.get("remote_host")
        files = data.get("files", [])
        
        if not remote_host:
            return jsonify({"status": "error", "message": "remote_host is required"}), 400
            
        if not isinstance(files, list) or not files:
            return jsonify({"status": "error", "message": "files must be a non-empty list"}), 400

        # Get OUR IP address (where files should be sent)
        env = load_env_vars()
        our_host = env.get("host")
        
        if not our_host:
            return jsonify({"status": "error", "message": "Cannot determine local host IP"}), 500

        # Tell the REMOTE peer to send files to US
        # This is the key insight: we call the remote's /send_files endpoint
        # and pass OUR IP as the destination
        try:
            response = requests.post(
                f"http://{remote_host}:5000/send_files",
                json={
                    "remote_host": our_host,  # Send to US
                    "files": files            # Files on REMOTE system
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                return jsonify({
                    "status": "success",
                    "message": f"Requested {len(files)} file(s) from {remote_host}",
                    "remote_response": result
                }), 200
            else:
                return jsonify({
                    "status": "error",
                    "message": f"Remote peer returned error: {response.text}"
                }), response.status_code
                
        except requests.RequestException as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to contact remote peer: {str(e)}"
            }), 500

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route('/peers', methods=['GET'])
def list_peers():
    """List known peers and their trust status."""
    try:
        store = PeerStore()
        peers = store.list_peers()
        return jsonify({"status": "success", "peers": peers}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500




@app.route("/pki/ca", methods=["GET"])
def fetch_ca():
    ca_path = os.environ.get("CA_CERT")
    if not ca_path or not os.path.exists(ca_path):
        return {"error": "CA not initialized"}, 404
    return send_file(ca_path)





@app.route('/peers/approve', methods=['POST'])
def approve_peer():
    try:
        data = request.get_json() or {}
        fp = data.get('fingerprint')
        password = data.get('password')
        if not fp:
            return jsonify({'status': 'error', 'message': 'fingerprint required'}), 400
        store = PeerStore()
        store.approve_peer(fp, password=password)
        return jsonify({'status': 'success', 'fingerprint': fp}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/peers/reject', methods=['POST'])
def reject_peer():
    try:
        data = request.get_json() or {}
        fp = data.get('fingerprint')
        if not fp:
            return jsonify({'status': 'error', 'message': 'fingerprint required'}), 400
        store = PeerStore()
        store.reject_peer(fp)
        return jsonify({'status': 'success', 'fingerprint': fp}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/peers/verify', methods=['POST'])
def verify_peer_password():
    try:
        data = request.get_json() or {}
        fp = data.get('fingerprint')
        password = data.get('password')
        if not fp or not password:
            return jsonify({'status': 'error', 'message': 'fingerprint and password required'}), 400
        store = PeerStore()
        ok = store.verify_password(fp, password)
        return jsonify({'status': 'success', 'verified': bool(ok)}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



if __name__ == "__main__":
    start_peer_discovery()
    app.run(host='0.0.0.0', port=5000, debug=True)