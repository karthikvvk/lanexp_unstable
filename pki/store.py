"""Simple JSON-backed peer store for TOFU decisions.

This stores peers in a JSON file with 0600 permissions. Passwords are hashed
with bcrypt when provided. Certificate PEMs are encrypted at rest using Fernet.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Dict, Optional

import bcrypt
from cryptography.fernet import Fernet

from .utils import fingerprint_pem, load_cert_pem


class PeerStoreError(Exception):
    pass


class PeerStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get("PEERS_FILE") or os.path.join(os.getcwd(), "pkica_export", "peers.json")
        self._lock = threading.Lock()
        self._data: Dict[str, Dict] = {}
        self._encryption_key = self._load_or_create_key()
        self._cipher = Fernet(self._encryption_key)
        self._ensure_file()
        self._load()

    def _load_or_create_key(self) -> bytes:
        """Load or create encryption key for certificate storage."""
        key_file = os.path.join(os.path.dirname(self.path), ".peers_key")
        if os.path.exists(key_file):
            try:
                with open(key_file, "rb") as f:
                    return f.read()
            except Exception:
                pass
        
        # Generate new key
        key = Fernet.generate_key()
        try:
            with open(key_file, "wb") as f:
                f.write(key)
            os.chmod(key_file, 0o600)
        except Exception:
            pass
        return key

    def _ensure_file(self) -> None:
        directory = os.path.dirname(self.path)
        os.makedirs(directory, exist_ok=True)
        if not os.path.exists(self.path):
            with open(self.path, "w") as f:
                json.dump({}, f)
            # Restrict permissions
            try:
                os.chmod(self.path, 0o600)
            except Exception:
                pass

    def _load(self) -> None:
        with self._lock:
            try:
                with open(self.path, "r") as f:
                    data = json.load(f)
                    # Decrypt cert_pem fields
                    self._data = {}
                    for fp, rec in data.items():
                        if rec.get("cert_pem"):
                            try:
                                encrypted = rec["cert_pem"].encode()
                                decrypted = self._cipher.decrypt(encrypted).decode()
                                rec["cert_pem"] = decrypted
                            except Exception:
                                # Already plaintext, corrupted, or wrong key - keep as-is
                                pass
                        self._data[fp] = rec
            except (json.JSONDecodeError, FileNotFoundError):
                self._data = {}

    def _save(self) -> None:
        with self._lock:
            # Encrypt cert_pem before saving
            data_to_save = {}
            for fp, rec in self._data.items():
                rec_copy = dict(rec)
                if rec_copy.get("cert_pem"):
                    try:
                        encrypted = self._cipher.encrypt(rec_copy["cert_pem"].encode()).decode()
                        rec_copy["cert_pem"] = encrypted
                    except Exception:
                        # If encryption fails, keep plaintext (fallback)
                        pass
                data_to_save[fp] = rec_copy
            
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump(data_to_save, f, indent=2)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
                os.chmod(self.path, 0o600)
            except Exception:
                if os.path.exists(tmp):
                    os.remove(tmp)

    def list_peers(self) -> Dict[str, Dict]:
        return dict(self._data)

    def get_peer(self, fingerprint: str) -> Optional[Dict]:
        return self._data.get(fingerprint.lower())

    def add_pending(self, cert_pem: str, note: Optional[str] = None) -> str:
        fp = fingerprint_pem(cert_pem)
        now = int(time.time())
        if fp in self._data:
            return fp

        self._data[fp] = {
            "fingerprint": fp,
            "cert_pem": cert_pem if isinstance(cert_pem, str) else cert_pem.decode("utf-8"),
            "status": "pending",
            "added_at": now,
            "password_hash": None,
            "note": note,
        }
        self._save()
        return fp

    def approve_peer(self, fingerprint: str, password: Optional[str] = None) -> None:
        fp = fingerprint.lower()
        if fp not in self._data:
            raise PeerStoreError("peer not found")
        self._data[fp]["status"] = "trusted"
        if password:
            self.set_password(fp, password)
        self._save()

    def reject_peer(self, fingerprint: str) -> None:
        fp = fingerprint.lower()
        if fp not in self._data:
            raise PeerStoreError("peer not found")
        self._data[fp]["status"] = "rejected"
        self._data[fp]["rejected_at"] = int(time.time())
        self._save()

    def revoke_peer(self, fingerprint: str) -> None:
        """Revoke a previously trusted peer (like CRL).
        
        :param fingerprint: Fingerprint of peer to revoke
        :raises PeerStoreError: If peer not found
        """
        fp = fingerprint.lower()
        if fp not in self._data:
            raise PeerStoreError("peer not found")
        self._data[fp]["status"] = "revoked"
        self._data[fp]["revoked_at"] = int(time.time())
        self._save()

    def is_revoked(self, fingerprint: str) -> bool:
        """Check if a peer is revoked.
        
        :param fingerprint: Fingerprint of peer
        :return: True if revoked, False otherwise
        """
        fp = fingerprint.lower()
        rec = self._data.get(fp)
        return rec is not None and rec.get("status") == "revoked"

    def set_password(self, fingerprint: str, password: str) -> None:
        fp = fingerprint.lower()
        if fp not in self._data:
            raise PeerStoreError("peer not found")
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        self._data[fp]["password_hash"] = hashed.decode("utf-8")
        self._save()

    def verify_password(self, fingerprint: str, password: str) -> bool:
        fp = fingerprint.lower()
        rec = self._data.get(fp)
        if not rec or not rec.get("password_hash"):
            return False
        try:
            return bcrypt.checkpw(password.encode("utf-8"), rec["password_hash"].encode("utf-8"))
        except Exception:
            return False
