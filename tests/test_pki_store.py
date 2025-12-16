import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from pki.store import PeerStore


def make_test_cert_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"store.example"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=10))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_peer_store_lifecycle(tmp_path, monkeypatch):
    peers_file = tmp_path / "peers.json"
    monkeypatch.setenv("PEERS_FILE", str(peers_file))

    store = PeerStore()
    cert_pem = make_test_cert_pem()

    fp = store.add_pending(cert_pem, note="test")
    assert fp in store.list_peers()

    rec = store.get_peer(fp)
    assert rec["status"] == "pending"

    store.approve_peer(fp, password="s3cr3t")
    rec2 = store.get_peer(fp)
    assert rec2["status"] == "trusted"
    assert store.verify_password(fp, "s3cr3t") is True
    assert store.verify_password(fp, "wrong") is False

    store.reject_peer(fp)
    assert store.get_peer(fp)["status"] == "rejected"
