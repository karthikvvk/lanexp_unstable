"""Utility helpers for certificate handling and fingerprinting."""
from __future__ import annotations

import os
import hashlib
from typing import Union
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def load_cert_pem(path_or_pem: str) -> bytes:
    """Load certificate PEM from a file path or return the given PEM string as bytes.

    If the input contains 'BEGIN CERTIFICATE' it is treated as PEM content.
    Otherwise it is treated as a filesystem path and the file is read.
    """
    if "BEGIN CERTIFICATE" in path_or_pem:
        return path_or_pem.encode("utf-8")

    if os.path.isfile(path_or_pem):
        with open(path_or_pem, "rb") as f:
            return f.read()

    raise FileNotFoundError(f"Certificate PEM not found or invalid: {path_or_pem}")


def cert_pem_to_der(cert_pem: Union[str, bytes]) -> bytes:
    """Convert PEM (str or bytes) to DER bytes using cryptography.

    Raises on invalid input.
    """
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("utf-8")

    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_bytes(serialization.Encoding.DER)


def fingerprint_pem(cert_pem: Union[str, bytes]) -> str:
    """Return SHA-256 fingerprint (hex lowercase) for a PEM certificate."""
    der = cert_pem_to_der(cert_pem)
    h = hashlib.sha256(der).hexdigest().lower()
    return h


def verify_cert_validity(cert_pem: Union[str, bytes]) -> bool:
    """Check if certificate is not expired.
    
    :param cert_pem: Certificate in PEM format (str or bytes)
    :return: True if cert is valid (not expired), False otherwise
    """
    try:
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode()
        cert = x509.load_pem_x509_certificate(cert_pem)
        now = datetime.now(timezone.utc)
        # Handle both naive and aware datetimes from cryptography
        nvb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        nva = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        return nvb <= now <= nva
    except Exception:
        return False


def get_peer_cert_pem_from_writer(writer) -> str | None:
    """Attempt to extract peer certificate (PEM) from a QUIC stream writer.

    This inspects the transport/protocol objects attached to the writer and
    searches for certificate objects or DER bytes. Returns PEM as a string
    when found, otherwise None.
    
    NOTE: This is a best-effort extraction due to aioquic internals not exposing
    a public API for peer certificates. Use mTLS (CA_CERT) to ensure cert verification
    happens at TLS level.
    """
    try:
        transport = getattr(writer, "transport", None)
        if transport is None:
            return None

        protocol = getattr(transport, "protocol", None)
        if protocol is None:
            return None

        quic = getattr(protocol, "_quic", None)
        if quic is None:
            return None

        # Try SSL object first (most reliable)
        try:
            ssl_obj = getattr(quic, "_ssl_object", None)
            if ssl_obj and hasattr(ssl_obj, "getpeercert"):
                der_bytes = ssl_obj.getpeercert(binary_form=True)
                if der_bytes:
                    cert = x509.load_der_x509_certificate(der_bytes)
                    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        except Exception:
            pass

        # Inspect likely attributes on the QuicConnection or nested objects
        candidates = []
        for name in dir(quic):
            if "cert" in name.lower() or "peer" in name.lower():
                try:
                    val = getattr(quic, name)
                    candidates.append(val)
                except Exception:
                    continue

        # Try to find a DER/bytes certificate
        for val in candidates:
            # bytes or bytearray might be DER
            if isinstance(val, (bytes, bytearray)) and len(val) > 32:
                try:
                    cert = x509.load_der_x509_certificate(bytes(val))
                    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                except Exception:
                    continue

            # list/tuple of certs
            if isinstance(val, (list, tuple)) and val:
                for item in val:
                    try:
                        if isinstance(item, (bytes, bytearray)):
                            cert = x509.load_der_x509_certificate(bytes(item))
                            return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                        # cryptography.x509.Certificate
                        if hasattr(item, "public_bytes"):
                            pem = item.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                            return pem
                    except Exception:
                        continue

        if hasattr(quic, "tls"):
            tls = quic.tls
            # Try to find cert in tls object
            if hasattr(tls, "peer_certificate") and tls.peer_certificate:
                 return tls.peer_certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            
            # Look for _peer_certificate (private)
            if hasattr(tls, "_peer_certificate") and tls._peer_certificate:
                 return tls._peer_certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # No candidate found
        return None
    except Exception:
        return None


def generate_csr(private_key_pem: bytes, common_name: str) -> bytes:
    """Generate a Certificate Signing Request (CSR).
    
    :param private_key_pem: Private key bytes (PEM)
    :param common_name: Common Name (CN) for the subject
    :return: CSR bytes (PEM)
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(key, hashes.SHA256())
    
    return csr.public_bytes(serialization.Encoding.PEM)


def sign_csr(csr_pem: bytes, ca_cert_pem: bytes, ca_key_pem: bytes, days: int = 365) -> bytes:
    """Sign a CSR using the CA certificate and key.
    
    :param csr_pem: CSR bytes (PEM)
    :param ca_cert_pem: CA certificate bytes (PEM)
    :param ca_key_pem: CA private key bytes (PEM)
    :param days: Validity period in days
    :return: Signed certificate bytes (PEM)
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from datetime import timedelta
    
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    return cert.public_bytes(serialization.Encoding.PEM)
