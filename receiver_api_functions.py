#!/usr/bin/env python3
"""
Receiver-side QUIC API functions using aioquic.

This module exposes a function-based API to start and stop a QUIC
listener. Each incoming stream is interpreted as one "file transfer"
using the same protocol as the sender:

    [2 bytes] filename length (big-endian unsigned short)
    [N bytes] filename (UTF-8)
    [8 bytes] file size (big-endian unsigned long long)
    [..]      file data

The file is saved with the original filename in the current working
directory (or wherever you redirect it to), and an optional callback
is invoked when a file is fully received.
"""

import asyncio
import os
import ssl
import struct
import inspect
from typing import Awaitable, Callable, Optional

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from pki.store import PeerStore
from pki.utils import fingerprint_pem, verify_cert_validity, get_peer_cert_pem_from_writer


# Type for the callback:
#   def on_file_received(filepath: str, filesize: int) -> None | Awaitable[None]
OnFileReceivedCallback = Callable[[str, int], object]


# -----------------------------
# Internal helpers
# -----------------------------

async def _call_callback(
    callback: Optional[OnFileReceivedCallback],
    filepath: str,
    filesize: int,
) -> None:
    if callback is None:
        return

    if inspect.iscoroutinefunction(callback):
        await callback(filepath, filesize)
    else:
        # Run sync callback in a thread to avoid blocking the event loop
        await asyncio.to_thread(callback, filepath, filesize)


async def _handle_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_file_received: Optional[OnFileReceivedCallback],
    save_dir: Optional[str] = None,
    require_client_cert: bool = False,
) -> None:
    """
    Handle a single incoming QUIC stream:
        - Extract TLS-presented client certificate (primary trust source)
        - Parse header (filename + size)
        - Verify TOFU status
        - Save file to disk
        - Invoke callback
        - Send ACK
    """
    try:
        # STEP 1: Extract TLS certificate FIRST (before reading user-supplied data)
        # This is the PRIMARY trust source, not the filename header
        tls_cert_pem = None
        tls_fp = None
        try:
            # Try basic get_extra_info debug
            peercert_info = writer.get_extra_info("peercert")
            
            tls_cert_pem = get_peer_cert_pem_from_writer(writer)
            if require_client_cert and not tls_cert_pem:
                 print("[WARNING Receiver] Client cert extraction failed (aioquic limitation). Proceeding to Password Auth logic.")
                 # Do not return/reject here. Let auth handle it.
                 # writer.write(b"REJECTED:no_client_cert")
                 # await writer.drain()
                 # return


            if tls_cert_pem:
                # Validate certificate is not expired
                if not verify_cert_validity(tls_cert_pem):
                    writer.write(b"REJECTED:cert_expired")
                    await writer.drain()
                    return
                tls_fp = fingerprint_pem(tls_cert_pem).lower()
        except Exception:
            pass
        
        # If mTLS is required and no cert was presented, reject immediately
        if require_client_cert and not tls_fp:
            writer.write(b"REJECTED:no_client_cert")
            await writer.drain()
            return

        # STEP 2: Read filename length (2 bytes)
        raw = await reader.readexactly(2)
        (name_len,) = struct.unpack("!H", raw)

        # STEP 3: Read filename bytes
        filename_bytes = await reader.readexactly(name_len)
        filename = filename_bytes.decode("utf-8")
        
        # Parse filename to extract header fingerprint marker if present
        # But we will IGNORE it if TLS cert doesn't match
        header_fp = None
        if filename.startswith("FP:") and "|" in filename:
            try:
                marker, rest = filename.split("|", 1)
                _, fp = marker.split(":", 1)
                header_fp = fp.lower()
                filename = rest
            except Exception:
                pass

        filename = os.path.basename(filename)

        # SPECIAL: Handle Auth Handshake
        if filename == "__AUTH__":
            # Read password
            raw = await reader.readexactly(8)
            (pass_len,) = struct.unpack("!Q", raw)
            # Limit password size to prevent DoS
            if pass_len > 1024:
                writer.write(b"AUTH_FAIL:too_long")
                await writer.drain()
                return

            # Check status in PeerStore (TOFU)
            peer_store = PeerStore()
            peer_status = "pending"
            if tls_fp:
                peer_status = peer_store.get_peer_status(tls_fp)
            
            # If trusted, check if we need to re-auth? 
            # For now, we enforce password auth ALWAYS on __AUTH__ stream.
            if peer_status == "rejected":
                writer.write(b"AUTH_FAIL:rejected_peer")
                await writer.drain()
                return

            password = (await reader.readexactly(pass_len)).decode("utf-8")
            
            # Verify Password
            env_pass = os.environ.get("P2P_PASSWORD")
            
            if not env_pass:
                # If no password set on receiver, deny all or allow all?
                # Safer to deny.
                writer.write(b"AUTH_FAIL:no_password_set")
                await writer.drain()
                return

            # Simple string comparison (for now) or bcrypt verify if hashed?
            # Existing store uses bcrypt. But here we compare against ENV var.
            # Let's support both: direct ENV compare OR store verify.
            # But the requirement says "verify received pass... trusted".
            
            is_valid = (password == env_pass)
            is_valid = (password == env_pass)
            
            if is_valid:
                # Mark as TRUSTED in PeerStore
                if tls_fp:
                    store = PeerStore() # Initialize PeerStore here if needed for update_peer_status
                    store.update_peer_status(tls_fp, "trusted")
                    print(f"[+] Peer {tls_fp[:8]}... authenticated and marked TRUSTED.")
                else:
                    print(f"[+] Peer authenticated via Password (no cert bound).")
                
                writer.write(b"AUTH_OK")
            else:
                print(f"[!] Authentication FAILED for peer {tls_fp if tls_fp else 'unknown'}")
                writer.write(b"AUTH_FAIL:invalid_password")
            
            await writer.drain()
            return


        # STEP 4: Verify fingerprint consistency
        # If both TLS and header fingerprints exist, they MUST match
        if tls_fp and header_fp and tls_fp != header_fp:
            writer.write(b"REJECTED:fingerprint_mismatch")
            await writer.drain()
            return
        
        # Use TLS fingerprint as authoritative (if available), fall back to header
        peer_fingerprint = tls_fp or header_fp

        # STEP 5: Read filesize (8 bytes)
        raw = await reader.readexactly(8)
        (filesize,) = struct.unpack("!Q", raw)

        # STEP 6: Check TOFU / peer store
        store = PeerStore()
        if peer_fingerprint:
            rec = store.get_peer(peer_fingerprint)
            
            # Check if revoked (like CRL)
            if store.is_revoked(peer_fingerprint):
                writer.write(b"REJECTED:revoked")
                await writer.drain()
                return
            
            if rec is None:
                # Unknown peer -> add pending and reject transfer
                if tls_cert_pem:
                    store.add_pending(cert_pem=tls_cert_pem, note="Auto-discovered via TLS")
                writer.write(b"REJECTED:pending")
                await writer.drain()
                return
            
            if rec.get("status") != "trusted":
                writer.write(b"REJECTED:not_trusted")
                await writer.drain()
                return
        elif require_client_cert:
            # mTLS required but no fingerprint extracted
            writer.write(b"REJECTED:cert_extraction_failed")
            await writer.drain()
            return

        # STEP 7: Determine output path
        base_dir = save_dir or os.getcwd()
        # if we have a fingerprint, save inside per-peer subdir
        if peer_fingerprint:
            base_dir = os.path.join(base_dir, peer_fingerprint)
        os.makedirs(base_dir, exist_ok=True)
        path = os.path.join(base_dir, filename)

        parent_dir = os.path.dirname(path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        
        # STEP 8: Read file data and write to disk
        bytes_written = 0
        with open(path, "wb") as f:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                bytes_written += len(chunk)

        # Invoke callback
        await _call_callback(on_file_received, path, bytes_written)

        # Send ACK
        writer.write(b"OK")
        await writer.drain()

    except asyncio.IncompleteReadError:
        # Stream closed unexpectedly
        pass
    except Exception as exc:
        # Log or handle any unexpected error
        pass
    finally:
        try:
            writer.write_eof()
            await writer.drain()
        except Exception:
            pass


# -----------------------------
# Public API
# -----------------------------

async def start_receiver(
    host: str = "0.0.0.0",
    port: int = 4433,
    *,
    certificate: str,
    private_key: str,
    ca_cert: Optional[str] = None,
    alpn_protocol: str = "file-transfer",
    on_file_received: Optional[OnFileReceivedCallback] = None,
    save_dir: Optional[str] = None,
    require_client_cert: bool = False,
):
    """
    Start a QUIC receiver (listener) that accepts incoming streams
    and saves each as a file with the original filename.

    :param host: Local host/IP to bind to.
    :param port: UDP port to listen on.
    :param certificate: Path to TLS certificate (PEM).
    :param private_key: Path to TLS private key (PEM).
    :param ca_cert: Path to CA certificate for verifying client certs (optional).
    :param alpn_protocol: ALPN string; must match sender's.
    :param on_file_received: Optional callback invoked on each file.
    :param save_dir: Directory to save incoming files; defaults to cwd.
    :param require_client_cert: If True, enforce mTLS (CA_CERT must be set).

    :return: The aioquic server object.
    :raises ValueError: If require_client_cert=True but ca_cert is not provided.
    """
    # Validate mTLS configuration
    if require_client_cert and not ca_cert:
        raise ValueError("require_client_cert=True but ca_cert is not provided")
    
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[alpn_protocol],
    )
    config.load_cert_chain(certificate, private_key)
    
    # If a CA certificate is provided, require and verify client certificates
    if ca_cert:
        config.load_verify_locations(cafile=ca_cert)
        config.verify_mode = ssl.CERT_REQUIRED
    elif require_client_cert:
        raise ValueError("require_client_cert=True but ca_cert not provided")

    def stream_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Spawn the coroutine to actually handle the stream
        asyncio.create_task(
            _handle_stream(
                reader,
                writer,
                on_file_received,
                save_dir,
                require_client_cert=require_client_cert or bool(ca_cert),
            )
        )

    server = await serve(
        host=host,
        port=port,
        configuration=config,
        stream_handler=stream_handler,
    )

    return server


async def stop_receiver(server) -> None:
    """
    Stop a previously started QUIC receiver.
    """
    server.close()
    await server.wait_closed()
