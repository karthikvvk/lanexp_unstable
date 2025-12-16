import asyncio
import os
import tempfile
import struct

from pki.store import PeerStore
from pki.utils import fingerprint_pem
from receiver_api_functions import _handle_stream


class DummyWriter:
    def __init__(self):
        self.data = bytearray()

    def write(self, b: bytes):
        self.data += b

    async def drain(self):
        return

    def write_eof(self):
        pass


class DummyReader:
    def __init__(self, data: bytes):
        self._buf = bytearray(data)

    async def readexactly(self, n: int) -> bytes:
        if len(self._buf) < n:
            raise asyncio.IncompleteReadError(partial=bytes(self._buf), expected=n)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def read(self, n: int) -> bytes:
        if not self._buf:
            return b""
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def build_stream_bytes(fp: str, filename: str, payload: bytes) -> bytes:
    name = f"FP:{fp}|{filename}".encode('utf-8')
    name_len = struct.pack('!H', len(name))
    size = struct.pack('!Q', len(payload))
    return name_len + name + size + payload


def test_handle_stream_saves_trusted_peer(tmp_path, monkeypatch):
    # prepare peer store and mark fingerprint as trusted
    peers_file = tmp_path / "peers.json"
    monkeypatch.setenv('PEERS_FILE', str(peers_file))
    store = PeerStore()

    # create a fake cert and fingerprint
    cert_pem = "-----BEGIN CERTIFICATE-----\nMIID...FAKE...\n-----END CERTIFICATE-----"
    # we will use a made-up fingerprint here
    fp = 'a1b2c3d4e5f6'
    # add to store as trusted
    store._data[fp] = {
        'fingerprint': fp,
        'cert_pem': '',
        'status': 'trusted',
        'added_at': 0,
        'password_hash': None,
        'note': 'test'
    }
    store._save()

    payload = b'hello'
    bytes_stream = build_stream_bytes(fp, 'greeting.txt', payload)

    reader = DummyReader(bytes_stream)
    writer = DummyWriter()

    # use tmp_path as save_dir
    async def run():
        await _handle_stream(reader, writer, on_file_received=None, save_dir=str(tmp_path))

    asyncio.get_event_loop().run_until_complete(run())

    # file should be saved under tmp_path/<fp>/greeting.txt
    path = tmp_path / fp / 'greeting.txt'
    assert path.exists()
    assert path.read_bytes() == payload
