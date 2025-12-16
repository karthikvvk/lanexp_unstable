# PKI and TOFU (Overview)

This project now includes a minimal PKI/TOFU implementation for peer-to-peer
certificate-based authentication.

Environment variables (new):

- `CA_CERT` -- path to root CA PEM used for verifying client/server certs (optional)
- `CLIENT_CERT` -- path to this peer's certificate PEM (optional)
- `CLIENT_KEY` -- path to this peer's private key PEM (optional)
- `PEERS_FILE` -- path to peers JSON store (default: `pkica_export/peers.json`)
- `TOFU_MODE` -- (future) mode for automatic acceptance or manual

REST endpoints (new):

- `GET /peers` -- list known peers and status (pending/trusted/rejected)
- `POST /peers/approve` -- approve a pending peer (`{"fingerprint": "...", "password": "..."}`)
- `POST /peers/reject` -- reject a peer (`{"fingerprint": "..."}`)
- `POST /peers/verify` -- verify a peer password (`{"fingerprint": "...", "password": "..."}`)

How TOFU works (short):

- The sender prefixes the filename with `FP:<sha256>|` containing the SHA-256
  fingerprint of its certificate when a client certificate is available.
- The receiver consults the peer store. If the fingerprint is unknown, it is
  recorded as `pending` and the transfer is rejected until an operator approves
  the fingerprint via the `/peers/approve` endpoint.

Security note: at present, the receiver relies on the fingerprint supplied by
the sender in the file header. We also support configuring mutual TLS (mTLS)
by providing `CA_CERT` to the receiver which will require client certificates
at TLS level. Future work: extract the TLS-presented client cert from the
QUIC handshake and verify it matches the fingerprint in the header.
