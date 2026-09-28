
# Enis V4 Deployable Bridge
FastAPI bridge intended to sit behind a hosting provider's HTTPS/TLS proxy.

Endpoints cover health, admin-authenticated pairing/job creation/approval/status, device-authenticated outbound polling, and result return.

## Deploy
Docker-compatible hosting:
1. Deploy this directory/repository.
2. Set a long random `ENIS_V4_ADMIN_TOKEN` secret in the host secret manager.
3. TLS must be enabled by the hosting provider/reverse proxy.
4. Do not expose the admin token in the Windows client.
5. Pair the device once and store its device secret using Windows Credential Manager/DPAPI.

`render.yaml` is included as an example deployment descriptor, but this package has NOT been deployed to a real account by ChatGPT.

## Production hardening still required
The in-memory dictionaries are for first connectivity testing only. Before persistent use, replace them with PostgreSQL, hash/rotate device credentials, add rate limits, server-side audit records, one-time pairing expiry, result size limits, and authenticated user sessions.
