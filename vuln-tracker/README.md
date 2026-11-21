# Vulnerability Tracker

This is a full-stack vulnerability findings management system developed for the Secure Software Development course. It acts as a centralized hub for security teams to receive, triage, assign, and track software vulnerabilities from both internal staff and external security researchers.


## Quick Start (Docker)

All dependencies, builds, database migrations, and Keycloak test accounts are provisioned automatically inside Docker containers.

### Prerequisites
- Docker Desktop/Engine
- Ports `5173` and `8081` available on localhost
- Dotnet 10 (only if you want to run the tests)

### 1. Clone the repository and enter the project folder
```
cd SSD_Project/vuln-tracker
```

### 2. Generate a local `.env` file

**Windows (PowerShell):**
```powershell
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create();
$b = @(16,16,24,32) | ForEach-Object { $a = New-Object byte[] $_; $rng.GetBytes($a); ,$a };
@(
  "POSTGRES_PASSWORD=$([BitConverter]::ToString($b[0]).Replace('-','').ToLower())",
  "KEYCLOAK_ADMIN_PASSWORD=$([BitConverter]::ToString($b[1]).Replace('-','').ToLower())",
  "OIDC_CLIENT_SECRET=$([BitConverter]::ToString($b[2]).Replace('-','').ToLower())",
  "ENCRYPTION_KEY_K1=$([Convert]::ToBase64String($b[3]))"
) | Set-Content -Encoding ascii .env
```

**Linux / macOS (Bash):**
```bash
cat <<EOF> .env
POSTGRES_PASSWORD=$(openssl rand -hex 16)
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -hex 16)
OIDC_CLIENT_SECRET=$(openssl rand -hex 24)
ENCRYPTION_KEY_K1=$(openssl rand -base64 32)
EOF
```

### 3. Build and start all containers
```
docker compose up --build -d
```

Wait roughly 30 seconds/1 minute for Keycloak to finish importing the realm and for the API to apply the database migrations


Once all 4 containers are running:
- **Application UI:** `http://localhost:5173`
- **Keycloak Identity Provider:** `http://localhost:8081`


## Test Users

Keycloak automatically imports the `vulntracker` realm (`vuln-tracker/keycloak/vulntracker-realm.json`) on startup with four pre-configured accounts covering every internal role.

| Username | Password | Role | Access Summary |
| :--- | :--- | :--- | :--- |
| `alice` | `PmPass123!` | **PM** | Full triage access: view, create, update, assign findings, set SLA targets, export/verify reports, and inspect/verify audit logs. |
| `dana` | `AnalystPass123!` | **Analyst** | Can view, create, update, and assign findings, and export/verify reports. Cannot set SLAs or read audit logs. |
| `bob` | `DevPass123!` | **Developer** | Can view findings and export/verify reports. Can only update findings assigned to them and cannot set status to `AcceptedRisk`. |
| `carol` | `AuditorPass123!` | **Auditor** | Strict read-only access to all findings, reports, and audit logs (including verification). Cannot modify any data. |
| *(Unauthenticated)* | *None* | **External Reporter** | Can submit a new finding via the public disclosure form on `/` and receive a reference ID. Cannot view internal data. |


## REST API Endpoints

All routes are accessed through the Nginx reverse proxy at `http://localhost:5173`.

| Method | Endpoint | Description | Auth / Policy Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Container health check. | Public |
| `GET` | `/api/auth/login` | Starts the Keycloak OIDC login flow. | Public |
| `POST` | `/api/auth/logout` | Clears the local session cookie and logs out of Keycloak. | Public / Authenticated |
| `GET` | `/api/auth/me` | Returns current authentication status, `sub`, username, and roles. | Public |
| `POST` | `/api/findings/public` | Submits an external vulnerability report (rate-limited). | Public |
| `GET` | `/api/findings` | Lists all findings (decrypted for authorized internal roles). | `PM`, `Analyst`, `Developer`, `Auditor` |
| `POST` | `/api/findings` | Creates a new internal finding. | `PM`, `Analyst` |
| `PUT` | `/api/findings/{id}` | Updates title, description, and status of a finding. | `PM`, `Analyst`, or assigned `Developer` (no `AcceptedRisk`) |
| `PATCH` | `/api/findings/{id}/assign` | Assigns a finding to a user by Keycloak `sub` ID. | `PM`, `Analyst` |
| `PATCH` | `/api/findings/{id}/sla` | Sets the SLA target due date on a finding. | `PM` |
| `GET` | `/api/reports/public-key` | Returns the active report-signing public key (PEM) and algorithm. | Public |
| `GET` | `/api/reports/export` | Exports a filtered, digitally signed JSON vulnerability report. | `PM`, `Analyst`, `Developer`, `Auditor` |
| `POST` | `/api/reports/verify` | Verifies the cryptographic signature and hash of an exported report. | `PM`, `Analyst`, `Developer`, `Auditor` |
| `GET` | `/api/auditlogs` | Lists recorded audit events (optionally filtered by `findingId`). | `PM`, `Auditor` |
| `GET` | `/api/auditlogs/verify` | Recomputes and validates the entire HMAC-SHA256 audit hash chain. | `PM`, `Auditor` |

