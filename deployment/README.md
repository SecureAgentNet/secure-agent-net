# SecureAgentNet Gateway Production Deployment Guide

This guide details how to configure, secure, and deploy the SecureAgentNet gateway in a production multi-host network. 

---

## 1. Production Architecture

External agent clients (like Windows VMs or remote hosts) connect exclusively over **HTTPS (port 443)**. The gateway architecture restricts public network access to backend services using Docker network isolation and localhost bindings.

```
                  [ External Agent Clients ]
                              │
                    HTTPS (Port 443) only
                              ▼
                   [ Nginx Reverse Proxy ]
                              │
                    Internal Docker Network
                              ▼
           ┌──────────────────┴──────────────────┐
           ▼                                     ▼
   [ Gateway API ]                        [ Web Dashboard ]
      (port 5000)                           (port 5000/WSGI)
           │                                     │
           ├───────────────┬─────────────────────┤
           ▼               ▼                     ▼
     [ Postgres ]       [ Redis ]            [ Vault ]
   (127.0.0.1:5432)  (127.0.0.1:6379)     (127.0.0.1:8200)
```

### Security Hardening Measures
* **TLS Encryption:** All traffic is encrypted using TLSv1.2 or TLSv1.3 with secure ciphers.
* **Localhost Port Bindings:** Postgres, Redis, Vault, and Ollama ports are bound strictly to `127.0.0.1` so they cannot be accessed from the network.
* **Sandbox Limits:** Container execution CPU and memory quotas are enforced in `docker-compose.prod.yml`.
* **PII Redaction & Circuit Breaking:** Enabled on all incoming execute requests to prevent data exfiltration.

---

## 2. Prerequisites

Ensure the following packages are installed on the deployment host:
* Docker Engine 24.0+
* Docker Compose V2
* OpenSSL (for certificate generation)

---

## 3. Step-by-Step Deployment

Follow these steps to deploy the production stack:

### Step 3.1: Configure Environment Variables
Copy `.env.example` to `.env` if you haven't already:
```bash
cp .env.example .env
```
Edit `.env` to configure secure secrets:
* `POSTGRES_PASSWORD`: Use a strong database password.
* `REDIS_PASSWORD`: Use a strong Redis password.
* `SECRET_KEY`: Use a cryptographically secure key (e.g. generated via `openssl rand -hex 32`).

### Step 3.2: Generate TLS/SSL Certificates
For internal or local multi-host testing, run the certificate generator script to create self-signed certificates:
```bash
bash deployment/scripts/generate_certs.sh
```
This writes `securenet.crt` and `securenet.key` to the `deployment/certs/` directory, which Nginx mounts on startup.

> [!NOTE]
> For actual public production deployments, replace these with valid certificates from **Let's Encrypt** or your organization's Certificate Authority (CA).

### Step 3.3: Deploy the Docker Stack
Build the gateway image and deploy the production services using the deploy script:
```bash
bash deployment/scripts/deploy.sh --mode docker
```
This builds the production Docker image and runs the stack inside background containers.

### Step 3.4: Initialize & Unseal Vault
HashiCorp Vault starts in a sealed state with raft storage. Run the Vault initializer script to bootstrap the cryptographic infrastructure:
```bash
bash deployment/scripts/init_vault.sh
```
This script:
1. Runs `vault operator init` to initialize the store (creates a key share).
2. Writes the unseal keys and root token to `deployment/vault_keys.txt`.
3. Unseals Vault automatically.
4. Enables the `transit` secrets engine (for audit log hashing) and `kv-v2` secrets engine (for agent credentials).
5. Automatically updates your `.env` file with the generated `VAULT_TOKEN`.

> [!WARNING]
> Save the contents of `deployment/vault_keys.txt` to a secure offline vault (e.g., 1Password, Bitwarden) and **delete the local file** immediately in a real production environment.

### Step 3.5: Restart Gateway App Container
Since the Vault token has been generated and written to `.env`, restart the app container to load the active credentials:
```bash
docker compose -f deployment/docker-compose.prod.yml restart app
```

---

## 4. Accessing the System

Once deployed, the gateway services are available at:
* **Dashboard & API:** `https://<YOUR_SERVER_IP>/dashboard/`
* **Health Check:** `https://<YOUR_SERVER_IP>/health`
* **MCP Execute Endpoint:** `https://<YOUR_SERVER_IP>/api/v1/mcp/execute`

---

## 5. Network Firewalling (UFW)

To secure the host, it is highly recommended to block all incoming traffic except for SSH (22) and HTTPS (443). Using `ufw` on Debian/Ubuntu/Parrot OS:

```bash
# Block all incoming by default
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow 22/tcp

# Allow secure gateway proxy traffic (port 443)
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

To limit access only to specific authorized agent host IPs (e.g. your Windows VM IP `192.168.1.50`):
```bash
sudo ufw delete allow 443/tcp
sudo ufw allow from 192.168.1.50 to any port 443 proto tcp
```

---

## 6. Maintenance & Server Restarts

If the deployment server is rebooted:
1. Docker will automatically restart all containers.
2. HashiCorp Vault will boot up in a **sealed** state.
3. Simply run the unseal script to restore system operations:
   ```bash
   bash deployment/scripts/init_vault.sh
   ```
4. Confirm health status by running:
   ```bash
   curl -k https://localhost/health
   ```
