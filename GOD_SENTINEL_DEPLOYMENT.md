# AI GOD (GOD-X) v0.6.0 · GOD SENTINEL Deployment, Enrollment & Verification Guide

## Architecture Overview

GOD SENTINEL v0.6.0 extends **AI GOD (GOD-X)** with distributed, authorized server intelligence while preserving all existing GRI, GIN, Knowledge Graph, Chat, and Governance modules:

1. **Linux & Windows Python Micro-Agent (`sentinel-agent/god_sentinel_agent.py`)**: Zero-dependency Python 3.9+ collector for CPU/RAM/disk/load, service health, process lifecycle diffing, authentication logs, `journalctl` system journal events, network socket metadata, SHA-256 file integrity monitoring (FIM) for explicitly configured paths, outbound HTTPS-only enforcement (with `--allow-insecure-localhost` for loopback testing), and durable offline JSONL buffering with exponential backoff.
2. **Go Micro-Agent (`sentinel-agent/SentinelAgent.go`)**: Zero-dependency Go 1.22+ agent reading Linux `/proc/loadavg`, `/proc/stat`, `/proc/meminfo`, and `syscall.Statfs` system load metrics and transmitting TLS 1.2/1.3 heartbeats both to `/api/sentinel/agent/heartbeat` and directly to Cloud Firestore (`users/{uid}/sentinelHeartbeats/{heartbeatId}`) for real-time 5-minute Heartbeat Pulse streaming into `SentinelProvider`.
3. **GOD Central Event Pipeline (`server.ts`, `src/server/sentinelQueue.ts`, `src/db/schema.ts`)**: Authenticates enrolled devices with SHA-256 hashed per-device bearer tokens (`crypto.timingSafeEqual`), normalizes timestamps and schemas, redacts sensitive keys, deduplicates repeated fingerprints, stamps provenance and `dataOrigin` (`real_telemetry` vs `synthetic_demo`), and persists to Cloud SQL (PostgreSQL via Drizzle ORM).
4. **Regional Intelligence & GOD Investigator (`src/shared/sentinelAnalytics.ts`, `src/shared/sentinelPlaybooks.ts`, `src/server/sentinelBrain.ts`)**: Correlates cross-server anomalies across regions and provides **10 defensive playbooks** (Phishing, Ransomware, Credential Stuffing, Brute Force, Malware, SQL Injection, XSS, DDoS, MITM, Account Takeover) that strictly separate **Confirmed Facts (cited event IDs)**, **Hypotheses**, and **Unknowns**.
5. **Honest Operational Status & Safety Boundaries**:
   - In authenticated mode, zero fabricated servers are ever pre-populated. A server appears online only after authenticated enrollment and a verified heartbeat.
   - Demo/drill records are visibly tagged `SYNTHETIC DEMO`.
   - Zero public agent listening port, zero credential collection, zero unrestricted remote shell, human approval required before isolation/process termination/firewall policy updates, global Emergency Stop enforced server-side (`HTTP 423`).

---

## First Milestone: Enroll One Authorized Linux Server & Verify End-to-End

### 1. Issue a Single-Use Enrollment Token
1. Sign in to **AI GOD (GOD-X)** with Google and open **Sentinel Command → Enroll & Deploy**.
2. Create an enrollment token for your target region (e.g., `asia-southeast1`) and OS (`linux`).
3. Copy the one-time token (`gsen_...`). Only its SHA-256 hash is stored server-side.

### 2. Install & Enroll the Python Linux Micro-Agent
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin god-sentinel
sudo mkdir -p /opt/god-sentinel /var/lib/god-sentinel
sudo cp sentinel-agent/god_sentinel_agent.py /opt/god-sentinel/
sudo chown -R god-sentinel:god-sentinel /var/lib/god-sentinel

# Enroll over HTTPS (exchanges single-use token for per-device credential saved with 0600 permissions)
sudo -u god-sentinel python3 /opt/god-sentinel/god_sentinel_agent.py \
  --controller https://YOUR_GOD_CONTROLLER_URL \
  --state-dir /var/lib/god-sentinel \
  --region asia-southeast1 \
  --enroll gsen_YOUR_SINGLE_USE_TOKEN \
  --once
```
*(For local loopback testing against `http://127.0.0.1:3000`, explicitly pass `--allow-insecure-localhost`.)*

### 3. Optional: Run the Go Micro-Agent (`SentinelAgent.go`) with Firestore Real-Time Heartbeats
```bash
cd sentinel-agent
go build -o god-sentinel-go SentinelAgent.go

# Enroll + stream 15s heartbeats to the GOD Controller & Firestore SentinelProvider
./god-sentinel-go \
  --controller https://YOUR_GOD_CONTROLLER_URL \
  --region asia-southeast1 \
  --enroll gsen_YOUR_SINGLE_USE_TOKEN \
  --interval 15 \
  --firestore-project YOUR_GCP_PROJECT_ID \
  --firestore-db ai-studio-584e6f80-ce9a-45a2-a4f1-448c9c721cfd \
  --firestore-uid YOUR_FIREBASE_UID \
  --firestore-token "$FIREBASE_ID_TOKEN"
```

### 4. Run a Labeled Synthetic Verification Drill
```bash
sudo -u god-sentinel python3 /opt/god-sentinel/god_sentinel_agent.py \
  --controller https://YOUR_GOD_CONTROLLER_URL \
  --state-dir /var/lib/god-sentinel \
  --simulate-suspicious
```
In **Sentinel Command**:
- Inspect the live 5-minute Green/Yellow/Red **Heartbeat Pulse Chart** and server metrics under **Fleet & Health**.
- Inspect the **Cross-Server Attack Timeline** and **Evidence Repository** (filterable by `Real Only` vs `Synthetic Demo`) under **Alerts & Correlation**.
- Select any of the **10 GOD Investigator Playbooks** under **Incidents & GOD Brain** to run a Gemini investigation with cited **Confirmed Facts**, **Hypotheses**, and **Unknowns**.
- Review proposed containment actions under **Approvals & Audit** — zero destructive remediation ever runs automatically.

### 5. Enable Hardened `systemd` Service (Linux)
```bash
sudo cp sentinel-agent/god-sentinel.service /etc/systemd/system/god-sentinel.service
sudo sed -i 's|https://YOUR_GOD_CONTROLLER_URL|https://your-actual-controller-host|g' /etc/systemd/system/god-sentinel.service
sudo systemctl daemon-reload
sudo systemctl enable --now god-sentinel.service
sudo systemctl status god-sentinel.service
```

---

## Automated Verification Suite

```bash
# TypeScript pure logic, playbooks, 5-minute heartbeat math & Firestore rules tests
npx --yes tsx --test firestore.rules.test.ts src/shared/godCoreLogic.test.ts src/shared/ginAnalytics.test.ts src/shared/griAnalytics.test.ts src/shared/knowledgeGraphLayout.test.ts src/shared/sentinelAnalytics.test.ts

# Python micro-agent tests (HTTPS validation, load average, redaction, FIM, offline buffer)
python3 -m unittest discover -s sentinel-agent -p "test_*.py" -v
```
