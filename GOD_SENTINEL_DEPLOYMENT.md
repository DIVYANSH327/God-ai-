# GOD SENTINEL v0.8 — Deployment, Enrollment & Scaling Guide

## Architecture Overview

GOD SENTINEL v0.8 extends AI GOD with distributed, authorized defensive server monitoring and incident investigation:

1. **Sentinel Micro-Agent (`sentinel-agent/god_sentinel_agent.py`)**: Zero-dependency Python 3.9+ collector for Linux and Windows with strict CPU/RAM/rate ceilings, SHA-256 file integrity monitoring, process lifecycle diffing, authentication & network metadata collection, and durable offline JSONL buffering with exponential backoff.
2. **GOD Controller & Event Pipeline (`server.ts`, `src/server/sentinelQueue.ts`)**: Authenticates enrolled agents with SHA-256 hashed per-device tokens (`crypto.timingSafeEqual`), normalizes and redacts telemetry, deduplicates repeated fingerprints, stamps provenance, and persists into PostgreSQL via Drizzle ORM (`src/db/schema.ts`).
3. **Regional Intelligence & GOD Central Brain (`src/shared/sentinelAnalytics.ts`, `src/server/sentinelBrain.ts`)**: Correlates multi-server activity across regions (lateral movement, auth sprays, suspicious process/network/FIM chains) and invokes Gemini (`gemini-4-hydrogen`) for evidence-based hypotheses, MITRE ATT&CK mapping, timelines, and structured reports.
4. **Human-Approval Safety Boundary**: No hidden surveillance, no credential collection, no unrestricted remote shell, and no automatic destructive remediation. Isolating a server, terminating a process, or changing firewall policies requires explicit human approval and is recorded in `sentinel_audit_logs`.

---

## First Milestone: Enroll One Authorized Linux Server & Verify

### 1. Issue a Single-Use Enrollment Token
1. Open **AI GOD → Sentinel Command → Enroll & Deploy**.
2. Create an enrollment token for your target region (for example `asia-southeast1`) and OS (`linux`).
3. Copy the one-time token (`gsen_...`). Only its SHA-256 hash is stored server-side.

### 2. Install & Enroll on Linux
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin god-sentinel
sudo mkdir -p /opt/god-sentinel /var/lib/god-sentinel
sudo cp sentinel-agent/god_sentinel_agent.py /opt/god-sentinel/
sudo chown -R god-sentinel:god-sentinel /var/lib/god-sentinel

# Enroll securely (exchanges single-use token for per-device secret saved with 0600 permissions)
sudo -u god-sentinel python3 /opt/god-sentinel/god_sentinel_agent.py \
  --controller https://YOUR_GOD_CONTROLLER_URL \
  --state-dir /var/lib/god-sentinel \
  --region asia-southeast1 \
  --enroll gsen_YOUR_SINGLE_USE_TOKEN \
  --once
```

### 3. Run the Simulated Suspicious Event Verification Drill
```bash
sudo -u god-sentinel python3 /opt/god-sentinel/god_sentinel_agent.py \
  --controller https://YOUR_GOD_CONTROLLER_URL \
  --state-dir /var/lib/god-sentinel \
  --simulate-suspicious
```
In **Sentinel Command**:
- Confirm live heartbeat and CPU/RAM/Disk metrics under **Fleet & Health**.
- Inspect deduplicated events and regional alerts under **Alerts & Correlation**.
- Run **Gemini Central Brain Investigation** under **Incidents & GOD Brain** to inspect MITRE ATT&CK mappings (`T1110`, `T1059.004`, `T1071.001`, `T1565.001`), hypotheses, and timeline.
- Review any proposed containment action under **Approvals & Audit** — nothing executes without operator approval.

### 4. Enable Hardened `systemd` Service (Linux)
```bash
sudo cp sentinel-agent/god-sentinel.service /etc/systemd/system/god-sentinel.service
sudo sed -i 's|https://YOUR_GOD_CONTROLLER_URL|https://your-actual-controller-host|g' /etc/systemd/system/god-sentinel.service
sudo systemctl daemon-reload
sudo systemctl enable --now god-sentinel.service
sudo systemctl status god-sentinel.service
```

---

## Windows Server Deployment

1. Install Python 3.9+ (standard library only, no third-party packages required).
2. Place `god_sentinel_agent.py` in `C:\ProgramData\GodSentinel\`.
3. Enroll using an enrollment token issued for `windows`:
   ```powershell
   python C:\ProgramData\GodSentinel\god_sentinel_agent.py `
     --controller https://YOUR_GOD_CONTROLLER_URL `
     --state-dir C:\ProgramData\GodSentinel\state `
     --region asia-southeast1 `
     --enroll gsen_YOUR_SINGLE_USE_TOKEN `
     --once
   ```
4. Register as a least-privilege Windows Scheduled Task running at startup under a dedicated read-only monitoring account.

---

## Scaling to Multiple Authorized Servers & Regions

- Issue one unique single-use enrollment token per authorized server (or per provisioning batch via automation) tagged with its region (`asia-southeast1`, `us-central1`, `eu-west1`).
- Use **Fleet & Health** to adjust per-host `maxCpuPercent`, `maxMemoryMb`, `maxEventsPerMinute`, and `targetVersion` policies without granting shell access.
- Revoke decommissioned or compromised servers immediately from **Fleet & Health** (`POST /api/sentinel/agents/:id/revoke`) to invalidate their per-device token hash on the next request.

## Running Automated Tests

```bash
# TypeScript pure analytics & correlation tests
npx --yes tsx --test src/shared/sentinelAnalytics.test.ts

# Python micro-agent tests
python3 -m unittest sentinel-agent/test_sentinel_agent.py
```
