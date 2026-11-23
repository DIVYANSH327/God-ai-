#!/usr/bin/env python3
"""
GOD SENTINEL v0.8 Micro-Agent (Linux & Windows)
===============================================
Lightweight, authorized, least-privilege defensive telemetry collector.

Safety Invariants:
- Authorized server enrollment only (single-use enrollment token -> per-device secret).
- Read-only telemetry collection; zero credential collection (strict secret redaction).
- Zero unrestricted remote shell or arbitrary command execution.
- Zero automatic destructive remediation; containment requires human approval in GOD Command Center.
- Bounded CPU, memory, and event-rate limits with durable offline buffering & exponential backoff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AGENT_VERSION = "0.8.0"

DEFAULT_LIMITS = {
    "maxCpuPercent": 5,
    "maxMemoryMb": 64,
    "maxEventsPerMinute": 120,
    "heartbeatIntervalSec": 30,
    "offlineBufferMaxEvents": 5000,
}

DEFAULT_LINUX_FIM_PATHS = [
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/etc/passwd",
]

DEFAULT_WINDOWS_FIM_PATHS = [
    r"C:\Windows\System32\drivers\etc\hosts",
]

SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|private[_-]?key|token|api[_-]?key|shadow|ntlm|cookie|authorization|bearer|credential)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|password\s*=\s*\S+)",
    re.IGNORECASE,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def redact_text(value: str) -> str:
    return SECRET_VALUE_RE.sub("[REDACTED_BY_SENTINEL_POLICY]", value)[:512]


def redact_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for key, val in payload.items():
        if SECRET_KEY_RE.search(str(key)):
            cleaned[key] = "[REDACTED_BY_SENTINEL_POLICY]"
        elif isinstance(val, str):
            cleaned[key] = redact_text(val)
        elif isinstance(val, dict):
            cleaned[key] = redact_payload(val)
        elif isinstance(val, list):
            cleaned[key] = [
                redact_payload(v) if isinstance(v, dict) else (redact_text(v) if isinstance(v, str) else v)
                for v in val[:30]
            ]
        else:
            cleaned[key] = val
    return cleaned


def apply_resource_limits(max_memory_mb: int) -> None:
    """Apply OS-level memory ceiling on Linux when permitted by container/host."""
    if platform.system().lower() != "linux":
        return
    try:
        import resource  # type: ignore

        limit_bytes = max(32, int(max_memory_mb)) * 1024 * 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if hard == resource.RLIM_INFINITY or limit_bytes <= hard:
            # Keep a safe floor for Python runtime virtual address space while capping RSS via systemd
            target = max(limit_bytes * 4, 256 * 1024 * 1024)
            if hard == resource.RLIM_INFINITY or target <= hard:
                resource.setrlimit(resource.RLIMIT_AS, (target, hard))
    except Exception:
        pass


def detect_primary_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def collect_system_metrics() -> Dict[str, Any]:
    system = platform.system().lower()
    cpu_percent = 0
    ram_percent = 0
    disk_percent = 0
    uptime_sec = 0
    services: List[Dict[str, Any]] = []

    try:
        root_path = "C:\\" if system == "windows" else "/"
        usage = shutil.disk_usage(root_path)
        if usage.total > 0:
            disk_percent = int(round((usage.used / usage.total) * 100))
    except Exception:
        disk_percent = 0

    if system == "linux":
        cpu_percent = _read_linux_cpu_percent()
        ram_percent = _read_linux_ram_percent()
        uptime_sec = _read_linux_uptime_sec()
        services = _read_linux_services()
    elif system == "windows":
        cpu_percent, ram_percent, uptime_sec, services = _read_windows_metrics()

    return {
        "cpuPercent": max(0, min(100, cpu_percent)),
        "ramPercent": max(0, min(100, ram_percent)),
        "diskPercent": max(0, min(100, disk_percent)),
        "uptimeSec": max(0, uptime_sec),
        "services": services[:20],
    }


def _read_linux_cpu_percent() -> int:
    try:
        def read_times() -> Tuple[int, int]:
            with open("/proc/stat", "r", encoding="utf-8") as fh:
                parts = fh.readline().split()[1:]
            nums = [int(x) for x in parts[:8]]
            idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
            total = sum(nums)
            return idle, total

        idle1, total1 = read_times()
        time.sleep(0.15)
        idle2, total2 = read_times()
        delta_total = max(1, total2 - total1)
        delta_idle = max(0, idle2 - idle1)
        return int(round((1.0 - (delta_idle / delta_total)) * 100))
    except Exception:
        return 0


def _read_linux_ram_percent() -> int:
    try:
        meminfo: Dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, rest = line.split(":", 1)
                val_parts = rest.strip().split()
                if val_parts and val_parts[0].isdigit():
                    meminfo[key.strip()] = int(val_parts[0])
        total = meminfo.get("MemTotal", 0)
        avail = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        if total <= 0:
            return 0
        return int(round(((total - avail) / total) * 100))
    except Exception:
        return 0


def _read_linux_uptime_sec() -> int:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            return int(float(fh.read().split()[0]))
    except Exception:
        return 0


def _read_linux_services() -> List[Dict[str, Any]]:
    watched = ["sshd", "systemd-journald", "docker", "nginx", "postgresql", "cron", "node", "python3"]
    running_procs = snapshot_linux_processes()
    proc_names = {info["processName"].lower(): pid for pid, info in running_procs.items()}
    services: List[Dict[str, Any]] = []
    for svc in watched:
        if svc in proc_names:
            services.append({"name": svc, "state": "running", "pid": proc_names[svc]})
    return services


def _read_windows_metrics() -> Tuple[int, int, int, List[Dict[str, Any]]]:
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "$os=Get-CimInstance Win32_OperatingSystem;"
                "$cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average;"
                "$ram=[math]::Round((($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)*100);"
                "$up=[int]((Get-Date)-$os.LastBootUpTime).TotalSeconds;"
                "$svcs=Get-Service | Where-Object {$_.Name -in @('WinDefend','EventLog','MpsSvc','sshd','W32Time')} | Select-Object Name,Status;"
                "@{cpu=[int]$cpu;ram=[int]$ram;uptime=$up;services=$svcs} | ConvertTo-Json -Compress"
            ),
        ]
        out = subprocess.check_output(cmd, timeout=6, text=True)
        parsed = json.loads(out)
        raw_svcs = parsed.get("services") or []
        if isinstance(raw_svcs, dict):
            raw_svcs = [raw_svcs]
        services = [
            {
                "name": str(s.get("Name", "service")),
                "state": "running" if str(s.get("Status", "")).lower() in ("running", "4") else "stopped",
            }
            for s in raw_svcs
        ]
        return int(parsed.get("cpu", 0)), int(parsed.get("ram", 0)), int(parsed.get("uptime", 0)), services
    except Exception:
        return 0, 0, 0, []


def snapshot_linux_processes() -> Dict[int, Dict[str, Any]]:
    procs: Dict[int, Dict[str, Any]] = {}
    proc_dir = Path("/proc")
    if not proc_dir.exists():
        return procs
    for entry in proc_dir.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="ignore").strip()
            raw_cmd = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
            procs[pid] = {
                "pid": pid,
                "processName": comm or "unknown",
                "command": redact_text(raw_cmd or comm),
            }
        except Exception:
            continue
    return procs


def diff_process_snapshots(
    previous: Dict[int, Dict[str, Any]], current: Dict[int, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not previous:
        return events

    for pid, info in current.items():
        if pid not in previous:
            events.append(
                {
                    "eventType": "process",
                    "severity": "info",
                    "summary": f"Process created: {info['processName']} (PID {pid})",
                    "payload": redact_payload({"action": "created", **info}),
                    "collector": "sentinel-process-watcher",
                    "observedAt": utc_now_iso(),
                }
            )
    for pid, info in previous.items():
        if pid not in current:
            events.append(
                {
                    "eventType": "process",
                    "severity": "info",
                    "summary": f"Process terminated: {info['processName']} (PID {pid})",
                    "payload": redact_payload({"action": "terminated", **info}),
                    "collector": "sentinel-process-watcher",
                    "observedAt": utc_now_iso(),
                }
            )
    return events[:25]


def parse_proc_net_tcp_hex_addr(hex_addr: str) -> Tuple[str, int]:
    ip_hex, port_hex = hex_addr.split(":")
    octets = [str(int(ip_hex[i : i + 2], 16)) for i in (6, 4, 2, 0)]
    return ".".join(octets), int(port_hex, 16)


def collect_linux_network_metadata(limit: int = 12) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    tcp_path = Path("/proc/net/tcp")
    if not tcp_path.exists():
        return events
    try:
        lines = tcp_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            state = parts[3]
            if state != "01":  # ESTABLISHED
                continue
            local_ip, local_port = parse_proc_net_tcp_hex_addr(parts[1])
            remote_ip, remote_port = parse_proc_net_tcp_hex_addr(parts[2])
            if remote_ip.startswith("127.") or remote_ip == "0.0.0.0":
                continue
            events.append(
                {
                    "eventType": "network",
                    "severity": "info",
                    "summary": f"Established TCP connection {local_ip}:{local_port} -> {remote_ip}:{remote_port}",
                    "payload": {
                        "protocol": "TCP",
                        "localIp": local_ip,
                        "localPort": local_port,
                        "remoteIp": remote_ip,
                        "remotePort": remote_port,
                        "state": "ESTABLISHED",
                    },
                    "collector": "sentinel-net-metadata",
                    "observedAt": utc_now_iso(),
                }
            )
            if len(events) >= limit:
                break
    except Exception:
        pass
    return events


def compute_file_sha256(file_path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def check_file_integrity(
    watched_paths: List[str], baseline: Dict[str, str]
) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    events: List[Dict[str, Any]] = []
    updated = dict(baseline)
    for path in watched_paths:
        digest = compute_file_sha256(path)
        if digest is None:
            continue
        prev = updated.get(path)
        if prev is not None and prev != digest:
            events.append(
                {
                    "eventType": "fim",
                    "severity": "high",
                    "summary": f"File integrity checksum changed for {path}",
                    "payload": {
                        "filePath": path,
                        "previousSha256": prev[:16],
                        "currentSha256": digest[:16],
                    },
                    "collector": "sentinel-fim-sha256",
                    "observedAt": utc_now_iso(),
                }
            )
        updated[path] = digest
    return updated, events


def parse_auth_log_lines(lines: List[str]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    failed_re = re.compile(
        r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9a-fA-F.:]+)"
    )
    accepted_re = re.compile(
        r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+([0-9a-fA-F.:]+)"
    )
    for line in lines[-50:]:
        m_fail = failed_re.search(line)
        if m_fail:
            user, src_ip = m_fail.group(1), m_fail.group(2)
            events.append(
                {
                    "eventType": "auth",
                    "severity": "medium",
                    "summary": f"Failed SSH authentication for user {user} from {src_ip}",
                    "payload": {"username": user, "sourceIp": src_ip, "action": "auth_failed", "remotePort": 22},
                    "collector": "sentinel-auth-log",
                    "observedAt": utc_now_iso(),
                }
            )
            continue
        m_ok = accepted_re.search(line)
        if m_ok:
            method, user, src_ip = m_ok.group(1), m_ok.group(2), m_ok.group(3)
            events.append(
                {
                    "eventType": "auth",
                    "severity": "info",
                    "summary": f"Accepted {method} login for user {user} from {src_ip}",
                    "payload": {
                        "method": method,
                        "username": user,
                        "sourceIp": src_ip,
                        "action": "auth_accepted",
                        "remotePort": 22,
                    },
                    "collector": "sentinel-auth-log",
                    "observedAt": utc_now_iso(),
                }
            )
    return events


def build_simulated_suspicious_drill_events(hostname: str) -> List[Dict[str, Any]]:
    """
    First Milestone validation drill: emits a deterministic, clearly tagged
    simulated suspicious telemetry chain (auth brute-force + /tmp script execution
    + outbound port 4444 metadata + critical sshd_config checksum drift).
    Zero harmful actions are performed on the host.
    """
    now = utc_now_iso()
    return [
        {
            "eventType": "auth",
            "severity": "high",
            "summary": f"[SIMULATED DRILL] Repeated failed SSH logins for deploy from 198.51.100.77 on {hostname}",
            "payload": {
                "sourceIp": "198.51.100.77",
                "username": "deploy",
                "remotePort": 22,
                "action": "ssh_brute_force_detected",
                "failedAttempts": 18,
            },
            "collector": "sentinel-auth-drill",
            "observedAt": now,
            "simulatedDrill": True,
        },
        {
            "eventType": "process",
            "severity": "high",
            "summary": "[SIMULATED DRILL] Suspicious child shell launched from /tmp/audit_probe.sh",
            "payload": {
                "pid": 49122,
                "processName": "bash",
                "parentProcess": "sshd",
                "command": "bash /tmp/audit_probe.sh --check",
                "action": "created",
            },
            "collector": "sentinel-process-drill",
            "observedAt": now,
            "simulatedDrill": True,
        },
        {
            "eventType": "network",
            "severity": "high",
            "summary": "[SIMULATED DRILL] Unexpected outbound TCP socket to 198.51.100.77:4444",
            "payload": {
                "protocol": "TCP",
                "remoteIp": "198.51.100.77",
                "remotePort": 4444,
                "state": "ESTABLISHED",
            },
            "collector": "sentinel-net-drill",
            "observedAt": now,
            "simulatedDrill": True,
        },
        {
            "eventType": "fim",
            "severity": "critical",
            "summary": "[SIMULATED DRILL] SHA-256 checksum drift detected on /etc/ssh/sshd_config",
            "payload": {
                "filePath": "/etc/ssh/sshd_config",
                "previousSha256": "8b7df143d91c716e",
                "currentSha256": "d2f9e0a7c13144a9",
            },
            "collector": "sentinel-fim-drill",
            "observedAt": now,
            "simulatedDrill": True,
        },
    ]


class OfflineEventBuffer:
    """Durable JSONL offline buffer with bounded max capacity for disconnected retries."""

    def __init__(self, path: Path, max_events: int = 5000) -> None:
        self.path = path
        self.max_events = max(50, max_events)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0
        existing = self.load_all()
        for evt in events:
            item = dict(evt)
            item["bufferedOffline"] = True
            item["retryAttempt"] = int(item.get("retryAttempt", 0)) + 1
            existing.append(item)
        trimmed = existing[-self.max_events :]
        with open(self.path, "w", encoding="utf-8") as fh:
            for item in trimmed:
                fh.write(json.dumps(item) + "\n")
        return len(trimmed)

    def load_all(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        items: List[Dict[str, Any]] = []
        with open(self.path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception:
                    continue
        return items

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()


class SentinelControllerClient:
    def __init__(self, controller_url: str, state_dir: Path) -> None:
        self.controller_url = controller_url.rstrip("/")
        self.state_dir = state_dir
        self.state_file = state_dir / "agent_state.json"
        self.buffer = OfflineEventBuffer(state_dir / "buffer.jsonl")
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def load_state(self) -> Optional[Dict[str, Any]]:
        if not self.state_file.exists():
            return None
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def save_state(self, state: Dict[str, Any]) -> None:
        self.state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
        try:
            os.chmod(self.state_file, 0o600)
        except Exception:
            pass

    def _http_post_json(
        self, path: str, body: Dict[str, Any], headers: Optional[Dict[str, str]] = None, timeout: int = 12
    ) -> Dict[str, Any]:
        url = f"{self.controller_url}{path}"
        req_headers = {
            "Content-Type": "application/json",
            "User-Agent": f"GOD-Sentinel-Agent/{AGENT_VERSION}",
        }
        if headers:
            req_headers.update(headers)
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    def enroll(self, enrollment_token: str, region: str, hostname: Optional[str] = None) -> Dict[str, Any]:
        os_type = "windows" if platform.system().lower() == "windows" else "linux"
        os_version = f"{platform.system()} {platform.release()}"
        payload = {
            "enrollmentToken": enrollment_token,
            "hostname": hostname or socket.gethostname(),
            "ipAddress": detect_primary_ip(),
            "osType": os_type,
            "osVersion": os_version,
            "agentVersion": AGENT_VERSION,
            "region": region,
            "resourceLimits": DEFAULT_LIMITS,
        }
        res = self._http_post_json("/api/sentinel/agent/enroll", payload)
        state = {
            "controllerUrl": self.controller_url,
            "agentId": res["agent"]["id"],
            "deviceToken": res["deviceToken"],
            "hostname": res["agent"]["hostname"],
            "region": res["agent"]["region"],
            "enrolledAt": utc_now_iso(),
            "resourceLimits": res["agent"].get("resourceLimits", DEFAULT_LIMITS),
        }
        self.save_state(state)
        return state

    def _auth_headers(self, state: Dict[str, Any]) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {state['deviceToken']}",
            "X-Sentinel-Agent-Id": state["agentId"],
        }

    def send_heartbeat(self, state: Dict[str, Any], metrics: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "agentVersion": AGENT_VERSION,
            **metrics,
        }
        return self._http_post_json(
            "/api/sentinel/agent/heartbeat", payload, headers=self._auth_headers(state)
        )

    def send_events_with_buffering(
        self, state: Dict[str, Any], events: List[Dict[str, Any]], max_retries: int = 3
    ) -> Tuple[bool, Dict[str, Any]]:
        buffered = self.buffer.load_all()
        combined = buffered + [
            {**e, "payload": redact_payload(e.get("payload", {}))} for e in events
        ]
        if not combined:
            return True, {"persistedCount": 0, "deduplicatedCount": 0}

        max_per_min = int(state.get("resourceLimits", {}).get("maxEventsPerMinute", 120))
        batch = combined[:max_per_min]

        for attempt in range(max_retries):
            try:
                res = self._http_post_json(
                    "/api/sentinel/agent/events",
                    {"events": batch},
                    headers=self._auth_headers(state),
                )
                self.buffer.clear()
                remainder = combined[max_per_min:]
                if remainder:
                    self.buffer.append(remainder)
                return True, res
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                if attempt < max_retries - 1:
                    sleep_s = (0.5 * (2**attempt)) + random.uniform(0.05, 0.25)
                    time.sleep(sleep_s)
                else:
                    buffered_count = self.buffer.append(events)
                    return False, {"error": str(err), "bufferedCount": buffered_count}
        return False, {"error": "Unknown delivery error"}


def main() -> int:
    parser = argparse.ArgumentParser(description="GOD SENTINEL v0.8 Authorized Micro-Agent")
    parser.add_argument("--controller", default="http://127.0.0.1:3000", help="GOD Controller base URL")
    parser.add_argument("--state-dir", default=str(Path.home() / ".god-sentinel"), help="Local state & offline buffer dir")
    parser.add_argument("--enroll", dest="enroll_token", help="Single-use enrollment token issued in GOD Command Center")
    parser.add_argument("--region", default="asia-southeast1", help="Server region label")
    parser.add_argument("--hostname", default=None, help="Override reported hostname")
    parser.add_argument("--fim-path", action="append", default=[], help="Additional file path for SHA-256 FIM")
    parser.add_argument("--once", action="store_true", help="Send one heartbeat + telemetry snapshot and exit")
    parser.add_argument(
        "--simulate-suspicious",
        action="store_true",
        help="Send a clearly labeled simulated suspicious event chain for Milestone 1 verification",
    )
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    client = SentinelControllerClient(args.controller, state_dir)

    state = client.load_state()
    if args.enroll_token:
        state = client.enroll(args.enroll_token, args.region, args.hostname)
        print(json.dumps({"event": "enrolled", "agentId": state["agentId"], "hostname": state["hostname"], "region": state["region"]}))

    if not state:
        print("Error: Agent is not enrolled. Run with --enroll <token> --controller <url> first.", file=sys.stderr)
        return 2

    limits = state.get("resourceLimits", DEFAULT_LIMITS)
    apply_resource_limits(int(limits.get("maxMemoryMb", 64)))

    watched_fim = list(args.fim_path) + (
        DEFAULT_WINDOWS_FIM_PATHS if platform.system().lower() == "windows" else DEFAULT_LINUX_FIM_PATHS
    )
    fim_baseline, _ = check_file_integrity(watched_fim, {})
    prev_procs = snapshot_linux_processes() if platform.system().lower() == "linux" else {}

    while True:
        metrics = collect_system_metrics()
        try:
            hb_res = client.send_heartbeat(state, metrics)
            print(json.dumps({"event": "heartbeat_ok", "agentId": state["agentId"], "metrics": metrics, "approvedDirectives": len(hb_res.get("approvedActions", []))}))
        except Exception as err:
            print(json.dumps({"event": "heartbeat_deferred", "error": str(err)}), file=sys.stderr)

        events: List[Dict[str, Any]] = []
        if platform.system().lower() == "linux":
            curr_procs = snapshot_linux_processes()
            events.extend(diff_process_snapshots(prev_procs, curr_procs))
            prev_procs = curr_procs
            events.extend(collect_linux_network_metadata(limit=6))

        fim_baseline, fim_events = check_file_integrity(watched_fim, fim_baseline)
        events.extend(fim_events)

        if args.simulate_suspicious:
            events.extend(build_simulated_suspicious_drill_events(state["hostname"]))

        if events:
            ok, delivery = client.send_events_with_buffering(state, events)
            print(json.dumps({"event": "telemetry_delivery", "ok": ok, "sent": len(events), "result": delivery}))

        if args.once or args.simulate_suspicious:
            return 0

        interval = max(10, int(limits.get("heartbeatIntervalSec", 30)))
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
