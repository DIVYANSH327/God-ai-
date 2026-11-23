import tempfile
import unittest
from pathlib import Path

from god_sentinel_agent import (
    OfflineEventBuffer,
    build_simulated_suspicious_drill_events,
    check_file_integrity,
    diff_process_snapshots,
    parse_auth_log_lines,
    parse_proc_net_tcp_hex_addr,
    redact_payload,
)


class SentinelMicroAgentTests(unittest.TestCase):
    def test_redact_payload_removes_credentials_and_secrets(self) -> None:
        raw = {
            "username": "ops-user",
            "password": "leaked-password",
            "api_token": "tok_secret",
            "note": "Authorization Bearer supersecretvalue1234567890",
            "port": 443,
        }
        cleaned = redact_payload(raw)
        self.assertEqual(cleaned["username"], "ops-user")
        self.assertEqual(cleaned["password"], "[REDACTED_BY_SENTINEL_POLICY]")
        self.assertEqual(cleaned["api_token"], "[REDACTED_BY_SENTINEL_POLICY]")
        self.assertIn("[REDACTED_BY_SENTINEL_POLICY]", cleaned["note"])
        self.assertEqual(cleaned["port"], 443)

    def test_file_integrity_detects_sha256_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sshd_config"
            target.write_text("PermitRootLogin no\n", encoding="utf-8")
            baseline, events1 = check_file_integrity([str(target)], {})
            self.assertEqual(len(events1), 0)
            self.assertIn(str(target), baseline)

            target.write_text("PermitRootLogin yes\n", encoding="utf-8")
            _, events2 = check_file_integrity([str(target)], baseline)
            self.assertEqual(len(events2), 1)
            self.assertEqual(events2[0]["eventType"], "fim")
            self.assertEqual(events2[0]["severity"], "high")

    def test_offline_buffer_persists_and_clears(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            buf = OfflineEventBuffer(Path(tmpdir) / "buffer.jsonl", max_events=100)
            count = buf.append([{"eventType": "auth", "summary": "Failed SSH login"}])
            self.assertEqual(count, 1)
            loaded = buf.load_all()
            self.assertEqual(len(loaded), 1)
            self.assertTrue(loaded[0]["bufferedOffline"])
            self.assertEqual(loaded[0]["retryAttempt"], 1)
            buf.clear()
            self.assertEqual(len(buf.load_all()), 0)

    def test_process_diff_and_proc_net_tcp_parser(self) -> None:
        prev = {100: {"pid": 100, "processName": "sshd", "command": "/usr/sbin/sshd"}}
        curr = {
            100: {"pid": 100, "processName": "sshd", "command": "/usr/sbin/sshd"},
            205: {"pid": 205, "processName": "bash", "command": "bash /tmp/test.sh"},
        }
        diff = diff_process_snapshots(prev, curr)
        self.assertEqual(len(diff), 1)
        self.assertEqual(diff[0]["payload"]["action"], "created")

        ip, port = parse_proc_net_tcp_hex_addr("0100007F:01BB")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 443)

    def test_auth_log_parser_and_drill_chain(self) -> None:
        lines = [
            "Nov 22 10:12:01 web-01 sshd[912]: Failed password for invalid user admin from 203.0.113.55 port 55112 ssh2",
            "Nov 22 10:12:15 web-01 sshd[913]: Accepted publickey for deploy from 10.10.1.5 port 51200 ssh2",
        ]
        parsed = parse_auth_log_lines(lines)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["payload"]["action"], "auth_failed")
        self.assertEqual(parsed[1]["payload"]["action"], "auth_accepted")

        drill = build_simulated_suspicious_drill_events("sg-prod-01")
        self.assertEqual(len(drill), 4)
        self.assertTrue(all(ev.get("simulatedDrill") for ev in drill))


if __name__ == "__main__":
    unittest.main()
