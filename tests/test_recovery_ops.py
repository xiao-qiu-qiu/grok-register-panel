# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import recovery_ops
import sso_to_auth_json


class _FakeTextStream:
    def __init__(self):
        self.calls = []

    def reconfigure(self, **kwargs):
        self.calls.append(kwargs)


def test_sso_converter_configures_utf8_stdio():
    stdout = _FakeTextStream()
    stderr = _FakeTextStream()
    with (
        mock.patch.object(sso_to_auth_json.sys, "stdout", stdout),
        mock.patch.object(sso_to_auth_json.sys, "stderr", stderr),
    ):
        sso_to_auth_json._configure_utf8_stdio()

    expected = {"encoding": "utf-8", "errors": "backslashreplace"}
    assert stdout.calls == [expected]
    assert stderr.calls == [expected]


def test_start_recovery_forces_utf8_child_output():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runtime = root / "python.exe"
        runtime.touch()
        config = root / "config.json"
        config.write_text("{}", encoding="utf-8")
        log_dir = root / "log"
        captured = {}

        def fake_popen(command, **kwargs):
            captured["command"] = command
            captured["env"] = kwargs["env"]
            return SimpleNamespace(pid=1234)

        with (
            mock.patch.object(recovery_ops, "VENV_PY", runtime),
            mock.patch.object(recovery_ops, "CONFIG_FILE", config),
            mock.patch.object(recovery_ops, "LOG_DIR", log_dir),
            mock.patch.object(recovery_ops, "REPORT_FILE", log_dir / "report.json"),
            mock.patch.object(recovery_ops, "PID_FILE", log_dir / "recovery.pid"),
            mock.patch.object(recovery_ops, "ACCOUNTS_DIR", root / "accounts"),
            mock.patch.object(recovery_ops, "find_managed_processes", return_value=[]),
            mock.patch.object(
                recovery_ops,
                "worker_proxy_snapshot",
                return_value={"configured": True, "urls": ["http://user:pass@127.0.0.1:7890"]},
            ),
            mock.patch.object(
                recovery_ops,
                "recovery_status",
                return_value={"pending_count": 0, "recoverable_count": 1},
            ),
            mock.patch.object(recovery_ops.subprocess, "Popen", side_effect=fake_popen),
            mock.patch.object(recovery_ops, "write_pid_file"),
        ):
            result = recovery_ops.start_recovery("accounts")

        assert result["ok"] is True
        assert captured["env"]["PYTHONUNBUFFERED"] == "1"
        assert captured["env"]["PYTHONUTF8"] == "1"
        assert captured["env"]["PYTHONIOENCODING"] == "utf-8"
        assert captured["env"]["GROK_RECOVERY_PROXY"] == "http://user:pass@127.0.0.1:7890"
        assert "--accounts-dir" in captured["command"]
        assert all("user:pass" not in str(part) for part in captured["command"])


def test_converter_uses_recovery_proxy_when_config_proxy_is_missing():
    with tempfile.TemporaryDirectory() as temp:
        config = Path(temp) / "config.json"
        config.write_text("{}", encoding="utf-8")
        args = SimpleNamespace(
            from_config=str(config),
            cpa_auth_dir=None,
            grok2api_auth_dir=None,
            cpa_remote_url=None,
            cpa_management_key=None,
            proxy="",
            prefer=None,
            bfs_check=None,
            bfs_skip_write=None,
            bfs_disable=None,
        )
        with mock.patch.dict(
            os.environ,
            {"GROK_RECOVERY_PROXY": "http://127.0.0.1:7890"},
        ):
            sso_to_auth_json.apply_config_defaults(args)

        assert args.proxy == "http://127.0.0.1:7890"


if __name__ == "__main__":
    test_sso_converter_configures_utf8_stdio()
    test_start_recovery_forces_utf8_child_output()
    test_converter_uses_recovery_proxy_when_config_proxy_is_missing()
    print("OK recovery ops")
