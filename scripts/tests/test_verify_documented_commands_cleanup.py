#!/usr/bin/env python3
"""The throwaway-gateway cleanup in verify-documented-commands.py reads a PID file written by
the binary under test; that PID must be proven ours before any signal (AAASM-6434).

Run: python3 -I scripts/tests/test_verify_documented_commands_cleanup.py
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("vdc", ROOT / "scripts/qa/verify-documented-commands.py")
V = importlib.util.module_from_spec(_spec)
sys.modules["vdc"] = V
_spec.loader.exec_module(V)


class StopStartedGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="vdc-clean-")))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "home"
        (self.home / ".aasm").mkdir(parents=True)
        self.debug = self.tmp / "debug"
        self.debug.mkdir()
        self.procs: list[subprocess.Popen] = []
        self.addCleanup(self._reap)
        # `aasm stop` itself is not under test: stub the subprocess helper.
        p = mock.patch.object(V, "_run", return_value=None)
        p.start()
        self.addCleanup(p.stop)
        d = mock.patch.object(V, "_debug_dir", return_value=self.debug)
        d.start()
        self.addCleanup(d.stop)

    def _reap(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)

    def _stop(self, pid_text: str) -> None:
        (self.home / ".aasm" / "gateway.pid").write_text(pid_text)
        V._stop_started_gateway("aasm", {}, str(self.home))

    def test_unsafe_pids_are_never_signalled(self) -> None:
        for pid in (0, 1, -1, os.getpid()):
            with self.subTest(pid=pid), mock.patch.object(os, "kill") as kill, \
                    mock.patch.object(os, "killpg") as killpg:
                self._stop(f"{pid}\n127.0.0.1:1\n")
                kill.assert_not_called()
                killpg.assert_not_called()

    def test_foreign_process_named_in_pidfile_survives(self) -> None:
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], cwd=self.tmp,
                             start_new_session=True)
        self.procs.append(p)
        time.sleep(0.3)
        self._stop(f"{p.pid}\n")
        time.sleep(0.5)
        self.assertIsNone(p.poll(), "a foreign process named in gateway.pid was signalled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
