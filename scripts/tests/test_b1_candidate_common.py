"""Ownership proof for `kill_owned_daemon` (AAASM-6419): per-PID, never a pattern kill.

Real child processes are used; the negative control is a foreign process that must survive.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qa"))
import b1_candidate_common as c  # noqa: E402


_SLEEP = [sys.executable, "-c", "import time; time.sleep(60)"]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class KillOwnedDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        base = Path(os.path.realpath(self._td.name))
        self.real = base / "real"
        self.real.mkdir()
        self.link = base / "link"
        self.link.symlink_to(self.real)
        self.foreign = base / "foreign"
        self.foreign.mkdir()
        self.procs: list[subprocess.Popen] = []
        self.addCleanup(self._reap)

    def _reap(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)

    def _spawn(self, argv: list[str], cwd: Path) -> subprocess.Popen:
        p = subprocess.Popen(argv, cwd=cwd, start_new_session=True)
        self.procs.append(p)
        time.sleep(0.3)
        return p

    def _pidfile(self, pid: int) -> Path:
        pf = self.real / "daemon.pid"
        pf.write_text(f"{pid}\n")
        return pf

    def _assert_killed(self, p: subprocess.Popen) -> None:
        self.assertIsNotNone(p.wait(timeout=10))

    def test_symlinked_owner_with_realpath_argv_is_killed(self) -> None:
        p = self._spawn(_SLEEP + [str(self.real)], self.foreign)
        c.kill_owned_daemon(self._pidfile(p.pid), self.link)
        self._assert_killed(p)

    def test_bare_name_launch_with_cwd_under_owner_is_killed(self) -> None:
        p = self._spawn(["sleep", "60"], self.real)
        c.kill_owned_daemon(self._pidfile(p.pid), self.link)
        self._assert_killed(p)

    def test_foreign_pid_is_not_killed(self) -> None:
        p = self._spawn(["sleep", "60"], self.foreign)
        c.kill_owned_daemon(self._pidfile(p.pid), self.link)
        time.sleep(0.5)
        self.assertIsNone(p.poll())
        self.assertTrue(_alive(p.pid))

    def test_sibling_dir_sharing_name_prefix_is_not_owned(self) -> None:
        owner = self.real.parent / "ab"
        sibling = self.real.parent / "abc"
        owner.mkdir()
        sibling.mkdir()
        p = self._spawn(_SLEEP + [str(sibling / "x")], sibling)
        c.kill_owned_daemon(self._pidfile(p.pid), owner)
        time.sleep(0.5)
        self.assertIsNone(p.poll())

    def test_file_mentioned_under_owner_does_not_prove_ownership(self) -> None:
        p = self._spawn(_SLEEP + [str(self.real / "x.log")], self.foreign)
        c.kill_owned_daemon(self._pidfile(p.pid), self.real)
        time.sleep(0.5)
        self.assertIsNone(p.poll())

    def test_flag_equals_owner_path_is_owned(self) -> None:
        p = self._spawn(_SLEEP + [f"--home={self.real}"], self.foreign)
        c.kill_owned_daemon(self._pidfile(p.pid), self.link)
        self._assert_killed(p)

    def test_non_path_lsof_names_are_ignored(self) -> None:
        # A socket-style name must never be resolved against the harness cwd.
        cwd = os.getcwd()
        os.chdir(self.real)
        self.addCleanup(os.chdir, cwd)
        p = self._spawn(_SLEEP, self.foreign)
        fake = "p1\nn*:8080\nn->0xdeadbeef\nnpipe\n"
        with mock.patch.object(c, "_run_text", side_effect=["sleep\n", fake]):
            self.assertFalse(c.pid_owned_by(p.pid, self.real))

    def test_ownership_is_reproven_before_sigkill(self) -> None:
        p = self._spawn(_SLEEP, self.real)
        proofs = iter([True, False])
        sent: list[int] = []
        with mock.patch.object(c, "pid_owned_by", side_effect=lambda *_: next(proofs)), \
                mock.patch.object(c.os, "kill", side_effect=lambda pid, sig: sent.append(sig)), \
                mock.patch.object(c.time, "sleep"):
            c.kill_owned_daemon(self._pidfile(p.pid), self.real)
        self.assertEqual(sent[0], signal.SIGTERM)
        self.assertNotIn(signal.SIGKILL, sent)

    def test_pid_one_self_and_parent_are_never_owned(self) -> None:
        # the harness itself has its cwd/fds under tmp dirs, so only the explicit guard stops these
        for pid in (-1, 0, 1, os.getpid(), os.getppid()):
            self.assertFalse(c.pid_owned_by(pid, Path(os.getcwd())), pid)

    def test_relative_owner_fails_closed(self) -> None:
        self.assertFalse(c.pid_owned_by(os.getpid(), Path("relative")))

    def test_pidfile_naming_owned_dir_alone_proves_nothing(self) -> None:
        p = self._spawn(_SLEEP + [str(self.foreign)], self.foreign)
        c.kill_owned_daemon(self._pidfile(p.pid), self.real)
        time.sleep(0.5)
        self.assertIsNone(p.poll())


if __name__ == "__main__":
    unittest.main(verbosity=2)
