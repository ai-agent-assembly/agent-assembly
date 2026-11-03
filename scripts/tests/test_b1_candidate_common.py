"""Ownership proof for `kill_owned_daemon` (AAASM-6419): per-PID, never a pattern kill.

Real child processes are used; the negative control is a foreign process that must survive.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import TestCase, main, mock, skipUnless

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qa"))
import b1_candidate_common as c  # noqa: E402


# pid_owned_by fails closed (returns False) when this lsof is absent, e.g. on the
# ubuntu CI runner where lsof lives in /usr/bin. The tests below that need a real
# positive ownership proof, or a real lsof listing to be meaningful, cannot run
# there; every negative control that does not depend on lsof still runs.
_NEEDS_LSOF = skipUnless(
    os.path.exists(c.LSOF), f"{c.LSOF} is absent: the real ownership proof fails closed here")

_SLEEP = [sys.executable, "-c", "import time; time.sleep(60)"]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class KillOwnedDaemonTests(TestCase):
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

    def _own_binary(self, owner: Path) -> Path:
        """A real compiled binary copied into <owner>/bin, as the harness does for the daemons."""
        cc = shutil.which("cc")
        if cc is None:
            self.skipTest("no C compiler to build a real binary")
        src = self.foreign / "nap.c"
        src.write_text("#include <unistd.h>\nint main(void){sleep(60);return 0;}\n")
        built = self.foreign / "nap"
        subprocess.run([cc, "-o", str(built), str(src)], check=True, capture_output=True)
        (owner / "bin").mkdir(exist_ok=True)
        dest = owner / "bin" / "aasm"
        shutil.copy2(built, dest)
        return dest

    @_NEEDS_LSOF
    def test_binary_executed_from_owner_bin_is_killed(self) -> None:
        exe = self._own_binary(self.real)
        p = self._spawn([str(exe)], self.foreign)
        c.kill_owned_daemon(self._pidfile(p.pid), self.link)  # symlinked owner spelling
        self._assert_killed(p)

    @_NEEDS_LSOF
    def test_multiline_pidfile_as_written_by_aasm_gateway_start_is_honoured(self) -> None:
        exe = self._own_binary(self.real)
        p = self._spawn([str(exe)], self.foreign)
        pf = self.real / "daemon.pid"
        pf.write_text(f"{p.pid}\n127.0.0.1:50051\n2026-11-03T00:00:00Z\n")
        c.kill_owned_daemon(pf, self.real)
        self._assert_killed(p)

    def _run_in_child(self, pidfile: Path) -> subprocess.CompletedProcess:
        """kill_owned_daemon in a child with a hard limit, so a regression that blocks on the
        pidfile fails this test instead of hanging the suite."""
        code = (
            "import sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(Path(c.__file__).parent)!r})\n"
            "import b1_candidate_common as c\n"
            "from unittest import mock\n"
            "with mock.patch.object(c.os, 'kill') as k, mock.patch.object(c, '_proven', return_value=True):\n"
            f"    c.kill_owned_daemon(Path({str(pidfile)!r}), Path({str(self.real)!r}))\n"
            "    sys.exit(3 if k.called else 0)\n"
        )
        return subprocess.run([sys.executable, "-I", "-c", code], timeout=30, capture_output=True)

    def test_fifo_pidfile_neither_hangs_nor_signals(self) -> None:
        fifo = self.real / "fifo.pid"
        os.mkfifo(fifo)
        self.assertEqual(self._run_in_child(fifo).returncode, 0)

    def test_symlink_to_a_device_pidfile_is_not_read(self) -> None:
        link = self.real / "zero.pid"
        link.symlink_to("/dev/zero")
        self.assertEqual(self._run_in_child(link).returncode, 0)

    def test_oversize_pidfile_signals_nothing(self) -> None:
        pf = self.real / "big.pid"
        pf.write_text(f"{os.getpid() + 12345}\n" + "x" * (c.PIDFILE_MAX_BYTES + 10))
        self.assertEqual(self._run_in_child(pf).returncode, 0)

    def test_symlink_to_a_regular_pidfile_is_honoured(self) -> None:
        self.assertEqual(c._read_pidfile_pid(self._pidfile(4242)), 4242)
        link = self.real / "link.pid"
        link.symlink_to(self.real / "daemon.pid")
        self.assertEqual(c._read_pidfile_pid(link), 4242)

    def test_kill_errors_do_not_escape_cleanup(self) -> None:
        for exc in (ProcessLookupError, PermissionError):
            with mock.patch.object(c, "_proven", return_value=True), \
                    mock.patch.object(c.os, "kill", side_effect=exc), \
                    mock.patch.object(c.time, "sleep"):
                c.kill_owned_daemon(self._pidfile(4242), self.real)

    # ---- F1: UNKNOWN (lsof slow/failed) is retried, FOREIGN never is, neither is signalled
    def _kill_with_lsof(self, side_effect, pid: int = 4242):
        err = io.StringIO()
        with mock.patch.object(c, "_run_text", side_effect=side_effect) as lsof, \
                mock.patch.object(c, "LSOF", sys.executable), \
                mock.patch.object(c.os, "kill") as kill, \
                mock.patch.object(c.time, "sleep"), \
                contextlib.redirect_stderr(err):
            c.kill_owned_daemon(self._pidfile(pid), self.real)
        return lsof, kill, err.getvalue()

    def test_unknown_proof_is_retried_and_then_the_owned_daemon_is_killed(self) -> None:
        owned = f"p4242\nftxt\nn{self.real}/bin/aasm\n"
        calls = []

        def flaky(*_):
            calls.append(1)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired("lsof", 10)
            if len(calls) == 2:
                raise OSError("fork failed")
            return owned

        lsof, kill, _ = self._kill_with_lsof(flaky)
        self.assertGreaterEqual(lsof.call_count, 3)
        self.assertEqual(kill.call_args_list[0].args, (4242, signal.SIGTERM))

    def test_persistent_unknown_signals_nothing_and_reports_the_leak(self) -> None:
        lsof, kill, err = self._kill_with_lsof(subprocess.TimeoutExpired("lsof", 10))
        self.assertEqual(lsof.call_count, c.PROOF_ATTEMPTS)
        kill.assert_not_called()
        self.assertIn("not killed: ownership unproven", err)
        self.assertIn("pid=4242", err)
        self.assertIn(str(self.real), err)

    def test_proven_foreign_is_not_retried_nor_signalled(self) -> None:
        foreign = "p4242\nftxt\nn/usr/bin/other\n"
        lsof, kill, err = self._kill_with_lsof(lambda *_: foreign)
        self.assertEqual(lsof.call_count, 1)
        kill.assert_not_called()
        self.assertNotIn("not killed", err)

    # ---- F3: the regular-file guard itself, not just "nothing was signalled"
    def test_non_regular_pidfiles_are_refused_before_any_read(self) -> None:
        fifo = self.real / "f.pid"
        os.mkfifo(fifo)
        directory = self.real / "d.pid"
        directory.mkdir()
        device = self.real / "z.pid"
        device.symlink_to("/dev/zero")
        for path in (fifo, directory, device):
            with self.subTest(path=path.name), mock.patch.object(c.os, "read") as read:
                self.assertIsNone(c._read_pidfile_pid(path))
                read.assert_not_called()

    def test_pidfile_open_failure_is_none(self) -> None:
        self.assertIsNone(c._read_pidfile_pid(self.real / "absent.pid"))

    def test_garbage_or_empty_pidfile_signals_nothing(self) -> None:
        for body in ("", "\n", "not-a-pid\n127.0.0.1:1\n"):
            pf = self.real / "daemon.pid"
            pf.write_text(body)
            with mock.patch.object(c.os, "kill") as kill:
                c.kill_owned_daemon(pf, self.real)
            kill.assert_not_called()

    @_NEEDS_LSOF
    def test_bare_name_path_launch_of_owner_binary_is_killed(self) -> None:
        exe = self._own_binary(self.real)
        env = {**os.environ, "PATH": f"{exe.parent}:{os.environ['PATH']}"}
        p = subprocess.Popen(["aasm"], cwd=self.foreign, env=env, start_new_session=True)
        self.procs.append(p)
        time.sleep(0.3)
        c.kill_owned_daemon(self._pidfile(p.pid), self.real)
        self._assert_killed(p)

    def _assert_survives(self, p: subprocess.Popen, owner: Path) -> None:
        c.kill_owned_daemon(self._pidfile(p.pid), owner)
        time.sleep(0.5)
        self.assertIsNone(p.poll())
        self.assertTrue(_alive(p.pid))

    def test_foreign_pid_is_not_killed(self) -> None:
        self._assert_survives(self._spawn(_SLEEP, self.foreign), self.link)

    def test_owner_dir_as_argv_is_not_proof(self) -> None:
        self._assert_survives(self._spawn(_SLEEP + [str(self.real)], self.foreign), self.link)
        self._assert_survives(self._spawn(_SLEEP + [f"--home={self.real}"], self.foreign), self.real)

    def test_cwd_under_owner_is_not_proof(self) -> None:
        self._assert_survives(self._spawn(_SLEEP, self.real), self.link)

    def test_open_file_under_owner_is_not_proof(self) -> None:
        # The child inherits its own descriptor; the parent's handle is closed right after spawn.
        with open(self.real / "daemon.log", "w") as f:
            p = subprocess.Popen(_SLEEP, cwd=self.foreign, stdout=f, start_new_session=True)
        self.procs.append(p)
        time.sleep(0.3)
        self._assert_survives(p, self.real)

    def test_prefix_sibling_binary_is_not_owned(self) -> None:
        owner = self.real.parent / "ab"
        sibling = self.real.parent / "abc"
        owner.mkdir()
        sibling.mkdir()
        exe = self._own_binary(sibling)
        self._assert_survives(self._spawn([str(exe)], sibling), owner)

    def test_txt_parser_takes_only_absolute_txt_entries(self) -> None:
        out = ("p9\nfcwd\ntDIR\nn/under/cwd\nftxt\ntREG\nn/usr/lib/dyld\nftxt\ntREG\nn/bin/x\n"
               "f3\ntREG\nn/not/txt\nftxt\ntunknown\nn*:8080\nf4\ntIPv4\nn->0xdead\n")
        self.assertEqual(c._txt_images(out), ["/usr/lib/dyld", "/bin/x"])

    def test_lsof_dyld_plus_binary_lists_accept_binary_under_owner(self) -> None:
        fake = f"p2\nftxt\nn/usr/lib/dyld\nftxt\nn{self.real}/bin/aasm\n"
        # lsof layer mocked; LSOF repointed at an existing path so the existence guard
        # does not short-circuit before the mocked listing is parsed.
        with mock.patch.object(c, "_run_text", return_value=fake), \
                mock.patch.object(c, "LSOF", sys.executable):
            self.assertTrue(c.pid_owned_by(2**22, self.link))

    def test_ownership_is_reproven_before_sigkill(self) -> None:
        p = self._spawn(_SLEEP, self.real)
        proofs = iter([True, False])
        sent: list[int] = []
        with mock.patch.object(c, "_proven", side_effect=lambda *_: next(proofs)), \
                mock.patch.object(c.os, "kill", side_effect=lambda pid, sig: sent.append(sig)), \
                mock.patch.object(c.time, "sleep"):
            c.kill_owned_daemon(self._pidfile(p.pid), self.real)
        self.assertEqual(sent[0], signal.SIGTERM)
        self.assertNotIn(signal.SIGKILL, sent)

    @staticmethod
    def _image_dir(pid: int) -> Path:
        """Directory holding a txt image `pid` really maps (its interpreter), so that without
        the pid guard the image rule alone WOULD accept that pid."""
        out = subprocess.run([c.LSOF, "-p", str(pid), "-Fftn"], capture_output=True, text=True,
                             timeout=10, check=False).stdout
        imgs = [os.path.realpath(i) for i in c._txt_images(out)]
        exe = os.path.realpath(sys.executable)
        return Path(next((i for i in imgs if i == exe), imgs[0])).parent

    @_NEEDS_LSOF
    def test_self_is_never_owned_even_when_it_maps_an_image_under_owner(self) -> None:
        owner = self._image_dir(os.getpid())
        self.assertTrue(c._txt_images(subprocess.run(
            [c.LSOF, "-p", str(os.getpid()), "-Fftn"], capture_output=True, text=True).stdout))
        self.assertFalse(c.pid_owned_by(os.getpid(), owner))

    @_NEEDS_LSOF
    def test_parent_is_never_owned_even_when_it_maps_an_image_under_owner(self) -> None:
        owner = self._image_dir(os.getpid())  # the child's parent is this very interpreter
        code = (
            "import os, sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(Path(c.__file__).parent)!r})\n"
            "import b1_candidate_common as c\n"
            f"print(c.pid_owned_by(os.getppid(), Path({str(owner)!r})))\n"
        )
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                             timeout=60, check=True).stdout.strip()
        self.assertEqual(out, "False")

    def test_pid_zero_one_and_negative_are_never_owned(self) -> None:
        for pid in (-1, 0, 1):
            self.assertFalse(c.pid_owned_by(pid, Path("/")), pid)

    def test_relative_owner_fails_closed(self) -> None:
        self.assertFalse(c.pid_owned_by(os.getpid(), Path("relative")))


if __name__ == "__main__":
    main(verbosity=2)
