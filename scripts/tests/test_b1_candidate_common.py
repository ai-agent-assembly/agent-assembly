"""Ownership proof for `kill_owned_daemon` (AAASM-6419): per-PID, never a pattern kill.

Real child processes are used; the negative control is a foreign process that must survive.
"""

from __future__ import annotations

import os
import shutil
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

    def test_binary_executed_from_owner_bin_is_killed(self) -> None:
        exe = self._own_binary(self.real)
        p = self._spawn([str(exe)], self.foreign)
        c.kill_owned_daemon(self._pidfile(p.pid), self.link)  # symlinked owner spelling
        self._assert_killed(p)

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
        f = open(self.real / "daemon.log", "w")
        self.addCleanup(f.close)
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
        with mock.patch.object(c, "_run_text", return_value=fake):  # lsof layer mocked
            self.assertTrue(c.pid_owned_by(2**22, self.link))

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

    @staticmethod
    def _image_dir(pid: int) -> Path:
        """Directory holding a txt image `pid` really maps (its interpreter), so that without
        the pid guard the image rule alone WOULD accept that pid."""
        out = subprocess.run([c.LSOF, "-p", str(pid), "-Fftn"], capture_output=True, text=True,
                             timeout=10, check=False).stdout
        imgs = [os.path.realpath(i) for i in c._txt_images(out)]
        exe = os.path.realpath(sys.executable)
        return Path(next((i for i in imgs if i == exe), imgs[0])).parent

    def test_self_is_never_owned_even_when_it_maps_an_image_under_owner(self) -> None:
        owner = self._image_dir(os.getpid())
        self.assertTrue(c._txt_images(subprocess.run(
            [c.LSOF, "-p", str(os.getpid()), "-Fftn"], capture_output=True, text=True).stdout))
        self.assertFalse(c.pid_owned_by(os.getpid(), owner))

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
    unittest.main(verbosity=2)
