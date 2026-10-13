"""Cross-module lifecycle tests with real 7-Zip and synthetic Windows file locks.

Only tempfile fixtures are written. Burp launches and dialogs are replaced;
production registry/file associations are never changed.
"""
from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest

import testenv  # noqa: F401  (isolated burpzip.ini)
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import archiver as ar
import burpzip as bz
import gui
import launcher as L

HOLDER = """
import sys
with open(sys.argv[1], 'r+b') as project:
    if sys.argv[2] == 'changed':
        project.seek(0, 2)
        project.write(b'\\nsynthetic session edit\\n')
        project.flush()
    print('held', flush=True)
    sys.stdin.readline()
"""


@unittest.skipUnless(os.name == "nt" and ar.SEVEN_ZIP,
                     "Lifecycle fixtures require Windows locks and 7-Zip")
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-lifecycle-test-")
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.project = self.folder / "Lab [VA2026-00001] (Round-1).burp"
        self.data = os.urandom(128 * 1024) + b"\0" * (512 * 1024)
        self.project.write_bytes(self.data)
        self.edited = time.time() - 30 * 86400
        os.utime(self.project, (self.edited, self.edited))
        result = ar.archive_project(str(self.project), level=0, threads=1)
        self.archive = Path(result.archive_path)
        self.archive_hash = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertFalse(self.project.exists())
        self.launches = []
        self.holders = []
        self.messages = []
        for target in ("launcher.register_association", "launcher.unregister_association",
                       "launcher.find_burp", "gui.main"):
            patcher = mock.patch(target, side_effect=AssertionError("unexpected real-world action"))
            patcher.start()
            self.addCleanup(patcher.stop)

    def finish_holder(self, proc):
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
        if proc.poll() is None:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        if proc.stdout is not None:
            proc.stdout.close()

    def launch_holder(self, path, changed=False):
        self.assertEqual(Path(path), self.project)
        self.assertEqual(self.project.read_bytes(), self.data)
        proc = subprocess.Popen(
            [sys.executable, "-I", "-c", HOLDER, path, "changed" if changed else "unchanged"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(self.finish_holder, proc)
        self.assertEqual(proc.stdout.readline().strip(), "held")
        self.assertTrue(bz.is_in_use(path), "synthetic holder did not acquire the project")
        self.launches.append(path)
        self.holders.append(proc)
        return proc

    def open_via_cli(self, answer, changed=False, no_console=False, tty=True):
        real_wait = L.wait_until_released

        def wait(path, *args, **kwargs):
            callback = args[4] if len(args) > 4 else kwargs.get("on_state")

            def state(value):
                if value == "in-use":
                    proc = self.holders[-1]
                    proc.stdin.write("release\n")
                    proc.stdin.flush()
                    proc.stdin.close()
                if callback:
                    callback(value)

            return real_wait(path, appear_timeout=3, poll=0.02, on_state=state)

        class QuietProgress:
            """Exercise pythonw dispatch without an actual progress window."""
            def run(inner, fn):
                return fn(inner)

            def confirm(inner, question):
                return False

            def progress(inner, stage, fraction=None):
                pass

            def state(inner, state):
                pass

            stop_event = None

        stdout = None if no_console else io.StringIO()
        stdin = io.StringIO(answer + "\n")
        stdin.isatty = lambda: tty  # positive cases explicitly simulate a terminal
        with mock.patch("sys.stdin", stdin), \
                mock.patch.object(L, "launch_burp",
                               side_effect=lambda path: self.launch_holder(path, changed)), \
                mock.patch.object(L, "wait_until_released", side_effect=wait), \
                mock.patch("builtins.input", return_value=answer), \
                mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", io.StringIO()), \
                mock.patch.object(L, "gui_progress", return_value=QuietProgress()), \
                mock.patch.object(L, "gui_message", side_effect=lambda text, **kw: self.messages.append(text)):
            code = bz.main(["open", str(self.archive)])
        self.assertEqual(code, 0)
        self.assertEqual(self.launches, [str(self.project)])
        self.assertFalse(bz.is_in_use(str(self.project)))
        self.assertEqual(hashlib.sha256(self.archive.read_bytes()).hexdigest(), self.archive_hash)
        return stdout.getvalue() if stdout is not None else ""

    def test_scan_row_and_blank_console_consent_keep_restored_project(self):
        listing = bz.scan([self.folder])
        self.assertEqual(len(listing), 1)
        item = listing[0]
        self.assertEqual(item.kind, "archive")
        self.assertEqual(item.meta["orig_name"], self.project.name)
        self.assertAlmostEqual(item.age_days, 30, places=3)
        self.assertEqual(item.size, self.archive.stat().st_size)
        cells = gui.row_values(item, 14, 0)
        self.assertEqual(cells["status"], "Zipped (.burpz)")
        self.assertEqual(cells["size"], bz.human_size(len(self.data)))
        self.assertIn("weeks ago", cells["edited"])
        self.assertIn("saved", cells["archive"])
        output = self.open_via_cli("")
        self.assertIn("left unpacked", output)
        self.assertEqual(self.project.read_bytes(), self.data)
        self.assertAlmostEqual(self.project.stat().st_mtime, self.edited, places=3)

    def test_explicit_yes_removes_unchanged_copy_only_after_real_archive_verification(self):
        output = self.open_via_cli("yes")
        self.assertIn("unchanged", output)
        self.assertFalse(self.project.exists())
        self.assertEqual(ar.list_versions(str(self.project)), [str(self.archive)])
        restored = ar.restore_project(str(self.archive))
        self.assertEqual(Path(restored).read_bytes(), self.data)

    def test_explicit_yes_creates_changed_version_and_retains_old_archive(self):
        output = self.open_via_cli("y", changed=True)
        self.assertIn("re-compressed", output)
        self.assertFalse(self.project.exists())
        versions = ar.list_versions(str(self.project))
        self.assertEqual(len(versions), 2)
        self.assertIn(str(self.archive), versions)
        newest = next(path for path in versions if path != str(self.archive))
        restored = ar.restore_project(newest)
        self.assertEqual(Path(restored).read_bytes(), self.data + b"\nsynthetic session edit\n")
        old_dest = self.folder / "old-version.burp"
        ar.restore_project(str(self.archive), str(old_dest))
        self.assertEqual(old_dest.read_bytes(), self.data)

    def test_redirected_yes_never_authorizes_source_deletion(self):
        output = self.open_via_cli("yes", tty=False)
        self.assertIn("left unpacked", output)
        self.assertEqual(self.project.read_bytes(), self.data)
        self.assertEqual(ar.list_versions(str(self.project)), [str(self.archive)])

    def test_pythonw_entry_dispatch_keeps_project_when_gui_declines(self):
        self.open_via_cli("", no_console=True)
        self.assertEqual(self.project.read_bytes(), self.data)
        self.assertEqual(len(self.messages), 1)
        self.assertIn("left unpacked", self.messages[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
