"""Tests for launcher.py: discovery, argv, release detection, association, open flow.

No real Burp launch, no real file-association changes (registry tests use the
scratch key HKCU\\Software\\BurpZipTest), synthetic temp files only.
"""
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import winreg
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import launcher as L

TEST_ROOT = r"Software\BurpZipTest"

HOLDER = r"""
import sys, time
path, plan = sys.argv[1], sys.argv[2]
# plan: comma separated "h<sec>" (hold open) / "f<sec>" (free) steps
print("start", flush=True)
for step in plan.split(","):
    secs = float(step[1:])
    if step[0] == "h":
        f = open(path, "r+b")
        time.sleep(secs)
        f.close()
    else:
        time.sleep(secs)
"""


def touch(path: str, data: bytes = b"") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Path(path).write_bytes(data)
    return path


class FindBurpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.env = mock.patch.dict(os.environ, {
            "LOCALAPPDATA": os.path.join(self.d, "local"),
            "ProgramFiles": os.path.join(self.d, "pf"),
            "ProgramW6432": os.path.join(self.d, "pf"),
            "ProgramFiles(x86)": os.path.join(self.d, "pf86")})
        self.env.start()
        self.reg = mock.patch.object(L, "_registry_dirs", return_value=[])
        self.reg_mock = self.reg.start()

    def tearDown(self):
        self.reg.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_localappdata_exe(self):
        exe = touch(os.path.join(self.d, "local", "Programs", "BurpSuitePro", "BurpSuite.exe"))
        self.assertEqual(L.find_burp(), [exe])

    def test_program_files_exe(self):
        exe = touch(os.path.join(self.d, "pf", "BurpSuitePro", "BurpSuite.exe"))
        self.assertEqual(L.find_burp(), [exe])

    def test_registry_dir_preferred(self):
        touch(os.path.join(self.d, "local", "Programs", "BurpSuitePro", "BurpSuite.exe"))
        reg_dir = os.path.join(self.d, "custom")
        exe = touch(os.path.join(reg_dir, "BurpSuite.exe"))
        self.reg_mock.return_value = [reg_dir]
        self.assertEqual(L.find_burp(), [exe])

    def test_exe_anywhere_beats_java_fallback(self):
        reg_dir = os.path.join(self.d, "custom")
        touch(os.path.join(reg_dir, "burpsuite.jar"))
        touch(os.path.join(reg_dir, "jre", "bin", "javaw.exe"))
        self.reg_mock.return_value = [reg_dir]
        exe = touch(os.path.join(self.d, "pf", "BurpSuitePro", "BurpSuite.exe"))
        self.assertEqual(L.find_burp(), [exe])

    def test_java_fallback(self):
        base = os.path.join(self.d, "local", "Programs", "BurpSuitePro")
        jar = touch(os.path.join(base, "burpsuite.jar"))
        java = touch(os.path.join(base, "jre", "bin", "javaw.exe"))
        touch(os.path.join(base, "jre", "bin", "java.exe"))
        self.assertEqual(L.find_burp(), [java, "-jar", jar])

    def test_not_found(self):
        with self.assertRaises(L.LauncherError):
            L.find_burp()

    def test_registry_readers_do_not_crash(self):
        self.reg.stop()
        try:
            dirs = L._registry_dirs()
        finally:
            self.reg_mock = self.reg.start()
        self.assertIsInstance(dirs, list)


class LaunchTests(unittest.TestCase):
    def test_launch_argv_and_flags(self):
        with mock.patch.object(L, "find_burp", return_value=[r"C:\B\BurpSuite.exe"]), \
                mock.patch.object(L.subprocess, "Popen") as popen:
            L.launch_burp("rel dir\\My Project.burp")
        argv = popen.call_args.args[0]
        kw = popen.call_args.kwargs
        self.assertEqual(argv[0], r"C:\B\BurpSuite.exe")
        self.assertEqual(argv[-1], "--project-file=" + os.path.abspath("rel dir\\My Project.burp"))
        self.assertEqual(len(argv), 2)
        self.assertTrue(kw["creationflags"] & L.DETACHED_PROCESS)
        self.assertEqual(kw["stdin"], subprocess.DEVNULL)

    def test_launch_java_fallback_argv(self):
        cmd = [r"C:\B\jre\bin\javaw.exe", "-jar", r"C:\B\burpsuite.jar"]
        with mock.patch.object(L, "find_burp", return_value=cmd), \
                mock.patch.object(L.subprocess, "Popen") as popen:
            L.launch_burp(r"C:\p\x.burp")
        self.assertEqual(popen.call_args.args[0], cmd + [r"--project-file=C:\p\x.burp"])

    def test_launch_oserror_wrapped(self):
        with mock.patch.object(L, "find_burp", return_value=[r"C:\nope\BurpSuite.exe"]), \
                mock.patch.object(L.subprocess, "Popen", side_effect=OSError("boom")):
            with self.assertRaises(L.LauncherError):
                L.launch_burp(r"C:\p\x.burp")

    def test_open_project_requires_file(self):
        with self.assertRaises(L.LauncherError):
            L.open_project(os.path.join(tempfile.gettempdir(), "does-not-exist-burpzip.burp"))


class WaitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.f = touch(os.path.join(self.tmp.name, "p.burp"), os.urandom(4096) + b"\0" * 4096)

    def tearDown(self):
        self.tmp.cleanup()

    def holder(self, plan: str) -> subprocess.Popen:
        p = subprocess.Popen([sys.executable, "-c", HOLDER, self.f, plan],
                             stdout=subprocess.PIPE, text=True)
        p.stdout.readline()
        self.addCleanup(p.stdout.close)
        return p

    def test_released_after_holder_closes(self):
        states = []
        p = self.holder("f0.3,h1.5")
        try:
            t0 = time.monotonic()
            ok = L.wait_until_released(self.f, appear_timeout=10, poll=0.1, on_state=states.append)
            elapsed = time.monotonic() - t0
        finally:
            p.wait(10)
        self.assertTrue(ok)
        self.assertEqual(states, ["waiting-open", "in-use", "released"])
        self.assertGreaterEqual(elapsed, 1.5)

    def test_brief_gap_is_not_a_release(self):
        # open 1s, free 0.15s (< 3 polls of 0.2s), open 1.2s, then released
        p = self.holder("h1.0,f0.15,h1.2")
        try:
            t0 = time.monotonic()
            ok = L.wait_until_released(self.f, appear_timeout=10, poll=0.2)
            elapsed = time.monotonic() - t0
        finally:
            p.wait(10)
        self.assertTrue(ok)
        self.assertGreaterEqual(elapsed, 2.2)

    def test_appear_timeout(self):
        states = []
        t0 = time.monotonic()
        self.assertFalse(L.wait_until_released(self.f, appear_timeout=0.5, poll=0.1,
                                               on_state=states.append))
        self.assertLess(time.monotonic() - t0, 3)
        self.assertEqual(states[-1], "timeout")

    def test_stop_event(self):
        stop = threading.Event()
        p = self.holder("h5")
        try:
            threading.Timer(0.5, stop.set).start()
            t0 = time.monotonic()
            self.assertFalse(L.wait_until_released(self.f, appear_timeout=10, poll=0.1,
                                                   stop_event=stop))
            self.assertLess(time.monotonic() - t0, 3)
        finally:
            p.kill()
            p.wait()


class FakeResult:
    def __init__(self, archive_path):
        self.archive_path = archive_path


def fake_archiver(folder: str, calls: list, changed: bool = True):
    m = types.ModuleType("archiver")

    class ArchiveError(Exception):
        pass

    def read_meta(a):
        return {"orig_name": "Proj.burp", "sha256": "x", "size": 3}

    def restore_project(a, dest_path=None, progress=None):
        calls.append(("restore", a, dest_path))
        touch(dest_path, b"abc")
        return dest_path

    def rezip_after_use(p, archive_path=None, level=5, threads=2, progress=None):
        calls.append(("rezip", p, archive_path, level))
        return FakeResult(os.path.join(folder, "Proj.new.burpz")) if changed else None

    m.ArchiveError, m.read_meta = ArchiveError, read_meta
    m.restore_project, m.rezip_after_use = restore_project, rezip_after_use
    return m


class OpenArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.archive = touch(os.path.join(self.d, "Proj.20261012-101010.burpz"), b"7z")
        self.calls = []
        self.patches = [
            mock.patch.object(L, "launch_burp", side_effect=lambda p: self.calls.append(("launch", p))),
            mock.patch.object(L, "wait_until_released", return_value=True),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def run_open(self, changed=True, **kw):
        with mock.patch.dict(sys.modules, {"archiver": fake_archiver(self.d, self.calls, changed)}):
            return L.open_archive(self.archive, poll=0.01, **kw)

    def test_restore_launch_rezip(self):
        questions = []
        s = self.run_open(confirm=lambda q: questions.append(q) or True, level=9)
        proj = os.path.join(self.d, "Proj.burp")
        self.assertEqual([c[0] for c in self.calls], ["restore", "launch", "rezip"])
        self.assertEqual(self.calls[2], ("rezip", proj, self.archive, 9))
        self.assertIn("re-compress proj.burp now?", questions[0].lower())
        self.assertTrue(s["restored"] and s["launched"] and s["released"] and s["rezipped"])
        self.assertEqual(s["status"], "rezipped")
        self.assertTrue(s["new_archive"].endswith("Proj.new.burpz"))

    def test_unchanged_rezip_returns_none(self):
        s = self.run_open(changed=False, confirm=lambda q: True)
        self.assertEqual(s["status"], "rezipped")
        self.assertIsNone(s["new_archive"])
        self.assertIn("unchanged", L.describe(s))

    def test_declined(self):
        s = self.run_open(confirm=lambda q: False)
        self.assertEqual([c[0] for c in self.calls], ["restore", "launch"])
        self.assertEqual(s["status"], "kept")
        self.assertFalse(s["rezipped"])
        self.assertEqual(Path(s["project"]).read_bytes(), b"abc")

    def test_absent_confirmation_keeps_restored_project(self):
        s = self.run_open()
        self.assertEqual([c[0] for c in self.calls], ["restore", "launch"])
        self.assertEqual(s["status"], "kept")
        self.assertFalse(s["rezipped"])
        self.assertEqual(Path(s["project"]).read_bytes(), b"abc")

    def test_console_eof_keeps_restored_project(self):
        with mock.patch.object(L.sys, "stdin", mock.Mock(isatty=lambda: True)), \
                mock.patch("builtins.input", side_effect=EOFError) as prompt:
            s = self.run_open(confirm=L._console_confirm)
        prompt.assert_called_once()
        self.assertEqual([c[0] for c in self.calls], ["restore", "launch"])
        self.assertEqual(s["status"], "kept")
        self.assertFalse(s["rezipped"])
        self.assertEqual(Path(s["project"]).read_bytes(), b"abc")

    def test_existing_project_just_launched(self):
        touch(os.path.join(self.d, "Proj.burp"), b"abc")
        s = self.run_open(confirm=lambda q: True)
        self.assertEqual([c[0] for c in self.calls], ["launch", "rezip"])
        self.assertIsNone(self.calls[1][2])  # archiver picks newest version
        self.assertFalse(s["restored"])

    def test_never_opened_no_rezip(self):
        asked = []
        with mock.patch.object(L, "wait_until_released", return_value=False):
            s = self.run_open(confirm=lambda q: asked.append(q) or True)
        self.assertEqual(s["status"], "not-opened")
        self.assertEqual(asked, [])
        self.assertNotIn("rezip", [c[0] for c in self.calls])

    def test_bad_orig_name_refused(self):
        fake = fake_archiver(self.d, self.calls)
        fake.read_meta = lambda a: {"orig_name": "..\\evil.exe"}
        with mock.patch.dict(sys.modules, {"archiver": fake}):
            with self.assertRaises(L.LauncherError):
                L.open_archive(self.archive)
        self.assertEqual(self.calls, [])


class ConsoleConfirmTests(unittest.TestCase):
    def setUp(self):
        tty = mock.patch.object(L.sys, "stdin", mock.Mock(isatty=lambda: True))
        tty.start()
        self.addCleanup(tty.stop)

    def test_non_tty_yes_is_not_consent(self):
        with mock.patch.object(L.sys, "stdin", mock.Mock(isatty=lambda: False)), \
                mock.patch("builtins.input", return_value="yes") as prompt:
            self.assertFalse(L._console_confirm("Re-compress now?"))
        prompt.assert_not_called()

    def test_missing_stdin_is_not_consent(self):
        with mock.patch.object(L.sys, "stdin", None), \
                mock.patch("builtins.input", return_value="yes") as prompt:
            self.assertFalse(L._console_confirm("Re-compress now?"))
        prompt.assert_not_called()

    def test_only_explicit_yes_is_affirmative(self):
        for answer, expected in (("y", True), ("YES", True), (" yes ", True),
                                 ("", False), ("n", False), ("no", False),
                                 ("maybe", False)):
            with self.subTest(answer=answer), \
                    mock.patch("builtins.input", return_value=answer) as prompt:
                self.assertEqual(L._console_confirm("Re-compress now?"), expected)
                self.assertIn("[y/N]", prompt.call_args.args[0])

    def test_unavailable_input_is_not_consent(self):
        for exc in (EOFError(), OSError("stdin unavailable"),
                    RuntimeError("input(): lost sys.stdin")):
            with self.subTest(error=type(exc).__name__), \
                    mock.patch("builtins.input", side_effect=exc):
                self.assertFalse(L._console_confirm("Re-compress now?"))


class AssociationTests(unittest.TestCase):
    def setUp(self):
        self.root = mock.patch.object(L, "CLASSES_ROOT", TEST_ROOT + r"\Classes")
        self.root.start()
        self.notify = mock.patch.object(L, "_notify_shell")
        self.notify_mock = self.notify.start()
        self.icon = mock.patch.object(L, "burp_exe_for_icon", return_value=r"C:\B\BurpSuite.exe")
        self.icon.start()

    def tearDown(self):
        self.icon.stop()
        self.notify.stop()
        self.root.stop()
        L._delete_tree(winreg.HKEY_CURRENT_USER, TEST_ROOT)

    def q(self, sub, name=""):
        return L._read_reg_str(winreg.HKEY_CURRENT_USER, rf"{TEST_ROOT}\Classes\{sub}", name)

    def test_register_unregister_roundtrip(self):
        self.assertFalse(L.is_association_registered())
        cmd = L.register_association(r"C:\Py\pythonw.exe", r"C:\T\burpzip.py")
        self.assertEqual(cmd, r'"C:\Py\pythonw.exe" "C:\T\burpzip.py" open "%1"')
        self.assertTrue(L.is_association_registered())
        self.assertEqual(self.q(".burpz"), "BurpZip.Archive")
        self.assertEqual(self.q("BurpZip.Archive"), "Burp project archive")
        self.assertEqual(self.q(r"BurpZip.Archive\shell\open\command"), cmd)
        self.assertEqual(self.q(r"BurpZip.Archive\DefaultIcon"), r"C:\B\BurpSuite.exe,0")
        self.assertTrue(self.notify_mock.called)
        L.unregister_association()
        self.assertFalse(L.is_association_registered())
        with self.assertRaises(FileNotFoundError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{TEST_ROOT}\Classes\BurpZip.Archive")
        with self.assertRaises(FileNotFoundError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{TEST_ROOT}\Classes\.burpz")

    def test_unregister_keeps_foreign_owner(self):
        L.register_association(r"C:\Py\pythonw.exe", r"C:\T\burpzip.py")
        L._set(".burpz", "Other.App")
        L.unregister_association()
        self.assertEqual(self.q(".burpz"), "Other.App")
        self.assertFalse(L.is_association_registered())

    def test_real_root_untouched(self):
        self.assertEqual(L.CLASSES_ROOT, TEST_ROOT + r"\Classes")


class PythonwTests(unittest.TestCase):
    def test_prefers_real_install_over_store_and_alias(self):
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "Program Files", "WindowsApps", "PSF.Python_3.12.1_x64")
            alias = os.path.join(d, "Microsoft", "WindowsApps", "PSF.Python_q")
            real = os.path.join(d, "Python312")
            for base in (store, alias, real):
                touch(os.path.join(base, "pythonw.exe"))
                touch(os.path.join(base, "python.exe"))
            self.assertEqual(L.resolve_pythonw([os.path.join(real, "python.exe")]),
                             os.path.join(real, "pythonw.exe"))
            # Store: versioned install skipped, stable alias used
            self.assertEqual(L.resolve_pythonw([os.path.join(store, "python.exe"),
                                                os.path.join(alias, "python.exe")]),
                             os.path.join(alias, "pythonw.exe"))
            self.assertEqual(L.resolve_pythonw([os.path.join(alias, "python.exe"),
                                                os.path.join(real, "python.exe")]),
                             os.path.join(real, "pythonw.exe"))
            with self.assertRaises(L.LauncherError):
                L.resolve_pythonw([os.path.join(store, "python.exe")])

    def test_resolves_on_this_machine(self):
        w = L.resolve_pythonw()
        self.assertTrue(w.lower().endswith("pythonw.exe"))
        self.assertFalse(L._is_store_install(w))


class GuiSmokeTests(unittest.TestCase):
    def test_build_and_destroy(self):
        try:
            win = L.GuiProgress("burpzip test", withdraw=True)
        except Exception as e:  # no display / Tk unavailable
            self.skipTest(f"Tk unavailable: {e}")
        try:
            win.progress("extract", 0.5)
            win.state("in-use")
            win._apply(*win._q.get_nowait())
            win._apply(*win._q.get_nowait())
            win.root.update()
            self.assertIn("Burp is using", win.text.get())
        finally:
            win.destroy()


if __name__ == "__main__":
    unittest.main()
