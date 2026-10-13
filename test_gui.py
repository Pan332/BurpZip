"""Tests for gui.py: pure helpers plus a headless (withdrawn) Tk smoke test.

No real .burp files are touched; the worker test uses a fake archiver module
and an empty temp folder as scan root. Windows are always destroyed.
"""
import os
import runpy
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import burpzip as bz  # noqa: E402
import gui  # noqa: E402

MB = 1024**2
GB = 1024**3
_NO_STORE = mock.patch.object(bz, "DEFAULT_NATIVE_STORE",
                              Path(tempfile.gettempdir()) / "burpzip-gui-test-no-native-store")


def setUpModule():
    # Never see the user's real Burp folder from GUI tests.
    _NO_STORE.start()


def tearDownModule():
    _NO_STORE.stop()


def item(path, kind, size, age, in_use=False, meta=None):
    it = bz.Item(path=path, kind=kind, size=size, mtime=time.time() - age * 86400,
                 age_days=age, in_use=in_use)
    if meta is not None:
        it.meta = meta
    return it


def root_exists(root):
    try:
        return bool(root.winfo_exists())
    except gui.tk.TclError:
        return False


def pump_until(test, root, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        if root_exists(root):
            root.update()
        time.sleep(0.01)
    test.assertTrue(predicate(), "Tk/worker did not reach the expected state")


def close_app(test, app, gates=()):
    # Always release synthetic workers, including when a regression assertion fails.
    for gate in gates:
        gate.set()
    app.close()
    pump_until(test, app.root,
               lambda: not app._worker.is_alive() and not root_exists(app.root))
    test.assertIsNone(app._after_id)


class EngagementKeyTests(unittest.TestCase):
    def test_bracketed_id_wins(self):
        self.assertEqual(gui.engagement_key("2569-07-09-[VA2026-00123]-Contoso-Portal-(Round-1).burp"),
                         "VA2026-00123")
        self.assertEqual(gui.engagement_key("2569-07-20-[va2026-00123]-Contoso-Portal-(Round-2).burp"),
                         "VA2026-00123")

    def test_revisit_numbered_copies_group(self):
        a = gui.engagement_key("2569-03-23-Revisit_Fabrikam.burp")
        b = gui.engagement_key("2569-03-27-Revisit_Fabrikam_2.burp")
        self.assertEqual(a, "fabrikam")
        self.assertEqual(a, b)

    def test_init_and_misspelled_revisit_case_insensitive(self):
        a = gui.engagement_key("2568-12-16-Init-Northwinddatacenter.burp")
        b = gui.engagement_key("2569-01-08-Reviste-NorthwindDatacenter.burp")
        self.assertEqual(a, "northwinddatacenter")
        self.assertEqual(a, b)

    def test_underscore_date_backup_and_archive_suffixes(self):
        base = gui.engagement_key("2569-03-02_ShopApp.burp")
        self.assertEqual(base, "shopapp")
        self.assertEqual(gui.engagement_key("2569-03-02_ShopApp (backup).burp"), base)
        self.assertEqual(gui.engagement_key("2569-03-02_ShopApp (2).burp"), base)
        self.assertEqual(gui.engagement_key("2569-03-02_ShopApp.burp.backup"), base)
        self.assertEqual(gui.engagement_key("2569-03-02_ShopApp.20261012-101500.burpz"), base)

    def test_distinct_engagements_differ(self):
        self.assertNotEqual(gui.engagement_key("2569-03-23-Revisit_Fabrikam.burp"),
                            gui.engagement_key("2568-12-16-Init-Northwinddatacenter.burp"))


class StatusTests(unittest.TestCase):
    def test_project_statuses(self):
        self.assertEqual(gui.item_status(item("a.burp", "project", GB, 3), 14, 100 * MB), "Active")
        self.assertEqual(gui.item_status(item("a.burp", "project", GB, 30), 14, 100 * MB), "Old")
        self.assertEqual(gui.item_status(item("a.burp", "project", 10 * MB, 30), 14, 100 * MB),
                         "Small")
        self.assertEqual(gui.item_status(item("a.burp", "project", GB, 30, in_use=True), 14,
                                         100 * MB), "In use")

    def test_backup_and_archive(self):
        self.assertEqual(gui.item_status(item("a.burp.backup", "backup", GB, 30), 14, 0), "Backup")
        self.assertEqual(gui.item_status(item("a.burp.backup", "backup", GB, 30, True), 14, 0),
                         "In use")
        self.assertEqual(gui.item_status(item("a.burpz", "archive", MB, 1), 14, 0), "Zipped (.burpz)")
        self.assertEqual(gui.status_tag("Old"), "old")
        self.assertEqual(gui.status_tag("In use"), "inuse")
        self.assertEqual(gui.status_tag("Backup"), "backup")

    def test_archive_row_uses_meta(self):
        now = time.time()
        meta = {"size": 1000 * MB, "mtime": now - 20 * 86400,
                "archived_at": "2026-10-01T10:00:00"}
        a = item(r"C:\Users\x\p\A.20261001-100000.burpz", "archive", 80 * MB, 1, meta=meta)
        v = gui.row_values(a, 14, 100 * MB, home=r"C:\Users\x", now=now)
        self.assertEqual(v["folder"], r"~\p")
        self.assertEqual(v["size"], bz.human_size(1000 * MB))
        self.assertIn("2 weeks ago", v["edited"])
        self.assertIn("archived 2026-10-01", v["edited"])
        self.assertIn("92% saved", v["archive"])

    def test_archive_without_meta_is_defensive(self):
        a = item(r"C:\p\A.burpz", "archive", 80 * MB, 3)
        v = gui.row_values(a, 14, 100 * MB, home=r"C:\Users\x")
        self.assertEqual(v["status"], "Zipped (.burpz)")
        self.assertEqual(v["archive"], bz.human_size(80 * MB))

    def test_summary_and_filter(self):
        items = [item(r"C:\p\A.burp", "project", GB, 3),
                 item(r"C:\p\A.burp.backup", "backup", GB, 5),
                 item(r"C:\q\B.burpz", "archive", 100 * MB, 1, meta={"size": GB})]
        s = gui.summarize(items)
        self.assertEqual((s["projects"], s["backups"], s["archives"]), (1, 1, 1))
        self.assertEqual(s["saved_bytes"], GB - 100 * MB)
        self.assertTrue(gui.matches_filter(items[2], "q", home="Z:"))
        self.assertFalse(gui.matches_filter(items[0], "zzz", home="Z:"))

    def test_plan_never_deletes_backups(self):
        items = [item(r"C:\p\A.burp", "project", GB, 30),
                 item(r"C:\p\A.burp.backup", "backup", GB, 40)]
        plan = gui.archive_only_plan(bz.build_plan(items, 14, 10 * GB))
        acts = {Path(s["path"]).name: s["action"] for s in plan["steps"]}
        self.assertEqual(acts, {"A.burp.backup": "skip", "A.burp": "archive"})
        self.assertIn("Archive 1 project(s)", gui.plan_summary(plan))


class FlexibleCallTests(unittest.TestCase):
    def test_passes_only_accepted_aliases(self):
        def f(path, level=5, stop=None):
            return (path, level, stop)
        ev = threading.Event()
        self.assertEqual(gui.call_flexible(f, "x", level=9, stop_event=ev, log=print),
                         ("x", 9, ev))
        self.assertTrue(gui.accepts_option(f, "stop_event"))
        self.assertFalse(gui.accepts_option(f, "confirm"))

    def test_force_alias_reaches_newer_backup_confirmation(self):
        def delete_backup(path, force_newer=False):
            return path, force_newer
        self.assertEqual(gui.call_flexible(delete_backup, "demo.burp.backup", force=True),
                         ("demo.burp.backup", True))
        self.assertEqual(gui.call_flexible(delete_backup, "demo.burp.backup", force=None),
                         ("demo.burp.backup", False))

    def test_missing_module_raises_clear_error(self):
        with self.assertRaises(gui.MissingFeature) as cm:
            gui.load_function("burpzip_no_such_module_xyz", "archive_project")
        self.assertIn("archive_project", str(cm.exception))


class GuiPlanTests(unittest.TestCase):
    def test_make_plan_delegates_independent_volume_budgets_and_scan_roots(self):
        app = gui.BurpZipApp.__new__(gui.BurpZipApp)
        app.settings = dict(gui.DEFAULT_SETTINGS, days=90, min_size_mb=256,
                            extra_folders=[r"Z:\extra"])
        app.base_roots = [Path(r"C:\synthetic"), Path(r"D:\synthetic")]
        app.items = [item(r"C:\synthetic\demo.burp", "project", GB, 100),
                     item(r"D:\synthetic\demo.burp.backup", "backup", GB, 100),
                     item(r"D:\synthetic\demo.burpz", "archive", 100 * MB, 1),
                     item(r"C:\synthetic\ignore.txt", "other", MB, 100)]
        for candidate in app.items:
            candidate.notes = ["scan note"]
        shared_plan = {
            "free_now": 5 * GB,
            "free_after": 6 * GB,
            "steps": [{"path": app.items[1].path, "action": "delete-backup",
                       "size": GB, "frees": GB, "notes": []}],
            "volumes": [{"volume": "mock-volume", "free_now": 5 * GB,
                         "free_after": 6 * GB, "notes": []}],
        }
        with mock.patch.object(bz, "build_volume_plan", create=True,
                               return_value=shared_plan) as volume_plan, \
                mock.patch.object(bz, "build_plan", return_value=shared_plan) as legacy, \
                mock.patch.object(gui.shutil, "disk_usage", return_value=mock.Mock(free=5 * GB)):
            result = app.make_plan()
        volume_plan.assert_called_once()
        legacy.assert_not_called()
        pool, days, min_size = volume_plan.call_args.args
        self.assertEqual([candidate.path for candidate in pool],
                         [candidate.path for candidate in app.items[:3]])
        self.assertEqual((days, min_size), (90, 256 * MB))
        self.assertEqual(volume_plan.call_args.kwargs, {"roots": app.scan_roots()})
        for original, copied in zip(app.items, pool):
            self.assertIsNot(original, copied)
            self.assertIsNot(original.notes, copied.notes)
        self.assertEqual(result["steps"][0]["action"], "skip")
        self.assertEqual(result["steps"][0]["frees"], 0)
        self.assertEqual(shared_plan["steps"][0]["action"], "delete-backup")
        self.assertEqual(result["volumes"], shared_plan["volumes"])


class GuiStartupTests(unittest.TestCase):
    def test_main_preserves_saved_days_unless_explicitly_overridden(self):
        app_class = gui.BurpZipApp
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp, "gui_settings.json")
            settings_path.write_text('{"days": 90}', encoding="utf-8")
            for override, expected in (({}, 90), ({"days": 14}, 14), ({"days": 30}, 30)):
                with self.subTest(override=override):
                    root = mock.Mock()
                    initialized = []

                    def construct(root, **kwargs):
                        # Exercise the real settings overlay, but build no widgets
                        # and start no real worker or scanner.
                        app = app_class(root, items=[], autoscan=False, **kwargs)
                        initialized.append(app.days)
                        return app

                    with mock.patch.object(gui.tk, "Tk", return_value=root), \
                            mock.patch.object(gui.ttk, "Style"), \
                            mock.patch.object(gui, "default_settings_path", return_value=settings_path), \
                            mock.patch.object(app_class, "_build"), \
                            mock.patch.object(app_class, "refresh"), \
                            mock.patch.object(gui.threading, "Thread"), \
                            mock.patch.object(gui, "BurpZipApp", side_effect=construct):
                        gui.main(roots=[Path(tmp)], **override)
                    self.assertEqual(initialized, [expected])
                    root.mainloop.assert_called_once()
                    self.assertEqual(settings_path.read_text(encoding="utf-8"), '{"days": 90}')
            self.assertEqual(gui.load_settings(None)["days"], 10)

    def test_standalone_parser_has_no_implicit_days_override(self):
        import argparse
        parser = argparse.ArgumentParser()
        with mock.patch("argparse.ArgumentParser", return_value=parser), \
                mock.patch.object(sys, "argv", [str(Path(gui.__file__))]), \
                mock.patch.object(gui.tk, "Tk", side_effect=RuntimeError("mocked startup reached")):
            with self.assertRaisesRegex(RuntimeError, "mocked startup reached"):
                runpy.run_path(gui.__file__, run_name="__main__")
        self.assertIsNone(parser.parse_args([]).days)
        self.assertEqual(parser.parse_args(["--days", "14"]).days, 14)
        self.assertEqual(parser.parse_args(["--days", "90"]).days, 90)


class GuiSmokeTests(unittest.TestCase):
    def make_items(self):
        return [
            item(r"C:\fake\2569-07-09-[VA2026-00123]-Contoso-Portal-(Round-1).burp", "project", GB, 40),
            item(r"C:\fake\2569-07-20-[VA2026-00123]-Contoso-Portal-(Round-2).burp", "project", GB, 2),
            item(r"C:\fake\2569-03-23-Revisit_Fabrikam.burp", "project", 2 * GB, 90, in_use=True),
            item(r"C:\fake\2569-03-23-Revisit_Fabrikam.burp.backup", "backup", 2 * GB, 95),
            item(r"C:\fake\2569-03-27-Revisit_Fabrikam_2.20261001-101010.burpz", "archive", 90 * MB,
                 10, meta={"size": GB, "mtime": time.time() - 30 * 86400,
                           "archived_at": "2026-10-01T10:10:10"}),
        ]

    def test_construct_update_destroy(self):
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        app = None
        try:
            app = gui.BurpZipApp(root, roots=[Path(tempfile.gettempdir())],
                                 items=self.make_items(), settings_path=None, autoscan=False)
            root.update()
            self.assertEqual(len(app.tree.get_children()), 5)
            app.group_var.set(True)
            app.refresh()
            groups = app.tree.get_children()
            self.assertEqual(len(groups), 2)  # VA2026-00123 and fabrikam
            self.assertEqual(sum(len(app.tree.get_children(g)) for g in groups), 5)
            app.group_var.set(False)
            app.search_var.set("fabrikam")
            self.assertEqual(len(app.tree.get_children()), 3)
            app.search_var.set("")
            app.sort_by("size")
            first = app.by_iid[app.tree.get_children()[0]]
            self.assertEqual(first.size, 2 * GB)
            tags = {app.tree.item(i, "tags")[0] for i in app.tree.get_children()}
            self.assertTrue({"old", "inuse", "backup", "archived", "active"} <= tags)
            self.assertIn("Projects: 3", app.summary_var.get())
        finally:
            if app is not None:
                close_app(self, app)
            else:
                root.destroy()

    def test_worker_runs_fake_archiver_and_stop(self):
        import tkinter as tk
        calls = []

        def archive_project(path, level=5, stop_event=None):
            calls.append((path, level))
            stop_event.set()  # simulate user pressing Stop during the first file
            return "ok"
        fake = types.ModuleType("archiver")
        fake.archive_project = archive_project
        root = tk.Tk()
        root.withdraw()
        app = None
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(sys.modules, {"archiver": fake}), \
                mock.patch.object(bz, "burp_running", lambda: False):
            try:
                app = gui.BurpZipApp(root, roots=[Path(tmp)], items=[], settings_path=None,
                                     autoscan=False)
                paths = [str(Path(tmp, "a.burp")), str(Path(tmp, "b.burp"))]
                self.assertTrue(app.submit("t", lambda: app._archive_paths_job(paths)))
                for b in app._action_buttons:
                    self.assertTrue(b.instate(["disabled"]))
                deadline = time.time() + 20
                while app.busy and time.time() < deadline:
                    root.update()
                    time.sleep(0.02)
                self.assertFalse(app.busy)
                self.assertEqual(calls, [(paths[0], 5)])  # stopped before the second file
                log = app.log_text.get("1.0", "end")
                self.assertIn("Stopped before b.burp", log)
            finally:
                if app is not None:
                    close_app(self, app)
                else:
                    root.destroy()


class GuiShutdownTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = gui.tk.Tk()
        self.root.withdraw()
        self.app = gui.BurpZipApp(self.root, roots=[Path(self.tmp.name)], items=[],
                                  settings_path=None, autoscan=False)
        self.gates = []
        self.scan = mock.patch.object(self.app, "_scan_job")
        self.scan.start()
        self.addCleanup(self.scan.stop)
        self.addCleanup(close_app, self, self.app, self.gates)

    def gate(self):
        gate = threading.Event()
        self.gates.append(gate)
        return gate

    def assert_closing_keeps_root(self):
        started = time.monotonic()
        self.app.close()
        self.assertLess(time.monotonic() - started, 1,
                        "close must not join a worker on the Tk thread")
        self.assertTrue(root_exists(self.root), "root destroyed before the file operation ended")
        self.assertTrue(self.app.closing.is_set())
        self.assertTrue(self.app.stop_event.is_set())
        self.assertTrue(self.app._worker.is_alive())
        for button in self.app._action_buttons:
            self.assertTrue(button.instate(["disabled"]))
        with mock.patch.object(gui.messagebox, "showinfo") as info:
            self.assertFalse(self.app.submit("late task", lambda: None))
        info.assert_not_called()
        self.assertTrue(self.app.stop_event.is_set(), "rejected submit cleared Stop")

    def assert_closed(self):
        pump_until(self, self.root,
                   lambda: not self.app._worker.is_alive() and not root_exists(self.root))
        self.assertFalse(self.app.busy)
        self.assertIsNone(self.app._after_id)

    def test_worker_is_non_daemon_and_idle_close_rejects_submissions(self):
        self.assertFalse(self.app._worker.daemon)
        self.app.close()
        with mock.patch.object(gui.messagebox, "showinfo") as info:
            self.assertFalse(self.app.submit("after close", lambda: None))
        info.assert_not_called()
        self.assert_closed()
        self.app.close()  # idempotent after Tk destruction

    def test_close_during_archive_finishes_current_file_only(self):
        entered, release, completed = threading.Event(), self.gate(), threading.Event()
        paths = [str(Path(self.tmp.name, "demo.burp")),
                 str(Path(self.tmp.name, "next.burp"))]
        Path(paths[0]).write_bytes(b"synthetic archive source")
        Path(paths[1]).write_bytes(b"synthetic second source")
        handles, calls, ui_threads = [], [], []

        def archive_project(path, progress=None, **kwargs):
            calls.append(path)
            with open(path, "r+b") as handle:
                handles.append(handle)
                progress("compress", 0.5)
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("test gate was not released")
                handle.seek(0)
                self.assertEqual(handle.read(), b"synthetic archive source")
            completed.set()
            return "verified synthetic archive"

        original_log = self.app.log

        def log_on_tk(text):
            ui_threads.append(threading.get_ident())
            original_log(text)

        fake = types.ModuleType("archiver")
        fake.archive_project = archive_project
        with mock.patch.dict(sys.modules, {"archiver": fake}), \
                mock.patch.object(self.app, "log", side_effect=log_on_tk):
            try:
                self.assertTrue(self.app.submit("archive", lambda: self.app._archive_paths_job(paths)))
                self.assertTrue(entered.wait(2))
                self.assert_closing_keeps_root()
                self.root.update()
                self.assertFalse(completed.is_set())
                self.assertTrue(root_exists(self.root))
                release.set()
                self.assert_closed()
            finally:
                close_app(self, self.app, self.gates)
        self.assertTrue(completed.is_set())
        self.assertEqual(calls, paths[:1])
        self.assertTrue(handles and all(handle.closed for handle in handles))
        self.assertEqual(Path(paths[1]).read_bytes(), b"synthetic second source")
        self.assertTrue(ui_threads)
        self.assertEqual(set(ui_threads), {threading.get_ident()})

    def test_close_during_restore_keeps_tk_until_handle_is_closed(self):
        entered, release, completed = threading.Event(), self.gate(), threading.Event()
        archive = Path(self.tmp.name, "demo.20261012-101010.burpz")
        archive.write_bytes(b"synthetic archive stand-in")
        output = Path(self.tmp.name, "demo.burp")
        handles = []

        def restore_project(path, progress=None):
            self.assertEqual(path, str(archive))
            with output.open("wb") as handle:
                handles.append(handle)
                handle.write(b"synthetic ")
                progress("extract", 0.5)
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("test gate was not released")
                handle.write(b"restored project")
            completed.set()
            return str(output)

        fake = types.ModuleType("archiver")
        fake.restore_project = restore_project
        self.app.items = [item(str(archive), "archive", archive.stat().st_size, 1)]
        self.app.refresh()
        self.app.tree.selection_set(self.app.tree.get_children()[0])
        with mock.patch.dict(sys.modules, {"archiver": fake}):
            try:
                self.app.restore_selected()
                self.assertTrue(entered.wait(2))
                self.assert_closing_keeps_root()
                self.root.update()
                self.assertFalse(completed.is_set())
                release.set()
                self.assert_closed()
            finally:
                close_app(self, self.app, self.gates)
        self.assertTrue(completed.is_set())
        self.assertTrue(handles and all(handle.closed for handle in handles))
        self.assertEqual(output.read_bytes(), b"synthetic restored project")
        self.assertEqual(archive.read_bytes(), b"synthetic archive stand-in")

    def test_close_declines_pending_worker_confirmation_without_dialog(self):
        queued, answered, release = threading.Event(), threading.Event(), self.gate()
        answers = []
        original_post = self.app.post

        def observe_post(kind, *payload):
            original_post(kind, *payload)
            if kind == "ask":
                queued.set()

        def job():
            answers.append(self.app.ask_from_worker("Re-compress synthetic project?"))
            answered.set()
            if not release.wait(5):
                raise RuntimeError("test gate was not released")

        with mock.patch.object(self.app, "post", side_effect=observe_post), \
                mock.patch.object(gui.messagebox, "askyesno") as ask:
            try:
                self.assertTrue(self.app.submit("confirmation", job))
                self.assertTrue(queued.wait(2))  # no Tk pumping before close
                self.assert_closing_keeps_root()
                pump_until(self, self.root, answered.is_set)
                self.assertEqual(answers, [False])
                ask.assert_not_called()
                self.assertTrue(root_exists(self.root))
                release.set()
                self.assert_closed()
            finally:
                close_app(self, self.app, self.gates)

    def test_close_inside_dispatched_confirmation_defers_root_destruction(self):
        queued = threading.Event()
        answers, roots_during_dialog, callback_errors = [], [], []
        original_post = self.app.post

        def observe_post(kind, *payload):
            original_post(kind, *payload)
            if kind == "ask":
                queued.set()

        def job():
            answers.append(self.app.ask_from_worker("Re-compress synthetic project?"))
            self.app.post("progress", 1, 1)

        def close_in_modal(*args, **kwargs):
            # Real Tk messageboxes run a nested event loop. Reproduce that
            # without opening a visible dialog or making a second Tk root.
            self.app.close()
            deadline = time.monotonic() + 3
            while self.app._worker.is_alive() and time.monotonic() < deadline:
                if root_exists(self.root):
                    self.root.update()
                time.sleep(0.01)
            # Let any queued nested after callback run before returning.
            deadline = time.monotonic() + 0.2
            while root_exists(self.root) and time.monotonic() < deadline:
                self.root.update()
                time.sleep(0.01)
            roots_during_dialog.append(root_exists(self.root))
            return True  # Closing must override even this affirmative answer.

        with mock.patch.object(self.app, "post", side_effect=observe_post), \
                mock.patch.object(gui.messagebox, "askyesno", side_effect=close_in_modal), \
                mock.patch.object(self.root, "report_callback_exception",
                                  side_effect=lambda *error: callback_errors.append(error)):
            self.assertTrue(self.app.submit("modal confirmation", job))
            self.assertTrue(queued.wait(2))
            self.assert_closed()
        self.assertEqual(answers, [False])
        self.assertEqual(roots_during_dialog, [True], "nested poll destroyed a live modal root")
        self.assertEqual(callback_errors, [], "outer poll handled callbacks after Tk destruction")

    def test_close_cancels_waiting_open_without_launch_or_rezip(self):
        import launcher
        waiting = threading.Event()
        outcome = []
        project = Path(self.tmp.name, "demo.burp")
        project.write_bytes(b"synthetic project")

        def wait_job():
            outcome.append(launcher.wait_until_released(
                str(project), appear_timeout=30, poll=0.01, stop_event=self.app.stop_event,
                on_state=lambda state: (self.app.wstate(state), waiting.set())))

        with mock.patch.object(bz, "is_in_use", return_value=False), \
                mock.patch.object(launcher, "launch_burp") as launch:
            self.assertTrue(self.app.submit("waiting-open", wait_job))
            self.assertTrue(waiting.wait(2))
            self.app.close()
            self.assert_closed()
            launch.assert_not_called()
        self.assertEqual(outcome, [False])
        self.assertEqual(project.read_bytes(), b"synthetic project")


class BurpFolderRowTests(unittest.TestCase):
    def native(self, resident, edited_days=12):
        it = item(r"C:\Users\x\Downloads\BurpProjects\P.burp", "project", 768 * MB, edited_days)
        it.native, it.native_resident = "native", resident
        it.meta = {"archive_size": 100 * MB, "size": 768 * MB, "mtime": it.mtime}
        return it

    def test_zipped_row_shows_age_and_saving(self):
        it = self.native(resident=False)
        now = time.time()
        self.assertEqual(gui.edited_text(it, now), bz.human_age(12))
        self.assertEqual(gui.archive_text(it), f"{bz.human_size(100 * MB)} zip (87% saved)")

    def test_unpacked_row_shows_zip_but_no_saving(self):
        it = self.native(resident=True)
        self.assertEqual(gui.archive_text(it), f"unpacked (zip {bz.human_size(100 * MB)})")
        self.assertEqual(gui.native_saved(it), 0)

    def test_summary_counts_burp_folder_separately(self):
        zipped, unpacked = self.native(False), self.native(True)
        s = gui.summarize([zipped, unpacked])
        self.assertEqual(s["burp_folder"], 2)
        self.assertEqual(s["burp_folder_saved"], 668 * MB)
        self.assertEqual(s["project_bytes"], 768 * MB)   # only the unpacked one uses disk
        self.assertEqual(s["projects"], 0)

    def test_burp_folder_status_labels(self):
        self.assertEqual(gui.item_status(self.native(resident=False), 10, 0), "Burp folder: zipped")
        self.assertEqual(gui.item_status(self.native(resident=True), 10, 0), "Burp folder: unpacked")
        edited = self.native(resident=True)
        edited.native_modified = True
        self.assertEqual(gui.item_status(edited, 10, 0), "Burp folder: unpacked (edited)")
        self.assertEqual(gui.status_tag("Burp folder: zipped"), "protected")
        self.assertEqual(gui.status_tag("Zipped (.burpz)"), "archived")

    def test_native_without_catalog_info_stays_blank(self):
        it = self.native(False)
        it.meta = None
        self.assertEqual(gui.archive_text(it), "")


class BurpFolderGuiTests(unittest.TestCase):
    """Burp folder menu/toolbar wiring; the native side is mocked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = gui.tk.Tk()
        self.root.withdraw()
        self.app = gui.BurpZipApp(self.root, roots=[Path(self.tmp.name)], items=[],
                                  settings_path=None, autoscan=False)
        self.scan = mock.patch.object(self.app, "_scan_job")
        self.scan.start()
        self.addCleanup(self.scan.stop)
        self.addCleanup(close_app, self, self.app)
        self.store = Path(self.tmp.name) / "BurpProjects-store"

    def wait_idle(self):
        pump_until(self, self.root, lambda: not self.app.busy)

    def test_menu_and_toolbar_exist(self):
        bar = self.app.menubar
        labels = [bar.entrycget(i, "label") for i in range(bar.index("end") + 1)
                  if bar.type(i) == "cascade"]
        self.assertIn("Burp folder", labels)
        texts = [b.cget("text") for b in self.app._all_buttons]
        self.assertIn("Add to Burp folder", texts)
        self.assertIn("Unpack now", texts)

    def test_provider_indicator_states(self):
        self.app.update_provider_status()
        self.assertEqual(self.app.provider_lbl.cget("text"), "No Burp folder")
        with mock.patch.object(self.app, "native_store", return_value=self.store):
            with mock.patch.object(gui.burpzip, "provider_running", return_value=True):
                self.app.update_provider_status()
                self.assertIn("Provider running", self.app.provider_lbl.cget("text"))
            with mock.patch.object(gui.burpzip, "provider_running", return_value=False):
                self.app.update_provider_status()
                self.assertEqual(self.app.provider_lbl.cget("text"), "Provider stopped")

    def test_actions_without_store_point_to_setup(self):
        with mock.patch.object(self.app, "_info") as info:
            self.app.add_to_burp_folder()
            self.app.unpack_selected()
            self.app.start_provider()
        self.assertEqual(info.call_count, 3)
        self.assertIn("Set up the Burp folder", info.call_args[0][0])
        self.assertFalse(self.app.busy)

    def test_add_archive_moves_it_into_store_with_provider_paused(self):
        archive = Path(self.tmp.name) / "Example.20261012-101500.burpz"
        archive.write_bytes(b"synthetic")
        it = item(str(archive), "archive", 9, 30)
        entry = {"name": "Example.burp", "archive_sha256": "00" * 32}
        paused = mock.MagicMock()
        with mock.patch.object(self.app, "native_store", return_value=self.store),                 mock.patch.object(self.app, "selected_items", return_value=[it]),                 mock.patch.object(self.app, "_ordinary_action", return_value=True),                 mock.patch.object(gui.messagebox, "askyesno", return_value=True),                 mock.patch.object(gui.burpzip, "paused_provider", return_value=paused),                 mock.patch("native_store.add_archive", return_value=entry) as add,                 mock.patch.object(gui.burpzip, "remove_verified_input", return_value=True) as remove:
            self.app.add_to_burp_folder()
            self.wait_idle()
        add.assert_called_once_with(str(self.store), str(archive))
        remove.assert_called_once_with(str(archive), entry)
        paused.__enter__.assert_called_once()
        paused.__exit__.assert_called_once()
        self.assertIn("Example.burp is in the Burp folder", self.app.log_text.get("1.0", "end"))

    def test_add_declined_changes_nothing(self):
        it = item(str(Path(self.tmp.name) / "A.burp"), "project", 9, 30)
        with mock.patch.object(self.app, "native_store", return_value=self.store),                 mock.patch.object(self.app, "selected_items", return_value=[it]),                 mock.patch.object(self.app, "_ordinary_action", return_value=True),                 mock.patch.object(gui.messagebox, "askyesno", return_value=False),                 mock.patch("native_store.add_archive") as add:
            self.app.add_to_burp_folder()
        add.assert_not_called()
        self.assertFalse(self.app.busy)

    def test_unpack_only_managed_projects(self):
        ordinary = item(str(Path(self.tmp.name) / "A.burp"), "project", 9, 30)
        with mock.patch.object(self.app, "native_store", return_value=self.store),                 mock.patch.object(self.app, "selected_items", return_value=[ordinary]),                 mock.patch.object(self.app, "_info") as info,                 mock.patch("native_provider.materialize_root") as materialize:
            self.app.unpack_selected()
        materialize.assert_not_called()
        self.assertIn("projects in the Burp folder", info.call_args[0][0])

    def test_unpack_runs_selected_names_with_provider_paused(self):
        managed = item(str(Path(self.tmp.name) / "Managed.burp"), "project", 9, 30)
        paused = mock.MagicMock()
        with mock.patch.object(self.app, "native_store", return_value=self.store),                 mock.patch.object(self.app, "selected_items", return_value=[managed]),                 mock.patch.object(gui.burpzip, "managed_project", return_value=True),                 mock.patch.object(gui.burpzip, "paused_provider", return_value=paused),                 mock.patch("native_provider.materialize_root") as materialize:
            self.app.unpack_selected()
            self.wait_idle()
        materialize.assert_called_once_with(str(self.store), names=["Managed.burp"])
        paused.__exit__.assert_called_once()

    def test_rezip_runs_selected_projects_and_skips_failures(self):
        managed = [item(str(Path(self.tmp.name) / n), "project", 9, 30) for n in ("A.burp", "B.burp")]
        paused = mock.MagicMock()

        def rezip(store, name, level):
            if name == "A.burp":
                raise RuntimeError("Project is in use (open in Burp?)")
            return {"status": "rezipped", "size": 2 * GB, "archive_size": 300 * MB}
        with mock.patch.object(self.app, "native_store", return_value=self.store), \
                mock.patch.object(self.app, "selected_items", return_value=managed), \
                mock.patch.object(gui.burpzip, "managed_project", return_value=True), \
                mock.patch.object(gui.messagebox, "askyesno", return_value=True), \
                mock.patch.object(gui.burpzip, "paused_provider", return_value=paused), \
                mock.patch("native_provider.rezip_project", side_effect=rezip) as call:
            self.app.rezip_selected()
            self.wait_idle()
        self.assertEqual([c.args[1] for c in call.call_args_list], ["A.burp", "B.burp"])
        log = self.app.log_text.get("1.0", "end")
        self.assertIn("skipped A.burp: Project is in use", log)
        self.assertIn("done: " + bz.human_size(2 * GB) + " -> " + bz.human_size(300 * MB), log)
        paused.__exit__.assert_called_once()

    def test_rezip_ignores_ordinary_rows(self):
        with mock.patch.object(self.app, "native_store", return_value=self.store), \
                mock.patch.object(self.app, "selected_items",
                                  return_value=[item(str(Path(self.tmp.name) / "A.burp"), "project", 9, 30)]), \
                mock.patch.object(self.app, "_info") as info, \
                mock.patch("native_provider.rezip_project") as call:
            self.app.rezip_selected()
        call.assert_not_called()
        self.assertIn("projects in the Burp folder", info.call_args[0][0])

    def plan(self):
        return {"steps": [{"action": "archive", "path": str(Path(self.tmp.name) / "Old.burp"),
                           "size": GB, "frees": GB // 2},
                          {"action": "skip", "path": str(Path(self.tmp.name) / "New.burp"),
                           "size": GB, "frees": 0}], "free_now": 10 * GB}

    def test_archive_all_old_goes_straight_into_burp_folder(self):
        with mock.patch.object(self.app, "native_store", return_value=self.store), \
                mock.patch.object(self.app, "make_plan", return_value=self.plan()), \
                mock.patch.object(self.app, "confirm_text", return_value=True) as confirm, \
                mock.patch.object(self.app, "_add_to_burp_job") as add, \
                mock.patch.object(self.app, "_run_plan_job") as ordinary:
            self.app.archive_all_old()
            self.wait_idle()
        add.assert_called_once_with(self.store, [("project", str(Path(self.tmp.name) / "Old.burp"))])
        ordinary.assert_not_called()
        self.assertIn("straight into the Burp folder", confirm.call_args[0][1])

    def test_archive_all_old_without_burp_folder_is_ordinary(self):
        with mock.patch.object(self.app, "native_store", return_value=None), \
                mock.patch.object(self.app, "make_plan", return_value=self.plan()), \
                mock.patch.object(self.app, "confirm_text", return_value=True), \
                mock.patch.object(self.app, "_add_to_burp_job") as add, \
                mock.patch.object(self.app, "_run_plan_job") as ordinary:
            self.app.archive_all_old()
            self.wait_idle()
        ordinary.assert_called_once()
        add.assert_not_called()

    def test_archive_all_old_declined_does_nothing(self):
        with mock.patch.object(self.app, "native_store", return_value=self.store), \
                mock.patch.object(self.app, "make_plan", return_value=self.plan()), \
                mock.patch.object(self.app, "confirm_text", return_value=False), \
                mock.patch.object(self.app, "_add_to_burp_job") as add:
            self.app.archive_all_old()
        add.assert_not_called()
        self.assertFalse(self.app.busy)

    def test_setup_refuses_when_already_configured(self):
        with mock.patch.object(self.app, "native_store", return_value=self.store),                 mock.patch.object(self.app, "_info") as info:
            self.app.setup_burp_folder()
        self.assertIn("already set up", info.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
