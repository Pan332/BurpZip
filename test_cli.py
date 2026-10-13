"""Scanner/CLI integration tests; only mocks and synthetic temporary files."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import archiver as ar
import burpzip as bz
import gui
import launcher

MB = 1024**2
GB = 1024**3


class CliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-cli-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.project = self.root / "demo.burp"
        self.project.write_bytes(b"synthetic project")
        self.archive = self.root / "demo.20261012-101500.burpz"
        self.archive.write_bytes(b"synthetic archive")
        self.backup = self.root / "demo.burp.backup"
        self.backup.write_bytes(b"synthetic backup")
        now = time.time()
        os.utime(self.project, (now, now))
        os.utime(self.backup, (now - 86400, now - 86400))
        self.result = ar.ArchiveResult(str(self.project), str(self.archive), 100, 20,
                                       "a" * 64, 1.0, True)
        self.calls = {}
        # Even a failing test must not reach a real launch, association or deletion.
        targets = {
            "archive": "archiver.archive_project", "run": "archiver.run_plan",
            "restore": "archiver.restore_project", "rezip": "archiver.rezip_after_use",
            "backup": "archiver.delete_backup", "open": "launcher.cli_open",
            "register": "launcher.register_association", "unregister": "launcher.unregister_association",
            "gui": "gui.main", "dialog": "launcher.gui_message",
        }
        for name, target in targets.items():
            patcher = mock.patch(target)
            self.calls[name] = patcher.start()
            self.addCleanup(patcher.stop)
        self.calls["archive"].return_value = self.result
        self.calls["run"].return_value = [self.result]
        self.calls["restore"].return_value = str(self.project)
        self.calls["rezip"].return_value = self.result
        self.calls["backup"].return_value = 16
        self.calls["open"].return_value = 0
        self.calls["register"].return_value = "synthetic association command"
        self.calls["gui"].return_value = 0
        for target, value in (("burpzip.is_in_use", False), ("burpzip.burp_running", False),
                              ("burpzip.shutil.disk_usage", SimpleNamespace(free=10 * GB))):
            patcher = mock.patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def invoke(self, args, answer="n", tty=True, eof=False):
        out, err = io.StringIO(), io.StringIO()
        stdin = io.StringIO()
        stdin.isatty = lambda: tty
        prompt = mock.patch("builtins.input", side_effect=EOFError) if eof else \
            mock.patch("builtins.input", return_value=answer)
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", stdin), prompt:
            try:
                code = bz.main(args)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def assert_no_mutation(self):
        for name in ("archive", "run", "restore", "rezip", "backup", "open", "register", "unregister"):
            self.calls[name].assert_not_called()

    def prepared_scan(self):
        i = bz.Item(str(self.project), "project", GB, time.time() - 30 * 86400, 30)
        patcher = mock.patch("burpzip.scan", return_value=[i])
        scan = patcher.start()
        self.addCleanup(patcher.stop)
        return scan

    def test_default_and_explicit_gui_dispatch(self):
        self.assertEqual(self.invoke([])[0], 0)
        self.assertEqual(self.invoke(["gui"])[0], 0)
        self.assertEqual(self.calls["gui"].call_args_list, [mock.call([]), mock.call([])])
        self.assert_no_mutation()

    def test_gui_and_open_work_without_console_streams(self):
        with mock.patch("sys.stdout", None), mock.patch("sys.stderr", None), mock.patch("sys.stdin", None):
            self.assertEqual(bz.main([]), 0)
            self.assertEqual(bz.main(["open", str(self.archive)]), 0)
        self.calls["gui"].assert_called_once_with([])
        self.calls["open"].assert_called_once_with(str(self.archive))

    def test_all_help_commands_are_nonmutating(self):
        for command in (None, "scan", "archive", "archive-old", "restore", "open", "rezip",
                        "delete-backup", "register", "unregister", "gui"):
            with self.subTest(command=command), mock.patch("burpzip.scan") as scan:
                args = ["--help"] if command is None else [command, "--help"]
                code, out, err = self.invoke(args)
                self.assertEqual(code, 0, err)
                self.assertIn("usage:", out)
                scan.assert_not_called()
                self.calls["gui"].assert_not_called()
        self.assert_no_mutation()

    def test_open_project_and_archive_delegate_return_code(self):
        for path in (self.project, self.archive):
            self.calls["open"].reset_mock()
            self.calls["open"].return_value = 7
            code, _, _ = self.invoke(["open", str(path)])
            self.assertEqual(code, 7)
            self.calls["open"].assert_called_once_with(str(path))

    def test_open_bad_path_fails_cleanly_without_launching(self):
        code, _, err = self.invoke(["open", str(self.root / "missing.burp")])
        self.assertNotEqual(code, 0)
        self.assertIn("not found", err.lower())
        self.assertNotIn("Traceback", err)
        self.calls["open"].assert_not_called()

    def test_archive_yes_dispatches_level_threads_and_deletion(self):
        code, _, err = self.invoke(["archive", str(self.project), "--level", "9", "--threads", "1", "--yes"])
        self.assertEqual(code, 0, err)
        self.calls["archive"].assert_called_once_with(str(self.project), level=9, threads=1,
                                                      delete_original=True)

    def test_archive_keep_original_requires_no_deletion_confirmation(self):
        code, _, err = self.invoke(["archive", str(self.project), "--keep-original"], tty=False)
        self.assertEqual(code, 0, err)
        self.calls["archive"].assert_called_once_with(str(self.project), level=5, threads=2,
                                                      delete_original=False)

    def test_archive_accepts_explicit_yes_answer(self):
        self.assertEqual(self.invoke(["archive", str(self.project)], answer="y")[0], 0)
        self.calls["archive"].assert_called_once()

    def test_mutation_confirmation_denies_empty_no_eof_and_noninteractive(self):
        commands = [["archive", str(self.project)], ["rezip", str(self.project)],
                    ["delete-backup", str(self.backup)]]
        for command in commands:
            for options in ({"answer": ""}, {"answer": "n"}, {"eof": True},
                            {"tty": False, "answer": "y"}):
                with self.subTest(command=command[0], options=options):
                    code, _, _ = self.invoke(command, **options)
                    self.assertNotEqual(code, 0)
                    self.assert_no_mutation()
        self.assertEqual(self.project.read_bytes(), b"synthetic project")
        self.assertEqual(self.backup.read_bytes(), b"synthetic backup")

    def test_archive_missing_or_wrong_second_path_prevents_all_work(self):
        wrong = self.root / "wrong.txt"
        wrong.write_bytes(b"synthetic")
        for path in (self.root / "missing.burp", wrong):
            with self.subTest(path=path):
                code, _, err = self.invoke(["archive", str(self.project), str(path), "--yes"])
                self.assertNotEqual(code, 0)
                self.assertNotIn("Traceback", err)
                self.calls["archive"].assert_not_called()

    def test_duplicate_archive_paths_processed_once(self):
        code, _, err = self.invoke(["archive", str(self.project), str(self.project), "--yes"])
        self.assertEqual(code, 0, err)
        self.calls["archive"].assert_called_once()

    def test_archive_failure_reports_nonzero_exit(self):
        self.calls["archive"].side_effect = ar.ArchiveError("fixture failure")
        code, _, err = self.invoke(["archive", str(self.project), "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("fixture failure", err)
        self.assertNotIn("Traceback", err)

    def test_archive_old_prints_plan_before_confirmation_and_uses_run_plan(self):
        self.prepared_scan()
        code, out, err = self.invoke(["archive-old", "--root", str(self.root), "--days", "21",
                                      "--min-mb", "0", "--level", "0", "--threads", "1", "--yes"])
        self.assertEqual(code, 0, err)
        self.assertIn("PLAN", out)
        args, kwargs = self.calls["run"].call_args
        self.assertEqual(kwargs, {"level": 0, "threads": 1})
        self.assertEqual(args[0]["days"], 21)
        self.assertEqual(args[0]["steps"][0]["action"], "archive")

    def test_archive_old_decline_eof_and_noninteractive_do_not_run(self):
        self.prepared_scan()
        for options in ({"answer": "n"}, {"answer": ""}, {"eof": True}, {"tty": False}):
            with self.subTest(options=options):
                code, out, _ = self.invoke(["archive-old", "--root", str(self.root)], **options)
                self.assertNotEqual(code, 0)
                self.assertIn("PLAN", out)
                self.calls["run"].assert_not_called()
                self.assert_no_mutation()

    def test_archive_old_explicit_interactive_yes_runs(self):
        self.prepared_scan()
        self.assertEqual(self.invoke(["archive-old", "--root", str(self.root)], answer="yes")[0], 0)
        self.calls["run"].assert_called_once()

    def test_archive_old_collected_errors_return_failure(self):
        self.prepared_scan()
        self.calls["run"].return_value = [self.result, ar.ArchiveError("fixture error")]
        code, _, err = self.invoke(["archive-old", "--root", str(self.root), "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("fixture error", err)

    def test_scan_only_writes_explicit_plan_and_serializes_metadata(self):
        scan = self.prepared_scan()
        plan = self.root / "explicit.json"
        before = set(self.root.iterdir())
        code, _, err = self.invoke(["scan", "--root", str(self.root)])
        self.assertEqual(code, 0, err)
        self.assertEqual(before, set(self.root.iterdir()))
        code, _, err = self.invoke(["scan", "--root", str(self.root), "--plan", str(plan)])
        self.assertEqual(code, 0, err)
        data = json.loads(plan.read_text(encoding="utf-8"))
        self.assertEqual(data["roots"], [str(self.root)])
        self.assertIn("meta", data["items"][0])
        self.assertEqual(scan.call_count, 2)
        self.assert_no_mutation()

    def test_plan_output_never_overwrites_projects_archives_or_existing_json(self):
        self.prepared_scan()
        existing = self.root / "exists.json"
        existing.write_bytes(b"existing plan")
        for path in (self.project, self.archive, self.backup, existing):
            with self.subTest(path=path):
                before = path.read_bytes()
                code, _, err = self.invoke(["scan", "--root", str(self.root), "--plan", str(path)])
                self.assertNotEqual(code, 0)
                self.assertEqual(path.read_bytes(), before)
                self.assertNotIn("Traceback", err)

    def test_plan_output_requires_json_and_existing_parent_directory(self):
        self.prepared_scan()
        for path in (self.root / "new.burp", self.root / "new.burpz", self.root / "new.txt",
                     self.root / "missing" / "plan.json"):
            with self.subTest(path=path):
                code, _, err = self.invoke(["scan", "--root", str(self.root), "--plan", str(path)])
                self.assertNotEqual(code, 0)
                self.assertFalse(path.exists())
                self.assertNotIn("Traceback", err)

    def test_plan_output_rejects_windows_ads_on_project(self):
        output = self.root / "demo.burp:plan.json"
        before = self.project.read_bytes()
        self.prepared_scan()
        code, _, err = self.invoke(["scan", "--root", str(self.root), "--plan", str(output)])
        self.assertNotEqual(code, 0)
        self.assertFalse(output.exists())
        self.assertEqual(self.project.read_bytes(), before)
        self.assertNotIn("Traceback", err)

    def test_plan_output_rejects_discovered_input_even_with_json_suffix(self):
        output = self.root / "protected.json"
        i = bz.Item(str(output), "project", 1, time.time(), 0)
        with mock.patch("burpzip.scan", return_value=[i]):
            code, _, err = self.invoke(["scan", "--root", str(self.root), "--plan", str(output)])
        self.assertNotEqual(code, 0)
        self.assertIn("scanned input", err)
        self.assertFalse(output.exists())

    def test_gui_none_result_is_success(self):
        self.calls["gui"].return_value = None
        self.assertEqual(self.invoke([])[0], 0)

    def test_scan_plan_delegates_to_shared_volume_planner_with_roots(self):
        self.prepared_scan()
        expected = {"free_now": GB, "free_after": GB, "days": 21,
                    "min_size": 5 * MB, "steps": [], "volumes": []}
        with mock.patch.object(bz, "build_volume_plan", return_value=expected, create=True) as planner:
            args = bz._parser().parse_args(["scan", "--root", str(self.root),
                                            "--days", "21", "--min-mb", "5"])
            items, plan, _ = bz._scan_plan(args)
        planner.assert_called_once_with(items, 21, 5 * MB, roots=[self.root])
        self.assertIs(plan, expected)

    def test_archive_old_uses_second_root_budget_and_never_mutates_during_planning(self):
        extra = self.root / "extra-volume"
        extra.mkdir()
        a = bz.Item(str(self.project), "project", GB, time.time() - 30 * 86400, 30)
        b = bz.Item(str(extra / "second.burp"), "project", GB, time.time() - 30 * 86400, 30)
        real_stat = bz.os.stat

        def stat(path, *args, **kwargs):
            resolved = Path(path)
            if resolved in (self.root, extra):
                return SimpleNamespace(st_dev=11 if resolved == self.root else 22, st_mode=0o040700)
            return real_stat(path, *args, **kwargs)

        def usage(path):
            return SimpleNamespace(free=GB if Path(path) == self.root else 3 * GB)

        with mock.patch.object(bz, "scan", return_value=[a, b]), \
                mock.patch.object(bz.os, "stat", side_effect=stat), \
                mock.patch.object(bz.shutil, "disk_usage", side_effect=usage):
            code, out, err = self.invoke(["archive-old", "--root", str(self.root),
                                          "--root", str(extra), "--yes"])
        self.assertEqual(code, 0, err)
        plan = self.calls["run"].call_args.args[0]
        self.assertEqual({s["path"]: s["action"] for s in plan["steps"]},
                         {a.path: "deferred", b.path: "archive"})
        self.assertEqual([v["free_now"] for v in plan["volumes"]], [GB, 3 * GB])
        self.assertIn("aggregate", out.lower())
        self.assertIn("estimated", out.lower())
        self.calls["archive"].assert_not_called()
        self.assertEqual(self.project.read_bytes(), b"synthetic project")

    def test_repeatable_roots_and_default_roots(self):
        scan = self.prepared_scan()
        extra = self.root / "extra"
        extra.mkdir()
        code, _, err = self.invoke(["scan", "--root", str(self.root), "--root", str(extra)])
        self.assertEqual(code, 0, err)
        scan.assert_called_once_with([self.root, extra])
        scan.reset_mock()
        with mock.patch("burpzip.default_roots", return_value=[self.root]):
            self.assertEqual(self.invoke(["scan"])[0], 0)
        scan.assert_called_once_with([self.root])

    def test_missing_roots_fail_before_scan_without_traceback(self):
        for command in ("scan", "archive-old"):
            with self.subTest(command=command), mock.patch("burpzip.scan") as scan:
                code, _, err = self.invoke([command, "--root", str(self.root / "missing")])
                self.assertNotEqual(code, 0)
                self.assertIn("root", err.lower())
                self.assertNotIn("Traceback", err)
                scan.assert_not_called()
                self.assert_no_mutation()

    def test_invalid_options_fail_before_work(self):
        invalid = [["scan", "--days", "-1"], ["scan", "--min-mb", "-1"],
                   ["archive-old", "--days", "-1"], ["archive-old", "--min-mb", "-1"],
                   ["archive", str(self.project), "--level", "-1", "--yes"],
                   ["archive", str(self.project), "--level", "10", "--keep-original"],
                   ["archive", str(self.project), "--threads", "0", "--yes"],
                   ["archive-old", "--level", "10", "--yes"],
                   ["archive-old", "--threads", "-2", "--yes"],
                   ["rezip", str(self.project), "--level", "10", "--yes"]]
        with mock.patch("burpzip.scan") as scan:
            for args in invalid:
                with self.subTest(args=args):
                    code, _, err = self.invoke(args)
                    self.assertEqual(code, 2, err)
                    self.assertIn("error:", err)
                    self.assertNotIn("Traceback", err)
                    scan.assert_not_called()
                    self.assert_no_mutation()

    def test_restore_dispatches_destination_without_overwrite(self):
        dest = self.root / "restored.burp"
        code, _, err = self.invoke(["restore", str(self.archive), "--dest", str(dest)])
        self.assertEqual(code, 0, err)
        self.calls["restore"].assert_called_once_with(str(self.archive), dest_path=str(dest))

    def test_restore_default_destination_and_api_error(self):
        self.assertEqual(self.invoke(["restore", str(self.archive)])[0], 0)
        self.calls["restore"].assert_called_once_with(str(self.archive), dest_path=None)
        self.calls["restore"].side_effect = ar.ArchiveError("destination already exists")
        code, _, err = self.invoke(["restore", str(self.archive)])
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)

    def test_restore_refuses_existing_explicit_destination_before_api(self):
        code, _, err = self.invoke(["restore", str(self.archive), "--dest", str(self.project)])
        self.assertNotEqual(code, 0)
        self.assertIn("exists", err)
        self.calls["restore"].assert_not_called()
        self.assertEqual(self.project.read_bytes(), b"synthetic project")

    def test_rezip_yes_dispatch_and_unchanged_summary(self):
        self.calls["rezip"].return_value = None
        code, out, err = self.invoke(["rezip", str(self.project), "--level", "9", "--yes"])
        self.assertEqual(code, 0, err)
        self.calls["rezip"].assert_called_once_with(str(self.project), level=9)
        self.assertIn("unchanged", out.lower())

    def test_delete_backup_yes_dispatch(self):
        code, _, err = self.invoke(["delete-backup", str(self.backup), "--yes"])
        self.assertEqual(code, 0, err)
        self.calls["backup"].assert_called_once_with(str(self.backup), force_newer=False)

    def test_newer_backup_requires_explicit_force_even_with_yes(self):
        now = time.time() + 60
        os.utime(self.backup, (now, now))
        code, _, err = self.invoke(["delete-backup", str(self.backup), "--yes"])
        self.assertNotEqual(code, 0)
        self.assertIn("force", err.lower())
        self.calls["backup"].assert_not_called()

    def test_forced_newer_backup_requires_typed_yes_or_force_with_yes_flag(self):
        now = time.time() + 60
        os.utime(self.backup, (now, now))
        command = ["delete-backup", str(self.backup), "--force-newer"]
        self.assertNotEqual(self.invoke(command, answer="y")[0], 0)
        self.calls["backup"].assert_not_called()
        self.assertEqual(self.invoke(command, answer="YES")[0], 0)
        self.calls["backup"].assert_called_once_with(str(self.backup), force_newer=True)
        self.calls["backup"].reset_mock()
        self.assertEqual(self.invoke(command + ["--yes"], tty=False)[0], 0)
        self.calls["backup"].assert_called_once_with(str(self.backup), force_newer=True)

    def test_backup_missing_parent_refuses_even_forced(self):
        self.project.unlink()  # our own synthetic fixture only
        code, _, err = self.invoke(["delete-backup", str(self.backup), "--force-newer", "--yes"])
        self.assertNotEqual(code, 0)
        self.assertIn("main project", err.lower())
        self.calls["backup"].assert_not_called()

    def test_register_unregister_only_explicit_dispatch(self):
        self.assertEqual(self.invoke(["register"])[0], 0)
        self.calls["register"].assert_called_once_with()
        self.assertEqual(self.invoke(["unregister"])[0], 0)
        self.calls["unregister"].assert_called_once_with()

    def test_launcher_errors_are_clean(self):
        self.calls["register"].side_effect = launcher.LauncherError("fixture launcher error")
        code, _, err = self.invoke(["register"])
        self.assertEqual(code, 1)
        self.assertIn("fixture launcher error", err)
        self.assertNotIn("Traceback", err)

    def test_real_cli_help_lists_commands_and_bad_root_has_no_traceback(self):
        script = str(Path(__file__).with_name("burpzip.py"))
        help_run = subprocess.run([sys.executable, script, "--help"], capture_output=True,
                                  text=True, timeout=10, stdin=subprocess.DEVNULL)
        self.assertEqual(help_run.returncode, 0, help_run.stderr)
        for command in ("archive-old", "delete-backup", "open", "gui"):
            self.assertIn(command, help_run.stdout)
        bad = subprocess.run([sys.executable, script, "scan", "--root", str(self.root / "absent")],
                             capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("root", bad.stderr.lower())
        self.assertNotIn("Traceback", bad.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
