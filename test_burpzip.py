"""Tests for burpzip planning rules and in-use detection (synthetic data only)."""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import burpzip as bz
import archiver as ar

MB = 1024**2
GB = 1024**3


def item(path, kind, size, age, in_use=False, mtime=None):
    return bz.Item(path=path, kind=kind, size=size,
                   mtime=mtime if mtime is not None else time.time() - age * 86400,
                   age_days=age, in_use=in_use)


class PlanTests(unittest.TestCase):
    def actions(self, plan):
        return {Path(s["path"]).name: s["action"] for s in plan["steps"]}

    def test_backups_always_require_manual_review_and_never_add_savings(self):
        items = [
            item(r"C:\p\A.burp", "project", 1 * GB, 30),
            item(r"C:\p\A.burp.backup", "backup", 1 * GB, 40),
            item(r"C:\p\B.burp.backup", "backup", 1 * GB, 40),  # no parent
            item(r"C:\p\C.burp", "project", 1 * GB, 50),
            item(r"C:\p\C.burp.backup", "backup", 1 * GB, 20),  # newer than parent
        ]
        plan = bz.build_plan(items, 14, 10 * GB)
        a = self.actions(plan)
        self.assertEqual(a["A.burp.backup"], "skip")
        self.assertEqual(a["B.burp.backup"], "skip")
        self.assertEqual(a["C.burp.backup"], "skip")
        backup_steps = [s for s in plan["steps"] if bz.classify(Path(s["path"]).name) == "backup"]
        self.assertTrue(all(s["frees"] == 0 and s["notes"] for s in backup_steps))
        expected = 10 * GB + sum(s["frees"] for s in plan["steps"] if s["action"] == "archive")
        self.assertEqual(plan["free_after"], expected)
        self.assertEqual(bz.build_plan(items, 100, 10 * GB)["free_after"], 10 * GB)

    def test_age_size_and_in_use_filters(self):
        items = [
            item(r"C:\p\new.burp", "project", 1 * GB, 3),
            item(r"C:\p\tiny.burp", "project", 16 * MB, 90),
            item(r"C:\p\open.burp", "project", 1 * GB, 90, in_use=True),
            item(r"C:\p\old.burp", "project", 1 * GB, 90),
        ]
        a = self.actions(bz.build_plan(items, 14, 10 * GB))
        self.assertNotIn("new.burp", a)
        self.assertNotIn("tiny.burp", a)
        self.assertEqual(a["open.burp"], "skip")
        self.assertEqual(a["old.burp"], "archive")

    def test_deferred_until_space_freed(self):
        # Full input + overhead + reserve: only the 1 GiB file fits initially.
        items = [
            item(r"C:\p\big.burp", "project", 3 * GB, 90),
            item(r"C:\p\small.burp", "project", 1 * GB, 90),
            item(r"C:\p\mid.burp", "project", 2 * GB, 90),
        ]
        plan = bz.build_plan(items, 14, int(1.8 * GB))
        a = self.actions(plan)
        self.assertEqual(a["small.burp"], "archive")
        self.assertEqual(a["mid.burp"], "archive")  # fits after small frees space
        self.assertEqual(a["big.burp"], "archive")  # after admitted smaller projects
        self.assertEqual([Path(s["path"]).name for s in plan["steps"] if s["action"] == "archive"],
                         ["small.burp", "mid.burp", "big.burp"])

    def test_archive_space_needed_uses_full_input_overhead_and_reserve(self):
        self.assertEqual(bz.archive_space_needed(0), 64 * MB + bz.SPACE_MARGIN)
        self.assertEqual(bz.archive_space_needed(2 * GB),
                         2 * GB + (2 * GB + 19) // 20 + bz.SPACE_MARGIN)
        needed = bz.archive_space_needed(GB)
        i = item(r"C:\p\demo.burp", "project", GB, 30)
        self.assertEqual(bz.build_plan([i], 14, needed - 1)["steps"][0]["action"], "deferred")
        self.assertEqual(bz.build_plan([i], 14, needed)["steps"][0]["action"], "archive")

    def test_never_runs_below_margin(self):
        items = [item(r"C:\p\big.burp", "project", 6 * GB, 90)]
        plan = bz.build_plan(items, 14, 1 * GB)
        self.assertEqual(plan["steps"][0]["action"], "deferred")

    def test_classify(self):
        self.assertEqual(bz.classify("x.burp"), "project")
        self.assertEqual(bz.classify("x.burp.backup"), "backup")
        self.assertEqual(bz.classify("x.burp.backup.temp_25690617_101831"), "backup")
        self.assertEqual(bz.classify("x.burp.20261012-101500.7z"), "archive")
        self.assertEqual(bz.classify("x.burp.7z"), "archive")
        self.assertEqual(bz.classify("x.20261012-101500.burpz"), "archive")
        self.assertEqual(bz.classify("X.BURPZ"), "archive")
        self.assertIsNone(bz.classify("x.burpz.partial"))
        self.assertIsNone(bz.classify("x.burp.txt"))

    def test_archives_are_never_plan_steps_even_when_source_matches_metadata(self):
        source = item(r"C:\p\same.burp", "project", GB, 30)
        archive = item(r"C:\p\same.20261012-101500.burpz", "archive", MB, 30)
        archive.meta = {"orig_name": "same.burp", "size": GB, "mtime": source.mtime}
        plan = bz.build_plan([source, archive], 14, 10 * GB)
        self.assertEqual(len(plan["steps"]), 1)
        self.assertEqual(plan["steps"][0]["action"], "archive")
        self.assertEqual(plan["steps"][0]["path"], source.path)

    def test_backup_bytes_cannot_make_a_deferred_project_fit(self):
        items = [item(r"C:\p\big.burp", "project", 6 * GB, 90),
                 item(r"C:\p\big.burp.backup", "backup", 5 * GB, 100)]
        plan = bz.build_plan(items, 14, GB)
        self.assertEqual(self.actions(plan)["big.burp"], "deferred")
        self.assertEqual(plan["free_after"], GB)

    def test_backup_parent_changes_basename_only(self):
        folder = str(Path(tempfile.gettempdir()) / "engagement.burp.backup.old")
        backup = str(Path(folder) / "demo.burp.backup.temp")
        self.assertEqual(bz.backup_parent(backup), str(Path(folder) / "demo.burp"))

    def test_planning_does_not_mutate_listing_notes(self):
        i = item(r"C:\p\demo.burp.backup", "backup", GB, 30)
        i.notes.append("original note")
        bz.build_plan([i], 14, GB)
        bz.build_plan([i], 14, GB)
        self.assertEqual(i.notes, ["original note"])

    def test_human_age(self):
        self.assertEqual(bz.human_age(15), "2 weeks ago")
        self.assertEqual(bz.human_age(90), "3 months ago")


class VolumePlanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-volume-test-")
        self.addCleanup(tmp.cleanup)
        self.first = Path(tmp.name) / "first"
        self.second = Path(tmp.name) / "second"
        self.first.mkdir()
        self.second.mkdir()

    def project(self, folder, name, size=GB):
        return item(str(folder / f"{name}.burp"), "project", size, 90)

    def plan(self, items, first_free, second_free, roots=None, bad_stat=None, bad_disk=None):
        def stat(folder):
            folder = Path(folder)
            if folder == bad_stat:
                raise OSError("synthetic volume unavailable")
            return SimpleNamespace(st_dev=11 if folder == self.first else 22)

        def usage(folder):
            folder = Path(folder)
            if folder == bad_disk:
                raise OSError("synthetic budget unavailable")
            return SimpleNamespace(free=first_free if folder == self.first else second_free)

        with mock.patch.object(bz.os, "stat", side_effect=stat), \
                mock.patch.object(bz.shutil, "disk_usage", side_effect=usage) as disk:
            plan = bz.build_volume_plan(items, 14, roots=roots)
        return plan, disk

    def test_second_volume_fits_even_when_first_volume_is_low(self):
        a, b = self.project(self.first, "first"), self.project(self.second, "second")
        plan, disk = self.plan([a, b], GB, 3 * GB, roots=[self.first, self.second])
        actions = {s["path"]: s["action"] for s in plan["steps"]}
        self.assertEqual(actions, {a.path: "deferred", b.path: "archive"})
        self.assertEqual([v["volume"] for v in plan["volumes"]], ["11", "22"])
        self.assertEqual([v["free_now"] for v in plan["volumes"]], [GB, 3 * GB])
        self.assertEqual(plan["free_now"], 4 * GB)
        self.assertEqual(plan["free_after"], 4 * GB + GB - int(GB * bz.RATIO_EXPECTED))
        self.assertEqual(disk.call_count, 2)

    def test_first_volume_savings_cannot_promote_second_volume(self):
        a = self.project(self.first, "large-first", 3 * GB)
        b = self.project(self.second, "small-second", GB)
        plan, _ = self.plan([a, b], 4 * GB, GB, roots=[self.first, self.second])
        actions = {s["path"]: s["action"] for s in plan["steps"]}
        self.assertEqual(actions, {a.path: "archive", b.path: "deferred"})
        self.assertEqual(plan["volumes"][1]["free_after"], GB)

    def test_each_volume_keeps_its_admission_prerequisite_order(self):
        items = [self.project(folder, f"{label}-{name}", size * GB)
                 for label, folder in (("first", self.first), ("second", self.second))
                 for name, size in (("big", 3), ("small", 1), ("mid", 2))]
        plan, _ = self.plan(items, int(1.8 * GB), int(1.8 * GB),
                            roots=[self.first, self.second])
        self.assertEqual([Path(s["path"]).stem for s in plan["steps"]],
                         ["first-small", "first-mid", "first-big",
                          "second-small", "second-mid", "second-big"])
        self.assertTrue(all(s["action"] == "archive" for s in plan["steps"]))

    def test_same_volume_roots_share_one_budget_and_savings(self):
        a, b = self.project(self.first, "small"), self.project(self.second, "large", 2 * GB)
        with mock.patch.object(bz.os, "stat", return_value=SimpleNamespace(st_dev=11)), \
                mock.patch.object(bz.shutil, "disk_usage",
                                  return_value=SimpleNamespace(free=int(1.8 * GB))) as disk:
            plan = bz.build_volume_plan([b, a], 14, roots=[self.first, self.second, self.first])
        self.assertEqual(len(plan["volumes"]), 1)
        self.assertEqual(plan["free_now"], int(1.8 * GB))
        self.assertEqual([s["path"] for s in plan["steps"]], [a.path, b.path])
        self.assertTrue(all(s["action"] == "archive" for s in plan["steps"]))
        disk.assert_called_once()

    def test_project_parent_discovers_volume_without_supplied_root(self):
        b = self.project(self.second, "second")
        plan, disk = self.plan([b], GB, 3 * GB)
        self.assertEqual([v["volume"] for v in plan["volumes"]], ["22"])
        self.assertEqual(plan["steps"][0]["action"], "archive")
        disk.assert_called_once()

    def test_stat_failure_is_isolated_zero_budget_with_notes(self):
        a, b = self.project(self.first, "first"), self.project(self.second, "second")
        plan, _ = self.plan([a, b], 5 * GB, 3 * GB, roots=[self.first, self.second],
                            bad_stat=self.first)
        self.assertEqual([s["action"] for s in plan["steps"]], ["deferred", "archive"])
        bad = plan["volumes"][0]
        self.assertTrue(bad["volume"].startswith("unavailable:"))
        self.assertEqual((bad["free_now"], bad["free_after"]), (0, 0))
        self.assertTrue(any("unavailable" in n for n in bad["notes"]))
        self.assertTrue(any("unavailable" in n for n in plan["steps"][0]["notes"]))
        self.assertEqual(a.notes, [])

    def test_disk_failure_closes_only_affected_volume(self):
        a, b = self.project(self.first, "first"), self.project(self.second, "second")
        plan, _ = self.plan([a, b], 5 * GB, 3 * GB, roots=[self.first, self.second],
                            bad_disk=self.first)
        self.assertEqual([s["action"] for s in plan["steps"]], ["deferred", "archive"])
        self.assertEqual(plan["free_now"], 3 * GB)
        self.assertEqual(plan["volumes"][0]["free_now"], 0)
        self.assertTrue(plan["volumes"][0]["notes"])

    def test_empty_roots_have_one_summary_each_without_steps(self):
        plan, disk = self.plan([], GB, 3 * GB, roots=[self.first, self.second])
        self.assertEqual(plan["steps"], [])
        self.assertEqual(len(plan["volumes"]), 2)
        self.assertEqual(plan["free_now"], plan["free_after"])
        self.assertEqual(disk.call_count, 2)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="burpzip-scan-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def meta(self, **updates):
        meta = {"tool": "burpzip", "format": 1, "orig_name": "demo.burp",
                "orig_path": str(self.root / "demo.burp"), "size": 1024,
                "mtime": time.time() - 90 * 86400, "sha256": "a" * 64,
                "archived_at": "2026-10-12T12:00:00+07:00", "level": 5}
        meta.update(updates)
        return meta

    def test_item_metadata_default_and_serialization(self):
        i = item("demo.burp", "project", 1, 0)
        self.assertIsNone(i.meta)
        self.assertIsNone(asdict(i)["meta"])

    def test_scan_uses_project_metadata_age_not_archive_timestamp_and_is_read_only(self):
        archive = self.root / "demo.20261012-101500.BURPZ"
        archive.write_bytes(b"synthetic archive")
        project = self.root / "demo.burp"
        project.write_bytes(b"synthetic project")
        meta = self.meta()
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        with mock.patch("archiver.read_meta", return_value=meta) as read, \
                mock.patch("burpzip.is_in_use", return_value=False) as probe:
            items = bz.scan([self.root, self.root])
        self.assertEqual(len(items), 2)
        found = next(i for i in items if i.kind == "archive")
        self.assertEqual(found.meta, meta)
        self.assertEqual(found.mtime, meta["mtime"])
        self.assertAlmostEqual(found.age_days, 90, places=3)
        self.assertEqual(found.size, len(b"synthetic archive"))
        self.assertFalse(found.in_use)
        read.assert_called_once_with(str(archive))
        probe.assert_called_once_with(str(project))
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        self.assertEqual(before, after)

    def test_corrupt_or_legacy_archive_is_listed_with_note_and_no_metadata(self):
        for name in ("corrupt.burpz", "legacy.burp.7z"):
            (self.root / name).write_bytes(b"not a 7z file")
        with mock.patch("archiver.read_meta", side_effect=ar.ArchiveError("invalid archive")):
            items = bz.scan([self.root])
        self.assertEqual(len(items), 2)
        for found in items:
            self.assertEqual(found.kind, "archive")
            self.assertIsNone(found.meta)
            self.assertTrue(any("metadata" in n.lower() and "invalid archive" in n
                                for n in found.notes))

    def test_invalid_metadata_never_becomes_a_restorable_listing(self):
        (self.root / "bad.burpz").write_bytes(b"synthetic archive")
        invalid = [{"mtime": "nan"}, {"mtime": float("inf")}, {"size": "lots"},
                   {"size": -1}, {"size": True}, {"orig_name": "../demo.burp"},
                   {"orig_name": "demo.txt"}, {"sha256": "bad"}, {"format": True},
                   {"tool": "other"}]
        for changes in invalid:
            with self.subTest(changes=changes), \
                    mock.patch("archiver.read_meta", return_value=self.meta(**changes)):
                found = bz.scan([self.root])[0]
                self.assertIsNone(found.meta)
                self.assertTrue(found.notes)

    def test_scan_without_archives_does_not_import_archiver(self):
        (self.root / "plain.burp").write_bytes(b"synthetic")
        real_import = __import__

        def guarded(name, *args, **kwargs):
            if name == "archiver":
                self.fail("archiver must be loaded lazily")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=guarded), \
                mock.patch("burpzip.is_in_use", return_value=False):
            self.assertEqual(len(bz.scan([self.root])), 1)

    @unittest.skipUnless(ar.SEVEN_ZIP, "7-Zip is needed for synthetic metadata fixtures")
    def test_scan_real_synthetic_archive_and_corrupt_archive(self):
        project = self.root / "demo.burp"
        project.write_bytes(b"synthetic burp project\0" * 256)
        old = time.time() - 60 * 86400
        os.utime(project, (old, old))
        result = ar.archive_project(str(project), level=0, threads=1, delete_original=False)
        (self.root / "corrupt.burpz").write_bytes(b"not an archive")
        found = {Path(i.path).name: i for i in bz.scan([self.root])}
        archive = found[Path(result.archive_path).name]
        self.assertEqual(archive.meta["orig_name"], "demo.burp")
        self.assertAlmostEqual(archive.age_days, 60, places=3)
        self.assertTrue(project.exists())
        self.assertIsNone(found["corrupt.burpz"].meta)
        self.assertTrue(found["corrupt.burpz"].notes)

    @unittest.skipUnless(ar.SEVEN_ZIP, "7-Zip is needed for the encrypted input fixture")
    def test_encrypted_archive_scan_does_not_prompt_or_hang(self):
        meta_file = self.root / "burpzip-meta.json"
        meta_file.write_text("{}", encoding="utf-8")
        archive = self.root / "encrypted.burpz"
        made = subprocess.run([ar.SEVEN_ZIP, "a", "-t7z", "-pfixture-only", "-mhe=on", "-y",
                               str(archive), "--", str(meta_file)],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        self.assertEqual(made.returncode, 0, made.stderr)
        # Bound the child process so a regression cannot hang the test runner.
        script = ("import pathlib,sys;sys.path.insert(0,sys.argv[1]);import burpzip;"
                  "i=burpzip.scan([pathlib.Path(sys.argv[2])])[0];"
                  "assert i.kind=='archive' and i.meta is None and i.notes")
        checked = subprocess.run([sys.executable, "-I", "-c", script,
                                  str(Path(__file__).parent), str(self.root)],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)


class InUseTests(unittest.TestCase):
    def test_detects_file_held_open_by_other_process(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "held.burp")
            Path(f).write_bytes(b"\0" * 4096)
            self.assertFalse(bz.is_in_use(f))
            holder = subprocess.Popen(
                [sys.executable, "-c",
                 "import sys,time;f=open(sys.argv[1],'r+b');print('ok',flush=True);time.sleep(30)", f],
                stdout=subprocess.PIPE, text=True)
            try:
                holder.stdout.readline()
                self.assertTrue(bz.is_in_use(f))
            finally:
                holder.kill()
                holder.wait()
                holder.stdout.close()
            self.assertFalse(bz.is_in_use(f))


class NativeProtectionTests(unittest.TestCase):
    def test_public_in_use_protected_kinds_never_delete_probe(self):
        for kind in ("native", "cloud", "unknown", "store"):
            with self.subTest(kind=kind), \
                    mock.patch.object(bz, "native_state", return_value=SimpleNamespace(kind=kind)), \
                    mock.patch.object(bz.ctypes, "WinDLL", create=True) as dll:
                self.assertTrue(bz.is_in_use("synthetic.burp"))
            dll.assert_not_called()

    def test_classification_failure_is_unknown_not_ordinary(self):
        fake = SimpleNamespace(classify_path=mock.Mock(side_effect=RuntimeError("offline unknown")))
        with mock.patch.dict(sys.modules, {"native_cfapi": fake}):
            state = bz.native_state("synthetic.burp")
        self.assertEqual(state.kind, "unknown")
        self.assertIn("offline unknown", state.note)

    def test_scan_classifies_all_kinds_before_stat_metadata_and_probe(self):
        for extension in (".burp", ".burp.backup", ".burpz"):
            for native in ("native", "cloud", "unknown", "store"):
                with self.subTest(extension=extension, native=native):
                    entry = SimpleNamespace(name="demo" + extension, path="synthetic/demo" + extension,
                                            stat=mock.Mock(side_effect=AssertionError("protected stat")))
                    state = SimpleNamespace(kind=native, size=23, ready=False, modified=None,
                                            note="protected synthetic fixture")
                    with mock.patch.object(bz, "walk", return_value=iter([entry])), \
                            mock.patch.object(bz, "native_state", return_value=state), \
                            mock.patch.object(bz, "_listing_meta") as metadata, \
                            mock.patch.object(bz, "is_in_use") as probe:
                        found = bz.scan([Path("synthetic")])[0]
                    entry.stat.assert_not_called()
                    metadata.assert_not_called()
                    probe.assert_not_called()
                    self.assertEqual((found.kind, found.native), (bz.classify(entry.name), native))
                    self.assertEqual(found.size, 23)
                    self.assertIsNone(found.meta)
                    self.assertTrue(found.in_use)
                    self.assertIn(native, found.notes[0])

    def test_walk_foreign_or_unknown_root_never_enumerates(self):
        for kind in ("cloud", "unknown"):
            with self.subTest(kind=kind), \
                    mock.patch.object(bz, "native_state", return_value=SimpleNamespace(kind=kind)), \
                    mock.patch.object(bz.os, "scandir") as scan:
                self.assertEqual(list(bz.walk(Path("synthetic"))), [])
            scan.assert_not_called()

    def test_planners_exclude_protected_projects_backups_and_archives(self):
        protected = [item("synthetic/demo" + suffix, kind, GB, 90)
                     for kind, suffix in (("project", ".burp"), ("backup", ".burp.backup"),
                                           ("archive", ".burpz"))]
        for candidate, native in zip(protected, ("native", "unknown", "store")):
            candidate.native = native
        self.assertEqual(bz.build_plan(protected, 0, 10 * GB, min_size=0)["steps"], [])
        with mock.patch.object(bz.os, "stat") as stat, \
                mock.patch.object(bz.shutil, "disk_usage") as usage:
            self.assertEqual(bz.build_volume_plan(protected, 0, min_size=0)["steps"], [])
        stat.assert_not_called()
        usage.assert_not_called()

    def test_protected_scan_root_does_not_contribute_volume_budget(self):
        with mock.patch.object(bz, "native_state", return_value=SimpleNamespace(kind="native")), \
                mock.patch.object(bz.os, "stat") as stat, \
                mock.patch.object(bz.shutil, "disk_usage") as usage:
            plan = bz.build_volume_plan([], 0, roots=[Path("synthetic")])
        self.assertEqual((plan["free_now"], plan["free_after"]), (0, 0))
        stat.assert_not_called()
        usage.assert_not_called()

    def test_managed_open_requires_all_leaf_anchors_not_readiness(self):
        valid = SimpleNamespace(kind="native", root_id="root", file_id="file", identity=b"own", ready=False)
        self.assertTrue(bz.managed_project(valid, "demo.burp"))
        self.assertFalse(bz.managed_project(valid, "demo.burp.backup"))
        for missing in ("root_id", "file_id", "identity"):
            fields = vars(valid).copy()
            fields[missing] = None
            self.assertFalse(bz.managed_project(SimpleNamespace(**fields), "demo.burp"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
