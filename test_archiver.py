"""Tests for archiver (synthetic files in temp dirs only; runs the real 7z.exe)."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import archiver as ar  # noqa: E402

MB = 1024**2
Usage = namedtuple("Usage", "total used free")


def make_project(folder: str, name: str = "proj.burp", mb: int = 4, seed: int = 1,
                 age_days: float = 30) -> str:
    """Synthetic project: alternating random and zero MB blocks."""
    path = os.path.join(folder, name)
    rnd = os.urandom(MB) if seed else b"\x01" * MB
    with open(path, "wb") as f:
        for i in range(mb):
            f.write(rnd if i % 2 == 0 else b"\0" * MB)
    t = time.time() - age_days * 86400
    os.utime(path, (t, t))
    return path


def make_reference(folder: str, data: bytes, *, name: str = "proj.burp",
                   payload: bytes | None = None, **changes) -> str:
    """Real 7z fixture with independent synthetic metadata and optional payload."""
    meta = {"format": 1, "tool": "burpzip", "orig_name": name,
            "size": len(data), "mtime": 1791763200.0,
            "sha256": hashlib.sha256(data).hexdigest()}
    meta.update(changes)
    archive = os.path.join(folder, "reference.burpz")
    with tempfile.TemporaryDirectory() as inputs:
        metadata = os.path.join(inputs, ar.META_NAME)
        Path(metadata).write_text(json.dumps(meta), encoding="utf-8")
        subprocess.run([ar.find_7z(), "a", "-t7z", "-spd", archive, "--", metadata],
                       capture_output=True, check=True)
        if payload is not None:
            project = os.path.join(inputs, name)
            Path(project).write_bytes(payload)
            subprocess.run([ar.find_7z(), "a", "-t7z", "-spd", archive, "--", project],
                           capture_output=True, check=True)
    return archive


class HeldOpen:
    """Hold a file open from a child process (like Burp would)."""

    def __init__(self, path: str):
        self.path = path

    def __enter__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-c",
             "import sys,time;f=open(sys.argv[1],'r+b');print('ok',flush=True);time.sleep(60)",
             self.path], stdout=subprocess.PIPE, text=True)
        self.proc.stdout.readline()
        return self

    def __exit__(self, *exc):
        self.proc.kill()
        self.proc.wait()
        self.proc.stdout.close()


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def files(self):
        return sorted(os.listdir(self.dir))

    def synthetic_archive(self, meta, payload=None, entry="proj.burp"):
        """Real 7z fixture from isolated synthetic metadata/payload only."""
        arc = os.path.join(self.dir, "reference.burpz")
        with tempfile.TemporaryDirectory() as source:
            meta_path = Path(source, ar.META_NAME)
            meta_path.write_text(json.dumps(meta), encoding="utf-8")
            subprocess.run([ar.find_7z(), "a", "-t7z", "-spd", arc, "--", str(meta_path)],
                           capture_output=True, check=True)
            if payload is not None:
                project = Path(source, entry)
                project.write_bytes(payload)
                subprocess.run([ar.find_7z(), "a", "-t7z", "-spd", arc, "--", str(project)],
                               capture_output=True, check=True)
        return arc

    def synthetic_meta(self, project):
        data = Path(project).read_bytes()
        return {"tool": "burpzip", "format": 1, "orig_name": Path(project).name,
                "size": len(data), "mtime": os.stat(project).st_mtime,
                "sha256": hashlib.sha256(data).hexdigest()}


class ArchiveTests(Base):
    def test_find_7z(self):
        self.assertTrue(os.path.isfile(ar.find_7z()))

    def test_archive_verify_delete_roundtrip(self):
        p = make_project(self.dir)
        data = Path(p).read_bytes()
        stages = []
        r = ar.archive_project(p, progress=lambda s, f: stages.append(s))
        self.assertTrue(r.deleted_original)
        self.assertFalse(os.path.exists(p))
        self.assertTrue(os.path.isfile(r.archive_path))
        self.assertRegex(os.path.basename(r.archive_path), r"^proj\.\d{8}-\d{6}\.burpz$")
        self.assertEqual(r.original_size, len(data))
        self.assertLess(r.archive_size, len(data))
        self.assertEqual(self.files(), [os.path.basename(r.archive_path)])  # no partial/tmp
        for s in ("hash", "compress", "test", "verify", "delete"):
            self.assertIn(s, stages)
        meta = ar.read_meta(r.archive_path)
        self.assertEqual(meta["orig_name"], "proj.burp")
        self.assertEqual(meta["size"], len(data))
        self.assertEqual(meta["sha256"], r.sha256)
        self.assertEqual(meta["format"], 1)
        self.assertEqual(meta["tool"], "burpzip")
        self.assertEqual(meta["level"], 5)

    def test_archive_without_delete_and_no_overwrite(self):
        p = make_project(self.dir)
        r1 = ar.archive_project(p, delete_original=False)
        r2 = ar.archive_project(p, delete_original=False)
        self.assertTrue(os.path.exists(p))
        self.assertFalse(r1.deleted_original)
        self.assertNotEqual(r1.archive_path, r2.archive_path)
        self.assertEqual(len(ar.list_versions(p)), 2)
        self.assertEqual(ar.list_versions(p)[0], r2.archive_path)  # newest first
        self.assertEqual(ar.list_versions("proj.burp", self.dir), ar.list_versions(p))

    def test_archive_entries_order_and_separate_blocks(self):
        p = make_project(self.dir)
        r = ar.archive_project(p, delete_original=False)
        out = subprocess.run([ar.find_7z(), "l", "-slt", r.archive_path],
                             capture_output=True, text=True).stdout
        paths = [ln[7:] for ln in out.splitlines() if ln.startswith("Path = ")][1:]
        blocks = [ln[8:] for ln in out.splitlines() if ln.startswith("Block = ")]
        self.assertEqual(paths, ["burpzip-meta.json", "proj.burp"])
        self.assertEqual(len(set(blocks)), 2)  # meta in its own folder -> fast read
        self.assertNotIn("Encrypted = +", out)

    def test_read_meta_fast_path(self):
        p = make_project(self.dir, mb=24)
        r = ar.archive_project(p, delete_original=False)
        t = time.monotonic()
        meta = ar.read_meta(r.archive_path)
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertEqual(meta["sha256"], r.sha256)

    def test_refuse_when_in_use(self):
        p = make_project(self.dir)
        with HeldOpen(p):
            with self.assertRaisesRegex(ar.ArchiveError, "in use"):
                ar.archive_project(p)
        self.assertEqual(self.files(), ["proj.burp"])

    def test_refuse_when_insufficient_space(self):
        p = make_project(self.dir)
        with mock.patch("archiver.shutil.disk_usage", return_value=Usage(10**9, 10**9, MB)):
            with self.assertRaisesRegex(ar.ArchiveError, "not enough free space"):
                ar.archive_project(p)
        self.assertEqual(self.files(), ["proj.burp"])

    def test_partial_cleaned_on_7z_failure(self):
        p = make_project(self.dir)
        before = Path(p).read_bytes()

        def failing(partial, *a, **k):
            Path(partial).write_bytes(b"junk")
            Path(partial + ".tmp").write_bytes(b"junk")
            raise ar.ArchiveError("7z a failed (exit 2): simulated")

        with mock.patch("archiver._add_project", side_effect=failing):
            with self.assertRaisesRegex(ar.ArchiveError, "simulated"):
                ar.archive_project(p)
        self.assertEqual(self.files(), ["proj.burp"])
        self.assertEqual(Path(p).read_bytes(), before)

    def test_partial_cleaned_on_verify_mismatch(self):
        p = make_project(self.dir)
        with mock.patch("archiver._sha256_entry", return_value="0" * 64):
            with self.assertRaisesRegex(ar.ArchiveError, "verification failed"):
                ar.archive_project(p)
        self.assertEqual(self.files(), ["proj.burp"])

    def test_original_kept_if_changed_before_delete(self):
        p = make_project(self.dir)
        real = ar._test_archive

        def touch_then_test(partial, progress):
            real(partial, progress)
            with open(p, "ab") as f:
                f.write(b"x")

        with mock.patch("archiver._test_archive", side_effect=touch_then_test):
            with self.assertRaisesRegex(ar.ArchiveError, "changed"):
                ar.archive_project(p)
        self.assertEqual(self.files(), ["proj.burp"])

    def test_archive_negative_source_mtime_rejected_before_writes(self):
        p = make_project(self.dir, mb=1)
        before = Path(p).read_bytes()
        os.utime(p, (-1, -1))
        self.assertLess(os.stat(p).st_mtime, 0)
        with mock.patch("archiver._add_meta", wraps=ar._add_meta) as add:
            with self.assertRaisesRegex(ar.ArchiveError, "mtime|timestamp"):
                ar.archive_project(p)
        add.assert_not_called()
        self.assertEqual(self.files(), ["proj.burp"])
        self.assertEqual(Path(p).read_bytes(), before)

    def test_archive_reader_rejects_staged_metadata_preserves_source(self):
        p = make_project(self.dir, mb=1)
        before = Path(p).read_bytes()
        with mock.patch("archiver.read_meta", side_effect=ar.ArchiveError("invalid staged metadata")) as read:
            with self.assertRaisesRegex(ar.ArchiveError, "invalid staged metadata"):
                ar.archive_project(p)
        read.assert_called_once()
        self.assertEqual(self.files(), ["proj.burp"])
        self.assertEqual(Path(p).read_bytes(), before)

    def test_archive_valid_but_wrong_staged_metadata_preserves_source(self):
        p = make_project(self.dir, mb=1)
        before = Path(p).read_bytes()
        real_read = ar.read_meta

        def wrong_metadata(partial):
            return dict(real_read(partial), orig_name="different.burp")

        with mock.patch("archiver.read_meta", side_effect=wrong_metadata):
            with self.assertRaisesRegex(ar.ArchiveError, "metadata does not match"):
                ar.archive_project(p)
        self.assertEqual(self.files(), ["proj.burp"])
        self.assertEqual(Path(p).read_bytes(), before)

    def test_archive_conservative_space_cutoff_before_writes(self):
        p = make_project(self.dir, mb=1)
        needed = ar.bz.archive_space_needed(os.path.getsize(p))
        with mock.patch("archiver._free", return_value=needed - 1), \
                mock.patch("archiver._add_meta") as add:
            with self.assertRaisesRegex(ar.ArchiveError, "not enough free space"):
                ar.archive_project(p)
        add.assert_not_called()
        self.assertEqual(self.files(), ["proj.burp"])
        with mock.patch("archiver._free", return_value=needed):
            result = ar.archive_project(p, delete_original=False)
        self.assertTrue(os.path.isfile(result.archive_path))

    def test_archive_rechecks_space_before_project_update(self):
        p = make_project(self.dir, mb=1)
        needed = ar.bz.archive_space_needed(os.path.getsize(p))
        with mock.patch("archiver._free", side_effect=[needed, needed, needed - 1]), \
                mock.patch("archiver._add_project") as add:
            with self.assertRaisesRegex(ar.ArchiveError, "not enough free space"):
                ar.archive_project(p)
        add.assert_not_called()
        self.assertEqual(self.files(), ["proj.burp"])

    def test_archive_committed_copy_kept_if_original_delete_fails(self):
        p = make_project(self.dir, mb=1)
        before = Path(p).read_bytes()
        with mock.patch("archiver._delete_original", side_effect=PermissionError("locked")):
            with self.assertRaisesRegex(ar.ArchiveError, "original not deleted"):
                ar.archive_project(p)
        self.assertEqual(Path(p).read_bytes(), before)
        versions = ar.list_versions(p)
        self.assertEqual(len(versions), 1)
        self.assertEqual(ar.read_meta(versions[0])["sha256"], hashlib.sha256(before).hexdigest())

    def test_archive_stage_is_reserved_and_invocation_owned(self):
        p = make_project(self.dir, mb=1)
        real_add = ar._add_meta
        staged = []

        def check_stage(partial, meta_path):
            staged.append(partial)
            self.assertNotEqual(os.path.dirname(partial), self.dir)
            self.assertTrue(os.path.isdir(os.path.dirname(partial)))
            real_add(partial, meta_path)

        with mock.patch("archiver._add_meta", side_effect=check_stage):
            result = ar.archive_project(p)
        self.assertFalse(os.path.exists(os.path.dirname(staged[0])))
        self.assertEqual(self.files(), [os.path.basename(result.archive_path)])

    def test_bracketed_project_partial_cleanup_preserves_neighbor(self):
        p = make_project(self.dir, name="proj[1].burp", mb=1)
        neighbor = os.path.join(self.dir, "proj1.partial.tmp")
        Path(neighbor).write_bytes(b"unrelated")

        def failing(partial, *args, **kwargs):
            Path(partial + ".tmp1").write_bytes(b"own temporary file")
            raise ar.ArchiveError("simulated")

        with mock.patch("archiver._add_project", side_effect=failing):
            with self.assertRaisesRegex(ar.ArchiveError, "simulated"):
                ar.archive_project(p)
        self.assertEqual(self.files(), ["proj1.partial.tmp", "proj[1].burp"])
        self.assertEqual(Path(neighbor).read_bytes(), b"unrelated")

    def test_archive_commit_collision_keeps_existing_destination(self):
        p = make_project(self.dir, mb=1)
        collision = os.path.join(self.dir, "collision.burpz")
        real_test = ar._test_archive

        def insert_destination(partial, progress):
            real_test(partial, progress)
            Path(collision).write_bytes(b"older archive")

        with mock.patch("archiver._new_archive_path", return_value=collision), \
                mock.patch("archiver._test_archive", side_effect=insert_destination):
            with self.assertRaises(ar.ArchiveError):
                ar.archive_project(p)
        self.assertTrue(os.path.exists(p))
        self.assertEqual(Path(collision).read_bytes(), b"older archive")
        self.assertEqual(self.files(), ["collision.burpz", "proj.burp"])

    def test_literal_brackets_roundtrip(self):
        p = make_project(self.dir, name="proj[1].burp", mb=1)
        data = Path(p).read_bytes()
        result = ar.archive_project(p)
        ar.restore_project(result.archive_path)
        self.assertEqual(Path(p).read_bytes(), data)
        self.assertIsNone(ar.rezip_after_use(p, result.archive_path))

    def test_bad_level(self):
        p = make_project(self.dir)
        with self.assertRaises(ar.ArchiveError):
            ar.archive_project(p, level=12)

    def test_admission_uses_full_source_overhead_and_reserve_boundary(self):
        p = make_project(self.dir, mb=1)
        needed = os.path.getsize(p) + 64 * MB + ar.bz.SPACE_MARGIN
        with mock.patch("archiver.shutil.disk_usage", return_value=Usage(10**10, 0, needed - 1)), \
                mock.patch("archiver._add_meta") as add:
            with self.assertRaisesRegex(ar.ArchiveError, "not enough free space"):
                ar.archive_project(p)
            add.assert_not_called()
        with mock.patch("archiver.shutil.disk_usage", return_value=Usage(10**10, 0, needed)):
            result = ar.archive_project(p, delete_original=False)
        self.assertTrue(os.path.isfile(result.archive_path))
        self.assertTrue(os.path.isfile(p))

    def test_live_admission_rechecked_before_project_compression(self):
        p = make_project(self.dir, mb=1)
        needed = os.path.getsize(p) + 64 * MB + ar.bz.SPACE_MARGIN
        with mock.patch("archiver.shutil.disk_usage",
                        side_effect=[Usage(10**10, 0, needed), Usage(10**10, 0, needed),
                                     Usage(10**10, 0, 0)]), \
                mock.patch("archiver._add_project") as add:
            with self.assertRaisesRegex(ar.ArchiveError, "not enough free space"):
                ar.archive_project(p)
            add.assert_not_called()
        self.assertEqual(self.files(), ["proj.burp"])

    def test_delete_failure_preserves_verified_new_and_older_archive(self):
        p = make_project(self.dir, mb=1)
        older = ar.archive_project(p, delete_original=False).archive_path
        older_data = Path(older).read_bytes()
        with mock.patch("archiver._delete_original", side_effect=PermissionError("synthetic denied")):
            with self.assertRaisesRegex(ar.ArchiveError, "archive kept"):
                ar.archive_project(p)
        versions = ar.list_versions(p)
        self.assertEqual(len(versions), 2)
        self.assertEqual(Path(older).read_bytes(), older_data)
        self.assertTrue(os.path.isfile(p))
        self.assertEqual(ar.read_meta(versions[0])["sha256"], ar._sha256_file(p, os.path.getsize(p)))

    def test_bracketed_project_roundtrip_and_literal_partial_cleanup(self):
        p = make_project(self.dir, "proj[1].burp", mb=1)
        data = Path(p).read_bytes()
        r = ar.archive_project(p)
        self.assertEqual(Path(ar.restore_project(r.archive_path)).read_bytes(), data)
        real = ar._add_project

        def failing(partial, *args, **kwargs):
            Path(partial + ".tmp123").write_bytes(b"synthetic scratch")
            raise ar.ArchiveError("synthetic failure")

        with mock.patch("archiver._add_project", side_effect=failing):
            with self.assertRaisesRegex(ar.ArchiveError, "synthetic failure"):
                ar.archive_project(p)
        self.assertEqual(self.files(), sorted([Path(p).name, Path(r.archive_path).name]))
        self.assertEqual(Path(p).read_bytes(), data)

    def test_archive_commit_race_does_not_overwrite_destination(self):
        p = make_project(self.dir, mb=1)
        final = os.path.join(self.dir, "raced.burpz")
        real = ar._test_archive

        def create_destination(partial, progress):
            real(partial, progress)
            Path(final).write_bytes(b"existing synthetic archive")

        with mock.patch("archiver._new_archive_path", return_value=final), \
                mock.patch("archiver._test_archive", side_effect=create_destination):
            with self.assertRaises(ar.ArchiveError):
                ar.archive_project(p)
        self.assertEqual(Path(final).read_bytes(), b"existing synthetic archive")
        self.assertTrue(os.path.isfile(p))
        self.assertFalse(os.path.exists(final + ar.PARTIAL_EXT))


class RestoreTests(Base):
    def test_restore_roundtrip_bytes_and_mtime(self):
        p = make_project(self.dir, age_days=45)
        data = Path(p).read_bytes()
        mtime = os.stat(p).st_mtime
        r = ar.archive_project(p)
        stages = []
        out = ar.restore_project(r.archive_path, progress=lambda s, f: stages.append(s))
        self.assertEqual(os.path.normcase(out), os.path.normcase(p))
        self.assertEqual(Path(out).read_bytes(), data)
        self.assertAlmostEqual(os.stat(out).st_mtime, mtime, delta=0.01)
        self.assertTrue(os.path.isfile(r.archive_path))  # archive kept
        self.assertNotIn("proj.burp.partial", self.files())
        self.assertIn("extract", stages)

    def test_restore_to_other_dest(self):
        p = make_project(self.dir)
        r = ar.archive_project(p)
        dest = os.path.join(self.dir, "other.burp")
        self.assertEqual(ar.restore_project(r.archive_path, dest), dest)
        self.assertEqual(ar.read_meta(r.archive_path)["size"], os.path.getsize(dest))

    def test_restore_refuses_existing_dest(self):
        p = make_project(self.dir)
        r = ar.archive_project(p, delete_original=False)
        before = Path(p).read_bytes()
        with self.assertRaisesRegex(ar.ArchiveError, "already exists"):
            ar.restore_project(r.archive_path)
        self.assertEqual(Path(p).read_bytes(), before)

    def test_restore_refuses_insufficient_space(self):
        p = make_project(self.dir)
        r = ar.archive_project(p)
        with mock.patch("archiver.shutil.disk_usage", return_value=Usage(10**9, 10**9, MB)):
            with self.assertRaisesRegex(ar.ArchiveError, "not enough free space"):
                ar.restore_project(r.archive_path)
        self.assertEqual(self.files(), [os.path.basename(r.archive_path)])

    def test_restore_mismatch_removes_partial(self):
        p = make_project(self.dir)
        r = ar.archive_project(p)
        real = ar.read_meta

        def bad_meta(a):
            m = real(a)
            m["sha256"] = "0" * 64
            return m

        with mock.patch("archiver.read_meta", side_effect=bad_meta):
            with self.assertRaisesRegex(ar.ArchiveError, "does not match"):
                ar.restore_project(r.archive_path)
        self.assertEqual(self.files(), [os.path.basename(r.archive_path)])

    def test_read_meta_rejects_non_burpzip(self):
        f = os.path.join(self.dir, "x.txt")
        Path(f).write_text("hi")
        arc = os.path.join(self.dir, "plain.7z")
        subprocess.run([ar.find_7z(), "a", arc, f], capture_output=True, check=True)
        with self.assertRaises(ar.ArchiveError):
            ar.read_meta(arc)


class MetadataSafetyTests(Base):
    def test_invalid_metadata_rejected_before_use(self):
        archive = os.path.join(self.dir, "metadata.burpz")
        Path(archive).write_bytes(b"synthetic archive stand-in")
        good = {"format": 1, "tool": "burpzip", "orig_name": "proj.burp",
                "size": 0, "mtime": 0.0, "sha256": hashlib.sha256(b"").hexdigest()}
        invalid = [("size", x) for x in (-1, True, 1.5, "2", None)]
        invalid += [("mtime", x) for x in (-1, True, "2", None, float("nan"),
                                            float("inf"), 10**400)]
        invalid += [("sha256", x) for x in (None, 42, "g" * 64, "a" * 63)]
        invalid += [("orig_name", x) for x in (None, 5, "", "x.txt", "../x.burp",
                     r"..\x.burp", "x.burp:stream.burp", "CON.burp", "con .burp",
                     "COM1.burp", "LPT9.burp", "COM¹.burp", "burpzip-meta.json",
                     "x.burp.", "x?.burp", "x\n.burp", "x\0.burp")]
        invalid += [("format", True)]
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                meta = dict(good, **{field: value})
                encoded = json.dumps(meta).encode("utf-8")
                with mock.patch("archiver._stream_7z", side_effect=lambda args, sink: sink(encoded)):
                    with self.assertRaises(ar.ArchiveError):
                        ar.read_meta(archive)

    def test_valid_empty_metadata_and_brackets_accepted(self):
        archive = make_reference(self.dir, b"", name="project[1].burp", payload=b"")
        self.assertEqual(ar.read_meta(archive)["size"], 0)
        restored = ar.restore_project(archive)
        self.assertEqual(Path(restored).read_bytes(), b"")


class RestoreSafetyTests(Base):
    def test_restore_metadata_only_empty_archive_rejected_before_staging(self):
        archive = make_reference(self.dir, b"")
        before = Path(archive).read_bytes()
        dest = os.path.join(self.dir, "proj.burp")
        with mock.patch("archiver.tempfile.mkstemp", wraps=tempfile.mkstemp) as stage:
            with self.assertRaisesRegex(ar.ArchiveError, "payload|entry"):
                ar.restore_project(archive)
        stage.assert_not_called()
        self.assertFalse(os.path.exists(dest))
        self.assertEqual(self.files(), ["reference.burpz"])
        self.assertEqual(Path(archive).read_bytes(), before)

    def test_restore_rejects_overflow_before_writing_chunk(self):
        archive = make_reference(self.dir, b"ok", payload=b"ok" + b"x" * 1000)
        written = []
        # Isolate the streaming guard even if a listing claims the expected size.
        with mock.patch("archiver._require_entry"), \
                self.assertRaisesRegex(ar.ArchiveError, "exceeds|overflow"):
            ar.restore_project(archive, progress=lambda stage, value: written.append(stage))
        self.assertNotIn("extract", written)
        self.assertEqual(self.files(), ["reference.burpz"])

    def test_restore_leaves_foreign_partial_untouched(self):
        archive = make_reference(self.dir, b"ok", payload=b"ok")
        foreign = os.path.join(self.dir, "proj.burp.partial")
        Path(foreign).write_bytes(b"another invocation")
        restored = ar.restore_project(archive)
        self.assertEqual(Path(restored).read_bytes(), b"ok")
        self.assertEqual(Path(foreign).read_bytes(), b"another invocation")

    def test_concurrent_restore_commits_only_its_own_verified_bytes(self):
        dest = os.path.join(self.dir, "shared.burp")
        first, second = b"verified first payload", b"different second payload"
        archives = {os.path.abspath(os.path.join(self.dir, "a.burpz")): first,
                    os.path.abspath(os.path.join(self.dir, "b.burpz")): second}
        ready, release = threading.Event(), threading.Event()
        failures = []
        worker = []

        def meta(path):
            data = archives[path]
            return {"orig_name": "shared.burp", "size": len(data), "mtime": 1791763200.0,
                    "sha256": hashlib.sha256(data).hexdigest()}

        def second_progress(stage, fraction):
            if stage == "verify":
                ready.set()
                if not release.wait(10):
                    raise AssertionError("first restore did not finish")

        def second_restore():
            try:
                ar.restore_project(list(archives)[1], dest, progress=second_progress)
            except Exception as exc:
                failures.append(exc)

        def first_progress(stage, fraction):
            if stage == "verify":
                thread = threading.Thread(target=second_restore)
                worker.append(thread)
                thread.start()
                self.assertTrue(ready.wait(10), "second restore never staged its bytes")

        with mock.patch("archiver.read_meta", side_effect=meta), \
                mock.patch("archiver._require_entry"), \
                mock.patch("archiver._stream_7z", side_effect=lambda args, sink: sink(archives[args[-3]])):
            try:
                self.assertEqual(ar.restore_project(list(archives)[0], dest,
                                                   progress=first_progress), dest)
                self.assertEqual(Path(dest).read_bytes(), first)
            finally:
                release.set()
                for thread in worker:
                    thread.join(10)
                    self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ar.ArchiveError)
        self.assertEqual(self.files(), ["shared.burp"])


class RezipTests(Base):
    def test_rezip_metadata_only_reference_keeps_original(self):
        for data in (b"only good project", b""):
            with self.subTest(size=len(data)), tempfile.TemporaryDirectory() as folder:
                p = os.path.join(folder, "proj.burp")
                Path(p).write_bytes(data)
                archive = make_reference(folder, data)
                with self.assertRaisesRegex(ar.ArchiveError, "payload|verification|entry"):
                    ar.rezip_after_use(p, archive)
                self.assertEqual(Path(p).read_bytes(), data)
                self.assertTrue(os.path.isfile(archive))

    def test_rezip_wrong_payload_reference_keeps_original(self):
        data = b"only good project"
        p = os.path.join(self.dir, "proj.burp")
        Path(p).write_bytes(data)
        archive = make_reference(self.dir, data, payload=b"X" * len(data))
        with self.assertRaisesRegex(ar.ArchiveError, "payload|verification|entry"):
            ar.rezip_after_use(p, archive)
        self.assertEqual(Path(p).read_bytes(), data)
        self.assertTrue(os.path.isfile(archive))

    def test_rezip_reference_name_must_match_source(self):
        p = os.path.join(self.dir, "proj.burp")
        Path(p).write_bytes(b"same bytes")
        archive = make_reference(self.dir, b"same bytes", name="other.burp", payload=b"same bytes")
        with self.assertRaisesRegex(ar.ArchiveError, "name|reference"):
            ar.rezip_after_use(p, archive)
        self.assertEqual(Path(p).read_bytes(), b"same bytes")

    def test_rezip_unchanged_runs_integrity_test_before_delete(self):
        p = make_project(self.dir, mb=1)
        result = ar.archive_project(p, delete_original=False)
        with mock.patch("archiver._test_archive", side_effect=ar.ArchiveError("corrupt archive")) as test:
            with self.assertRaisesRegex(ar.ArchiveError, "corrupt archive"):
                ar.rezip_after_use(p, result.archive_path)
        test.assert_called_once()
        self.assertTrue(os.path.isfile(p))
        self.assertTrue(os.path.isfile(result.archive_path))

    def test_rezip_unchanged_deletes_copy(self):
        p = make_project(self.dir)
        r = ar.archive_project(p)
        ar.restore_project(r.archive_path)
        self.assertIsNone(ar.rezip_after_use(p))
        self.assertFalse(os.path.exists(p))
        self.assertEqual(ar.list_versions(p, self.dir), [r.archive_path])

    def test_rezip_changed_creates_new_version(self):
        p = make_project(self.dir)
        r1 = ar.archive_project(p)
        ar.restore_project(r1.archive_path)
        with open(p, "r+b") as f:
            f.seek(100)
            f.write(b"changed by burp")
        r2 = ar.rezip_after_use(p, r1.archive_path)
        self.assertIsInstance(r2, ar.ArchiveResult)
        self.assertTrue(r2.deleted_original)
        self.assertFalse(os.path.exists(p))
        self.assertEqual(ar.list_versions(p, self.dir), [r2.archive_path, r1.archive_path])
        self.assertNotEqual(ar.read_meta(r2.archive_path)["sha256"], r1.sha256)

    def test_rezip_refuses_in_use(self):
        p = make_project(self.dir)
        r = ar.archive_project(p)
        ar.restore_project(r.archive_path)
        with HeldOpen(p):
            with self.assertRaisesRegex(ar.ArchiveError, "in use"):
                ar.rezip_after_use(p)
        self.assertTrue(os.path.exists(p))


class BackupTests(Base):
    def setUp(self):
        super().setUp()
        self.proj = make_project(self.dir, mb=1, age_days=10)
        self.bak = os.path.join(self.dir, "proj.burp.backup")
        Path(self.bak).write_bytes(b"b" * 1000)

    def set_age(self, path, days):
        t = time.time() - days * 86400
        os.utime(path, (t, t))

    def test_deletes_older_backup(self):
        self.set_age(self.bak, 20)
        self.assertEqual(ar.delete_backup(self.bak), 1000)
        self.assertFalse(os.path.exists(self.bak))
        self.assertTrue(os.path.exists(self.proj))

    def test_refuses_newer_backup_unless_forced(self):
        self.set_age(self.bak, 1)
        with self.assertRaisesRegex(ar.ArchiveError, "newer"):
            ar.delete_backup(self.bak)
        self.assertTrue(os.path.exists(self.bak))
        self.assertEqual(ar.delete_backup(self.bak, force_newer=True), 1000)

    def test_refuses_when_project_missing(self):
        orphan = os.path.join(self.dir, "orphan.burp.backup.temp_1")
        Path(orphan).write_bytes(b"x")
        with self.assertRaisesRegex(ar.ArchiveError, "missing"):
            ar.delete_backup(orphan, force_newer=True)
        self.assertTrue(os.path.exists(orphan))

    def test_refuses_in_use(self):
        self.set_age(self.bak, 20)
        with HeldOpen(self.bak):
            with self.assertRaisesRegex(ar.ArchiveError, "in use"):
                ar.delete_backup(self.bak)
        self.assertTrue(os.path.exists(self.bak))

    def test_refuses_non_backup(self):
        with self.assertRaisesRegex(ar.ArchiveError, "not a Burp backup"):
            ar.delete_backup(self.proj, force_newer=True)
        self.assertTrue(os.path.exists(self.proj))


class RunPlanTests(Base):
    def test_runs_archive_steps_and_continues_past_errors(self):
        a = make_project(self.dir, "a.burp")
        b = make_project(self.dir, "b.burp", seed=0)
        bak = os.path.join(self.dir, "a.burp.backup")
        Path(bak).write_bytes(b"x")
        t = time.time() - 99 * 86400
        os.utime(bak, (t, t))
        plan = {"steps": [
            {"action": "delete-backup", "path": bak},
            {"action": "archive", "path": a},
            {"action": "archive", "path": os.path.join(self.dir, "missing.burp")},
            {"action": "skip", "path": b},
            {"action": "archive", "path": b},
        ]}
        res = ar.run_plan(plan)
        self.assertEqual(len(res), 3)
        self.assertIsInstance(res[0], ar.ArchiveResult)
        self.assertIsInstance(res[1], ar.ArchiveError)
        self.assertIsInstance(res[2], ar.ArchiveResult)
        self.assertTrue(os.path.exists(bak))  # backups never deleted by run_plan
        self.assertFalse(os.path.exists(a) or os.path.exists(b))

    def test_live_guard_uses_conservative_admission_boundary(self):
        p = make_project(self.dir, mb=1)
        plan = {"steps": [{"action": "archive", "path": p}]}
        needed = ar.bz.archive_space_needed(os.path.getsize(p))
        with mock.patch("archiver._free", return_value=needed - 1), \
                mock.patch("archiver.archive_project") as archive:
            results = ar.run_plan(plan)
        archive.assert_not_called()
        self.assertIsInstance(results[0], ar.ArchiveError)
        with mock.patch("archiver._free", return_value=needed), \
                mock.patch("archiver.archive_project", return_value="allowed") as archive:
            self.assertEqual(ar.run_plan(plan), ["allowed"])
        archive.assert_called_once()
        self.assertTrue(os.path.exists(p))

    def test_live_space_check_and_stop_event(self):
        a = make_project(self.dir, "a.burp")
        plan = {"steps": [{"action": "archive", "path": a}]}
        with mock.patch("archiver.shutil.disk_usage", return_value=Usage(10**9, 10**9, MB)):
            res = ar.run_plan(plan)
        self.assertIsInstance(res[0], ar.ArchiveError)
        stop = threading.Event()
        stop.set()
        self.assertEqual(ar.run_plan(plan, stop_event=stop), [])
        self.assertTrue(os.path.exists(a))


class NativeGuardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-guard-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.project = str(self.root / "demo.burp")
        self.archive = str(self.root / "demo.burpz")
        self.dest = str(self.root / "new.burp")

    def test_direct_mutations_guard_before_file_or_content_probes(self):
        calls = [lambda: ar.archive_project(self.project, delete_original=False),
                 lambda: ar.rezip_after_use(self.project, self.archive),
                 lambda: ar.delete_backup(self.project + ".backup", force_newer=True),
                 lambda: ar._delete_original(self.project, (1, 0)),
                 lambda: ar._sha256_file(self.project, 1)]
        for call in calls:
            with self.subTest(call=call), \
                    mock.patch.object(ar.bz, "require_ordinary_path", side_effect=RuntimeError("native protected")), \
                    mock.patch.object(ar.os.path, "isfile") as file_probe, \
                    mock.patch.object(ar.bz, "is_in_use") as lock, \
                    mock.patch.object(ar, "_stat_key") as stat, \
                    mock.patch("builtins.open") as content:
                with self.assertRaisesRegex(ar.ArchiveError, "protected"):
                    call()
                file_probe.assert_not_called()
                lock.assert_not_called()
                stat.assert_not_called()
                content.assert_not_called()

    def test_run_plan_guard_precedes_preprobe_and_dispatch(self):
        with mock.patch.object(ar.bz, "require_ordinary_path", side_effect=RuntimeError("store protected")), \
                mock.patch.object(ar.os.path, "isfile") as file_probe, \
                mock.patch.object(ar.os.path, "getsize") as size, \
                mock.patch.object(ar, "archive_project") as archive:
            results = ar.run_plan({"steps": [{"action": "archive", "path": self.project}]})
        self.assertIsInstance(results[0], ar.ArchiveError)
        file_probe.assert_not_called()
        size.assert_not_called()
        archive.assert_not_called()

    def test_archive_destination_and_parent_guard_precedes_source_hash(self):
        def require(path):
            if str(path) == str(self.root):
                raise RuntimeError("protected parent")
        fake = SimpleNamespace(require_ordinary_path=mock.Mock(side_effect=require))
        with mock.patch.dict(sys.modules, {"native_cfapi": fake}), \
                mock.patch.object(ar.os.path, "isfile") as file_probe, \
                mock.patch.object(ar, "_sha256_file") as content:
            with self.assertRaisesRegex(ar.ArchiveError, "parent"):
                ar.archive_project(self.project)
        file_probe.assert_not_called()
        content.assert_not_called()

    def test_read_meta_protected_input_never_invokes_7z_or_isfile(self):
        for kind in ("native", "cloud", "unknown"):
            with self.subTest(kind=kind), \
                    mock.patch.object(ar.bz, "native_state", return_value=SimpleNamespace(kind=kind)), \
                    mock.patch.object(ar.os.path, "isfile") as file_probe, \
                    mock.patch.object(ar, "_stream_7z") as stream:
                with self.assertRaisesRegex(ar.ArchiveError, "hydration"):
                    ar.read_meta(self.archive)
                file_probe.assert_not_called()
                stream.assert_not_called()

    def test_store_archive_read_is_allowed_but_default_restore_is_not(self):
        meta = {"tool": "burpzip", "format": 1, "orig_name": "demo.burp", "size": 0,
                "mtime": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        def state(path):
            return SimpleNamespace(kind="store" if str(path).startswith(str(self.root)) else "ordinary")
        with mock.patch.object(ar.bz, "native_state", side_effect=state), \
                mock.patch.object(ar.os.path, "isfile", return_value=True), \
                mock.patch.object(ar, "_stream_7z", side_effect=lambda args, sink: sink(json.dumps(meta).encode())):
            self.assertEqual(ar.read_meta(self.archive), meta)
        with mock.patch.object(ar.bz, "native_state", side_effect=state), \
                mock.patch.object(ar.bz, "require_ordinary_path", side_effect=RuntimeError("store protected")), \
                mock.patch.object(ar, "read_meta", return_value=meta), \
                mock.patch.object(ar.tempfile, "mkstemp") as stage:
            with self.assertRaisesRegex(ar.ArchiveError, "store"):
                ar.restore_project(self.archive)
        stage.assert_not_called()

    def test_explicit_restore_destination_guard_precedes_metadata(self):
        with mock.patch.object(ar.bz, "native_state", return_value=SimpleNamespace(kind="ordinary")), \
                mock.patch.object(ar.bz, "require_ordinary_path", side_effect=RuntimeError("cloud destination")), \
                mock.patch.object(ar, "read_meta") as meta, \
                mock.patch.object(ar.tempfile, "mkstemp") as stage:
            with self.assertRaisesRegex(ar.ArchiveError, "destination"):
                ar.restore_project(self.archive, self.dest)
        meta.assert_not_called()
        stage.assert_not_called()

    def test_deletion_edge_rechecks_classification(self):
        for delete in (lambda: ar._delete_original(self.project, (1, 0)),):
            with mock.patch.object(ar.bz, "require_ordinary_path",
                                   side_effect=[None, RuntimeError("became native")]), \
                    mock.patch.object(ar, "_stat_key", return_value=(1, 0)), \
                    mock.patch.object(ar.bz, "is_in_use", return_value=False), \
                    mock.patch.object(ar.os, "remove") as remove:
                with self.assertRaisesRegex(ar.ArchiveError, "became native"):
                    delete()
            remove.assert_not_called()

    def test_verify_archive_checks_exact_size_hash_and_never_deletes(self):
        meta = {"orig_name": "demo.burp", "size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        sequence = []
        with mock.patch.object(ar.bz, "native_state", return_value=SimpleNamespace(kind="store")), \
                mock.patch.object(ar, "read_meta", side_effect=lambda path: sequence.append("meta") or meta), \
                mock.patch.object(ar, "_test_archive", side_effect=lambda path, progress: sequence.append("test")), \
                mock.patch.object(ar, "_sha256_entry", side_effect=lambda *args, **kw: sequence.append("hash") or meta["sha256"]) as sha, \
                mock.patch.object(ar.os, "remove") as remove:
            self.assertIs(ar.verify_archive(self.archive), meta)
        self.assertEqual(sequence, ["meta", "test", "hash"])
        sha.assert_called_once_with(self.archive, "demo.burp", None, size=0)
        remove.assert_not_called()

    def test_verify_archive_hash_mismatch_and_missing_empty_entry_fail(self):
        meta = {"orig_name": "demo.burp", "size": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        for failure in (None, ar.ArchiveError("missing empty entry")):
            with self.subTest(failure=failure), \
                    mock.patch.object(ar.bz, "native_state", return_value=SimpleNamespace(kind="ordinary")), \
                    mock.patch.object(ar, "read_meta", return_value=meta), \
                    mock.patch.object(ar, "_test_archive"), \
                    mock.patch.object(ar, "_sha256_entry", return_value="0" * 64, side_effect=failure), \
                    mock.patch.object(ar.os, "remove") as remove:
                with self.assertRaises(ar.ArchiveError):
                    ar.verify_archive(self.archive)
                remove.assert_not_called()


class CancellationTests(unittest.TestCase):
    def blocked_child(self, stop):
        killed = threading.Event()
        class Pipe:
            def read(self, size):
                stop.set()
                if not killed.wait(2):
                    raise AssertionError("cancellation never killed the hung child")
                return b""
            read1 = read
            def __iter__(self):
                return iter(())
        proc = mock.MagicMock()
        proc.__enter__.return_value = proc
        proc.stdout = Pipe()
        proc.stderr = Pipe()
        proc.kill.side_effect = killed.set
        # Even a nominal success return cannot turn cancellation into success.
        proc.wait.return_value = 0
        return proc, killed

    def test_cancel_hung_run_and_stream_kill_wait_and_join_threads(self):
        for streaming in (False, True):
            with self.subTest(streaming=streaming):
                stop = threading.Event()
                proc, killed = self.blocked_child(stop)
                with mock.patch.object(ar.subprocess, "Popen", return_value=proc), \
                        mock.patch.object(ar, "_exe", return_value="fake-7z"):
                    with self.assertRaisesRegex(ar.ArchiveError, "cancelled"):
                        if streaming:
                            ar._stream_7z(["e"], lambda data: self.fail("cancelled data exposed"), stop_event=stop)
                        else:
                            ar._run_7z(["t"], stop_event=stop)
                self.assertTrue(killed.is_set())
                proc.wait.assert_called()
                self.assertFalse(any(t.name in ("burpzip-7z-cancel", "burpzip-7z-stderr")
                                     for t in threading.enumerate()))

    def test_precancel_never_starts_child_or_reads_archive(self):
        stop = threading.Event()
        stop.set()
        with mock.patch.object(ar.subprocess, "Popen") as child, \
                mock.patch.object(ar.bz, "native_state") as classify:
            for call in (lambda: ar._run_7z(["t"], stop_event=stop),
                         lambda: ar._stream_7z(["e"], lambda data: None, stop_event=stop),
                         lambda: ar.read_meta("fake.burpz", stop_event=stop),
                         lambda: ar.verify_archive("fake.burpz", stop_event=stop),
                         lambda: ar.restore_project("fake.burpz", stop_event=stop)):
                with self.assertRaisesRegex(ar.ArchiveError, "cancelled"):
                    call()
        child.assert_not_called()
        classify.assert_not_called()

    def test_verify_forwards_control_only_when_provided(self):
        stop = threading.Event()
        meta = {"orig_name": "demo.burp", "size": 3, "sha256": "a" * 64}
        with mock.patch.object(ar.bz, "native_state", return_value=SimpleNamespace(kind="store")), \
                mock.patch.object(ar, "read_meta", return_value=meta) as read, \
                mock.patch.object(ar, "_test_archive") as test, \
                mock.patch.object(ar, "_sha256_entry", return_value="a" * 64) as sha:
            ar.verify_archive("fake.burpz", stop_event=stop)
        read.assert_called_once_with("fake.burpz", stop_event=stop)
        test.assert_called_once_with("fake.burpz", None, stop_event=stop)
        sha.assert_called_once_with("fake.burpz", "demo.burp", None, size=3, stop_event=stop)

    def test_restore_cancel_before_commit_discards_only_own_partial(self):
        with tempfile.TemporaryDirectory(prefix="burpzip-cancel-test-") as root:
            archive, dest = str(Path(root, "fake.burpz")), str(Path(root, "new.burp"))
            foreign = Path(root, "new.burp.partial")
            foreign.write_bytes(b"foreign")
            stop = threading.Event()
            data = b"synthetic payload"
            meta = {"orig_name": "new.burp", "size": len(data), "mtime": 0,
                    "sha256": hashlib.sha256(data).hexdigest()}
            def stream(args, sink, **kw):
                sink(data)
                stop.set()
            with mock.patch.object(ar.bz, "require_ordinary_path"), \
                    mock.patch.object(ar.bz, "native_state", return_value=SimpleNamespace(kind="ordinary")), \
                    mock.patch.object(ar, "read_meta", return_value=meta), \
                    mock.patch.object(ar, "_require_entry"), \
                    mock.patch.object(ar, "_check_space"), \
                    mock.patch.object(ar, "_stream_7z", side_effect=stream), \
                    mock.patch.object(ar, "_commit_no_clobber") as commit:
                with self.assertRaisesRegex(ar.ArchiveError, "cancelled"):
                    ar.restore_project(archive, dest, stop_event=stop)
            commit.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [foreign])
            self.assertEqual(foreign.read_bytes(), b"foreign")


if __name__ == "__main__":
    unittest.main(verbosity=2)
