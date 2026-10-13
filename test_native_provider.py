"""Provider state machine against a simulated CFAPI adapter.

The fake adapter models placeholders in memory over ordinary temp files. The
store, its journal and 7-Zip extraction are real. No sync root is registered,
nothing touches Windows Cloud Files, and Burp is never launched.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest

import testenv  # noqa: F401  (isolated burpzip.ini)
from unittest import mock

import archiver as ar
import native_cfapi as cf
import native_provider as np
import native_store as ns


def _sha(path) -> str:
    with open(path, "rb") as source:
        return hashlib.sha256(source.read()).hexdigest()


REAL_API = cf.WindowsCfApi()


class FakeSnapshot:
    def __init__(self, stream, path, file_id, size, mtime):
        self._stream, self.path, self.file_id, self.size, self.mtime = stream, path, file_id, size, mtime

    def read(self, count: int) -> bytes:
        return self._stream.read(count)


def _norm(path) -> str:
    return os.path.normcase(os.path.abspath(path))


class FakeCfApi:
    """In-memory placeholder state; bytes live in ordinary files on disk."""

    def __init__(self):
        self.lock = threading.RLock()
        self.roots: dict[str, bytes] = {}
        self.files: dict[str, dict] = {}
        self.calls: list[tuple] = []
        self.connection = None
        self.callback = None
        self.corrupt_retrieve = False
        self.transfer_delay = 0.0
        self.in_use_paths: set[str] = set()
        self.fail_dehydrate = False
        self.auto_validate = True
        self.catalog_at_ack: list[dict] = []
        self.store_path = None
        self._keys = 0
        self.done = threading.Event()

    # -- metadata -------------------------------------------------------
    def file_id(self, path) -> str:
        st = os.stat(path)
        return f"{st.st_dev:08x}:{st.st_ino:016x}"

    def inspect_root(self, path):
        identity = self.roots.get(_norm(path))
        if identity is None:
            # Unregistered paths use the REAL nonhydrating adapter query, so
            # marker/link/cloud refusals behave exactly as on Windows.
            return REAL_API.inspect_root(path)
        owned = cf.decode_root_identity(identity)
        return {"identity": identity, "root_id": owned["root_id"],
                "root_file_id": owned["root_file_id"], "root_path": os.path.abspath(path)}

    def inspect(self, path) -> cf.PathState:
        key = _norm(path)
        with self.lock:
            row = self.files.get(key)
            if row is None:
                return cf.PathState(kind="ordinary", path=os.path.abspath(path),
                                    file_id=self.file_id(path) if os.path.exists(path) else None,
                                    size=os.path.getsize(path) if os.path.exists(path) else 0)
            if row["reverted"]:
                # Like Windows: still inside the owned root, no placeholder identity.
                return cf.PathState(kind="native", path=os.path.abspath(path), root_path=row["root"],
                                    root_id=row["root_id"], file_id=self.file_id(path),
                                    size=os.path.getsize(path), modified=True, resident=True)
            resident = row["validated"] or row["modified"]
            size = os.path.getsize(path) if resident else row["size"]
            return cf.PathState(kind="native", path=os.path.abspath(path), root_path=row["root"],
                                root_id=row["root_id"], file_id=self.file_id(path),
                                identity=row["identity"], size=size,
                                ready=row["validated"] and not row["modified"],
                                modified=row["modified"], resident=resident)

    # -- mutation -------------------------------------------------------
    def register(self, root, identity: bytes) -> None:
        self.calls.append(("register", root))
        self.roots[_norm(root)] = identity

    def create(self, root, name, size, mtime, identity) -> str:
        self.calls.append(("create", name))
        path = os.path.join(root, name)
        with open(path, "xb"):
            pass
        owned = cf.decode_root_identity(self.roots[_norm(root)])
        self.files[_norm(path)] = {"root": os.path.abspath(root), "root_id": owned["root_id"],
                                   "identity": identity, "size": size, "written": set(),
                                   "validated": False, "modified": False, "reverted": False}
        return self.file_id(path)

    def connect(self, root, on_request):
        self.calls.append(("connect", root))
        self.callback = on_request
        self.connection = object()
        return self.connection

    def disconnect(self, connection) -> None:
        self.calls.append(("disconnect",))
        self.callback = None

    def _row(self, request):
        return self.files[_norm(request.path)]

    def transfer(self, request, offset, data) -> None:
        if self.transfer_delay:
            time.sleep(self.transfer_delay)
        with self.lock:
            self.calls.append(("transfer", offset, len(data)))
            with open(request.path, "r+b") as out:
                out.seek(offset)
                out.write(data)
            row = self._row(request)
            row["written"].add((offset, len(data)))
            complete = sum(n for _, n in row["written"]) >= row["size"] and not row.get("validating")
            if complete:
                row["validating"] = True
        if complete and self.auto_validate:
            # Like Windows with VALIDATION_REQUIRED: once the fetch range is on
            # disk, the OS issues a separate VALIDATE_DATA callback.
            threading.Thread(target=self.request, args=(request.path, "validate")).start()

    def retrieve(self, request, offset, length) -> bytes:
        with open(request.path, "rb") as source:
            source.seek(offset)
            data = source.read(length)
        if self.corrupt_retrieve and offset == 0 and data:
            data = bytes([data[0] ^ 0xFF]) + data[1:]
        return data

    def ack(self, request, offset, length, status=0) -> None:
        if request.event != "validate":
            # Matches live Windows: ACK_DATA on a FETCH_DATA key is rejected.
            self.calls.append(("ack-rejected", request.event))
            raise cf.NativeError("CfExecute failed (HRESULT 0x8007018e)")
        with open(os.path.join(self.store_path, ns.MARKER), encoding="utf-8") as marker:
            catalog = json.load(marker)
        self.catalog_at_ack.append(next(iter(catalog["files"].values())))
        with self.lock:
            self.calls.append(("ack", request.event, offset, length))
            row = self._row(request)
            if sum(n for _, n in row["written"]) >= row["size"]:
                row["validated"] = True
        self.done.set()

    def fail(self, request, status=cf.STATUS_CLOUD_FILE_UNSUCCESSFUL) -> None:
        self.calls.append(("fail", request.event, status))
        self.done.set()

    def progress(self, request, total, completed) -> None:
        self.calls.append(("progress", total, completed))

    def hydrate(self, path) -> None:
        self.calls.append(("hydrate", os.path.basename(path)))
        self.done.clear()
        self.request(path)
        if not self.done.wait(60):
            raise cf.NativeError("fake hydrate timed out")

    @contextlib.contextmanager
    def locked_snapshot(self, path, expected_file_id):
        state = self.inspect(path)
        if state.kind != "native" or not state.identity or state.file_id != expected_file_id \
                or not state.resident:
            raise cf.NativeError("Re-zip requires the owned, fully resident placeholder")
        if _norm(path) in self.in_use_paths:
            raise cf.NativeError("Project is in use (open in Burp?)")
        self.calls.append(("snapshot", os.path.basename(path)))
        with open(path, "rb") as source:
            st = os.fstat(source.fileno())
            yield FakeSnapshot(source, path, expected_file_id, st.st_size, st.st_mtime)

    def dehydrate_locked(self, snapshot, identity, size, mtime) -> None:
        self.calls.append(("dehydrate", os.path.basename(snapshot.path)))
        if self.fail_dehydrate:
            raise cf.NativeError("CfUpdatePlaceholder failed (HRESULT 0x800701b2)")
        with self.lock:
            row = self.files[_norm(snapshot.path)]
            row.update(identity=identity, size=size, written=set(), validated=False,
                       modified=False, validating=False)
        with open(snapshot.path, "r+b") as out:
            out.truncate(0)  # Dehydrated: no local bytes until the next fetch.

    def in_use(self, path) -> bool:
        return _norm(path) in self.in_use_paths or not self.inspect(path).resident

    def set_always_full(self, path) -> bool:
        self.calls.append(("always-full", os.path.basename(path)))
        return True

    def revert(self, path) -> None:
        self.calls.append(("revert", os.path.basename(path)))
        self.files[_norm(path)]["reverted"] = True

    def export_current(self, path, dest) -> None:
        raise cf.NativeError("current export unsupported")

    # -- OS simulation --------------------------------------------------
    def request(self, path, event="fetch", identity=None, file_size=None):
        row = self.files[_norm(path)]
        if event == "fetch" and not row["validated"]:
            # A new fetch of an unvalidated range is validated again by the OS.
            row["validating"] = False
            row["written"] = set()
        self._keys += 1
        req = cf.Request(event=event, path=os.path.abspath(path),
                         identity=row["identity"] if identity is None else identity,
                         connection=1, transfer=self._keys, request_key=self._keys, offset=0,
                         length=row["size"], file_size=row["size"] if file_size is None else file_size)
        self.callback(req)
        return req


@unittest.skipUnless(os.name == "nt" and ar.SEVEN_ZIP, "requires Windows and 7-Zip")
class ProviderTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-native-provider-test-")
        self.addCleanup(tmp.cleanup)
        base = tmp.name
        source_dir = os.path.join(base, "source")
        self.root = os.path.join(base, "root")
        self.store_dir = os.path.join(base, "store")
        for folder in (source_dir, self.root, self.store_dir):
            os.mkdir(folder)
        self.data = os.urandom(96 * 1024) + b"\0" * (2 * 1024 * 1024 + 123)
        project = os.path.join(source_dir, "Example.burp")
        with open(project, "wb") as out:
            out.write(self.data)
        result = ar.archive_project(project, level=0, threads=1, delete_original=False)
        self.archive = result.archive_path
        self.archive_sha = _sha(self.archive)
        self.api = FakeCfApi()
        self.api.store_path = self.store_dir
        ns.init_root(self.root, self.store_dir, api=self.api)
        self.entry = ns.add_archive(self.store_dir, self.archive, api=self.api)
        self.placeholder = os.path.join(self.root, "Example.burp")
        self.store = ns.NativeStore(self.store_dir, api=self.api)

    def tearDown(self):
        # The input archive is never modified or consumed by import/hydration.
        self.assertEqual(_sha(self.archive), self.archive_sha)

    def provider(self, deadline=60):
        return np.NativeProvider(self.store, self.api, deadline)

    def hydrate_once(self, provider):
        self.api.done.clear()
        self.api.request(self.placeholder)
        self.assertTrue(self.api.done.wait(60))
        deadline = time.monotonic() + 10
        while provider._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.02)

    def names(self):
        return [call[0] for call in self.api.calls]

    def test_import_creates_inert_placeholder(self):
        self.assertEqual(self.entry["phase"], "placeholder")
        self.assertFalse(self.entry["replay_disabled"])
        self.assertEqual(os.path.getsize(self.placeholder), 0)
        self.assertNotIn("transfer", self.names())

    def test_fetch_hydrates_same_path_with_verified_bytes(self):
        with self.provider() as provider:
            self.hydrate_once(provider)
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), self.data)
        entry = self.store.entry("Example.burp")
        self.assertEqual(entry["phase"], "resident")
        self.assertTrue(entry["replay_disabled"])
        self.assertEqual(provider.errors, [])
        self.assertEqual(self.names().count("ack"), 1)
        self.assertNotIn("fail", self.names())

    def test_replay_boundary_is_durable_before_ack(self):
        with self.provider() as provider:
            self.hydrate_once(provider)
        at_ack = self.api.catalog_at_ack[0]
        self.assertEqual(at_ack["phase"], "ack-intent")
        self.assertTrue(at_ack["replay_disabled"])
        self.assertEqual(at_ack["verified_sha256"], self.entry["payload_sha256"])
        ack_index = self.names().index("ack")
        self.assertTrue(all(i < ack_index for i, name in enumerate(self.names()) if name == "transfer"))

    def test_corrupt_persisted_bytes_are_never_acknowledged(self):
        self.api.corrupt_retrieve = True
        with self.provider() as provider:
            self.hydrate_once(provider)
        self.assertNotIn("ack", self.names())
        self.assertIn("fail", self.names())
        entry = self.store.entry("Example.burp")
        self.assertNotEqual(entry["phase"], "resident")
        self.assertFalse(entry["replay_disabled"])

    def test_resident_edits_are_never_replayed(self):
        with self.provider() as provider:
            self.hydrate_once(provider)
        edited = b"local edit" + self.data
        with open(self.placeholder, "wb") as out:
            out.write(edited)
        self.api.files[_norm(self.placeholder)]["modified"] = True
        transfers = self.names().count("transfer")
        with self.provider() as provider:
            self.api.done.clear()
            self.api.request(self.placeholder, file_size=len(edited))
            self.assertTrue(self.api.done.wait(30))
        self.assertEqual(self.names().count("transfer"), transfers)
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), edited)

    def test_wrong_identity_or_size_is_refused(self):
        with self.provider():
            self.api.done.clear()
            self.api.request(self.placeholder, identity=b"BZCFFILE-foreign")
            self.assertTrue(self.api.done.wait(10))
            self.api.done.clear()
            self.api.request(self.placeholder, file_size=self.entry["size"] + 1)
            self.assertTrue(self.api.done.wait(10))
        self.assertEqual(self.names().count("fail"), 2)
        self.assertNotIn("transfer", self.names())

    def test_deadline_fails_request_without_ack(self):
        self.api.transfer_delay = 0.6
        with self.provider(deadline=1) as provider:
            self.hydrate_once(provider)
        self.assertNotIn("ack", self.names())
        self.assertIn("fail", self.names())
        self.assertFalse(self.store.entry("Example.burp")["replay_disabled"])

    def test_cancel_stops_hydration(self):
        self.api.transfer_delay = 0.3
        with self.provider() as provider:
            self.api.done.clear()
            req = self.api.request(self.placeholder)
            time.sleep(0.5)
            self.api.callback(cf.Request(event="cancel", path=req.path, identity=req.identity,
                                         connection=req.connection, transfer=req.transfer,
                                         request_key=req.request_key, offset=0, length=req.length,
                                         file_size=req.file_size))
            deadline = time.monotonic() + 30
            while provider._queue.unfinished_tasks and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertNotIn("ack", self.names())
        self.assertNotEqual(self.store.entry("Example.burp")["phase"], "resident")

    def test_root_identity_mismatch_refuses_start(self):
        self.api.roots[_norm(self.root)] = cf.root_identity(
            "00000000-0000-4000-8000-000000000000", self.api.file_id(self.root))
        with self.assertRaises(cf.NativeError):
            self.provider().start()
        self.assertNotIn("connect", self.names())

    def test_materialize_hydrates_missing_projects(self):
        result = np.materialize_root(self.store, api=self.api)
        self.assertEqual(result["status"], "materialized")
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), self.data)
        self.assertNotIn("unregister", self.names())

    def test_snapshot_export_restores_historical_import(self):
        dest = os.path.join(os.path.dirname(self.root), "exported.burp")
        result = np.export_project(self.store, "Example.burp", dest, current=False, api=self.api)
        self.assertEqual(result["status"], "exported-imported-snapshot")
        with open(dest, "rb") as source:
            self.assertEqual(source.read(), self.data)
        self.assertNotIn("hydrate", self.names())
        self.assertEqual(os.path.getsize(self.placeholder), 0)

    def test_current_export_refused_without_hydrating(self):
        dest = os.path.join(os.path.dirname(self.root), "current.burp")
        with self.assertRaises(cf.NativeError):
            np.export_project(self.store, "Example.burp", dest, current=True, api=self.api)
        self.assertFalse(os.path.exists(dest))
        self.assertNotIn("hydrate", self.names())
        with self.assertRaises(cf.NativeError):
            np.export_project(self.store, "Example.burp", dest, current="yes", api=self.api)

    def test_export_never_overwrites(self):
        dest = os.path.join(os.path.dirname(self.root), "taken.burp")
        with open(dest, "wb") as out:
            out.write(b"keep")
        with self.assertRaises(cf.NativeError):
            np.export_project(self.store, "Example.burp", dest, current=False, api=self.api)
        with open(dest, "rb") as source:
            self.assertEqual(source.read(), b"keep")

    def test_detach_reverts_but_never_unregisters(self):
        with self.assertRaises(cf.NativeError) as caught:
            np.detach_root(self.store, api=self.api)
        self.assertIn("Registration and archive store retained", str(caught.exception))
        self.assertIn("revert", self.names())
        self.assertNotIn("unregister", self.names())
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), self.data)
        self.assertEqual(self.store.entry("Example.burp")["phase"], "reverted")
        self.assertTrue(os.path.exists(os.path.join(self.store_dir, self.entry["archive_rel"])))

    def test_serve_root_disconnects_on_stop_and_retains_registration(self):
        stop = threading.Event()
        result = {}
        thread = threading.Thread(target=lambda: result.update(
            np.serve_root(self.store, api=self.api, stop_event=stop)))
        thread.start()
        deadline = time.monotonic() + 10
        while self.api.callback is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.api.done.clear()
        self.api.request(self.placeholder)
        self.assertTrue(self.api.done.wait(60))
        stop.set()
        thread.join(30)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, {"status": "disconnected", "registration_retained": True})
        self.assertIn("disconnect", self.names())
        self.assertIn(_norm(self.root), self.api.roots)

    def test_failed_hydration_can_be_retried_in_same_session(self):
        self.api.corrupt_retrieve = True
        with self.provider() as provider:
            self.hydrate_once(provider)
            self.assertEqual(self.store.entry("Example.burp")["phase"], "transferred")
            self.assertNotIn("ack", self.names())
            self.api.corrupt_retrieve = False
            self.hydrate_once(provider)
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), self.data)
        self.assertEqual(self.store.entry("Example.burp")["phase"], "resident")

    def test_jobs_are_retired_so_limit_is_per_concurrent_job(self):
        # With a one-job limit, two failed attempts must not block a third.
        with mock.patch.object(np, "MAX_JOBS", 1):
            with self.provider() as provider:
                self.api.corrupt_retrieve = True
                self.hydrate_once(provider)
                self.hydrate_once(provider)
                self.api.corrupt_retrieve = False
                self.hydrate_once(provider)
                self.assertEqual(provider._jobs, {})
        self.assertEqual(self.store.entry("Example.burp")["phase"], "resident")
        self.assertFalse(any("job limit" in e for e in provider.errors))

    def test_late_validation_after_residency_is_acknowledged(self):
        with self.provider() as provider:
            self.hydrate_once(provider)
            acks = self.names().count("ack")
            self.api.done.clear()
            self.api.request(self.placeholder, event="validate")
            self.assertTrue(self.api.done.wait(10))
            self.assertEqual(self.names().count("ack"), acks + 1)
            transfers, fails = self.names().count("transfer"), self.names().count("fail")
            self.api.done.clear()
            self.api.request(self.placeholder)  # a late fetch must not replay
            self.assertTrue(self.api.done.wait(10))
        self.assertEqual(self.names().count("transfer"), transfers)
        self.assertEqual(self.names().count("fail"), fails + 1)

    def test_edited_project_survives_status_materialize_and_detach(self):
        with self.provider() as provider:
            self.hydrate_once(provider)
        edited = self.data + b"local edit"
        with open(self.placeholder, "ab") as out:
            out.write(b"local edit")
        self.api.files[_norm(self.placeholder)]["modified"] = True
        status = self.store.status()
        self.assertEqual(status["errors"], [])
        self.assertTrue(status["files"][0]["resident"])
        transfers = self.names().count("transfer")
        np.materialize_root(self.store, api=self.api)
        self.assertEqual(self.names().count("transfer"), transfers)
        with self.assertRaises(cf.NativeError):
            np.detach_root(self.store, api=self.api)
        self.assertEqual(self.store.entry("Example.burp")["phase"], "reverted")
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), edited)
        self.assertEqual(self.store.status()["errors"], [])

    # ----- re-zip after close -------------------------------------------------------
    def edit_resident(self, extra=b"burp saved more data"):
        with self.provider() as provider:
            self.hydrate_once(provider)
        with open(self.placeholder, "ab") as out:
            out.write(extra)
        self.api.files[_norm(self.placeholder)]["modified"] = True
        return self.data + extra

    def test_rezip_keeps_edits_and_reopens_them(self):
        edited = self.edit_resident()
        old = self.store.entry("Example.burp")
        result = np.rezip_project(self.store, "Example.burp", api=self.api, level=1)
        self.assertEqual(result["status"], "rezipped")
        self.assertEqual(result["size"], len(edited))
        new = self.store.entry("Example.burp")
        self.assertNotEqual(new["logical_file_id"], old["logical_file_id"])
        self.assertEqual((new["phase"], new["replay_disabled"], new["size"]), ("placeholder", False, len(edited)))
        self.assertEqual(new["file_id"], old["file_id"])
        self.assertEqual(os.path.getsize(self.placeholder), 0)
        self.assertFalse(os.path.exists(os.path.join(self.store_dir, old["archive_rel"])))
        self.assertTrue(os.path.exists(os.path.join(self.store_dir, new["archive_rel"])))
        reopened = ns.NativeStore(self.store_dir, api=self.api)  # journal/catalog still valid
        with np.NativeProvider(reopened, self.api, 60) as provider:
            self.api.done.clear()
            self.api.request(self.placeholder)
            self.assertTrue(self.api.done.wait(60))
            while provider._queue.unfinished_tasks:
                time.sleep(0.02)
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), edited)
        self.assertEqual(reopened.entry("Example.burp")["phase"], "resident")
        self.assertEqual(reopened.status()["errors"], [])

    def test_rezip_refused_while_in_use(self):
        self.edit_resident()
        self.api.in_use_paths.add(_norm(self.placeholder))
        before = self.store.entry("Example.burp")
        with self.assertRaises(cf.NativeError):
            np.rezip_project(self.store, "Example.burp", api=self.api, level=1)
        self.assertEqual(self.store.entry("Example.burp"), before)
        self.assertNotIn("dehydrate", self.names())

    def test_rezip_skips_a_project_that_was_never_unpacked(self):
        result = np.rezip_project(self.store, "Example.burp", api=self.api, level=1)
        self.assertEqual(result["status"], "skipped")
        self.assertNotIn("snapshot", self.names())

    def test_failed_dehydrate_abandons_new_generation_and_keeps_edits(self):
        edited = self.edit_resident()
        before = self.store.entry("Example.burp")
        self.api.fail_dehydrate = True
        with self.assertRaises(cf.NativeError):
            np.rezip_project(self.store, "Example.burp", api=self.api, level=1)
        after = ns.NativeStore(self.store_dir, api=self.api).entry("Example.burp")
        self.assertEqual(after["logical_file_id"], before["logical_file_id"])
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), edited)
        self.assertTrue(os.path.exists(os.path.join(self.store_dir, before["archive_rel"])))

    def test_idle_sweep_respects_cutoff(self):
        self.edit_resident()
        self.assertEqual(np.rezip_idle(self.store, api=self.api, idle_days=10), [])
        # Just unpacked, but the project's own edit date is months old (like a
        # real archived project): it must NOT look idle.
        old = time.time() - 60 * 86400
        os.utime(self.placeholder, (old, old))
        self.assertEqual(np.rezip_idle(self.store, api=self.api, idle_days=10), [])
        # Eleven days after it was unpacked, with no saves since: idle.
        later = time.time() + 11 * 86400
        with mock.patch.object(np.time, "time", return_value=later):
            done = np.rezip_idle(self.store, api=self.api, idle_days=10)
        self.assertEqual([d["status"] for d in done], ["rezipped"])

    def test_hydration_re_marks_always_full(self):
        with self.provider() as provider:
            self.hydrate_once(provider)
        self.assertIn("always-full", self.names())

    # ----- option B: ask when Burp closes a changed project ---------------------------
    def watcher(self, answer):
        busy = {"value": False}
        asked = []

        def ask(name, size):
            asked.append((name, size))
            return answer
        w = np.CloseWatcher(self.store, in_use=lambda path: busy["value"], ask=ask)
        return w, busy, asked

    def open_edit_close(self, w, busy, change=True):
        w.poll()                        # baseline: not open
        busy["value"] = True
        w.poll()                        # Burp opened it
        if change:
            later = time.time() + 5
            os.utime(self.placeholder, (later, later))   # Burp saved
        busy["value"] = False
        w.poll()                        # Burp closed it
        if w._asker is not None:
            w._asker.join(5)

    def test_close_after_edit_asks_and_yes_rezips(self):
        edited = self.edit_resident()
        w, busy, asked = self.watcher(True)
        self.open_edit_close(w, busy)
        self.assertEqual(asked, [("Example.burp", len(edited))])
        done = np.handle_close_answers(self.store, w, api=self.api, level=1)
        self.assertEqual([d["status"] for d in done], ["rezipped"])
        self.assertEqual(os.path.getsize(self.placeholder), 0)

    def test_close_without_changes_does_not_ask(self):
        self.edit_resident()
        w, busy, asked = self.watcher(True)
        self.open_edit_close(w, busy, change=False)
        self.assertEqual(asked, [])

    def test_no_keeps_project_unpacked(self):
        edited = self.edit_resident()
        w, busy, asked = self.watcher(False)
        self.open_edit_close(w, busy)
        done = np.handle_close_answers(self.store, w, api=self.api)
        self.assertEqual([d["status"] for d in done], ["kept"])
        with open(self.placeholder, "rb") as source:
            self.assertEqual(source.read(), edited)
        self.assertNotIn("dehydrate", self.names())

    def test_default_probe_comes_from_the_adapter(self):
        self.edit_resident()
        w = np.CloseWatcher(self.store, ask=lambda name, size: True)
        self.assertFalse(w.in_use(self.placeholder))
        self.api.in_use_paths.add(_norm(self.placeholder))
        self.assertTrue(w.in_use(self.placeholder))

    def test_stop_waits_for_an_open_question(self):
        asking = {"value": True}

        class Watcher:
            def __init__(self, store, **kwargs):
                pass

            def poll(self):
                pass

            def asking(self):
                return asking["value"]

            def answers(self):
                return []
        done = threading.Event()

        def serve():
            np.serve_root(self.store, api=self.api, idle_days=0, ask_on_close=True)
            done.set()
        with mock.patch.object(np, "CloseWatcher", Watcher):
            thread = threading.Thread(target=serve)
            thread.start()
            deadline = time.monotonic() + 10
            while self.api.callback is None and time.monotonic() < deadline:
                time.sleep(0.02)
            np.request_stop(self.store_dir)
            self.assertFalse(done.wait(2), "stopped while a re-zip question was open")
            asking["value"] = False
            self.assertTrue(done.wait(10), "did not stop after the question was answered")
            thread.join(10)
        self.assertFalse(os.path.exists(os.path.join(self.store_dir, np.STOP_REQUEST)))
        with open(os.path.join(self.store_dir, np.SERVE_LOG), encoding="utf-8") as log:
            self.assertIn("waiting for the open re-zip question", log.read())

    def test_zipped_projects_are_never_asked_about(self):
        w, busy, asked = self.watcher(True)
        self.open_edit_close(w, busy)
        self.assertEqual(asked, [])

    def test_invalid_deadline_rejected(self):
        for value in (0, 86401, 1.5, True):
            with self.assertRaises(cf.NativeError):
                np.NativeProvider(self.store, self.api, value)


if __name__ == "__main__":
    unittest.main()
