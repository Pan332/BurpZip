"""Native store tests: real 7-Zip, real journal/catalog, simulated CFAPI."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest

import testenv  # noqa: F401  (isolated burpzip.ini)
from collections import namedtuple
from unittest import mock

import archiver as ar
import native_cfapi as cf
import native_store as ns
from test_native_provider import FakeCfApi, _sha

Usage = namedtuple("Usage", "total used free")


@unittest.skipUnless(os.name == "nt" and ar.SEVEN_ZIP, "requires Windows and 7-Zip")
class StoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-native-store-test-")
        self.addCleanup(tmp.cleanup)
        self.base = tmp.name
        self.source = os.path.join(self.base, "source")
        self.root = os.path.join(self.base, "root")
        self.store_dir = os.path.join(self.base, "store")
        for folder in (self.source, self.root, self.store_dir):
            os.mkdir(folder)
        self.api = FakeCfApi()
        self.api.store_path = self.store_dir

    def calls(self):
        return [call[0] for call in self.api.calls]

    def make_archive(self, name="Example.burp", size=256 * 1024):
        project = os.path.join(self.source, name)
        with open(project, "wb") as out:
            out.write(os.urandom(size // 4) + b"\0" * (size - size // 4))
        return ar.archive_project(project, level=0, threads=1, delete_original=False).archive_path

    def init(self):
        return ns.init_root(self.root, self.store_dir, api=self.api)

    def imported(self):
        self.init()
        archive = self.make_archive()
        entry = ns.add_archive(self.store_dir, archive, api=self.api)
        return archive, entry, ns.NativeStore(self.store_dir, api=self.api)

    # -- init -----------------------------------------------------------
    def test_init_registers_new_empty_root_with_owned_identity(self):
        catalog = self.init()
        self.assertEqual(catalog["state"], "registered")
        self.assertEqual(self.calls(), ["register"])
        owned = cf.decode_root_identity(bytes.fromhex(catalog["root_identity"]))
        self.assertEqual(owned["root_id"], catalog["root_id"])

    def test_init_refuses_nonempty_overlapping_or_reused_folders(self):
        with open(os.path.join(self.root, "existing.burp"), "wb"):
            pass
        with self.assertRaises(cf.NativeError):
            self.init()
        os.remove(os.path.join(self.root, "existing.burp"))
        nested = os.path.join(self.root, "store")
        os.mkdir(nested)
        with self.assertRaises(cf.NativeError):
            ns.init_root(self.root, nested, api=self.api)
        os.rmdir(nested)
        with self.assertRaises(cf.NativeError):
            ns.init_root(self.root, self.root, api=self.api)
        self.init()
        other = os.path.join(self.base, "other-root")
        os.mkdir(other)
        with self.assertRaises(cf.NativeError):
            ns.init_root(other, self.store_dir, api=self.api)
        self.assertEqual(self.calls(), ["register"])

    # -- import ---------------------------------------------------------
    def test_import_preserves_input_and_creates_placeholder(self):
        self.init()
        archive = self.make_archive()
        before = _sha(archive)
        entry = ns.add_archive(self.store_dir, archive, api=self.api)
        self.assertEqual(_sha(archive), before)
        self.assertEqual(entry["archive_sha256"], before)
        self.assertEqual(entry["phase"], "placeholder")
        self.assertTrue(os.path.exists(os.path.join(self.root, "Example.burp")))
        self.assertEqual(_sha(os.path.join(self.store_dir, entry["archive_rel"])), before)

    def test_import_refuses_corrupt_non_burpz_and_duplicate(self):
        self.init()
        junk = os.path.join(self.source, "junk.burpz")
        with open(junk, "wb") as out:
            out.write(b"not a 7z archive")
        with self.assertRaises((cf.NativeError, ar.ArchiveError)):
            ns.add_archive(self.store_dir, junk, api=self.api)
        plain = os.path.join(self.source, "plain.7z")
        with open(plain, "wb") as out:
            out.write(b"x")
        with self.assertRaises(cf.NativeError):
            ns.add_archive(self.store_dir, plain, api=self.api)
        archive = self.make_archive()
        ns.add_archive(self.store_dir, archive, api=self.api)
        with self.assertRaises(cf.NativeError):
            ns.add_archive(self.store_dir, archive, api=self.api)
        self.assertEqual(self.calls().count("create"), 1)

    def test_import_refuses_foreign_root_entries(self):
        self.init()
        with open(os.path.join(self.root, "Stray.burp"), "wb"):
            pass
        with self.assertRaises(cf.NativeError):
            ns.add_archive(self.store_dir, self.make_archive(), api=self.api)
        self.assertNotIn("create", self.calls())

    # -- tamper detection -----------------------------------------------
    def test_tampered_manifest_blocks_reload(self):
        _, entry, _ = self.imported()
        manifest = os.path.join(self.store_dir, "archives", entry["logical_file_id"], "manifest.json")
        with open(manifest, "rb") as source:
            data = json.loads(source.read())
        data["size"] += 1
        os.chmod(manifest, 0o600)
        with open(manifest, "w", encoding="utf-8") as out:
            json.dump(data, out)
        with self.assertRaises(cf.NativeError):
            ns.NativeStore(self.store_dir, api=self.api)

    def test_tampered_catalog_blocks_reload(self):
        self.imported()
        marker = os.path.join(self.store_dir, ns.MARKER)
        with open(marker, "rb") as source:
            catalog = json.loads(source.read())
        next(iter(catalog["files"].values()))["payload_sha256"] = "00" * 32
        with open(marker, "w", encoding="utf-8") as out:
            json.dump(catalog, out)
        with self.assertRaises(cf.NativeError):
            ns.NativeStore(self.store_dir, api=self.api)

    # -- phases ---------------------------------------------------------
    def test_ack_intent_requires_verified_payload(self):
        _, entry, store = self.imported()
        with self.assertRaises(cf.NativeError):
            store.mark(entry, "ack-intent", verified_sha256="00" * 32,
                       verified_size=entry["size"], replay_disabled=True)
        with self.assertRaises(cf.NativeError):
            store.mark(entry, "ack-intent", verified_sha256=entry["payload_sha256"],
                       verified_size=entry["size"] + 1, replay_disabled=True)
        row = store.mark(entry, "ack-intent", verified_sha256=entry["payload_sha256"],
                         verified_size=entry["size"], replay_disabled=True)
        self.assertTrue(row["replay_disabled"])

    def test_replay_boundary_is_irreversible(self):
        _, entry, store = self.imported()
        row = store.mark(entry, "ack-intent", verified_sha256=entry["payload_sha256"],
                         verified_size=entry["size"], replay_disabled=True)
        for phase in ("placeholder", "staged", "transferred"):
            with self.assertRaises(cf.NativeError):
                store.mark(row, phase)
        with self.assertRaises(cf.NativeError):
            store.mark(row, "resident", replay_disabled=False)
        with self.assertRaises(cf.NativeError):
            store.mark(row, "resident", staging_path="C:\\elsewhere")
        reopened = ns.NativeStore(self.store_dir, api=self.api).entry("Example.burp")
        self.assertTrue(reopened["replay_disabled"])

    # -- lease / capacity / staging / status ---------------------------
    def test_second_instance_cannot_lease_while_held(self):
        _, _, store = self.imported()
        other = ns.NativeStore(self.store_dir, api=self.api)
        with store.lease():
            with self.assertRaises(cf.NativeError):
                with other.lease():
                    pass
        with other.lease():
            pass

    def test_staged_capacity_charges_only_destination(self):
        _, entry, store = self.imported()
        if store._volume(store._stage_parent()) != store._volume(self.root):
            self.skipTest("staging and root on different volumes")
        just_one = Usage(0, 0, entry["size"] + ns.SPACE_MARGIN + 1)
        with mock.patch.object(ns.shutil, "disk_usage", return_value=just_one):
            store.check_hydration_space(entry, staged=True)
            with self.assertRaises(cf.NativeError):
                store.check_hydration_space(entry)
        with self.assertRaises(cf.NativeError):
            store.check_hydration_space(entry, staged="yes")

    def test_staging_is_new_off_root_and_cleaned(self):
        _, entry, store = self.imported()
        with store.staging(entry) as stage:
            self.assertEqual(os.listdir(stage), [])
            for protected in (self.root, self.store_dir):
                self.assertNotEqual(os.path.commonpath([os.path.normcase(stage), os.path.normcase(protected)]),
                                    os.path.normcase(protected))
            with open(os.path.join(stage, "Example.burp"), "wb") as out:
                out.write(b"staged")
            self.assertEqual(len(store.catalog["staging"]), 1)
        self.assertFalse(os.path.exists(stage))
        self.assertEqual(store.catalog["staging"], [])

    def test_status_is_read_only(self):
        _, _, store = self.imported()
        revision = store.catalog["revision"]
        with open(os.path.join(self.store_dir, ns.JOURNAL), "rb") as source:
            journal = hashlib.sha256(source.read()).hexdigest()
        status = store.status()
        self.assertTrue(status["registered"])
        self.assertEqual(status["errors"], [])
        self.assertEqual(status["files"][0]["kind"], "native")
        self.assertFalse(status["files"][0]["ready"])
        self.assertEqual(ns.NativeStore(self.store_dir, api=self.api).catalog["revision"], revision)
        with open(os.path.join(self.store_dir, ns.JOURNAL), "rb") as source:
            self.assertEqual(hashlib.sha256(source.read()).hexdigest(), journal)

    def resident(self, store, entry):
        row = store.mark(entry, "ack-intent", verified_sha256=entry["payload_sha256"],
                         verified_size=entry["size"], replay_disabled=True)
        return store.mark(row, "resident")

    def test_rezip_generation_crash_recovery(self):
        archive, entry, store = self.imported()
        row = self.resident(store, entry)
        store.begin_rezip(row, archive)
        self.assertEqual(store.entry("Example.burp")["logical_file_id"], row["logical_file_id"])
        # Crash before the native switch: the file still has the OLD identity -> abandon.
        api_path = os.path.normcase(os.path.abspath(os.path.join(self.root, "Example.burp")))
        notes = ns.NativeStore(self.store_dir, api=self.api).recover_rezips()
        self.assertIn("abandoned", notes[0])
        self.assertEqual(ns.NativeStore(self.store_dir, api=self.api).entry("Example.burp")["logical_file_id"],
                         row["logical_file_id"])
        # Crash AFTER the native switch: the file has the NEW identity -> finish.
        again = ns.NativeStore(self.store_dir, api=self.api)
        new = again.begin_rezip(again.entry("Example.burp"), archive)
        self.api.files[api_path]["identity"] = bytes.fromhex(new["placeholder_identity"])
        notes = ns.NativeStore(self.store_dir, api=self.api).recover_rezips()
        self.assertIn("finished", notes[0])
        final = ns.NativeStore(self.store_dir, api=self.api)
        self.assertEqual(final.entry("Example.burp")["logical_file_id"], new["logical_file_id"])
        phases = sorted(r["phase"] for r in final.catalog["files"].values())
        self.assertEqual(phases, ["placeholder", "superseded", "superseded"])

    def test_rezip_requires_an_unpacked_project(self):
        archive, entry, store = self.imported()
        with self.assertRaises(cf.NativeError):
            store.begin_rezip(entry, archive)

    def test_tampered_pending_rezip_name_collision_rejected(self):
        archive, entry, store = self.imported()
        new = store.begin_rezip(self.resident(store, entry), archive)
        marker = os.path.join(self.store_dir, ns.MARKER)
        with open(marker, "rb") as source:
            catalog = json.loads(source.read())
        del catalog["files"][new["logical_file_id"]]["supersedes"]
        with open(marker, "w", encoding="utf-8") as out:
            json.dump(catalog, out)
        with self.assertRaises(cf.NativeError):
            ns.NativeStore(self.store_dir, api=self.api)

    def test_foreign_registration_reported_and_blocks_lease(self):
        _, _, store = self.imported()
        self.api.roots[os.path.normcase(os.path.abspath(self.root))] = cf.root_identity(
            "11111111-2222-4333-8444-555555555555", self.api.file_id(self.root))
        status = store.status()
        self.assertFalse(status["registered"])
        self.assertTrue(status["errors"])
        with self.assertRaises(cf.NativeError):
            with store.lease():
                pass


if __name__ == "__main__":
    unittest.main()
