"""Provider-control helpers shared by the CLI and GUI (no real provider is launched)."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import archiver as ar
import burpzip as bz
import native_store as ns
from test_native_provider import FakeCfApi


class StorePathTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-native-cli-test-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def test_native_store_path_requires_a_marker(self):
        store = self.base / "store"
        store.mkdir()
        with mock.patch.object(bz, "DEFAULT_NATIVE_STORE", self.base / "absent"):
            self.assertIsNone(bz.native_store_path(store))
            (store / ns.MARKER).write_text("{}", encoding="utf-8")
            self.assertEqual(bz.native_store_path(store), Path(os.path.abspath(store)))
            self.assertIsNone(bz.native_store_path(None))
        with mock.patch.object(bz, "DEFAULT_NATIVE_STORE", store):
            self.assertEqual(bz.native_store_path(None), Path(os.path.abspath(store)))

    def test_provider_not_running_without_lockfile(self):
        self.assertFalse(bz.provider_running(self.base))

    def test_stop_is_a_noop_when_not_running(self):
        with mock.patch("native_provider.request_stop") as request:
            self.assertFalse(bz.stop_provider(self.base))
        request.assert_not_called()

    def test_paused_provider_restarts_only_if_it_was_running(self):
        for was_running in (True, False):
            with mock.patch.object(bz, "stop_provider", return_value=was_running), \
                    mock.patch.object(bz, "start_provider") as start:
                with bz.paused_provider(self.base):
                    start.assert_not_called()
            self.assertEqual(start.called, was_running)

    def test_paused_provider_restarts_after_a_failure(self):
        with mock.patch.object(bz, "stop_provider", return_value=True), \
                mock.patch.object(bz, "start_provider") as start:
            with self.assertRaises(RuntimeError):
                with bz.paused_provider(self.base):
                    raise RuntimeError("import failed")
        start.assert_called_once()

    def test_remove_verified_input_only_deletes_identical_bytes(self):
        archive = self.base / "x.burpz"
        archive.write_bytes(b"verified bytes")
        good = {"archive_sha256": hashlib.sha256(b"verified bytes").hexdigest()}
        bad = {"archive_sha256": "00" * 32}
        self.assertFalse(bz.remove_verified_input(archive, bad))
        self.assertTrue(archive.exists())
        self.assertTrue(bz.remove_verified_input(archive, good))
        self.assertFalse(archive.exists())

    def test_autostart_shortcut_lives_in_the_users_startup_folder(self):
        with mock.patch.dict(os.environ, {"APPDATA": str(self.base)}):
            shortcut = bz._startup_shortcut()
            self.assertEqual(shortcut.parent, self.base / "Microsoft" / "Windows" / "Start Menu"
                             / "Programs" / "Startup")
            self.assertFalse(bz.autostart_enabled())
            shortcut.parent.mkdir(parents=True)
            shortcut.write_bytes(b"lnk")
            self.assertTrue(bz.autostart_enabled())
            bz.set_autostart(self.base, False)
            self.assertFalse(shortcut.exists())


@unittest.skipUnless(os.name == "nt" and ar.SEVEN_ZIP, "requires Windows and 7-Zip")
class LeaseDetectionTests(unittest.TestCase):
    def test_provider_running_reflects_a_held_store_lease(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-native-cli-test-")
        self.addCleanup(tmp.cleanup)
        root, store = Path(tmp.name, "root"), Path(tmp.name, "store")
        root.mkdir()
        store.mkdir()
        api = FakeCfApi()
        ns.init_root(str(root), str(store), api=api)
        native = ns.NativeStore(str(store), api=api)
        self.assertFalse(bz.provider_running(store))
        with native.lease():
            self.assertTrue(bz.provider_running(store))
        self.assertFalse(bz.provider_running(store))


if __name__ == "__main__":
    unittest.main()
