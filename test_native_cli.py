"""Provider-control helpers shared by the CLI and GUI (no real provider is launched)."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest

import testenv  # noqa: F401  (isolated burpzip.ini)
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


class ProviderModeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-native-cli-test-")
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name)

    def apply(self, mode):
        with mock.patch.object(bz, "set_autostart") as auto, \
                mock.patch.object(bz, "set_burp_shortcuts", return_value=[Path("D:/x.lnk")]) as links, \
                mock.patch.object(bz, "start_provider", return_value=True) as start:
            result = bz.apply_provider_mode(self.store, mode)
        return result, auto, links, start

    def test_logon_mode(self):
        result, auto, links, start = self.apply("logon")
        auto.assert_called_once_with(self.store, True)
        links.assert_called_once_with(False)
        start.assert_called_once()
        self.assertTrue(result["autostart_at_logon"])

    def test_with_burp_mode(self):
        result, auto, links, start = self.apply("with-burp")
        auto.assert_called_once_with(self.store, False)
        links.assert_called_once_with(True)
        start.assert_not_called()
        self.assertEqual(result["burp_shortcuts"], [str(Path("D:/x.lnk"))])

    def test_manual_mode_and_invalid(self):
        result, auto, links, start = self.apply("manual")
        auto.assert_called_once_with(self.store, False)
        links.assert_called_once_with(False)
        start.assert_not_called()
        with self.assertRaises(bz.CliUsageError):
            bz.apply_provider_mode(self.store, "sometimes")


class RunWithBurpTests(unittest.TestCase):
    BURP = r"C:\Burp\BurpSuitePro.exe"

    def run_burp(self, mode, started, running):
        import config
        settings = {**config.defaults(), "provider": mode}
        with mock.patch.object(bz, "_config", return_value=settings), \
                mock.patch.object(bz, "native_store_path", return_value=Path("S:/store")), \
                mock.patch.object(bz, "start_provider", return_value=started), \
                mock.patch.object(bz, "burp_running", side_effect=running), \
                mock.patch("launcher.find_burp", return_value=[self.BURP]), \
                mock.patch.object(bz.subprocess, "Popen") as popen, \
                mock.patch.object(bz.time, "sleep"), \
                mock.patch("native_provider.request_stop") as stop:
            result = bz.run_with_burp(poll=0, settle=0)
        return result, popen, stop

    def test_with_burp_starts_waits_and_stops(self):
        result, popen, stop = self.run_burp("with-burp", True, [False, True, True, True, False])
        popen.assert_called_once()
        self.assertEqual(popen.call_args[0][0], [self.BURP])
        stop.assert_called_once()
        self.assertTrue(result["provider_stop_requested"])

    def test_never_stops_a_provider_it_did_not_start(self):
        _, _, stop = self.run_burp("with-burp", False, [True, False])
        stop.assert_not_called()

    def test_logon_mode_keeps_provider_running(self):
        _, _, stop = self.run_burp("logon", True, [True, False])
        stop.assert_not_called()


class EnsureConfigTests(unittest.TestCase):
    def test_skipped_when_config_is_redirected(self):
        self.assertTrue(os.environ.get("BURPZIP_CONFIG"))
        with mock.patch.object(bz, "native_store_path") as find:
            self.assertIsNone(bz.ensure_config())
        find.assert_not_called()


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
