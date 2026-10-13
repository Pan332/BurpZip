"""burpzip.ini: load/save, shareable paths, safe fallbacks."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import testenv  # noqa: F401  (isolated burpzip.ini)

import config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-config-test-")
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "burpzip.ini"

    def test_missing_file_gives_defaults(self):
        self.assertFalse(config.exists(self.path))
        self.assertEqual(config.load(self.path), config.defaults())

    def test_round_trip(self):
        home = os.path.expanduser("~")
        settings = config.defaults()
        settings.update(folder=os.path.join(home, "Downloads", "BurpProjects"),
                        store=os.path.join(home, "Downloads", "BurpProjects-store"),
                        provider="with-burp", ask_on_close=False, idle_days=0, days=30,
                        min_size_mb=250, level=9, burp_path=r"D:\Tools\BurpSuitePro.exe",
                        extra_folders=[os.path.join(home, "Desktop"), r"E:\Engagements"])
        config.save(settings, self.path)
        self.assertEqual(config.load(self.path), settings)

    def test_profile_paths_are_written_shareably(self):
        settings = config.defaults()
        settings["store"] = os.path.join(os.path.expanduser("~"), "Downloads", "BurpProjects-store")
        config.save(settings, self.path)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn(r"store = %USERPROFILE%\Downloads\BurpProjects-store", text)
        self.assertNotIn(os.path.expanduser("~"), text)
        self.assertTrue(text.startswith("; Burpzip settings"))

    def test_invalid_values_fall_back_to_defaults(self):
        self.path.write_text("[burp_folder]\nprovider = sometimes\nask_on_close = maybe\nidle_days = -3\n"
                             "[archive]\nlevel = 12\ndays = 0\nmin_size_mb = lots\n", encoding="utf-8")
        loaded = config.load(self.path)
        for key in ("provider", "ask_on_close", "idle_days", "level", "days", "min_size_mb"):
            self.assertEqual(loaded[key], config.DEFAULTS[key], key)

    def test_hand_edited_file_with_variables(self):
        self.path.write_text("[burp_folder]\nstore = %USERPROFILE%\\X-store\nprovider = manual\n"
                             "ask_on_close = no\n[archive]\nextra_folders =\n    C:\\One\n    C:\\Two\n",
                             encoding="utf-8")
        loaded = config.load(self.path)
        self.assertEqual(loaded["store"], os.path.join(os.path.expanduser("~"), "X-store"))
        self.assertEqual((loaded["provider"], loaded["ask_on_close"]), ("manual", False))
        self.assertEqual(loaded["extra_folders"], [r"C:\One", r"C:\Two"])

    def test_corrupt_file_does_not_crash(self):
        self.path.write_text("this is [not an ini\n= =\n", encoding="utf-8")
        self.assertEqual(config.load(self.path), config.defaults())

    def test_env_override_and_default_location(self):
        with mock.patch.dict(os.environ, {"BURPZIP_CONFIG": str(self.path)}):
            self.assertEqual(config.config_path(), self.path)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BURPZIP_CONFIG", None)
            self.assertEqual(config.config_path(), Path(config.__file__).resolve().with_name("burpzip.ini"))


if __name__ == "__main__":
    unittest.main()
