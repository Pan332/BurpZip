"""Adapter tests that never register, create, hydrate or revert anything.

Mutation tests inject recording fake DLLs; the only real native calls are
nonhydrating metadata queries on ordinary temp files.
"""
from __future__ import annotations

import ctypes
import os
import re
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import native_cfapi as cf

ROOT_ID = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b"
FILE_ID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3"
SHA = "ab" * 32
SOURCE = Path(cf.__file__).read_text(encoding="utf-8")


class _Func:
    def __init__(self, log, name):
        self.log, self.name = log, name
        self.restype = self.argtypes = None

    def __call__(self, *args):
        self.log.append(self.name)
        return 0


class RecordingDll:
    def __init__(self):
        self.log: list[str] = []
        self._funcs: dict[str, _Func] = {}

    def __getattr__(self, name):
        if name.startswith("_") or name == "log":
            raise AttributeError(name)
        return self._funcs.setdefault(name, _Func(self.log, name))


class AbiTests(unittest.TestCase):
    @unittest.skipUnless(ctypes.sizeof(ctypes.c_void_p) == 8, "x64 layout table")
    def test_x64_layouts_match_checked_sdk_table(self):
        cf.verify_abi()

    def test_fixed_width_scalars(self):
        self.assertEqual(ctypes.sizeof(cf.DWORD), 4)
        self.assertEqual(ctypes.sizeof(cf.USHORT), 2)
        self.assertEqual(ctypes.sizeof(cf.WCHAR), 2)
        self.assertEqual(ctypes.sizeof(cf.CF_CONNECTION_KEY), 8)
        self.assertEqual(ctypes.sizeof(cf.HRESULT), 4)

    def test_documented_policy_constants(self):
        self.assertEqual(cf.CF_HYDRATION_POLICY_FULL, 2)
        self.assertEqual(cf.CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED, 1)
        self.assertEqual(cf.CF_POPULATION_POLICY_ALWAYS_FULL, 3)
        self.assertEqual(cf.CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC, 0x2)
        self.assertEqual(cf.CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL, 0x8)
        self.assertEqual(cf.CF_CALLBACK_TYPE_NONE, 0xFFFFFFFF)
        self.assertEqual(cf.CF_EOF, -1)

    def test_failure_statuses_are_signed_ntstatus(self):
        self.assertEqual(cf.STATUS_CLOUD_FILE_UNSUCCESSFUL, -1073688814)
        self.assertEqual(cf.STATUS_CLOUD_FILE_UNSUCCESSFUL & 0xFFFFFFFF, 0xC000CF12)
        self.assertEqual(cf.STATUS_CLOUD_FILE_REQUEST_CANCELED & 0xFFFFFFFF, 0xC000CF1B)

    def test_hresult_check(self):
        cf._check_hr(0, "ok")
        cf._check_hr(1, "S_FALSE")
        with self.assertRaises(cf.NativeError):
            cf._check_hr(0x80070005, "denied")
        with self.assertRaises(cf.NativeError):
            cf._check_hr(ctypes.c_int32(-2147024891), "denied")


class IdentityTests(unittest.TestCase):
    def test_root_identity_round_trip(self):
        blob = cf.root_identity(ROOT_ID, "0000abcd:00000000000000ff")
        decoded = cf.decode_root_identity(blob)
        self.assertEqual(decoded["root_id"], ROOT_ID)
        self.assertEqual(decoded["root_file_id"], "0000abcd:00000000000000ff")

    def test_file_identity_round_trip_binds_root_file_and_archive(self):
        blob = cf.file_identity(ROOT_ID, FILE_ID, SHA)
        decoded = cf.decode_file_identity(blob)
        self.assertEqual((decoded["root_id"], decoded["file_id"], decoded["archive_sha256"]),
                         (ROOT_ID, FILE_ID, SHA))
        other = cf.file_identity(ROOT_ID, FILE_ID, "cd" * 32)
        self.assertNotEqual(blob, other)

    def test_malformed_identities_rejected(self):
        blob = cf.file_identity(ROOT_ID, FILE_ID, SHA)
        for bad in (b"", blob[:-1], b"BZCFROOT" + blob[8:], blob + b"x", "text"):
            with self.assertRaises(cf.NativeError):
                cf.decode_file_identity(bad)
        root = cf.root_identity(ROOT_ID, "vol:file")
        for bad in (root[:-1], root[:8] + b"\x02\x00" + root[10:], b"BZCFFILE" + root[8:]):
            with self.assertRaises(cf.NativeError):
                cf.decode_root_identity(bad)

    def test_nil_or_invalid_uuid_and_sha_rejected(self):
        with self.assertRaises(cf.NativeError):
            cf.root_identity(str(uuid.UUID(int=0)), "vol:file")
        with self.assertRaises(cf.NativeError):
            cf.root_identity("not-a-uuid", "vol:file")
        with self.assertRaises(cf.NativeError):
            cf.root_identity(ROOT_ID, "")
        with self.assertRaises(cf.NativeError):
            cf.file_identity(ROOT_ID, FILE_ID, "zz" * 32)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.cfapi, self.kernel = RecordingDll(), RecordingDll()
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-native-test-gate-")
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def test_release_gate_is_a_strict_bool(self):
        self.assertIsInstance(cf.NATIVE_RELEASE_READY, bool)

    @mock.patch.object(cf, "NATIVE_RELEASE_READY", False)
    def test_default_adapter_blocks_every_mutation_before_dll_calls(self):
        api = cf.WindowsCfApi(cfapi=self.cfapi, kernel32=self.kernel)
        identity = cf.root_identity(ROOT_ID, "vol:file")
        request = cf.Request(path=os.path.join(self.root, "x.burp"))
        attempts = [
            lambda: api.register(self.root, identity),
            lambda: api.create(self.root, "x.burp", 1, 0.0, cf.file_identity(ROOT_ID, FILE_ID, SHA)),
            lambda: api.connect(self.root, lambda r: None),
            lambda: api.transfer(request, 0, b"x"),
            lambda: api.ack(request, 0, 1),
            lambda: api.hydrate(os.path.join(self.root, "x.burp")),
            lambda: api.revert(os.path.join(self.root, "x.burp")),
        ]
        for attempt in attempts:
            with self.assertRaises(cf.NativeError):
                attempt()
        self.assertEqual(self.cfapi.log, [])
        self.assertEqual(self.kernel.log, [])

    def test_test_mode_confined_to_dedicated_temp_roots(self):
        api = cf.WindowsCfApi(test_mode=True, cfapi=self.cfapi, kernel32=self.kernel)
        outside = os.path.join(os.path.expanduser("~"), "burpzip-native-test-x")
        for bad in (tempfile.gettempdir(), outside,
                    os.path.join(tempfile.gettempdir(), "not-burpzip-root")):
            with self.assertRaises(cf.NativeError):
                api._mutation(bad)
        self.assertEqual(self.cfapi.log, [])

    def test_current_export_is_explicitly_unsupported(self):
        api = cf.WindowsCfApi(test_mode=True, cfapi=self.cfapi, kernel32=self.kernel)
        with self.assertRaises(cf.NativeError):
            api.export_current(os.path.join(self.root, "x.burp"), os.path.join(self.root, "y.burp"))
        self.assertFalse(os.path.exists(os.path.join(self.root, "y.burp")))
        self.assertFalse(getattr(api, "CURRENT_EXPORT_SUPPORTED", False))

    def test_no_unregister_or_dehydrate_binding_exists(self):
        self.assertIsNone(re.search(r"CfUnregisterSyncRoot|CfDehydratePlaceholder", SOURCE))
        self.assertFalse(hasattr(cf.WindowsCfApi, "unregister"))
        self.assertFalse(hasattr(cf.WindowsCfApi, "dehydrate"))

    def test_dlls_load_only_from_system32(self):
        self.assertIn('WinDLL("CldApi.dll", use_last_error=True, winmode=0x800)', SOURCE)


class RequestTests(unittest.TestCase):
    def test_request_is_immutable_owned_data(self):
        req = cf.Request(event="fetch", path="C:\\r\\x.burp", identity=b"id", connection=1,
                         transfer=2, request_key=3, offset=0, length=10, file_size=10)
        with self.assertRaises(Exception):
            req.offset = 5
        self.assertIsInstance(req.identity, bytes)

    def test_signed_keys_accept_full_64bit_range(self):
        self.assertEqual(cf._signed64(0xFFFFFFFFFFFFFFFF), -1)
        for bad in (True, 1 << 64, -(1 << 63) - 1, 1.0):
            with self.assertRaises(cf.NativeError):
                cf._signed64(bad)


@unittest.skipUnless(os.name == "nt", "nonhydrating Windows metadata queries")
class ClassificationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="burpzip-classify-test-")
        self.addCleanup(tmp.cleanup)
        self.base = tmp.name

    def test_ordinary_file_and_folder(self):
        path = os.path.join(self.base, "Example.burp")
        with open(path, "wb") as out:
            out.write(b"synthetic")
        self.assertEqual(cf.classify_path(path).kind, "ordinary")
        self.assertEqual(cf.classify_path(self.base).kind, "ordinary")
        cf.require_ordinary_path(path)

    def test_store_marker_ancestry_is_protected(self):
        store = os.path.join(self.base, "store")
        os.makedirs(os.path.join(store, "archives"))
        with open(os.path.join(store, cf.STORE_MARKER), "wb"):
            pass
        inner = os.path.join(store, "archives", "import.burpz")
        with open(inner, "wb") as out:
            out.write(b"x")
        self.assertEqual(cf.classify_path(inner).kind, "store")
        with self.assertRaises(cf.NativeError):
            cf.require_ordinary_path(inner)

    def test_project_below_a_junction_stays_ordinary(self):
        import _winapi
        target = os.path.join(self.base, "target")
        os.mkdir(target)
        link = os.path.join(self.base, "link")
        _winapi.CreateJunction(target, link)
        self.addCleanup(os.rmdir, link)
        path = os.path.join(link, "Example.burp")
        with open(path, "wb") as out:
            out.write(b"synthetic")
        self.addCleanup(os.remove, path)
        self.assertEqual(cf.classify_path(path).kind, "ordinary")
        self.assertEqual(cf.classify_path(link).kind, "unknown")

    def test_store_folder_refused_as_sync_root_candidate(self):
        store = os.path.join(self.base, "store")
        os.mkdir(store)
        with open(os.path.join(store, cf.STORE_MARKER), "wb"):
            pass
        with self.assertRaises(cf.NativeError):
            cf.WindowsCfApi().inspect_root(store)

    def test_missing_path_classified_without_creating_it(self):
        missing = os.path.join(self.base, "absent", "New.burp")
        state = cf.classify_path(missing)
        self.assertIn(state.kind, ("ordinary", "unknown"))
        self.assertFalse(os.path.exists(os.path.dirname(missing)))


if __name__ == "__main__":
    unittest.main()
