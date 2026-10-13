"""OPT-IN live Windows Cloud Files test (set BURPZIP_NATIVE_LIVE=1).

Registers ONE new sync root under %TEMP%\\burpzip-native-test-*, creates a
synthetic placeholder backed by a real 7-Zip archive, and opens it from a
separate process. Never touches real projects, never launches Burp, and never
unregisters (unregistration can delete placeholders); the registration and
folder are deliberately retained and printed for manual removal.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

import archiver as ar
import native_cfapi as cf
import native_provider as np
import native_store as ns

LIVE = os.environ.get("BURPZIP_NATIVE_LIVE") == "1"
READER = ("import hashlib, sys\n"
          "with open(sys.argv[1], 'rb') as f:\n"
          "    print(hashlib.sha256(f.read()).hexdigest())\n")
SAVER = ("import sys\n"
         "f = open(sys.argv[1], 'r+b')\n"
         "print('open', flush=True)\n"
         "sys.stdin.readline()\n"
         "f.seek(0, 2); f.write(b'saved by burp'); f.flush()\n"
         "print('saved', flush=True)\n"
         "sys.stdin.read()\n"
         "f.close()\n")
HOLDER = ("import sys, time\n"
          "f = open(sys.argv[1], 'r+b')\n"
          "print('held', flush=True)\n"
          "time.sleep(60)\n")
APPENDER = ("import sys\n"
            "with open(sys.argv[1], 'ab') as f:\n"
            "    f.write(b'local edit after hydration')\n")


def _child(code: str, path: str, timeout: int = 120) -> subprocess.CompletedProcess:
    # A separate process: the provider connects with BLOCK_SELF_IMPLICIT_HYDRATION.
    return subprocess.run([sys.executable, "-I", "-c", code, path], capture_output=True,
                          text=True, timeout=timeout, stdin=subprocess.DEVNULL)


def _log(message: str) -> None:
    print(f"[live] {message}", flush=True)


@unittest.skipUnless(LIVE and os.name == "nt" and ar.SEVEN_ZIP, "set BURPZIP_NATIVE_LIVE=1 (registers a temp sync root)")
class LiveNativeTest(unittest.TestCase):
    def test_first_open_hydrates_same_path_and_edits_stay_authoritative(self):
        base = os.path.join(tempfile.gettempdir(), f"burpzip-native-test-{uuid.uuid4().hex[:12]}")
        root, store_dir, source = (os.path.join(base, n) for n in ("root", "store", "source"))
        for folder in (base, root, store_dir, source):
            os.mkdir(folder)
        _log(f"base folder (retained): {base}")

        data = os.urandom(256 * 1024) + b"\0" * (768 * 1024) + os.urandom(333)  # non-4KiB EOF
        expected = hashlib.sha256(data).hexdigest()
        project = os.path.join(source, "LiveExample.burp")
        with open(project, "wb") as out:
            out.write(data)
        archive = ar.archive_project(project, level=1, threads=1, delete_original=False).archive_path

        api = cf.WindowsCfApi(test_mode=True)
        catalog = ns.init_root(root, store_dir, api=api)
        _log(f"registered sync root {root} id={catalog['root_id']}")
        info = api.inspect_root(root)
        self.assertTrue(info["owned"])
        self.assertEqual(info["policies"], {"hydration": 2, "hydration_modifier": 1, "population": 3, "hardlink": 0})

        entry = ns.add_archive(store_dir, archive, api=api)
        placeholder = os.path.join(root, "LiveExample.burp")
        state = api.inspect(placeholder)
        _log(f"placeholder created: kind={state.kind} size={state.size} ready={state.ready} "
             f"modified={state.modified}")
        self.assertEqual((state.kind, state.size, state.ready), ("native", len(data), False))
        self.assertEqual(entry["phase"], "placeholder")
        self.assertEqual(cf.classify_path(placeholder).kind, "native")
        with self.assertRaises(cf.NativeError):
            cf.require_ordinary_path(placeholder)

        # 1. Provider offline: a read must fail, not return wrong bytes.
        offline = _child(READER, placeholder, timeout=90)
        _log(f"offline read: rc={offline.returncode} {offline.stderr.strip().splitlines()[-1:]}")
        self.assertNotEqual(offline.returncode, 0)
        self.assertFalse(api.inspect(placeholder).ready)

        store = ns.NativeStore(store_dir, api=api)
        with np.NativeProvider(store, api, deadline_seconds=120) as provider:
            # 2. First open from another process hydrates the SAME path.
            started = time.monotonic()
            first = _child(READER, placeholder)
            _log(f"first read: rc={first.returncode} sha_ok={first.stdout.strip() == expected} "
                 f"in {time.monotonic() - started:.1f}s errors={provider.errors} "
                 f"native={getattr(provider._connection, 'errors', None)} stderr={first.stderr.strip()[-300:]}")
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout.strip(), expected)
            deadline = time.monotonic() + 30
            while store.entry("LiveExample.burp")["phase"] != "resident" and time.monotonic() < deadline:
                time.sleep(0.1)
            row = store.entry("LiveExample.burp")
            state = api.inspect(placeholder)
            _log(f"provider errors after hydration: {provider.errors}")
            _log(f"after hydration: phase={row['phase']} replay_disabled={row['replay_disabled']} "
                 f"ready={state.ready} modified={state.modified} size={state.size}")
            self.assertEqual(row["phase"], "resident")
            self.assertTrue(row["replay_disabled"])
            self.assertTrue(state.ready)

            # 3. Second read is served locally (no new transfer needed).
            second = _child(READER, placeholder)
            self.assertEqual(second.stdout.strip(), expected)

            # 4. Local edit from another process: allowed, authoritative.
            edit = _child(APPENDER, placeholder)
            self.assertEqual(edit.returncode, 0, edit.stderr)
            state = api.inspect(placeholder)
            _log(f"after edit: size={state.size} modified={state.modified} ready={state.ready}")
            self.assertEqual(state.size, len(data) + len(b"local edit after hydration"))
            self.assertTrue(state.modified)

        # 5. Provider stopped (disconnected, NOT unregistered): edited bytes stay readable.
        edited = hashlib.sha256(data + b"local edit after hydration").hexdigest()
        after = _child(READER, placeholder)
        _log(f"read with provider stopped: rc={after.returncode} edited_ok={after.stdout.strip() == edited}")
        self.assertEqual(after.stdout.strip(), edited)
        self.assertIsNotNone(api.inspect_root(root), "registration must be retained")
        status = ns.NativeStore(store_dir, api=api).status()
        _log(f"status: registered={status['registered']} errors={status['errors']} "
             f"file={status['files'][0]['kind']} resident={status['files'][0]['resident']} "
             f"modified={status['files'][0]['modified']}")
        self.assertTrue(status["registered"])
        self.assertEqual(status["errors"], [])

        # 6. Materialize leaves edited bytes alone (nothing missing, no replay).
        store = ns.NativeStore(store_dir, api=api)
        self.assertEqual(np.materialize_root(store, api=api)["status"], "materialized")
        self.assertEqual(_child(READER, placeholder).stdout.strip(), edited)

        # 7. Detach reverts the placeholder to a plain file, keeps the edit, and
        #    reports incomplete because unregistration is never attempted.
        with self.assertRaises(cf.NativeError) as caught:
            np.detach_root(store, api=api)
        self.assertIn("Registration and archive store retained", str(caught.exception))
        state = api.inspect(placeholder)
        _log(f"after detach: identity={len(state.identity)}B resident={state.resident} "
             f"phase={ns.NativeStore(store_dir, api=api).entry('LiveExample.burp')['phase']}")
        self.assertEqual(state.identity, b"")
        self.assertTrue(state.resident)
        self.assertEqual(_child(READER, placeholder).stdout.strip(), edited)
        self.assertEqual(ns.NativeStore(store_dir, api=api).status()["errors"], [])
        self.assertIsNotNone(api.inspect_root(root), "registration must be retained")
        _log(f"RETAINED sync root registration: {root} (no automatic unregister)")


    def test_unpack_now_hydrates_explicitly_without_a_reader(self):
        base = os.path.join(tempfile.gettempdir(), f"burpzip-native-test-{uuid.uuid4().hex[:12]}")
        root, store_dir, source = (os.path.join(base, n) for n in ("root", "store", "source"))
        for folder in (base, root, store_dir, source):
            os.mkdir(folder)
        _log(f"base folder (retained): {base}")
        data = os.urandom(64 * 1024) + b"\0" * (2 * 1024 * 1024) + os.urandom(77)
        project = os.path.join(source, "Unpack.burp")
        with open(project, "wb") as out:
            out.write(data)
        archive = ar.archive_project(project, level=1, threads=1, delete_original=False).archive_path
        api = cf.WindowsCfApi(test_mode=True)
        ns.init_root(root, store_dir, api=api)
        ns.add_archive(store_dir, archive, api=api)
        placeholder = os.path.join(root, "Unpack.burp")
        self.assertFalse(api.inspect(placeholder).resident)

        started = time.monotonic()
        np.materialize_root(ns.NativeStore(store_dir, api=api), api=api, names=["Unpack.burp"])
        state = api.inspect(placeholder)
        row = ns.NativeStore(store_dir, api=api).entry("Unpack.burp")
        _log(f"unpack now: {time.monotonic() - started:.1f}s phase={row['phase']} "
             f"resident={state.resident} ready={state.ready}")
        self.assertTrue(state.ready)
        self.assertEqual(row["phase"], "resident")
        self.assertEqual(_child(READER, placeholder).stdout.strip(), hashlib.sha256(data).hexdigest())


    def test_rezip_after_edit_round_trips_the_edit(self):
        base = os.path.join(tempfile.gettempdir(), f"burpzip-native-test-{uuid.uuid4().hex[:12]}")
        root, store_dir, source = (os.path.join(base, n) for n in ("root", "store", "source"))
        for folder in (base, root, store_dir, source):
            os.mkdir(folder)
        _log(f"base folder (retained): {base}")
        data = os.urandom(128 * 1024) + b"\0" * (3 * 1024 * 1024) + os.urandom(99)
        project = os.path.join(source, "Rezip.burp")
        with open(project, "wb") as out:
            out.write(data)
        archive = ar.archive_project(project, level=1, threads=1, delete_original=False).archive_path
        api = cf.WindowsCfApi(test_mode=True)
        ns.init_root(root, store_dir, api=api)
        ns.add_archive(store_dir, archive, api=api)
        placeholder = os.path.join(root, "Rezip.burp")
        np.materialize_root(ns.NativeStore(store_dir, api=api), api=api)
        self.assertTrue(api.set_always_full(placeholder), "re-marking ALWAYS_FULL after hydration")

        self.assertFalse(api.in_use(placeholder), "unpacked and not open: free")
        holder = subprocess.Popen([sys.executable, "-I", "-c", HOLDER, placeholder],
                                  stdout=subprocess.PIPE, text=True)
        try:
            holder.stdout.readline()
            self.assertTrue(api.in_use(placeholder), "held open by another process: busy")
        finally:
            holder.kill()
            holder.wait()
            holder.stdout.close()
        time.sleep(0.3)
        self.assertFalse(api.in_use(placeholder), "released: free again")
        edit = _child(APPENDER, placeholder)  # Another process edits it, like Burp.
        self.assertEqual(edit.returncode, 0, edit.stderr)
        edited = hashlib.sha256(data + b"local edit after hydration").hexdigest()

        before = ns.NativeStore(store_dir, api=api).entry("Rezip.burp")
        result = np.rezip_project(ns.NativeStore(store_dir, api=api), "Rezip.burp", api=api, level=1)
        state = api.inspect(placeholder)
        after = ns.NativeStore(store_dir, api=api).entry("Rezip.burp")
        _log(f"rezip: {result} resident={state.resident} identity_new="
             f"{state.identity.hex() == after['placeholder_identity']} phase={after['phase']}")
        self.assertEqual(result["status"], "rezipped")
        self.assertFalse(state.resident)
        self.assertEqual(state.identity.hex(), after["placeholder_identity"])
        self.assertEqual(state.file_id, before["file_id"])
        self.assertFalse(os.path.exists(os.path.join(store_dir, before["archive_rel"])))

        self.assertTrue(api.in_use(placeholder), "a dehydrated placeholder never probes as free")
        offline = _child(READER, placeholder, timeout=90)
        self.assertNotEqual(offline.returncode, 0, "dehydrated: no bytes without the provider")
        with np.NativeProvider(ns.NativeStore(store_dir, api=api), api, deadline_seconds=120):
            reopened = _child(READER, placeholder)
        _log(f"reopen after rezip: rc={reopened.returncode} edited_ok={reopened.stdout.strip() == edited}")
        self.assertEqual(reopened.stdout.strip(), edited)
        self.assertEqual(ns.NativeStore(store_dir, api=api).status()["errors"], [])


    def test_close_after_edit_asks_once_and_yes_rezips(self):
        base = os.path.join(tempfile.gettempdir(), f"burpzip-native-test-{uuid.uuid4().hex[:12]}")
        root, store_dir, source = (os.path.join(base, n) for n in ("root", "store", "source"))
        for folder in (base, root, store_dir, source):
            os.mkdir(folder)
        _log(f"base folder (retained): {base}")
        data = os.urandom(64 * 1024) + b"\0" * (1024 * 1024)
        project = os.path.join(source, "Closed.burp")
        with open(project, "wb") as out:
            out.write(data)
        archive = ar.archive_project(project, level=1, threads=1, delete_original=False).archive_path
        api = cf.WindowsCfApi(test_mode=True)
        ns.init_root(root, store_dir, api=api)
        ns.add_archive(store_dir, archive, api=api)
        placeholder = os.path.join(root, "Closed.burp")
        store = ns.NativeStore(store_dir, api=api)
        np.materialize_root(store, api=api)

        asked = []
        watcher = np.CloseWatcher(store, ask=lambda name, size: asked.append((name, size)) or True)
        watcher.poll()                                     # baseline: not open
        holder = subprocess.Popen([sys.executable, "-I", "-c", SAVER, placeholder],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            holder.stdout.readline()                       # "Burp" has it open
            watcher.poll()
            holder.stdin.write("save\n")
            holder.stdin.flush()
            holder.stdout.readline()                       # saved, still open
            watcher.poll()
            self.assertEqual(asked, [], "never ask while the project is still open")
        finally:
            holder.stdin.close()                           # "Burp" closes it
            holder.wait(30)
            holder.stdout.close()
        watcher.poll()
        if watcher._asker is not None:
            watcher._asker.join(10)
        _log(f"close watcher asked: {asked}")
        self.assertEqual([name for name, _ in asked], ["Closed.burp"])
        done = np.handle_close_answers(store, watcher, api=api, level=1)
        _log(f"after Yes: {done}")
        self.assertEqual([d["status"] for d in done], ["rezipped"])
        self.assertFalse(api.inspect(placeholder).resident)
        watcher.poll()
        self.assertEqual(len(asked), 1, "asked exactly once")


if __name__ == "__main__":
    unittest.main()
