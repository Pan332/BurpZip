"""Experimental same-path hydration of immutable 7-Zip imports.

Native activation is release-gated. This module never unregisters a root,
replaces a placeholder, or replays an import over authoritative local edits.
"""
from __future__ import annotations

import hashlib
import os
import queue
import threading
import time
from datetime import datetime
from contextlib import ExitStack
from dataclasses import dataclass, field

import archiver
import native_cfapi as cf
from native_store import NativeStore

CHUNK = 1024 * 1024
MAX_JOBS = 16
MAX_ERRORS = 64
DEFAULT_DEADLINE = 600
DEFAULT_IDLE_DAYS = 10
IDLE_CHECK_SECONDS = 3600
CLOSE_CHECK_SECONDS = 10
SERVE_LOG = "serve.log"
STOP_REQUEST = "serve.stop"
LOG_LIMIT = 1024 * 1024


def _identity(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise cf.NativeError("invalid persisted placeholder identity") from exc
    raise cf.NativeError("missing placeholder identity")


def _deadline(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 86400:
        raise cf.NativeError("deadline must be an integer from 1 to 86400 seconds")
    return value


@dataclass
class _Job:
    entry: dict
    requests: list = field(default_factory=list)
    cancelled: set = field(default_factory=set)
    stop: threading.Event = field(default_factory=threading.Event)
    finished: threading.Event = field(default_factory=threading.Event)
    expires: float = 0.0
    completed: int = 0
    failure: str | None = None
    verified: bool = False
    acked: bool = False
    acked_keys: set = field(default_factory=set)
    entry_identity: bytes = b""


class NativeProvider:
    """One bounded hydration worker; callbacks only copy/coalesce requests.

    The caller holds the store lease for the whole connection lifetime. Native
    calls are never made while holding the callback dispatch lock.
    """

    def __init__(self, store: NativeStore, api=None,
                 deadline_seconds: int = DEFAULT_DEADLINE):
        self.store = store
        self.api = api if api is not None else store.api
        self.deadline_seconds = _deadline(deadline_seconds)
        self._lock = threading.RLock()
        self._jobs: dict[bytes, _Job] = {}
        # Identities verified + ACKed this session: late validations are
        # re-checked and ACKed; late fetches are refused (no replay).
        self._verified: set[bytes] = set()
        self._queue = queue.Queue(maxsize=MAX_JOBS)
        self._closing = threading.Event()
        self._connection = None
        self._worker = None
        self._lease = ExitStack()
        self.errors: list[str] = []
        self.error_count = 0
        self._failures: list[str] = []

    def start(self):
        if self._connection is not None or self._worker is not None:
            raise cf.NativeError("provider is already started")
        # The lease re-validates root/catalog/registration identity and raises
        # on any mismatch (status() only reports them). Reentrant on one thread.
        self._lease.enter_context(self.store.lease())
        self._worker = threading.Thread(target=self._run,
                                        name="burpzip-native-worker", daemon=False)
        self._worker.start()
        try:
            self._connection = self.api.connect(self.store.root, self.on_request)
        except BaseException:
            self._closing.set()
            self._worker.join(10)
            if self._worker.is_alive():
                raise cf.NativeError("provider startup failed; worker did not drain")
            self._worker = None
            self._lease.close()
            raise
        return self

    def stop(self):
        self._closing.set()
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            job.stop.set()
        if self._worker is not None:
            self._worker.join(15)
            if self._worker.is_alive():
                raise cf.NativeError(
                    "provider worker has not drained; connection/recovery state retained")
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                break
            self._settle(job, "provider stopped before hydration")
            self._queue.task_done()
        if self._connection is not None:
            self.api.disconnect(self._connection)
            self._connection = None
        self._worker = None
        self._lease.close()
        if self._failures:
            raise cf.NativeError("native request failure could not be reported: "
                                 + "; ".join(self._failures))

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        if exc is None:
            self.stop()
            return False
        try:
            self.stop()
        except Exception as stop_error:
            # Keep the original failure; a retained connection is reported.
            self._record(f"stop after failure: {stop_error}")
        return False

    @staticmethod
    def _key(request):
        return (request.connection, request.transfer, request.request_key,
                request.event, request.offset, request.length)

    def _record(self, message: str):
        with self._lock:
            self.errors.append(message)
            self.error_count += 1
            del self.errors[:-MAX_ERRORS]

    def _fail(self, request, message: str):
        if request.event == "cancel":
            return
        try:
            self.api.fail(request, cf.STATUS_CLOUD_FILE_UNSUCCESSFUL)
        except Exception as exc:
            with self._lock:
                self._failures.append(str(exc))
                del self._failures[:-MAX_ERRORS]
        self._record(message)

    def _late_validate(self, request, entry: dict):
        # Persisted bytes were verified and replay is durably disabled. ACK only
        # while the file is still the unmodified imported size; the ACK itself
        # is what makes the range validated ("ready").
        state = self.store.inspect_entry(entry)
        if state.modified or state.size != entry["size"]:
            self._fail(request, "local contents changed after verification")
            return
        self.api.ack(request, 0, entry["size"] or -1)
        self._mark_resident(entry)

    def _mark_resident(self, entry: dict) -> bool:
        # Windows publishes the validated range asynchronously after ACK_DATA.
        # Local edits are authoritative from here on; only readiness is polled.
        settle = time.monotonic() + 10
        while True:
            state = self.store.inspect_entry(entry)
            if state.ready or time.monotonic() >= settle:
                break
            time.sleep(0.05)
        if not state.ready:
            self._record("native state is not fully validated after ACK")
            return False
        current = self.store.entry(entry["name"])
        if current["phase"] != "resident":
            self.store.mark(current, "resident")
        # Keep Windows from partially dehydrating it; re-zip clears this explicitly.
        setter = getattr(self.api, "set_always_full", None)
        if setter is not None:
            try:
                setter(os.path.join(self.store.root, entry["name"]))
            except Exception as exc:
                self._record(f"could not re-mark always-full: {exc}")
        return True

    def _settle(self, job: _Job, message: str):
        """Retire a job and complete every request it did not already ACK."""
        with self._lock:
            job.finished.set()
            if self._jobs.get(job.entry_identity) is job:
                del self._jobs[job.entry_identity]
            if job.verified:
                self._verified.add(job.entry_identity)
            leftovers = [r for r in job.requests
                         if (r.connection, r.transfer, r.request_key) not in job.cancelled
                         and self._key(r) not in job.acked_keys]
        for request in leftovers:
            try:
                if job.verified and request.event == "validate":
                    self._late_validate(request, job.entry)
                elif job.verified:
                    self._fail(request, "resident contents are authoritative; no archive replay")
                else:
                    self._fail(request, message)
            except Exception as exc:
                self._fail(request, str(exc))

    def _entry_for(self, request) -> dict:
        path = os.path.abspath(request.path)
        if os.path.normcase(os.path.dirname(path)) != os.path.normcase(self.store.root):
            raise cf.NativeError("callback is outside the flat managed root")
        entry = self.store.entry(os.path.basename(path))
        if request.identity != _identity(entry["placeholder_identity"]):
            raise cf.NativeError("callback identity does not match immutable import")
        if request.file_size != entry["size"]:
            raise cf.NativeError("callback size differs from imported revision")
        if type(request.offset) is not int or request.offset < 0 \
                or type(request.length) is not int or request.length < -1:
            raise cf.NativeError("invalid callback range")
        return entry

    def on_request(self, request):
        """The adapter supplies owned strings/bytes/scalars, not borrowed pointers."""
        try:
            if request.event not in ("fetch", "validate", "cancel"):
                raise cf.NativeError("unsupported native callback")
            if self._closing.is_set():
                self._fail(request, "provider is stopping")
                return
            entry = self._entry_for(request)
            identity = request.identity
            fail_message = None
            late_ack = False
            with self._lock:
                job = self._jobs.get(identity)
                if self._closing.is_set() and request.event != "cancel":
                    job, fail_message = None, "provider is stopping"
                if request.event == "cancel":
                    if job is not None:
                        job.cancelled.add((request.connection, request.transfer,
                                           request.request_key))
                        active = [r for r in job.requests if
                                  (r.connection, r.transfer, r.request_key)
                                  not in job.cancelled]
                        if not active:
                            job.stop.set()
                    return
                if fail_message is not None:
                    pass
                elif job is None and identity in self._verified:
                    if request.event == "validate":
                        late_ack = True
                    else:
                        fail_message = "resident contents are authoritative; no archive replay"
                elif job is not None:
                    if len(job.requests) >= 256:
                        fail_message = "too many pending requests for one project"
                    elif not any(self._key(r) == self._key(request) for r in job.requests):
                        job.requests.append(request)
                else:
                    if len(self._jobs) >= MAX_JOBS:
                        fail_message = "provider job limit reached; retry after reconnect"
                    else:
                        job = _Job(entry, [request],
                                   expires=time.monotonic() + self.deadline_seconds,
                                   entry_identity=identity)
                        self._jobs[identity] = job
                        self._queue.put_nowait(job)
            if fail_message is not None:
                self._fail(request, fail_message)
            elif late_ack:
                self._late_validate(request, entry)
        except Exception as exc:
            self._fail(request, str(exc))

    def _active(self, job: _Job) -> list:
        with self._lock:
            return [r for r in job.requests
                    if (r.connection, r.transfer, r.request_key) not in job.cancelled]

    def _check(self, job: _Job):
        if self._closing.is_set() or job.stop.is_set() \
                or time.monotonic() >= job.expires:
            job.stop.set()
            raise cf.NativeError("hydration cancelled or timed out")
        state = self.store.inspect_entry(job.entry)
        if state.modified or state.size != job.entry["size"]:
            raise cf.NativeError("local contents changed; archive replay refused")
        return state

    def _watch(self, job: _Job):
        while not job.finished.wait(0.5):
            if self._closing.is_set() or time.monotonic() >= job.expires:
                job.stop.set()
                return
            for request in self._active(job):
                if request.event != "fetch":
                    continue
                try:
                    self.api.progress(request, job.entry["size"], job.completed)
                except Exception as exc:
                    job.failure = f"provider progress failed: {exc}"
                    job.stop.set()
                    return

    def _retrieve_hash(self, job: _Job, request) -> str:
        digest = hashlib.sha256()
        size = job.entry["size"]
        offset = 0
        while offset < size:
            self._check(job)
            length = min(CHUNK, size - offset)
            data = self.api.retrieve(request, offset, length)
            if not isinstance(data, bytes) or len(data) != length:
                raise cf.NativeError("persisted-data retrieval returned a short range")
            digest.update(data)
            offset += length
        return digest.hexdigest()

    def _complete(self, job: _Job, request):
        if self._retrieve_hash(job, request) != job.entry["payload_sha256"]:
            raise cf.NativeError("persisted contents do not match imported SHA-256")
        self._check(job)
        job.entry = self.store.mark(
            job.entry, "ack-intent", verified_sha256=job.entry["payload_sha256"],
            verified_size=job.entry["size"], replay_disabled=True)
        job.verified = True
        # Live Windows rejects ACK_DATA on FETCH_DATA keys (ERROR_CLOUD_FILE_
        # INVALID_REQUEST): a fetch is completed by its transfers. Only
        # VALIDATE_DATA is acknowledged. A validation arriving after this job
        # retires is ACKed by _late_validate(); _settle() never fails a fetch
        # whose bytes were fully transferred and verified.
        while True:
            with self._lock:
                for r in job.requests:
                    if r.event == "fetch":
                        job.acked_keys.add(self._key(r))
            pending = [r for r in self._active(job)
                       if r.event == "validate" and self._key(r) not in job.acked_keys]
            if not pending:
                break
            for current in pending:
                self._check(job)
                self.api.ack(current, 0, job.entry["size"] or -1)
                job.acked_keys.add(self._key(current))
                job.acked = True
        if job.acked and self._mark_resident(job.entry):
            job.entry = self.store.entry(job.entry["name"])

    def _hydrate(self, job: _Job):
        state = self._check(job)
        if state.ready:
            raise cf.NativeError("resident contents are authoritative; no archive replay")
        requests = self._active(job)
        if not requests:
            raise cf.NativeError("all requests cancelled")
        fetch = next((r for r in requests if r.event == "fetch"), None)
        if job.entry.get("replay_disabled") or fetch is None:
            self._complete(job, requests[0])
            return
        # Stream 7-Zip's output straight into the placeholder. Windows cancels a
        # fetch that delivers nothing for ~60 s (ERROR_CLOUD_FILE_REQUEST_TIMEOUT);
        # extracting a multi-GB project to a temp file first exceeded that. Each
        # transfer resets the timer. Nothing is trusted yet: Windows only exposes
        # the data after VALIDATE_DATA is ACKed, which _complete() does only after
        # the whole-stream SHA-256 and the read-back SHA-256 both match.
        name, size = job.entry["name"], job.entry["size"]
        self.store.check_hydration_space(job.entry, staged=True)  # No staging copy.
        with self.store.pinned_archive(job.entry, stop_event=job.stop, verify_payload=False) as archive:
            meta = archiver.read_meta(archive, stop_event=job.stop)
            if meta["orig_name"] != name or meta["size"] != size \
                    or meta["sha256"] != job.entry["payload_sha256"]:
                raise cf.NativeError("pinned archive metadata differs from the catalog")
            archiver._require_entry(archive, name, size, stop_event=job.stop)
            if job.entry["phase"] != "transferred":
                # A retry after a failed transfer keeps its later phase.
                job.entry = self.store.mark(job.entry, "staged")
            digest = hashlib.sha256()
            pending = bytearray()
            sent = 0
            chunks = 0

            def send(data: bytes) -> None:
                nonlocal sent, chunks
                if chunks % 16 == 0:
                    self._check(job)
                chunks += 1
                selected = next((r for r in self._active(job) if r.event == "fetch"), None)
                if selected is None:
                    raise cf.NativeError("no active fetch request remains")
                self.api.transfer(selected, sent, data)
                sent += len(data)
                job.completed = sent

            def sink(chunk: bytes) -> None:
                if sent + len(pending) + len(chunk) > size:
                    raise cf.NativeError("archive stream exceeds the imported size")
                digest.update(chunk)
                pending.extend(chunk)
                while len(pending) >= CHUNK:  # Transfers stay 4 KiB-aligned until EOF.
                    send(bytes(pending[:CHUNK]))
                    del pending[:CHUNK]

            archiver._stream_7z(["e", "-so", "-t7z", "-y", "-spd", archive, "--", name], sink,
                                stop_event=job.stop)
            if pending:
                send(bytes(pending))
            if sent != size or digest.hexdigest() != job.entry["payload_sha256"]:
                raise cf.NativeError("streamed contents differ from the imported revision; not validated")
        job.entry = self.store.mark(job.entry, "transferred")
        self._check(job)
        active = self._active(job)
        selected = next((r for r in active if r.event == "validate"), next(iter(active), None))
        if selected is None:
            raise cf.NativeError("no active validation request remains")
        self._complete(job, selected)

    def _run(self):
        while not self._closing.is_set() or not self._queue.empty():
            try:
                job = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            watch = threading.Thread(target=self._watch, args=(job,),
                                     name="burpzip-native-progress", daemon=False)
            watch.start()
            try:
                self._hydrate(job)
            except Exception as exc:
                job.failure = str(exc)
                self._record(job.failure)
            finally:
                self._settle(job, job.failure or "hydration did not complete")
                watch.join(5)
                if watch.is_alive():
                    with self._lock:
                        self._failures.append("provider progress thread did not drain")
                self._queue.task_done()

    @staticmethod
    def _complete_locally(entry: dict, state) -> bool:
        # Validated, or fully on disk past the durable no-replay boundary
        # (edited bytes are no longer counted as validated by Windows).
        return state.ready or (entry["replay_disabled"] and state.resident)

    def materialize(self, names: list[str] | None = None):
        wanted = None if names is None else {n.casefold() for n in names}
        for entry in self.store.entries():
            if wanted is not None and entry["name"].casefold() not in wanted:
                continue
            state = self.store.inspect_entry(entry)
            if self._complete_locally(entry, state):
                continue
            self.api.hydrate(os.path.join(self.store.root, entry["name"]))
            entry = self.store.entry(entry["name"])
            state = self.store.inspect_entry(entry)
            if not self._complete_locally(entry, state):
                raise cf.NativeError(f"materialization incomplete: {entry['name']}")
        if self.errors:
            raise cf.NativeError("materialization failed: " + "; ".join(self.errors))


def _store(value, api=None):
    return value if isinstance(value, NativeStore) else NativeStore(value, api=api)


def serve_log(store_path: str, message: str) -> None:
    """Append one UTC line to the store's serve.log (hidden runs have no console)."""
    path = os.path.join(store_path, SERVE_LOG)
    try:
        if os.path.exists(path) and os.path.getsize(path) > LOG_LIMIT:
            os.replace(path, path + ".1")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(path, "a", encoding="utf-8") as out:
            out.write(f"{stamp} {message}\n")
    except OSError:
        pass  # Logging must never stop the provider.


def request_stop(store_path: str) -> str:
    """Ask a running serve (any process) to disconnect at its next poll."""
    path = os.path.join(os.path.abspath(store_path), STOP_REQUEST)
    with open(path, "a", encoding="utf-8"):
        pass
    return path


def serve_root(store, deadline_seconds: int = DEFAULT_DEADLINE, *, api=None,
               stop_event: threading.Event | None = None, idle_days: int = DEFAULT_IDLE_DAYS,
               ask_on_close: bool = False):
    store = _store(store, api)
    stop = stop_event if stop_event is not None else threading.Event()
    stop_file = os.path.join(store.path, STOP_REQUEST)
    with store.lease():
        if os.path.lexists(stop_file):
            os.remove(stop_file)  # A stale request from an earlier run.
        idle_note = f"after {idle_days} days" if idle_days else "off"
        serve_log(store.path, f"serving {store.root} (pid {os.getpid()}; idle re-zip {idle_note})")
        for note in store.recover_rezips():
            serve_log(store.path, note)
        next_idle = time.monotonic() + 300
        watcher = CloseWatcher(store) if ask_on_close else None
        next_close = time.monotonic()

        def close_log(result: dict) -> None:
            if result["status"] == "rezipped":
                serve_log(store.path, f"re-zipped {result['name']} after Burp closed it "
                                      f"({result['size']} -> {result['archive_size']} bytes)")
            else:
                serve_log(store.path, f"after close, {result['name']} {result['status']}: "
                                      f"{result.get('reason')}")
        try:
            with NativeProvider(store, api, deadline_seconds) as provider:
                logged = 0
                try:
                    while not stop.wait(0.5):
                        if provider.error_count > logged:
                            fresh = provider.error_count - logged
                            for message in provider.errors[-fresh:]:
                                serve_log(store.path, f"error: {message}")
                            logged = provider.error_count
                        if os.path.lexists(stop_file):
                            serve_log(store.path, "stop requested")
                            break
                        if watcher is not None and time.monotonic() >= next_close:
                            next_close = time.monotonic() + CLOSE_CHECK_SECONDS
                            watcher.poll()
                            handle_close_answers(store, watcher, api=api, log=close_log)
                        if idle_days and time.monotonic() >= next_idle:
                            next_idle = time.monotonic() + IDLE_CHECK_SECONDS
                            for done in rezip_idle(store, api=api, idle_days=idle_days):
                                if done["status"] == "rezipped":
                                    serve_log(store.path, f"re-zipped idle project {done['name']} "
                                                          f"({done['size']} -> {done['archive_size']} bytes)")
                                else:
                                    serve_log(store.path, f"idle re-zip skipped {done['name']}: "
                                                          f"{done.get('reason')}")
                        if provider._failures:
                            raise cf.NativeError("provider could not fail pending native requests")
                except KeyboardInterrupt:
                    stop.set()
        except Exception as exc:
            serve_log(store.path, f"stopped on error: {exc}")
            raise
        finally:
            if os.path.lexists(stop_file):
                os.remove(stop_file)
        serve_log(store.path, "disconnected (registration retained)")
    return {"status": "disconnected", "registration_retained": True}


def rezip_project(store, name: str, *, api=None, level: int = 5) -> dict:
    """Re-zip an unpacked project's CURRENT bytes and shrink it back to a placeholder.

    Requires the store lease (no other provider running) and Burp not using the
    file. The old archive is only retired after the new one is verified and the
    placeholder carries the new identity; edits are never replaced by old bytes.
    """
    store = _store(store, api)
    api = store.api
    with store.lease():
        store.recover_rezips()
        entry = store.entry(name)
        state = store.inspect_entry(entry)
        if not entry["replay_disabled"] or not state.resident:
            return {"name": entry["name"], "status": "skipped", "reason": "not unpacked"}
        path = os.path.join(store.root, entry["name"])
        with api.locked_snapshot(path, entry["file_id"]) as snapshot:
            with store.staging(entry) as stage:
                staged = os.path.join(stage, entry["name"])
                digest, copied = hashlib.sha256(), 0
                with open(staged, "xb") as out:
                    for chunk in iter(lambda: snapshot.read(CHUNK), b""):
                        out.write(chunk)
                        digest.update(chunk)
                        copied += len(chunk)
                if copied != snapshot.size:
                    raise cf.NativeError("project changed size while being copied")
                os.utime(staged, (time.time(), snapshot.mtime))
                result = archiver.archive_project(staged, dest_dir=stage, level=level, threads=2,
                                                  delete_original=True)
                if result.sha256 != digest.hexdigest() or result.original_size != copied:
                    raise cf.NativeError("re-zipped archive does not match the locked project bytes")
                new = store.begin_rezip(entry, result.archive_path)
                try:
                    api.dehydrate_locked(snapshot, bytes.fromhex(new["placeholder_identity"]),
                                         copied, new["mtime"])
                except BaseException:
                    current = api.inspect(path)
                    if current.identity == bytes.fromhex(new["placeholder_identity"]):
                        store.finish_rezip(new, entry["file_id"])
                    else:
                        store.abort_rezip(new)
                    raise
                store.finish_rezip(new, entry["file_id"])
    return {"name": entry["name"], "status": "rezipped", "size": copied,
            "archive_size": result.archive_size}


def _last_activity(entry: dict, path: str) -> float:
    """Latest of the file's last write and when Burpzip last unpacked it.

    An unpacked project keeps its original (possibly months-old) edit time, so
    the file time alone would make a project look idle right after it opened.
    """
    stamps = [os.stat(path).st_mtime]
    try:
        stamps.append(datetime.fromisoformat(entry["updated_at"]).timestamp())
    except (KeyError, TypeError, ValueError):
        pass
    return max(stamps)


def rezip_idle(store, *, api=None, idle_days: int = DEFAULT_IDLE_DAYS, level: int = 5) -> list[dict]:
    """Re-zip unpacked projects not modified for idle_days and not in use."""
    store = _store(store, api)
    cutoff = time.time() - idle_days * 86400
    results = []
    with store.lease():
        for entry in store.entries():
            path = os.path.join(store.root, entry["name"])
            try:
                state = store.inspect_entry(entry)
                if not entry["replay_disabled"] or not state.resident or _last_activity(entry, path) > cutoff:
                    continue
                results.append(rezip_project(store, entry["name"], api=api, level=level))
            except Exception as exc:
                results.append({"name": entry["name"], "status": "skipped", "reason": str(exc)})
    return results


def _human(size: int) -> str:
    import burpzip
    return burpzip.human_size(size)


def ask_rezip_dialog(name: str, size: int) -> bool:
    """Topmost Yes/No box from the hidden provider; True means re-zip now."""
    import ctypes
    text = (f"Burp closed \"{name}\" ({_human(size)} unpacked).\n\n"
            "Re-zip it now to free the space?\n\n"
            "Your latest changes are kept. It unpacks again automatically the next time "
            "you open it in Burp.")
    flags = 0x4 | 0x20 | 0x10000 | 0x40000  # YESNO | ICONQUESTION | SETFOREGROUND | TOPMOST
    return ctypes.windll.user32.MessageBoxW(None, text, "Burpzip", flags) == 6  # IDYES


class CloseWatcher:
    """Notices when an unpacked Burp-folder project is released after being changed.

    poll() runs on the serve thread; questions are asked on a separate thread so
    the provider keeps serving while a dialog waits. Answers come back through
    answers() and are acted on by the serve thread, which owns the store lease.
    """

    def __init__(self, store: NativeStore, in_use=None, ask=ask_rezip_dialog):
        # burpzip.is_in_use deliberately reports every native path as busy (it
        # never probes placeholders); the adapter's probe is native-aware.
        self.store, self.ask = store, ask
        self.in_use = in_use if in_use is not None else store.api.in_use
        self._seen: dict[str, tuple[bool, float]] = {}  # name -> (busy, mtime when opened)
        self._asking: set[str] = set()
        self._questions: queue.Queue = queue.Queue()
        self._answers: queue.Queue = queue.Queue()
        self._asker: threading.Thread | None = None

    def poll(self) -> None:
        for entry in self.store.entries():
            name = entry["name"]
            if not entry["replay_disabled"]:
                self._seen.pop(name, None)  # Still zipped: nothing to ask about.
                continue
            path = os.path.join(self.store.root, name)
            try:
                busy = bool(self.in_use(path))
                stat_now = os.stat(path)
            except Exception:
                continue
            previous = self._seen.get(name)
            if busy:
                opened_mtime = previous[1] if previous is not None and previous[0] else stat_now.st_mtime
                self._seen[name] = (True, opened_mtime)
                continue
            self._seen[name] = (False, stat_now.st_mtime)
            if previous is not None and previous[0] and stat_now.st_mtime != previous[1] \
                    and name not in self._asking:
                self._asking.add(name)
                self._questions.put((name, stat_now.st_size))
                self._start_asker()

    def _start_asker(self) -> None:
        if self._asker is not None and self._asker.is_alive():
            return
        # Daemon: a dialog nobody answered must not keep the provider alive at stop.
        self._asker = threading.Thread(target=self._ask_loop, name="burpzip-close-prompt", daemon=True)
        self._asker.start()

    def _ask_loop(self) -> None:
        while True:
            try:
                name, size = self._questions.get(timeout=1)
            except queue.Empty:
                return
            try:
                answer = bool(self.ask(name, size))
            except Exception:
                answer = False
            self._answers.put((name, answer))

    def answers(self) -> list[tuple[str, bool]]:
        out = []
        while True:
            try:
                name, answer = self._answers.get_nowait()
            except queue.Empty:
                return out
            self._asking.discard(name)
            out.append((name, answer))


def handle_close_answers(store: NativeStore, watcher: CloseWatcher, *, api=None, level: int = 5,
                         log=None) -> list[dict]:
    """Re-zip the projects the user said Yes to; never touches the ones they declined."""
    done = []
    for name, yes in watcher.answers():
        if not yes:
            result = {"name": name, "status": "kept", "reason": "user chose not to re-zip"}
        else:
            try:
                result = rezip_project(store, name, api=api, level=level)
            except Exception as exc:
                result = {"name": name, "status": "skipped", "reason": str(exc)}
        done.append(result)
        if log is not None:
            log(result)
    return done


def materialize_root(store, deadline_seconds: int = DEFAULT_DEADLINE, *, api=None,
                     names: list[str] | None = None):
    store = _store(store, api)
    with store.lease():
        with NativeProvider(store, api, deadline_seconds) as provider:
            provider.materialize(names)
    return {"status": "materialized", "registration_retained": True}


def export_project(store, name: str, dest: str, current: bool,
                   deadline_seconds: int = DEFAULT_DEADLINE, *, api=None):
    if type(current) is not bool:
        raise cf.NativeError("choose current contents or imported snapshot explicitly")
    store = _store(store, api)
    dest = os.path.abspath(dest)
    cf.require_ordinary_path(dest)
    cf.require_ordinary_path(os.path.dirname(dest))
    if not archiver._safe_project_name(os.path.basename(dest)) or os.path.lexists(dest):
        raise cf.NativeError("export must name a new ordinary .burp destination")
    if current and not getattr(store.api, "CURRENT_EXPORT_SUPPORTED", False):
        # Never fall back to the historical archive, and do not hydrate first
        # when the adapter cannot take a protected snapshot afterwards.
        raise cf.NativeError(
            "current-content export is unsupported: no proven protected snapshot; "
            "use --snapshot for the historical import (not a backup of later edits)")
    with store.lease():
        entry = store.entry(name)
        if current:
            with NativeProvider(store, api, deadline_seconds) as provider:
                provider.materialize()
            store.api.export_current(os.path.join(store.root, entry["name"]), dest)
            return {"status": "exported-current", "path": dest}
        with store.pinned_archive(entry) as archive:
            archiver.restore_project(archive, dest)
        return {"status": "exported-imported-snapshot", "path": dest,
                "warning": "Historical import, not a backup of later edits."}


def detach_root(store, deadline_seconds: int = DEFAULT_DEADLINE, *, api=None):
    store = _store(store, api)
    with store.lease():
        with NativeProvider(store, api, deadline_seconds) as provider:
            provider.materialize()
            for entry in store.entries():
                if entry["phase"] == "reverted":
                    continue
                state = store.inspect_entry(entry)
                if not provider._complete_locally(entry, state):
                    raise cf.NativeError("detach requires complete current resident contents")
                path = os.path.join(store.root, entry["name"])
                provider.api.revert(path)
                state = provider.api.inspect(path)
                if state.identity or not state.resident or state.file_id != entry["file_id"]:
                    raise cf.NativeError("placeholder reversion postcondition failed")
                store.mark(entry, "reverted")
    raise cf.NativeError(
        "Projects materialized/reverted; provider disconnected. Registration and "
        "archive store retained: safe namespace-exclusive unregister is unavailable.")
