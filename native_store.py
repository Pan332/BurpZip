"""Off-root immutable imports and conservative native-provider state.

This module never unregisters a root, reads managed project contents, or repairs
an interrupted transaction by guessing. The JSONL intent is flushed *before*
atomic catalog publication. An unmatched intent blocks future mutations/replay.
These checked writes are not a claim of tested power-loss durability on Windows.

A lease is exclusive across cooperating processes. Windows archive pins also
exclude external write/delete opens; POSIX flock is advisory and is supplemented
by descriptor/path generation checks. Neither a lease nor a catalog authenticates
an externally substituted filesystem namespace.
"""
from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

import archiver
import native_cfapi as cfapi

NativeError = cfapi.NativeError
PathState = cfapi.PathState
MARKER = ".burpzip-native-store.json"
JOURNAL = "native-journal.jsonl"
LOCKFILE = ".burpzip-native.lock"
FORMAT = 1
PROVIDER = "burpzip-native"
SPACE_MARGIN = 512 * 1024**2
_CHUNK = 1024 * 1024
_JSON_LIMIT = 4 * 1024**2
_JOURNAL_LIMIT = 32 * 1024**2
_PHASES = ("prepared", "placeholder", "staged", "transferred", "ack-intent", "resident", "reverted",
           "superseded")
_POLICY = {
    "identity_format": 1,
    "hydration": "FULL",
    "validation_required": True,
    "population": "ALWAYS_FULL",
    "file_always_full": True,
}
_IMMUTABLE = (
    "root_id", "logical_file_id", "name", "archive_rel", "archive_sha256",
    "archive_size", "payload_sha256", "size", "mtime", "placeholder_identity", "created_at",
)
_ENTRY_KEYS = set(_IMMUTABLE) | {"file_id", "phase", "replay_disabled", "updated_at"}
_ENTRY_OPTIONAL = {"verified_sha256", "verified_size", "error", "note", "supersedes"}
_CATALOG_KEYS = {
    "format", "provider", "root_id", "root_path", "root_file_id", "root_identity",
    "store_path", "store_file_id", "policy", "created_at", "state", "revision", "files", "staging",
}


def _fail(message: str) -> None:
    raise NativeError(message)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _uuid(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail(f"invalid {label}")
    try:
        valid = str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        valid = False
    if not valid:
        _fail(f"invalid {label}")
    return value


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        _fail(f"invalid {label}")
    return value


def _timestamp(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 64:
        _fail(f"invalid {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        valid = parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0
    except (ValueError, OverflowError):
        valid = False
    if not valid:
        _fail(f"{label} must be an ISO UTC timestamp")


def _mtime(value: object) -> None:
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        valid = False
    if not valid:
        _fail("invalid import mtime")


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        _fail(f"invalid {label}")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
        _fail(f"invalid {label}")
    return value


def _identity(value: object) -> bytes:
    if isinstance(value, bytes) and value:
        return value
    if isinstance(value, str) and value and len(value) <= 8192:
        try:
            result = bytes.fromhex(value)
        except ValueError:
            _fail("invalid native identity encoding")
        if result and result.hex() == value:
            return result
    _fail("invalid native identity encoding")


def _safe_component(name: str) -> bool:
    if not name or name in (".", "..") or name.rstrip(" .") != name:
        return False
    if re.search(r'[<>:"/\\|?*\x00-\x1f]', name):
        return False
    device = name.split(".", 1)[0].rstrip(" ").upper()
    if device in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}:
        return False
    if re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", device):
        return False
    try:
        return len(name.encode("utf-16-le")) <= 510
    except UnicodeEncodeError:
        return False


def _project_name(value: object) -> str:
    if not isinstance(value, str) or not value.lower().endswith(".burp") or not _safe_component(value):
        _fail(f"not a flat Windows-safe .burp filename: {value!r}")
    return value


def _key(path: str) -> str:
    # Casefold even in POSIX fake tests: the persisted namespace is Windows-flat.
    return os.path.normpath(path).replace("\\", "/").casefold()


def _within(path: str, parent: str) -> bool:
    path_key, parent_key = _key(path), _key(parent).rstrip("/")
    return path_key == parent_key or path_key.startswith(parent_key + "/")


def _canonical(path: str | os.PathLike[str], *, persisted: bool = False) -> str:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        _fail("invalid native filesystem path")
    if os.name == "nt" and (raw.startswith("\\\\") or raw.startswith("//")):
        _fail("native paths must be local drive paths, not UNC/device paths")
    result = os.path.abspath(raw)
    if persisted and (not os.path.isabs(raw) or raw != result):
        _fail("persisted native paths must be canonical absolute paths")
    drive, tail = os.path.splitdrive(result)
    if os.name == "nt" and (len(drive) != 2 or drive[1] != ":"):
        _fail("native paths require a local drive")
    for component in tail.replace("\\", "/").split("/"):
        if component and not _safe_component(component):
            _fail(f"unsafe native path component: {component!r}")
    return result


def _parents(path: str) -> list[str]:
    result = [path]
    while True:
        parent = os.path.dirname(result[-1])
        if parent == result[-1]:
            return list(reversed(result))
        result.append(parent)


def _reparse(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)


def _stat_id(st: os.stat_result) -> str:
    return f"{st.st_dev}:{st.st_ino}"


def _generation(st: os.stat_result) -> tuple[int, ...]:
    # On Windows, st_ctime is creation time, and path stat (directory entry,
    # subject to name tunneling) can disagree with handle stat right after an
    # atomic replace. Volume + file ID already detect replacement.
    if os.name == "nt":
        return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _cloud_tag(st: os.stat_result) -> bool:
    # IO_REPARSE_TAG_CLOUD and its CLOUD_1..F variants. Callback threads see the
    # sync root's reparse ATTRIBUTE but a disguised tag of 0; any visible
    # non-cloud tag (junction/mount point/symlink) is still refused. The caller
    # also requires realpath == path and verifies the owned root identity.
    tag = getattr(st, "st_reparse_tag", 0)
    return tag == 0 or (tag & 0xFFFF0FFF) == 0x9000001A


def _directory(path: str, *, cloud_root: bool = False) -> os.stat_result:
    """Reject links/reparse traversal through every existing directory component.

    cloud_root permits a Cloud Files reparse tag on the LEAF only: callback
    threads see the registered sync root exposed as a cloud reparse point.
    Callers must then verify ownership through the adapter's root identity.
    """
    leaf = None
    for ancestor in _parents(path):
        try:
            current = os.lstat(ancestor)
        except OSError as exc:
            raise NativeError(f"native directory is unavailable: {ancestor}") from exc
        cloud_leaf = cloud_root and ancestor == path and stat.S_ISDIR(current.st_mode)             and not stat.S_ISLNK(current.st_mode) and _cloud_tag(current)
        if not cloud_leaf and (not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode)
                               or _reparse(current)):
            _fail(f"linked/reparse/non-directory native ancestry: {ancestor} "
                  f"(attributes 0x{getattr(current, 'st_file_attributes', 0):x}, "
                  f"reparse tag 0x{getattr(current, 'st_reparse_tag', 0):x})")
        leaf = current
    if _key(os.path.realpath(path)) != _key(path):
        _fail(f"native directory resolves outside its lexical path: {path}")
    assert leaf is not None
    return leaf


def _ordinary_directory(path: str, api, *, allow_marker: bool = False) -> os.stat_result:
    st = _directory(path)
    for ancestor in _parents(path):
        if not allow_marker and os.path.lexists(os.path.join(ancestor, MARKER)):
            _fail(f"ordinary operation cannot use native store ancestry: {ancestor}")
        if api.inspect_root(ancestor) is not None:
            _fail(f"ordinary operation cannot use registered/cloud ancestry: {ancestor}")
    return st


def _regular(path: str) -> os.stat_result:
    _directory(os.path.dirname(path))
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise NativeError(f"native store file is unavailable: {path}") from exc
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or _reparse(st) or st.st_nlink != 1:
        _fail(f"native store file must be a private ordinary file, not a link: {path}")
    return st


def _win_open(path: str, access: int, sharing: int, disposition: int):
    """Lazy CreateFileW with OPEN_REPARSE_POINT; caller owns the returned handle."""
    from ctypes import wintypes

    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    dll.CreateFileW.restype = wintypes.HANDLE
    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL
    handle = dll.CreateFileW(path, access, sharing, None, disposition, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise NativeError(f"exclusive native file access refused: {path} (WinError {ctypes.get_last_error()})")

    class FileInformation(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                    ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                    ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]

    dll.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
    dll.GetFileInformationByHandle.restype = wintypes.BOOL
    information = FileInformation()
    if not dll.GetFileInformationByHandle(handle, ctypes.byref(information)):
        error = ctypes.get_last_error()
        dll.CloseHandle(handle)
        raise NativeError(f"cannot verify ordinary native-store handle (WinError {error})")
    if information.attributes & (0x400 | 0x10) or information.links != 1:
        dll.CloseHandle(handle)
        _fail("native-store handle refers to a reparse/directory/hard-linked object")
    return dll, handle


@contextmanager
def _read_pin(path: str, share: int = 1) -> Iterator[object]:
    """Open an ordinary file without following its leaf and check the descriptor.

    Archives stay SHARE_READ (deny write/delete while pinned). Catalog/journal
    reads pass SHARE_ALL so a concurrent `status` never blocks the writer's
    atomic replace; generation checks still detect replacement.
    """
    before = _regular(path)
    if os.name == "nt":
        import msvcrt

        dll, handle = _win_open(path, 0x80000000, share, 3)  # read; OPEN_EXISTING
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            dll.CloseHandle(handle)
            raise
    else:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or _generation(opened) != _generation(before):
                _fail(f"file replaced while opening native store input: {path}")
            if os.name != "nt":
                import fcntl

                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                except OSError as exc:
                    raise NativeError(f"native archive is write-locked: {path}") from exc
            try:
                yield stream
            finally:
                if _generation(os.fstat(stream.fileno())) != _generation(opened) \
                        or _generation(_regular(path)) != _generation(opened):
                    _fail(f"native store input generation changed while pinned: {path}")
    finally:
        if fd != -1:
            os.close(fd)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate native JSON field: {key}")
        result[key] = value
    return result


def _json_bytes(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise NativeError("native state is not finite UTF-8 JSON data") from exc


def _parse_json(data: bytes) -> dict:
    def reject_constant(value):
        _fail(f"nonfinite native JSON value: {value}")

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise NativeError("corrupt native JSON state") from exc
    if not isinstance(value, dict):
        _fail("native state must be a JSON object")
    return value


def _retry_sharing(operation, *args) -> None:
    """Retry briefly when an antivirus scan or concurrent reader holds the file."""
    for delay in (0.05, 0.1, 0.2, 0.4, 0.8, 1.6):
        try:
            return operation(*args)
        except PermissionError:
            time.sleep(delay)
    return operation(*args)


def _load_json(path: str) -> dict:
    with _read_pin(path, share=7) as stream:
        data = stream.read(_JSON_LIMIT + 1)
    if len(data) > _JSON_LIMIT:
        _fail(f"oversized native JSON state: {path}")
    return _parse_json(data)


def _sync_directory(path: str) -> None:
    # POSIX can fsync directory publication. Windows' directory durability is
    # not asserted: file flush and checked os.replace are the bounded contract.
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_once(path: str, data: bytes) -> None:
    _directory(os.path.dirname(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(os.path.dirname(path))


def _atomic_json(path: str, value: dict) -> None:
    parent = os.path.dirname(path)
    _directory(parent)
    if os.path.lexists(path):
        _regular(path)
    temporary = os.path.join(parent, f".native-catalog-{uuid.uuid4()}.tmp")
    # Failure intentionally retains invocation-owned state; no guessed cleanup.
    _write_once(temporary, _json_bytes(value))
    _retry_sharing(os.replace, temporary, path)
    _sync_directory(parent)


def _manifest(entry: dict) -> dict:
    return {"format": FORMAT, "provider": PROVIDER, **{key: entry[key] for key in _IMMUTABLE}}


def _check_meta(meta: object) -> dict:
    if not isinstance(meta, dict) or type(meta.get("format")) is not int or meta["format"] != 1 \
            or meta.get("tool") != "burpzip":
        _fail("unsupported native import archive metadata")
    _project_name(meta.get("orig_name"))
    _integer(meta.get("size"), "payload size")
    _mtime(meta.get("mtime"))
    _sha(meta.get("sha256"), "payload sha256")
    return meta


def _validate_entry(entry: object, logical_id: str, root_id: str) -> None:
    if not isinstance(entry, dict) or set(entry) - (_ENTRY_KEYS | _ENTRY_OPTIONAL) or not _ENTRY_KEYS <= set(entry):
        _fail("incompatible/corrupt native file entry")
    _uuid(logical_id, "logical file UUID")
    if entry["logical_file_id"] != logical_id or entry["root_id"] != root_id:
        _fail("native entry IDs do not match their catalog")
    _project_name(entry["name"])
    if entry["archive_rel"] != f"archives/{logical_id}/import.burpz":
        _fail("unsafe or incompatible immutable archive path")
    _sha(entry["archive_sha256"], "archive sha256")
    _sha(entry["payload_sha256"], "payload sha256")
    _integer(entry["archive_size"], "archive size")
    _integer(entry["size"], "payload size")
    _mtime(entry["mtime"])
    if _identity(entry["placeholder_identity"]) != cfapi.file_identity(root_id, logical_id, entry["archive_sha256"]):
        _fail("native placeholder identity does not match the immutable import")
    if entry["phase"] not in _PHASES or type(entry["replay_disabled"]) is not bool:
        _fail("invalid native journal phase/replay boundary")
    if "supersedes" in entry:
        _uuid(entry["supersedes"], "superseded logical file UUID")
    if entry["file_id"] is None:
        if entry["phase"] not in ("prepared", "superseded"):
            _fail("native entry has no recorded OS file identity")
    else:
        _identifier(entry["file_id"], "OS file identity")
    _timestamp(entry["created_at"], "import created_at")
    _timestamp(entry["updated_at"], "import updated_at")
    if entry["phase"] in ("ack-intent", "resident", "reverted") and not entry["replay_disabled"]:
        _fail("authoritative local data cannot be archive-replay eligible")
    verified = {"verified_sha256", "verified_size"} & set(entry)
    if verified and verified != {"verified_sha256", "verified_size"}:
        _fail("incomplete native verified-generation fields")
    if verified:
        if _sha(entry["verified_sha256"], "verified sha256") != entry["payload_sha256"] \
                or _integer(entry["verified_size"], "verified size") != entry["size"]:
            _fail("verified generation does not match the immutable payload")
    if entry["phase"] == "ack-intent" and not verified:
        _fail("ACK intent has no verified complete payload")
    for field in ("error", "note"):
        if field in entry and (not isinstance(entry[field], str) or len(entry[field]) > 2048):
            _fail(f"invalid native {field}")


def _validate_catalog(catalog: dict, path: str, *, allow_intent: bool = False) -> None:
    if set(catalog) != _CATALOG_KEYS or type(catalog.get("format")) is not int or catalog["format"] != FORMAT \
            or catalog.get("provider") != PROVIDER:
        _fail("incompatible/corrupt native store catalog")
    root_id = _uuid(catalog["root_id"], "root UUID")
    root = _canonical(catalog["root_path"], persisted=True)
    store = _canonical(catalog["store_path"], persisted=True)
    if store != path or _within(root, store) or _within(store, root):
        _fail("native root/store path changed or overlaps")
    _identifier(catalog["root_file_id"], "root OS identity")
    _identifier(catalog["store_file_id"], "store OS identity")
    if _identity(catalog["root_identity"]) != cfapi.root_identity(root_id, catalog["root_file_id"]):
        _fail("native root identity does not match its catalog")
    if catalog["policy"] != _POLICY or type(catalog["policy"].get("identity_format")) is not int \
            or type(catalog["policy"].get("validation_required")) is not bool \
            or type(catalog["policy"].get("file_always_full")) is not bool:
        _fail("incompatible native retention/hydration policy")
    if catalog["state"] != "registered" and not (allow_intent and catalog["state"] == "init-intent"):
        _fail("native initialization is incomplete; retain root/store for manual recovery")
    _timestamp(catalog["created_at"], "root created_at")
    _integer(catalog["revision"], "catalog revision", 1)
    if not isinstance(catalog["files"], dict) or len(catalog["files"]) > 10000:
        _fail("invalid native file catalog")
    names, file_ids = {}, set()
    for logical_id, entry in catalog["files"].items():
        _validate_entry(entry, logical_id, root_id)
        if entry["phase"] == "superseded":
            continue  # Retired generation: name/file identity belong to its successor.
        folded = entry["name"].casefold()
        if folded in names:
            other = catalog["files"][names[folded]]
            pending = [e for e in (entry, other) if e["phase"] == "prepared" and "supersedes" in e]
            if len(pending) != 1 or pending[0]["supersedes"] not in (logical_id, names[folded]) \
                    or pending[0]["supersedes"] == pending[0]["logical_file_id"]:
                _fail("case-colliding native project names")
        else:
            names[folded] = logical_id
        if entry["file_id"] is not None:
            if entry["file_id"] in file_ids:
                _fail("duplicate native OS file identities")
            file_ids.add(entry["file_id"])
    if not isinstance(catalog["staging"], list) or len(catalog["staging"]) > 32:
        _fail("invalid owned staging references")
    stage_ids = set()
    for stage in catalog["staging"]:
        if not isinstance(stage, dict) or set(stage) != {"stage_id", "path", "logical_file_id", "created_at", "directory_id"}:
            _fail("corrupt owned staging reference")
        stage_id = _uuid(stage["stage_id"], "stage UUID")
        if stage_id in stage_ids or stage["logical_file_id"] not in catalog["files"]:
            _fail("duplicate/orphan owned staging reference")
        stage_ids.add(stage_id)
        stage_path = _canonical(stage["path"], persisted=True)
        if os.path.basename(stage_path) != f"burpzip-native-{stage_id}" \
                or _within(stage_path, root) or _within(stage_path, store):
            _fail("unsafe owned staging reference")
        _identifier(stage["directory_id"], "stage directory identity")
        _timestamp(stage["created_at"], "stage created_at")


def _journal_summary(entry: dict | None) -> dict | None:
    if entry is None:
        return None
    keys = ("logical_file_id", "archive_sha256", "placeholder_identity", "file_id", "phase", "replay_disabled")
    result = {key: entry[key] for key in keys}
    for key in ("verified_sha256", "verified_size"):
        if key in entry:
            result[key] = entry[key]
    return result


def _append_intent(path: str, catalog: dict, operation: str, phase: str, entry: dict | None = None) -> None:
    record = {
        "format": FORMAT, "operation_id": str(uuid.uuid4()), "type": operation, "phase": phase,
        "root_id": catalog["root_id"], "revision": catalog["revision"], "at": _utc(),
        "catalog_sha256": hashlib.sha256(_json_bytes(catalog)).hexdigest(),
        "entry": _journal_summary(entry), "staging": catalog["staging"],
    }
    data = _json_bytes(record)
    journal = os.path.join(path, JOURNAL)
    _directory(path)
    if os.path.lexists(journal):
        if _regular(journal).st_size + len(data) > _JOURNAL_LIMIT:
            _fail("native journal capacity reached; retain state for manual maintenance")
    fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "ab") as stream:
        if os.fstat(stream.fileno()).st_nlink != 1:
            _fail("native journal is not privately owned")
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path)


def _check_journal(path: str, catalog: dict) -> None:
    with _read_pin(os.path.join(path, JOURNAL), share=7) as stream:
        data = stream.read(_JOURNAL_LIMIT + 1)
    if not data or len(data) > _JOURNAL_LIMIT or not data.endswith(b"\n"):
        _fail("missing, oversized, or interrupted native journal")
    expected = 1
    last = None
    replay_disabled = set()
    for line in data.splitlines():
        row = _parse_json(line)
        if set(row) != {"format", "operation_id", "type", "phase", "root_id", "revision", "at", "catalog_sha256", "entry", "staging"} \
                or type(row["format"]) is not int or row["format"] != FORMAT \
                or row["root_id"] != catalog["root_id"] \
                or type(row["revision"]) is not int or row["revision"] != expected:
            _fail("incompatible/corrupt native journal sequence")
        _uuid(row["operation_id"], "journal operation UUID")
        _timestamp(row["at"], "journal at")
        _sha(row["catalog_sha256"], "journal catalog sha256")
        if row["type"] not in {"init", "import", "mark", "staging", "rezip"} or not isinstance(row["phase"], str):
            _fail("invalid native journal operation")
        summary = row["entry"]
        if summary is not None:
            if not isinstance(summary, dict) or set(summary) - {
                "logical_file_id", "archive_sha256", "placeholder_identity", "file_id", "phase",
                "replay_disabled", "verified_sha256", "verified_size",
            } or not {"logical_file_id", "archive_sha256", "placeholder_identity", "file_id", "phase", "replay_disabled"} <= set(summary):
                _fail("invalid native journal generation")
            logical_id = _uuid(summary["logical_file_id"], "journal logical file UUID")
            if logical_id not in catalog["files"]:
                _fail("journal refers to a missing immutable import")
            current = catalog["files"][logical_id]
            if summary["archive_sha256"] != current["archive_sha256"] \
                    or summary["placeholder_identity"] != current["placeholder_identity"] \
                    or summary["phase"] not in _PHASES or type(summary["replay_disabled"]) is not bool:
                _fail("journal generation mismatches immutable import")
            if summary["file_id"] is not None and summary["file_id"] != current["file_id"]:
                _fail("journal OS file identity changed")
            if logical_id in replay_disabled and not summary["replay_disabled"]:
                _fail("journal attempts to reverse authoritative local data")
            if summary["replay_disabled"]:
                replay_disabled.add(logical_id)
            if summary["phase"] == "ack-intent":
                if not summary["replay_disabled"] or summary.get("verified_sha256") != current["payload_sha256"] \
                        or summary.get("verified_size") != current["size"]:
                    _fail("invalid irreversible pre-ACK journal record")
        if not isinstance(row["staging"], list):
            _fail("invalid journal staging references")
        last = row
        expected += 1
    if last is None or last["revision"] != catalog["revision"] \
            or last["catalog_sha256"] != hashlib.sha256(_json_bytes(catalog)).hexdigest():
        _fail("native journal/catalog publication is interrupted or mismatched; no replay or guessed repair")
    for logical_id in replay_disabled:
        if not catalog["files"][logical_id]["replay_disabled"]:
            _fail("catalog lost an irreversible replay boundary")


class _ExclusiveLease:
    """Persistent lockfile; never unlink it (avoids stale-lock inode races)."""

    def __init__(self, path: str):
        self.path = path
        self.fd = None
        self.dll = None
        self.handle = None
        _directory(os.path.dirname(path))
        if os.path.lexists(path):
            _regular(path)
        try:
            if os.name == "nt":
                # Handle information was checked by _win_open. Do not reopen
                # this no-share lockfile for stat: that can violate sharing.
                self.dll, self.handle = _win_open(path, 0x80000000 | 0x40000000, 0, 4)  # OPEN_ALWAYS, no sharing
            else:
                import fcntl

                self.fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                if os.fstat(self.fd).st_nlink != 1:
                    _fail("native lockfile is hard-linked")
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, NativeError) as exc:
            self.close()
            raise NativeError("native store is leased or its lockfile is unsafe; stop the foreground provider first") from exc

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.handle is not None:
            success = self.dll.CloseHandle(self.handle)
            self.handle = None
            if not success:
                _fail("failed closing native lease handle")


class NativeStore:
    """A validated immutable catalog plus a process-instance provider lease."""

    def __init__(self, store_path: str, api=None):
        self.path = _canonical(store_path)
        self.api = api if api is not None else cfapi.WindowsCfApi()
        self._store_id = _stat_id(_directory(self.path))
        self._mutex = threading.RLock()
        self._lease_guard = threading.RLock()
        self._lease_handle = None
        self._lease_thread = None
        self._lease_depth = 0
        self._catalog = {}
        self._reload()
        self.root = self._catalog["root_path"]

    @property
    def catalog(self) -> dict:
        return copy.deepcopy(self._catalog)

    def _store_anchor(self) -> None:
        if _stat_id(_directory(self.path)) != self._store_id:
            _fail("native store directory was replaced")
        for ancestor in _parents(self.path):
            # The store's own folder carries the marker, which the adapter
            # (correctly) refuses to treat as an ordinary sync-root candidate.
            if ancestor != self.path and self.api.inspect_root(ancestor) is not None:
                _fail("native store has registered/cloud ancestry")
            if ancestor != self.path and os.path.lexists(os.path.join(ancestor, MARKER)):
                _fail("native store is nested inside another marked store")

    def _reload(self) -> None:
        # A reader without the lease (e.g. `status` while `serve` runs) can land
        # between the writer's journal append and catalog replace. Re-read
        # briefly; persistent mismatch still fails closed with no repair.
        for attempt in range(20):
            self._store_anchor()
            catalog = _load_json(os.path.join(self.path, MARKER))
            _validate_catalog(catalog, self.path)
            if catalog["store_file_id"] != self._store_id:
                _fail("native store OS identity does not match its catalog")
            if self._catalog and any(catalog[key] != self._catalog[key] for key in (
                "root_id", "root_path", "root_file_id", "root_identity", "store_path", "store_file_id", "policy",
                "created_at",
            )):
                _fail("native store/root immutable identity changed")
            try:
                _check_journal(self.path, catalog)
                break
            except NativeError:
                if self._lease_handle is not None or attempt == 19:
                    raise
                time.sleep(0.1)
        for entry in catalog["files"].values():
            manifest_path = os.path.join(self.path, "archives", entry["logical_file_id"], "manifest.json")
            if _load_json(manifest_path) != _manifest(entry):
                _fail("immutable native import manifest mismatches catalog")
        self._catalog = catalog

    def _root_anchor(self) -> None:
        self._store_anchor()
        root = self._catalog["root_path"]
        _directory(root, cloud_root=True)
        for ancestor in _parents(root):
            if os.path.lexists(os.path.join(ancestor, MARKER)):
                _fail("native root has store-marked ancestry")
            if ancestor != root and self.api.inspect_root(ancestor) is not None:
                _fail("native root is nested under another cloud registration")
        if self.api.file_id(root) != self._catalog["root_file_id"]:
            _fail("native root OS identity changed")
        info = self.api.inspect_root(root)
        if not isinstance(info, dict) or _identity(info.get("identity")) != _identity(self._catalog["root_identity"]):
            _fail("native root registration is missing or foreign")
        for field, expected in (("root_id", self._catalog["root_id"]), ("root_file_id", self._catalog["root_file_id"])):
            if field in info and info[field] != expected:
                _fail(f"native registration {field} mismatches catalog")
        if "policy" in info and info["policy"] != _POLICY:
            _fail("native registration policy mismatches catalog")

    @contextmanager
    def lease(self) -> Iterator[NativeStore]:
        """Fail immediately if another process/instance owns serve or mutation.

        Worker threads of this instance may mutate under a main-thread lease;
        explicit nested lease() calls are only permitted on its acquiring thread.
        """
        thread = threading.get_ident()
        with self._lease_guard:
            if self._lease_handle is not None:
                if self._lease_thread != thread:
                    _fail("native store already has a lease on another thread")
                self._lease_depth += 1
            else:
                self._store_anchor()
                handle = _ExclusiveLease(os.path.join(self.path, LOCKFILE))
                try:
                    with self._mutex:
                        self._reload()
                        self._root_anchor()
                except BaseException:
                    handle.close()
                    raise
                self._lease_handle = handle
                self._lease_thread = thread
                self._lease_depth = 1
        try:
            yield self
        finally:
            with self._lease_guard:
                self._lease_depth -= 1
                if self._lease_depth == 0:
                    handle = self._lease_handle
                    self._lease_handle = None
                    self._lease_thread = None
                    handle.close()

    @contextmanager
    def _auto_lease(self) -> Iterator[None]:
        # Do not hold _mutex while acquiring lease: lease acquisition reloads it.
        with self._lease_guard:
            held = self._lease_handle is not None
        if held:
            yield
        else:
            with self.lease():
                yield

    @staticmethod
    def _active(row: dict) -> bool:
        # Excludes retired generations and a not-yet-switched re-zip generation.
        return row["phase"] != "superseded" and not (row["phase"] == "prepared" and "supersedes" in row)

    def entries(self) -> list[dict]:
        with self._mutex:
            return copy.deepcopy([row for row in self._catalog["files"].values() if self._active(row)])

    def entry(self, name: str) -> dict:
        _project_name(name)
        with self._mutex:
            matches = [row for row in self._catalog["files"].values()
                       if self._active(row) and row["name"].casefold() == name.casefold()]
            if len(matches) != 1:
                _fail(f"native project is not cataloged: {name}")
            return copy.deepcopy(matches[0])

    def _matched(self, entry: dict) -> dict:
        if not isinstance(entry, dict):
            _fail("native operation requires a catalog entry")
        logical_id = entry.get("logical_file_id")
        if not isinstance(logical_id, str) or logical_id not in self._catalog["files"]:
            _fail("native entry is not owned by this store")
        current = self._catalog["files"][logical_id]
        if any(entry.get(key) != current[key] for key in _IMMUTABLE):
            _fail("native entry immutable IDs/generation changed")
        if entry.get("file_id") is not None and entry.get("file_id") != current["file_id"]:
            _fail("native entry OS file identity mismatches catalog")
        return copy.deepcopy(current)

    def archive_path(self, entry: dict) -> str:
        with self._mutex:
            self._store_anchor()
            row = self._matched(entry)
            result = os.path.join(self.path, "archives", row["logical_file_id"], "import.burpz")
            if _key(os.path.realpath(result)) != _key(result) or not _within(result, self.path):
                _fail("immutable native archive escapes its store")
            _regular(result)
            manifest_path = os.path.join(os.path.dirname(result), "manifest.json")
            if _load_json(manifest_path) != _manifest(row):
                _fail("immutable native import manifest changed")
            return result

    @contextmanager
    def pinned_archive(self, entry: dict, stop_event=None, *, verify_payload: bool = True) -> Iterator[str]:
        """Pin the exact immutable archive generation for reading.

        Always checks the archive file's full SHA-256 against the catalog (the
        archive was fully verified at import). verify_payload=False skips the
        extra full 7z test + payload SHA decompression passes: unpacking hashes
        the payload while streaming and again on read-back before validation,
        and Windows cancels a fetch that delivers nothing for ~60 seconds.
        """
        with self._auto_lease():
            with self._mutex:
                self._reload()
                row = self._matched(entry)
                path = self.archive_path(row)
            with _read_pin(path) as stream:
                before = os.fstat(stream.fileno())
                if before.st_size != row["archive_size"]:
                    _fail("immutable native archive size changed")
                digest = hashlib.sha256()

                def cancelled(*_args):
                    if stop_event is not None and stop_event.is_set():
                        _fail("native archive verification cancelled")

                cancelled()
                while True:
                    cancelled()
                    chunk = stream.read(_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                if digest.hexdigest() != row["archive_sha256"]:
                    _fail("immutable native archive full-file SHA-256 changed")
                meta = _check_meta(archiver.verify_archive(path, progress=cancelled) if verify_payload
                                   else archiver.read_meta(path))
                if (meta["orig_name"], meta["size"], meta["mtime"], meta["sha256"]) != \
                        (row["name"], row["size"], row["mtime"], row["payload_sha256"]):
                    _fail("immutable archive payload metadata changed")
                cancelled()
                self._check_pin(path, stream, before)
                try:
                    yield path
                finally:
                    self._check_pin(path, stream, before)

    @staticmethod
    def _check_pin(path: str, stream, before: os.stat_result) -> None:
        if _generation(os.fstat(stream.fileno())) != _generation(before) \
                or _generation(_regular(path)) != _generation(before):
            _fail("immutable archive descriptor/path generation changed")

    def _commit(self, candidate: dict, operation: str, phase: str, entry: dict | None = None) -> None:
        self._store_anchor()
        candidate["revision"] = self._catalog["revision"] + 1
        _validate_catalog(candidate, self.path)
        _append_intent(self.path, candidate, operation, phase, entry)
        _atomic_json(os.path.join(self.path, MARKER), candidate)
        self._catalog = candidate

    def mark(self, entry: dict, phase: str, **updates) -> dict:
        """Journal an exact generation before publishing; never reverse ACK intent."""
        if phase == "ackintent":
            phase = "ack-intent"
        if phase not in _PHASES or set(updates) - (_ENTRY_OPTIONAL | {"file_id", "replay_disabled"}):
            _fail("unsupported native phase/update fields")
        with self._auto_lease():
            with self._mutex:
                self._reload()
                self._root_anchor()
                current = self._matched(entry)
                if _PHASES.index(phase) < _PHASES.index(current["phase"]):
                    _fail("native phase cannot regress or re-enable archive replay")
                if "file_id" in updates and (current["file_id"] is not None or current["phase"] != "prepared"):
                    _fail("recorded native OS identity is immutable")
                if "replay_disabled" in updates and updates["replay_disabled"] is not True:
                    _fail("native replay boundary cannot be cleared")
                row = {**current, **updates, "phase": phase, "updated_at": _utc()}
                if phase in ("ack-intent", "resident", "reverted"):
                    row["replay_disabled"] = True
                _validate_entry(row, row["logical_file_id"], self._catalog["root_id"])
                candidate = copy.deepcopy(self._catalog)
                candidate["files"][row["logical_file_id"]] = row
                self._commit(candidate, "mark", phase, row)
                return copy.deepcopy(row)

    # ----- re-zip generations ---------------------------------------------------------
    def begin_rezip(self, entry: dict, archive: str) -> dict:
        """Publish a verified archive of the CURRENT bytes as a prepared new generation.

        The old generation stays authoritative until finish_rezip(); a crash in
        between is resolved by recover_rezips() from the file's real identity.
        """
        with self._auto_lease():
            with self._mutex:
                self._reload()
                self._root_anchor()
                current = self._matched(entry)
                if not self._active(current) or current["phase"] not in ("resident", "ack-intent") \
                        or not current["replay_disabled"]:
                    _fail("only an unpacked (resident) project can be re-zipped")
                archive = _canonical(archive)
                original = _regular(archive)
                if shutil.disk_usage(self.path).free < original.st_size + SPACE_MARGIN:
                    _fail("insufficient native store space for the re-zipped archive and reserve")
                logical_id = str(uuid.uuid4())
                private_dir = os.path.join(self.path, "archives", logical_id)
                os.mkdir(private_dir, 0o700)
                private_archive = os.path.join(private_dir, "import.burpz")
                digest, copied = hashlib.sha256(), 0
                with _read_pin(archive) as source:
                    fd = os.open(private_archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    with os.fdopen(fd, "wb") as output:
                        for chunk in iter(lambda: source.read(_CHUNK), b""):
                            copied += len(chunk)
                            output.write(chunk)
                            digest.update(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                _sync_directory(private_dir)
                with _read_pin(private_archive) as pinned:
                    before = os.fstat(pinned.fileno())
                    meta = _check_meta(archiver.verify_archive(private_archive))
                    NativeStore._check_pin(private_archive, pinned, before)
                if meta["orig_name"] != current["name"]:
                    _fail("re-zipped archive names a different project")
                now = _utc()
                row = {
                    "root_id": self._catalog["root_id"], "logical_file_id": logical_id, "name": current["name"],
                    "archive_rel": f"archives/{logical_id}/import.burpz", "archive_sha256": digest.hexdigest(),
                    "archive_size": copied, "payload_sha256": meta["sha256"], "size": meta["size"],
                    "mtime": meta["mtime"], "file_id": None,
                    "placeholder_identity": cfapi.file_identity(self._catalog["root_id"], logical_id,
                                                                digest.hexdigest()).hex(),
                    "phase": "prepared", "replay_disabled": False, "created_at": now, "updated_at": now,
                    "supersedes": current["logical_file_id"],
                }
                _write_once(os.path.join(private_dir, "manifest.json"), _json_bytes(_manifest(row)))
                candidate = copy.deepcopy(self._catalog)
                candidate["files"][logical_id] = row
                self._commit(candidate, "rezip", "prepared", row)
                return copy.deepcopy(row)

    def finish_rezip(self, new: dict, file_id: str) -> dict:
        """The placeholder now carries the new identity: retire the old generation."""
        with self._auto_lease():
            with self._mutex:
                self._reload()
                row = self._matched(new)
                if row["phase"] != "prepared" or "supersedes" not in row:
                    _fail("no pending re-zip generation to finish")
                old = self._catalog["files"][row["supersedes"]]
                if old["file_id"] != file_id:
                    _fail("re-zip target OS identity mismatch")
                now = _utc()
                candidate = copy.deepcopy(self._catalog)
                candidate["files"][old["logical_file_id"]] = {**old, "phase": "superseded", "updated_at": now}
                switched = {**row, "file_id": file_id, "phase": "placeholder", "updated_at": now}
                candidate["files"][row["logical_file_id"]] = switched
                self._commit(candidate, "rezip", "switched", switched)
                self._discard_archive(old)
                return copy.deepcopy(switched)

    def abort_rezip(self, new: dict) -> None:
        """The placeholder still carries the old identity: retire the unused generation."""
        with self._auto_lease():
            with self._mutex:
                self._reload()
                row = self._matched(new)
                if row["phase"] != "prepared" or "supersedes" not in row:
                    _fail("no pending re-zip generation to abort")
                candidate = copy.deepcopy(self._catalog)
                candidate["files"][row["logical_file_id"]] = {**row, "phase": "superseded", "updated_at": _utc()}
                self._commit(candidate, "rezip", "aborted", None)
                self._discard_archive(row)

    def recover_rezips(self) -> list[str]:
        """Resolve interrupted re-zips from the file's actual identity, never by guessing."""
        done = []
        with self._auto_lease():
            with self._mutex:
                self._reload()
                pending = [copy.deepcopy(r) for r in self._catalog["files"].values()
                           if r["phase"] == "prepared" and "supersedes" in r]
            for row in pending:
                old = self._catalog["files"][row["supersedes"]]
                path = os.path.join(self._catalog["root_path"], row["name"])
                state = self.api.inspect(path)
                if state.file_id == old["file_id"] and _identity(state.identity) == _identity(row["placeholder_identity"]):
                    self.finish_rezip(row, old["file_id"])
                    done.append(f"{row['name']}: finished interrupted re-zip")
                elif state.file_id == old["file_id"] and _identity(state.identity) == _identity(old["placeholder_identity"]):
                    self.abort_rezip(row)
                    done.append(f"{row['name']}: abandoned interrupted re-zip (project unchanged)")
                else:
                    _fail(f"interrupted re-zip of {row['name']} is ambiguous; retained for manual recovery")
        return done

    def _discard_archive(self, row: dict) -> None:
        # Only the retired generation's own private archive; its manifest stays for the journal.
        path = os.path.join(self.path, "archives", row["logical_file_id"], "import.burpz")
        try:
            _regular(path)
            _retry_sharing(os.remove, path)
        except (NativeError, OSError):
            pass  # Space is reclaimed later; correctness does not depend on it.

    def inspect_entry(self, entry: dict) -> PathState:
        """Metadata-only inspection. Ready local edits are authoritative, not corrupt."""
        with self._mutex:
            self._root_anchor()
            row = self._matched(entry)
            return self._inspect_row(row)

    def _inspect_row(self, row: dict) -> PathState:
        if row["file_id"] is None:
            _fail("native placeholder creation has no committed OS identity")
        path = os.path.join(self._catalog["root_path"], row["name"])
        try:
            st = os.lstat(path)
        except OSError as exc:
            raise NativeError(f"native placeholder is missing: {row['name']}") from exc
        # Native cloud reparse leaves are expected, but symlinks/hardlinks are not.
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
            _fail("native placeholder was replaced by a link/non-file")
        if self.api.file_id(path) != row["file_id"]:
            _fail("native placeholder OS identity changed")
        state = self.api.inspect(path)
        if state.file_id != row["file_id"] or _key(state.path) != _key(path):
            _fail("native inspection returned a different file identity/path")
        _integer(state.size, "observed native file size")
        if type(state.ready) is not bool or type(state.modified) is not bool:
            _fail("native inspection has ambiguous readiness/modified state")
        if row["phase"] == "reverted" and row["replay_disabled"] and not state.identity \
                and state.kind in ("ordinary", "native") and state.resident:
            # Reverted inside the still-registered root: a plain resident file.
            if _reparse(st) and not _cloud_tag(st):
                _fail("reverted ordinary file is a non-cloud reparse object")
            return state
        if state.kind != "native" or state.root_id != self._catalog["root_id"] \
                or state.root_path is None or _key(state.root_path) != _key(self._catalog["root_path"]) \
                or _identity(state.identity) != _identity(row["placeholder_identity"]):
            _fail("native placeholder ownership/generation is missing, foreign, or unknown")
        if row["replay_disabled"] and state.resident:
            return state  # Past the durable boundary: local edits are authoritative.
        if not state.ready and (state.modified or state.size != row["size"]):
            _fail("non-ready native bytes are modified or resized; immutable archive replay refused")
        return state

    def _stage_parent(self) -> str:
        # Expand 8.3 short names (C:\Users\FIRSTN~1) before the lexical link checks.
        parent = _canonical(os.path.realpath(tempfile.gettempdir()))
        _ordinary_directory(parent, self.api)
        if _within(parent, self._catalog["root_path"]) or _within(parent, self.path):
            _fail("default temporary staging lies inside the registered root/store")
        return parent

    @staticmethod
    def _volume(path: str) -> str:
        if os.name != "nt":
            return str(os.stat(path).st_dev)
        from ctypes import wintypes

        dll = ctypes.WinDLL("kernel32", use_last_error=True)
        dll.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        dll.GetVolumePathNameW.restype = wintypes.BOOL
        dll.GetVolumeNameForVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        dll.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL
        mount = ctypes.create_unicode_buffer(32768)
        volume = ctypes.create_unicode_buffer(128)
        if not dll.GetVolumePathNameW(path, mount, len(mount)) \
                or not dll.GetVolumeNameForVolumeMountPointW(mount.value, volume, len(volume)):
            _fail("cannot determine actual native staging/root volume")
        return volume.value.casefold()

    def check_hydration_space(self, entry: dict, staged: bool = False) -> dict:
        """Charge staging + root before extraction, only root after staging exists."""
        if type(staged) is not bool:
            _fail("staged capacity flag must be boolean")
        with self._mutex:
            self._root_anchor()
            row = self._matched(entry)
            stage = self._stage_parent()
            root = self._catalog["root_path"]
            volumes = {}
            # Once staged, the staged copy already consumed its space; charge
            # only the hydrated destination plus the reserve.
            for path in ((root,) if staged else (stage, root)):
                volume = self._volume(path)
                if volume not in volumes:
                    volumes[volume] = {"volume": volume, "needed": SPACE_MARGIN, "paths": [],
                                       "free": shutil.disk_usage(path).free}
                volumes[volume]["needed"] += row["size"]
                volumes[volume]["paths"].append(path)
            for capacity in volumes.values():
                if capacity["free"] < capacity["needed"]:
                    _fail(f"insufficient hydration space on {capacity['paths']}: "
                          f"need {capacity['needed']} bytes, have {capacity['free']}")
            return {"stage_path": stage, "root_path": root, "reserve": SPACE_MARGIN,
                    "volumes": list(volumes.values())}

    @contextmanager
    def staging(self, entry: dict) -> Iterator[str]:
        """Yield a NEW empty ordinary directory outside registered/marked ancestry.

        Only this invocation's identity-checked flat directory is cleaned. An
        unexpected directory/link or changed stage identity preserves recovery
        references instead of following attacker-controlled persisted paths.
        """
        with self._auto_lease():
            with self._mutex:
                self._reload()
                row = self._matched(entry)
                self.check_hydration_space(row)
                parent = self._stage_parent()
                stage_id = str(uuid.uuid4())
                path = os.path.join(parent, f"burpzip-native-{stage_id}")
                os.mkdir(path, 0o700)
                directory_id = _stat_id(_ordinary_directory(path, self.api))
                reference = {"stage_id": stage_id, "path": path, "logical_file_id": row["logical_file_id"],
                             "created_at": _utc(), "directory_id": directory_id}
                candidate = copy.deepcopy(self._catalog)
                candidate["staging"].append(reference)
                self._commit(candidate, "staging", "owned", row)
            body_error = None
            try:
                yield path
            except BaseException as exc:
                body_error = exc
                raise
            finally:
                try:
                    with self._mutex:
                        self._reload()
                        self._clean_stage(reference)
                        candidate = copy.deepcopy(self._catalog)
                        candidate["staging"] = [stage for stage in candidate["staging"]
                                                if stage["stage_id"] != stage_id]
                        self._commit(candidate, "staging", "released", self._matched(row))
                except Exception as cleanup:
                    # Keep the hydration failure visible; the persisted staging
                    # reference is retained for explicit recovery.
                    if body_error is None:
                        raise
                    raise NativeError(f"{body_error} (staging cleanup also failed: {cleanup}; "
                                      f"reference retained at {path})") from body_error

    def _clean_stage(self, reference: dict) -> None:
        # This method only receives the live invocation's reference, never a
        # persisted path selected by startup/status recovery.
        path = reference["path"]
        parent = self._stage_parent()
        if os.path.dirname(path) != parent or _stat_id(_ordinary_directory(path, self.api)) != reference["directory_id"]:
            _fail("owned staging directory changed; retain recovery reference")
        with os.scandir(path) as listing:
            children = list(listing)
        for child in children:
            if not _safe_component(child.name):
                _fail("unsafe staging child; retain recovery reference")
            _regular(child.path)
        for child in children:
            _regular(child.path)
            _retry_sharing(os.unlink, child.path)
        _retry_sharing(os.rmdir, path)

    def status(self) -> dict:
        """Read-only actual metadata; never infer completion from journal phase."""
        with self._mutex:
            self._reload()
            errors = []
            try:
                self._root_anchor()
                registered = True
            except (NativeError, OSError) as exc:
                registered = False
                errors.append(str(exc))
            files = []
            for row in self.entries():
                item = {"name": row["name"], "logical_file_id": row["logical_file_id"], "phase": row["phase"],
                        "replay_disabled": row["replay_disabled"], "expected_size": row["size"],
                        "kind": "unknown", "ready": False, "modified": None, "size": None, "note": ""}
                try:
                    state = self.inspect_entry(row)
                    item.update(kind=state.kind, ready=state.ready, resident=state.resident,
                                modified=state.modified, size=state.size,
                                file_id=state.file_id, note=state.note)
                    archive = self.archive_path(row)
                    item["archive_present"] = _regular(archive).st_size == row["archive_size"]
                    if not item["archive_present"]:
                        _fail("stored archive size changed")
                except (NativeError, OSError) as exc:
                    item["note"] = str(exc)
                    errors.append(f"{row['name']}: {exc}")
                files.append(item)
            return {"format": FORMAT, "root": self.root, "store": self.path, "root_id": self._catalog["root_id"],
                    "registered": registered, "revision": self._catalog["revision"], "files": files,
                    "staging": copy.deepcopy(self._catalog["staging"]), "errors": errors}


def init_root(root: str, store: str, api=None) -> dict:
    """Register only two new, existing empty ordinary folders; never auto-create."""
    api = api if api is not None else cfapi.WindowsCfApi()
    root, store = _canonical(root), _canonical(store)
    if _within(root, store) or _within(store, root):
        _fail("native root and store must be separate, nonoverlapping folders")
    root_st = _ordinary_directory(root, api)
    store_st = _ordinary_directory(store, api)
    if _stat_id(root_st) == _stat_id(store_st):
        _fail("native root/store alias the same directory")
    if os.listdir(root) or os.listdir(store):
        _fail("native initialization requires existing empty root and store folders")
    handle = _ExclusiveLease(os.path.join(store, LOCKFILE))
    try:
        if os.listdir(root) or set(os.listdir(store)) != {LOCKFILE} \
                or _stat_id(_ordinary_directory(root, api)) != _stat_id(root_st) \
                or _stat_id(_ordinary_directory(store, api)) != _stat_id(store_st):
            _fail("native initialization folders changed before registration intent")
        root_id = str(uuid.uuid4())
        root_file_id = _identifier(api.file_id(root), "root OS identity")
        identity = cfapi.root_identity(root_id, root_file_id)
        catalog = {
            "format": FORMAT, "provider": PROVIDER, "root_id": root_id, "root_path": root,
            "root_file_id": root_file_id, "root_identity": identity.hex(), "store_path": store,
            "store_file_id": _stat_id(store_st), "policy": copy.deepcopy(_POLICY), "created_at": _utc(),
            "state": "init-intent", "revision": 1, "files": {}, "staging": [],
        }
        _validate_catalog(catalog, store, allow_intent=True)
        _append_intent(store, catalog, "init", "init-intent")
        _atomic_json(os.path.join(store, MARKER), catalog)
        # Recheck immediately before the only registration side effect. There is
        # no claim that this eliminates hostile external namespace races.
        if os.listdir(root) or api.file_id(root) != root_file_id or api.inspect_root(root) is not None:
            _fail("native root changed before registration; initialization intent retained")
        _directory(root)
        api.register(root, identity)
        info = api.inspect_root(root)
        if api.file_id(root) != root_file_id or not isinstance(info, dict) \
                or _identity(info.get("identity")) != identity:
            _fail("native registration could not be verified; retain root/store without unregistering")
        catalog = {**catalog, "state": "registered", "revision": 2}
        _append_intent(store, catalog, "init", "registered")
        _atomic_json(os.path.join(store, MARKER), catalog)
        return copy.deepcopy(catalog)
    finally:
        handle.close()


def add_archive(store: str | NativeStore, archive: str, api=None) -> dict:
    """Preserve the input and publish an immutable verified import before create."""
    if isinstance(store, NativeStore):
        native = store
        if api is not None and api is not native.api:
            _fail("cannot replace a NativeStore adapter during import")
    else:
        native = NativeStore(store, api=api)
    archive = _canonical(archive)
    if not archive.lower().endswith(".burpz"):
        _fail("native import requires an existing .burpz archive")
    _ordinary_directory(os.path.dirname(archive), native.api)
    original = _regular(archive)
    with native._auto_lease():
        with native._mutex:
            native._reload()
            native._root_anchor()
            for row in native.entries():
                native.inspect_entry(row)
            inventory = os.listdir(native.root)
            known_names = {row["name"].casefold() for row in native.entries()}
            if len({name.casefold() for name in inventory}) != len(inventory) \
                    or any(name.casefold() not in known_names for name in inventory):
                _fail("native root contains foreign/untracked/case-colliding entries")
            if shutil.disk_usage(native.path).free < original.st_size + SPACE_MARGIN:
                _fail("insufficient native store space for immutable compressed copy and reserve")
            logical_id = str(uuid.uuid4())
            archive_parent = os.path.join(native.path, "archives")
            if not os.path.lexists(archive_parent):
                os.mkdir(archive_parent, 0o700)
            _directory(archive_parent)
            private_dir = os.path.join(archive_parent, logical_id)
            os.mkdir(private_dir, 0o700)
            private_archive = os.path.join(private_dir, "import.burpz")
            with _read_pin(archive) as source:
                source_stat = os.fstat(source.fileno())
                if _generation(source_stat) != _generation(original):
                    _fail("native import input changed before copying")
                fd = os.open(private_archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
                digest, copied = hashlib.sha256(), 0
                with os.fdopen(fd, "wb") as output:
                    while True:
                        chunk = source.read(_CHUNK)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > original.st_size:
                            _fail("native import source grew while copying")
                        output.write(chunk)
                        digest.update(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                NativeStore._check_pin(archive, source, source_stat)
                if copied != original.st_size:
                    _fail("native import source was truncated")
            _sync_directory(private_dir)
            with _read_pin(private_archive) as pinned:
                before = os.fstat(pinned.fileno())
                meta = _check_meta(archiver.verify_archive(private_archive))
                NativeStore._check_pin(private_archive, pinned, before)
            name = meta["orig_name"]
            if name.casefold() in known_names or any(name.casefold() == other.casefold() for other in inventory) \
                    or os.path.lexists(os.path.join(native.root, name)):
                _fail("native import name collides with an existing project; original/private copy retained")
            now = _utc()
            entry = {
                "root_id": native._catalog["root_id"], "logical_file_id": logical_id, "name": name,
                "archive_rel": f"archives/{logical_id}/import.burpz", "archive_sha256": digest.hexdigest(),
                "archive_size": copied, "payload_sha256": meta["sha256"], "size": meta["size"], "mtime": meta["mtime"],
                "file_id": None, "placeholder_identity": cfapi.file_identity(native._catalog["root_id"], logical_id,
                                                                            digest.hexdigest()).hex(),
                "phase": "prepared", "replay_disabled": False, "created_at": now, "updated_at": now,
            }
            _write_once(os.path.join(private_dir, "manifest.json"), _json_bytes(_manifest(entry)))
            candidate = copy.deepcopy(native._catalog)
            candidate["files"][logical_id] = entry
            native._commit(candidate, "import", "prepared", entry)
            native._root_anchor()
            if os.path.lexists(os.path.join(native.root, name)):
                _fail("native placeholder destination appeared; immutable prepared import retained")
            actual_file_id = _identifier(native.api.create(native.root, name, entry["size"], entry["mtime"],
                                                           _identity(entry["placeholder_identity"])), "created OS file identity")
            observed = {**entry, "file_id": actual_file_id}
            native._inspect_row(observed)
            return native.mark(entry, "placeholder", file_id=actual_file_id)
