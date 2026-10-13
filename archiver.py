"""burpzip archiver - compress, verify, restore and re-zip Burp project files.

Archives are plain 7z (no encryption) named
``<project stem>.<YYYYMMDD-HHMMSS>.burpz`` next to the project (or in an
optional ``dest_dir``). Each archive holds two entries, added in two separate
7z runs so they live in separate 7z folders (solid blocks):

1. ``burpzip-meta.json`` - small metadata record (read without touching the
   big project stream), then
2. the ``.burp`` project under its original file name.

Safety rules (see design notes in the project):

* refuse while the project is in use (Burp holds a lock on it);
* check free space before writing anything;
* write in invocation-owned staging, commit without overwriting only after
  ``7z t`` and the archived project's size + streamed SHA-256 match the source;
* re-check size, mtime and lock state right before deleting the original;
* on failure clean only our staging and leave the original untouched;
* retain a committed verified archive if deleting the original fails;
* backups are never deleted automatically.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

import burpzip as bz

CHUNK = 8 * 1024**2  # hash / stream chunk size
META_NAME = "burpzip-meta.json"
ARCHIVE_EXT = ".burpz"
PARTIAL_EXT = ".partial"
META_FORMAT = 1
STAMP_FMT = "%Y%m%d-%H%M%S"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
_PCT_RE = re.compile(rb"(\d{1,3})%")

Progress = Optional[Callable[[str, Optional[float]], None]]


class ArchiveError(Exception):
    """Raised when an archive/restore/delete operation is refused or fails."""


@dataclass
class ArchiveResult:
    project_path: str
    archive_path: str
    original_size: int
    archive_size: int
    sha256: str
    seconds: float
    deleted_original: bool


# --- 7-Zip discovery and process helpers ------------------------------------
def find_7z() -> str:
    """Locate 7z.exe in Program Files, Program Files (x86) or on PATH."""
    candidates = []
    for var in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        base = os.environ.get(var)
        if base:
            candidates.append(os.path.join(base, "7-Zip", "7z.exe"))
    candidates += [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"]
    for c in candidates:
        if os.path.isfile(c):
            return c
    for name in ("7z", "7z.exe", "7za", "7za.exe"):
        found = shutil.which(name)
        if found:
            return found
    raise ArchiveError("7-Zip (7z.exe) not found; install it from https://www.7-zip.org/")


try:
    SEVEN_ZIP: str = find_7z()
except ArchiveError:
    SEVEN_ZIP = ""


def _exe() -> str:
    """Return the 7z path, discovering it late if it was missing at import."""
    global SEVEN_ZIP
    if not SEVEN_ZIP:
        SEVEN_ZIP = find_7z()
    return SEVEN_ZIP


def _report(progress: Progress, stage: str, fraction: float | None) -> None:
    if progress is not None:
        progress(stage, fraction)


def _check_cancel(stop_event: threading.Event | None) -> None:
    if stop_event is not None and stop_event.is_set():
        raise ArchiveError("archive operation cancelled")


@contextmanager
def _cancel_child(proc, stop_event: threading.Event | None):
    """A cancellation watcher can unblock a hung child pipe without touching data."""
    if stop_event is None:
        yield
        return
    done = threading.Event()

    def watch() -> None:
        while not done.is_set():
            if stop_event.wait(0.05):
                if not done.is_set():
                    try:
                        proc.kill()
                    except OSError:
                        pass  # The child may already have exited.
                return

    watcher = threading.Thread(target=watch, name="burpzip-7z-cancel")
    watcher.start()
    try:
        yield
    finally:
        done.set()
        watcher.join()
        _check_cancel(stop_event)


def _control(stop_event: threading.Event | None) -> dict:
    return {"stop_event": stop_event} if stop_event is not None else {}


def _ordinary(*paths: str) -> None:
    for path in paths:
        try:
            bz.require_ordinary_path(path)
        except Exception as exc:
            raise ArchiveError(f"ordinary operation refused for {path}: {exc}") from exc


def _readable_archive(path: str) -> None:
    state = bz.native_state(path)
    if state.kind not in ("ordinary", "store"):
        raise ArchiveError(f"archive input is {state.kind}; implicit hydration refused: {path}")


def _run_7z(args: list[str], stage: str | None = None, progress: Progress = None,
            *, stop_event: threading.Event | None = None) -> str:
    """Run 7z with list args, parse -bsp1 percentages, raise on non-zero exit.

    Returns the tail of the combined output (for diagnostics).
    """
    _check_cancel(stop_event)
    cmd = [_exe(), *args]
    if stage:
        cmd.insert(2, "-bsp1")
    tail = b""
    last = -1
    with subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW) as proc:
        assert proc.stdout is not None
        with _cancel_child(proc, stop_event):
            try:
                while True:
                    chunk = proc.stdout.read1(65536)
                    _check_cancel(stop_event)
                    if not chunk:
                        break
                    tail = (tail + chunk)[-8192:]
                    if stage and progress:
                        found = _PCT_RE.findall(chunk)
                        if found:
                            pct = min(100, int(found[-1]))
                            if pct != last:
                                last = pct
                                progress(stage, pct / 100)
                rc = proc.wait()
            except BaseException:
                proc.kill()
                proc.wait()
                raise
    text = tail.decode("utf-8", errors="replace").replace("\b", "")
    if rc != 0:
        msg = " ".join(text.split())[-600:]
        raise ArchiveError(f"7z {args[0]} failed (exit {rc}): {msg}")
    return text


def _stream_7z(args: list[str], sink: Callable[[bytes], None],
               *, stop_event: threading.Event | None = None) -> None:
    """Run 7z writing to stdout (-so); feed stdout to ``sink`` in CHUNK pieces."""
    _check_cancel(stop_event)
    err: list[bytes] = []
    with subprocess.Popen([_exe(), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW) as proc:

        def drain() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                if sum(map(len, err)) < 16384:
                    err.append(line)

        t = threading.Thread(target=drain, name="burpzip-7z-stderr")
        t.start()
        assert proc.stdout is not None
        with _cancel_child(proc, stop_event):
            try:
                while True:
                    chunk = proc.stdout.read(CHUNK)
                    _check_cancel(stop_event)
                    if not chunk:
                        break
                    sink(chunk)
                rc = proc.wait()
            except BaseException:
                proc.kill()
                proc.wait()
                raise
            finally:
                t.join()
    if rc != 0:
        msg = " ".join(b"".join(err).decode("utf-8", errors="replace").split())[-600:]
        raise ArchiveError(f"7z {args[0]} failed (exit {rc}): {msg}")


# --- small helpers -----------------------------------------------------------
def _sha256_file(path: str, size: int, progress: Progress = None) -> str:
    _ordinary(path)
    h = hashlib.sha256()
    done = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            _report(progress, "hash", done / size if size else 1.0)
    return h.hexdigest()


def _require_entry(archive: str, entry: str, size: int,
                   *, stop_event: threading.Event | None = None) -> None:
    """Require one literal project entry, including when its size is zero.

    7z e -so succeeds with empty output for a missing selector; an empty hash
    alone therefore cannot prove that an empty project is actually archived.
    """
    _check_cancel(stop_event)
    _readable_archive(archive)
    listing = _run_7z(["l", "-slt", "-ba", "-t7z", "-sccUTF-8", "-spd",
                       archive, "--", entry], **_control(stop_event))
    paths = [line[7:] for line in listing.splitlines() if line.startswith("Path = ")]
    sizes = [line[7:] for line in listing.splitlines() if line.startswith("Size = ")]
    if paths != [entry] or sizes != [str(size)] or "Folder = +" in listing:
        raise ArchiveError(f"verification failed: archive payload entry {entry!r} "
                           f"is missing or has the wrong size in {archive}")


def _sha256_entry(archive: str, entry: str, progress: Progress = None,
                  size: int = 0, *, stop_event: threading.Event | None = None) -> str:
    """Stream one literal archive entry, checking its declared size and SHA-256."""
    _check_cancel(stop_event)
    _readable_archive(archive)
    _require_entry(archive, entry, size, **_control(stop_event))
    h = hashlib.sha256()
    done = 0

    def sink(chunk: bytes) -> None:
        nonlocal done
        if len(chunk) > size - done:
            raise ArchiveError("verification failed: archive payload exceeds declared size")
        h.update(chunk)
        done += len(chunk)
        _report(progress, "verify", min(1.0, done / size) if size else None)

    _stream_7z(["e", "-so", "-t7z", "-y", "-spd", archive, "--", entry], sink,
               **_control(stop_event))
    _check_cancel(stop_event)
    if done != size:
        raise ArchiveError("verification failed: archive payload size does not match")
    return h.hexdigest()


def _stat_key(path: str) -> tuple[int, float]:
    st = os.stat(path)
    return st.st_size, st.st_mtime


def _stem(project_path_or_name: str) -> str:
    name = Path(project_path_or_name).name
    return name[:-5] if name.lower().endswith(".burp") else name


def _free(path: str) -> int:
    return shutil.disk_usage(path).free


def _check_space(folder: str, needed: int, what: str) -> None:
    free = _free(folder)
    if free < needed:
        raise ArchiveError(f"not enough free space for {what} in {folder}: need "
                           f"{bz.human_size(needed)}, have {bz.human_size(free)}")


def _discard(partial: str) -> None:
    """Remove only this invocation's partial and literal-prefix 7z temp files."""
    folder, name = os.path.split(partial)
    if bz.native_state(folder).kind != "ordinary":
        return  # Retain recovery data if the staging namespace became protected.
    paths = [partial]
    try:
        with os.scandir(folder) as entries:
            paths.extend(e.path for e in entries if e.name.startswith(name + ".tmp"))
    except OSError:
        pass
    for path in paths:
        try:
            _ordinary(path)
            os.remove(path)
        except (ArchiveError, OSError):
            pass


def _commit_no_clobber(partial: str, final: str) -> None:
    """Commit on the same volume without replacing an existing destination."""
    _ordinary(partial, final)
    if os.path.lexists(final):
        raise ArchiveError(f"destination already exists: {final}")
    if os.name == "nt":
        # Windows rename refuses an existing destination, even after the check.
        os.rename(partial, final)
    else:
        # os.rename replaces on POSIX; an exclusive hard link does not.
        os.link(partial, final)
        os.unlink(partial)


def _safe_project_name(name: object) -> bool:
    """A bare Windows-safe .burp name, never an ADS or reserved device."""
    if not isinstance(name, str) or not name.lower().endswith(".burp") \
            or name.rstrip(" .") != name or re.search(r'[<>:"/\\\\|?*\x00-\x1f]', name):
        return False
    device = name.split(".", 1)[0].rstrip(" ").upper()
    return device not in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"} \
        and re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", device) is None


def _new_archive_path(folder: str, stem: str) -> str:
    """Return a not-yet-existing ``<stem>.<stamp>.burpz`` path (bumps seconds)."""
    _ordinary(folder)
    when = datetime.now()
    for _ in range(3600):
        final = os.path.join(folder, f"{stem}.{when.strftime(STAMP_FMT)}{ARCHIVE_EXT}")
        if not os.path.exists(final) and not os.path.exists(final + PARTIAL_EXT):
            return final
        when += timedelta(seconds=1)
    raise ArchiveError(f"could not pick a free archive name for {stem} in {folder}")


def _require_project(project_path: str) -> str:
    p = os.path.abspath(project_path)
    _ordinary(p)
    if not os.path.isfile(p):
        raise ArchiveError(f"project not found: {p}")
    if not _safe_project_name(os.path.basename(p)):
        raise ArchiveError(f"not a safe .burp project file: {p}")
    if bz.is_in_use(p):
        raise ArchiveError(f"project is in use (open in Burp?): {p}")
    return p


# --- archive ------------------------------------------------------------------
def _write_meta(tmpdir: str, project: str, size: int, mtime: float, sha: str,
                level: int) -> str:
    meta = {
        "format": META_FORMAT,
        "orig_name": os.path.basename(project),
        "orig_path": project,
        "size": size,
        "mtime": mtime,
        "sha256": sha,
        "archived_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "level": level,
        "tool": "burpzip",
    }
    path = os.path.join(tmpdir, META_NAME)
    _ordinary(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    return path


def _add_meta(partial: str, meta_path: str) -> None:
    _ordinary(partial, meta_path)
    _run_7z(["a", "-t7z", "-y", "-bso0", "-spd", partial, "--", meta_path])


def _add_project(partial: str, project: str, level: int, threads: int,
                 progress: Progress) -> None:
    _ordinary(partial, project)
    _run_7z(["a", "-t7z", "-m0=lzma2", f"-mx={level}", f"-mmt={threads}", "-y",
             "-spd", partial, "--", project], stage="compress", progress=progress)


def _test_archive(partial: str, progress: Progress,
                  *, stop_event: threading.Event | None = None) -> None:
    _check_cancel(stop_event)
    _readable_archive(partial)
    _run_7z(["t", "-t7z", "-y", partial], stage="test", progress=progress,
            **_control(stop_event))


def _validate_args(level: int, threads: int) -> None:
    if not isinstance(level, int) or not 0 <= level <= 9:
        raise ArchiveError(f"compression level must be 0..9, got {level!r}")
    if not isinstance(threads, int) or threads < 1:
        raise ArchiveError(f"threads must be >= 1, got {threads!r}")


def _delete_original(project: str, key: tuple[int, float]) -> None:
    """Delete the original only if it is unchanged and not in use."""
    _ordinary(project)
    if _stat_key(project) != key:
        raise ArchiveError(f"project changed during archiving: {project}")
    if bz.is_in_use(project):
        raise ArchiveError(f"project became in use during archiving: {project}")
    _ordinary(project)
    os.remove(project)


def _archive(project_path: str, dest_dir: str | None, level: int, threads: int,
             delete_original: bool, progress: Progress,
             known: tuple[str, tuple[int, float]] | None = None) -> ArchiveResult:
    start = time.monotonic()
    _validate_args(level, threads)
    _ordinary(project_path, dest_dir or os.path.dirname(os.path.abspath(project_path)))
    project = _require_project(project_path)
    folder = os.path.abspath(dest_dir) if dest_dir else os.path.dirname(project)
    _ordinary(folder)
    if not os.path.isdir(folder):
        raise ArchiveError(f"destination folder not found: {folder}")
    key = _stat_key(project)
    size, mtime = key
    if not math.isfinite(mtime) or mtime < 0:
        raise ArchiveError(f"unsupported source mtime: {mtime!r} in {project}")
    needed = bz.archive_space_needed(size)
    _check_space(folder, needed, "the archive")

    if known and known[1] == key:
        sha = known[0]
    else:
        sha = _sha256_file(project, size, progress)
    if _stat_key(project) != key:
        raise ArchiveError(f"project changed while hashing: {project}")

    final = _new_archive_path(folder, _stem(project))
    try:
        # Reserve a private, same-volume directory before any 7z writes. Two
        # invocations may pick the same final name, but must never share staging.
        with tempfile.TemporaryDirectory(prefix="burpzip-stage-", dir=folder) as stage:
            partial = os.path.join(stage, os.path.basename(final) + PARTIAL_EXT)
            try:
                _check_space(folder, needed, "the archive")
                with tempfile.TemporaryDirectory(prefix="burpzip-meta-", dir=stage) as tmp:
                    _add_meta(partial, _write_meta(tmp, project, size, mtime, sha, level))
                _report(progress, "compress", 0.0)
                # Updating a 7z creates a second archive alongside the small
                # metadata-only one; admit the full source, not guessed savings.
                _check_space(folder, needed, "the archive")
                _add_project(partial, project, level, threads, progress)
                _report(progress, "test", 0.0)
                _test_archive(partial, progress)
                _report(progress, "verify", 0.0)
                got = _sha256_entry(partial, os.path.basename(project), progress, size)
                if got != sha:
                    raise ArchiveError(f"verification failed: archived sha256 {got} != {sha}")
                # Verify using the same reader restore will use, not merely
                # that the metadata writer produced syntactically valid JSON.
                meta = read_meta(partial)
                if (meta["orig_name"], meta["size"], meta["mtime"], meta["sha256"]) != \
                        (os.path.basename(project), size, mtime, sha):
                    raise ArchiveError("verification failed: staged metadata does not match source")
                if _stat_key(project) != key:
                    raise ArchiveError(f"project changed during archiving: {project}")
                _commit_no_clobber(partial, final)
            except BaseException:
                _discard(partial)
                raise
    except BaseException as e:
        if isinstance(e, ArchiveError):
            raise
        if isinstance(e, Exception):
            raise ArchiveError(f"archiving {project} failed: {e}") from e
        raise

    deleted = False
    if delete_original:
        _report(progress, "delete", None)
        try:
            _delete_original(project, key)
            deleted = True
        except (ArchiveError, OSError) as e:
            # A verified archive is a useful recovery copy even if the source
            # becomes locked or its deletion fails. Preserve both copies.
            raise ArchiveError(f"original not deleted; verified archive kept at {final}: {e}") from e
    return ArchiveResult(project_path=project, archive_path=final, original_size=size,
                         archive_size=os.path.getsize(final), sha256=sha,
                         seconds=round(time.monotonic() - start, 3),
                         deleted_original=deleted)


def archive_project(project_path: str, dest_dir: str | None = None, level: int = 5,
                    threads: int = 2, delete_original: bool = True,
                    progress: Progress = None) -> ArchiveResult:
    """Archive one project to a new versioned .burpz, verify it, then delete it.

    ``progress(stage, fraction)`` receives stages 'hash', 'compress', 'test',
    'verify', 'delete' (fraction may be None). Raises ArchiveError on refusal
    or failure; the original is never modified in that case.
    """
    return _archive(project_path, dest_dir, level, threads, delete_original, progress)


# --- reading -----------------------------------------------------------------
def read_meta(archive_path: str, *, stop_event: threading.Event | None = None) -> dict:
    """Return metadata from ordinary/store input; never implicitly hydrate."""
    _check_cancel(stop_event)
    _readable_archive(archive_path)
    if not os.path.isfile(archive_path):
        raise ArchiveError(f"archive not found: {archive_path}")
    buf = bytearray()

    def sink(chunk: bytes) -> None:
        buf.extend(chunk)
        if len(buf) > 1024**2:
            raise ArchiveError("metadata entry is unexpectedly large")

    _stream_7z(["e", "-so", "-t7z", "-y", "-spd", archive_path, "--", META_NAME], sink,
               **_control(stop_event))
    _check_cancel(stop_event)
    try:
        meta = json.loads(buf.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ArchiveError(f"no valid {META_NAME} in {archive_path}") from e
    if not isinstance(meta, dict) or meta.get("tool") != "burpzip" \
            or type(meta.get("format")) is not int or meta["format"] != META_FORMAT:
        raise ArchiveError(f"unsupported archive metadata in {archive_path}")
    for field in ("orig_name", "size", "mtime", "sha256"):
        if field not in meta:
            raise ArchiveError(f"metadata missing '{field}' in {archive_path}")
    if not _safe_project_name(meta["orig_name"]):
        raise ArchiveError(f"unsafe orig_name in {archive_path}: {meta['orig_name']!r}")
    if type(meta["size"]) is not int or meta["size"] < 0:
        raise ArchiveError(f"invalid metadata size in {archive_path}")
    try:
        valid_mtime = type(meta["mtime"]) in (int, float) \
            and math.isfinite(meta["mtime"]) and meta["mtime"] >= 0
    except OverflowError:
        valid_mtime = False
    if not valid_mtime:
        raise ArchiveError(f"invalid metadata mtime in {archive_path}")
    sha = meta["sha256"]
    if not isinstance(sha, str) or re.fullmatch(r"[0-9a-fA-F]{64}", sha) is None:
        raise ArchiveError(f"invalid metadata sha256 in {archive_path}")
    meta["sha256"] = sha.lower()
    return meta


def verify_archive(archive_path: str, progress: Progress = None,
                   *, stop_event: threading.Event | None = None) -> dict:
    """Validate metadata, 7-Zip integrity and exact payload size/hash; never delete."""
    _check_cancel(stop_event)
    _readable_archive(archive_path)
    meta = read_meta(archive_path, **_control(stop_event))
    _test_archive(archive_path, progress, **_control(stop_event))
    got = _sha256_entry(archive_path, meta["orig_name"], progress,
                        size=meta["size"], **_control(stop_event))
    _check_cancel(stop_event)
    if got != meta["sha256"]:
        raise ArchiveError("verification failed: archive payload SHA-256 does not match metadata")
    return meta


def list_versions(project_path_or_orig_name: str, folder: str | None = None) -> list[str]:
    """Archive paths for a project in ``folder``, newest first (by name stamp)."""
    if folder is None:
        folder = os.path.dirname(os.path.abspath(project_path_or_orig_name))
    if bz.native_state(folder).kind not in ("ordinary", "store"):
        return []
    stem = _stem(project_path_or_orig_name)
    rx = re.compile(re.escape(stem) + r"\.(\d{8}-\d{6})" + re.escape(ARCHIVE_EXT) + "$",
                    re.IGNORECASE)
    found: list[tuple[str, float, str]] = []
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return []
    for e in entries:
        m = rx.match(e.name)
        if m and bz.native_state(e.path).kind in ("ordinary", "store") and e.is_file():
            found.append((m.group(1), e.stat().st_mtime, e.path))
    found.sort(reverse=True)
    return [p for _, _, p in found]


# --- restore -----------------------------------------------------------------
def restore_project(archive_path: str, dest_path: str | None = None,
                    progress: Progress = None,
                    *, stop_event: threading.Event | None = None) -> str:
    """Restore the project from an archive (archive is kept). Returns its path.

    Default destination is ``orig_name`` in the archive's folder. Refuses if
    the destination exists. Writes an exclusively reserved unique partial,
    bounds output by metadata size, checks size + SHA-256, restores the mtime,
    then commits without overwriting any existing destination.
    """
    _check_cancel(stop_event)
    archive_path = os.path.abspath(archive_path)
    _readable_archive(archive_path)
    if dest_path is not None:
        _ordinary(dest_path)
    meta = read_meta(archive_path, **_control(stop_event))
    dest = os.path.abspath(dest_path or os.path.join(os.path.dirname(archive_path),
                                                     meta["orig_name"]))
    _ordinary(dest)
    if os.path.lexists(dest):
        raise ArchiveError(f"destination already exists: {dest}")
    folder = os.path.dirname(dest)
    if not os.path.isdir(folder):
        raise ArchiveError(f"destination folder not found: {folder}")
    size = meta["size"]
    _check_space(folder, size + bz.SPACE_MARGIN, "the restored project")
    _require_entry(archive_path, meta["orig_name"], size, **_control(stop_event))
    _check_cancel(stop_event)
    _ordinary(dest)

    # mkstemp exclusively reserves this invocation's staging file. Never
    # pre-clean a shared <dest>.partial that may belong to another restore.
    partial = None
    h = hashlib.sha256()
    done = 0
    try:
        fd, partial = tempfile.mkstemp(prefix=os.path.basename(dest) + ".",
                                      suffix=PARTIAL_EXT, dir=folder)
        with os.fdopen(fd, "wb") as out:
            def sink(chunk: bytes) -> None:
                nonlocal done
                _check_cancel(stop_event)
                if len(chunk) > size - done:
                    raise ArchiveError("restored payload exceeds declared metadata size")
                out.write(chunk)
                h.update(chunk)
                done += len(chunk)
                _report(progress, "extract", min(1.0, done / size) if size else None)

            _stream_7z(["e", "-so", "-t7z", "-y", "-spd", archive_path,
                        "--", meta["orig_name"]], sink, **_control(stop_event))
        _report(progress, "verify", None)
        if done != size or h.hexdigest() != meta["sha256"]:
            raise ArchiveError(f"restored data does not match metadata "
                               f"(size {done} vs {size})")
        _check_cancel(stop_event)
        _ordinary(partial, dest)
        os.utime(partial, (time.time(), meta["mtime"]))
        _check_cancel(stop_event)
        _commit_no_clobber(partial, dest)
    except BaseException as e:
        if partial is not None:
            _discard(partial)
        if isinstance(e, ArchiveError) or not isinstance(e, Exception):
            raise
        raise ArchiveError(f"restore of {archive_path} failed: {e}") from e
    return dest


# --- re-zip after use ----------------------------------------------------------
def rezip_after_use(project_path: str, archive_path: str | None = None, level: int = 5,
                    threads: int = 2, progress: Progress = None) -> ArchiveResult | None:
    """After a restored project was used, put it back into archive form.

    If the reference metadata matches, verify 7z integrity and the actual
    payload's name, size and streamed SHA-256 before deleting the restored
    copy (returns None). Otherwise make a NEW versioned archive next to the
    reference archive; old versions are always kept.
    """
    _ordinary(project_path)
    if archive_path is not None:
        _ordinary(archive_path)
    project = _require_project(project_path)
    if archive_path is None:
        versions = list_versions(project)
        archive_path = versions[0] if versions else None
    dest_dir = os.path.dirname(os.path.abspath(archive_path)) if archive_path else None
    if archive_path:
        _ordinary(archive_path, dest_dir)
    key = _stat_key(project)
    sha = _sha256_file(project, key[0], progress)
    if archive_path:
        meta = read_meta(archive_path)
        if os.path.normcase(meta["orig_name"]) != os.path.normcase(os.path.basename(project)):
            raise ArchiveError(f"reference archive orig_name does not match project: {archive_path}")
        if meta["sha256"] == sha and meta["size"] == key[0]:
            # Metadata is only a claim. Before deleting the sole restored copy,
            # require integrity and the actual literal payload's hash and size.
            _report(progress, "test", 0.0)
            _test_archive(archive_path, progress)
            got = _sha256_entry(archive_path, meta["orig_name"], progress, key[0])
            if got != sha:
                raise ArchiveError(f"verification failed: reference archive payload sha256 {got} != {sha}")
            _report(progress, "delete", None)
            _delete_original(project, key)
            return None
    return _archive(project, dest_dir, level, threads, True, progress, known=(sha, key))


# --- backups -----------------------------------------------------------------
def delete_backup(backup_path: str, force_newer: bool = False) -> int:
    """Delete a leftover ``*.burp.backup*`` file on explicit user request.

    Only allowed when the main project exists, the backup is not in use and
    the backup is not newer than the project (unless ``force_newer``).
    Returns the bytes freed.
    """
    path = os.path.abspath(backup_path)
    parent = bz.backup_parent(path)
    _ordinary(path, parent)
    if not bz.BACKUP_RE.search(os.path.basename(path)):
        raise ArchiveError(f"not a Burp backup file: {path}")
    if not os.path.isfile(path):
        raise ArchiveError(f"backup not found: {path}")
    if not os.path.isfile(parent):
        raise ArchiveError(f"main project missing, backup may be the only copy: {parent}")
    if bz.is_in_use(path):
        raise ArchiveError(f"backup is in use: {path}")
    st = os.stat(path)
    if st.st_mtime > os.stat(parent).st_mtime and not force_newer:
        raise ArchiveError(f"backup is newer than the project; confirm with force: {path}")
    _ordinary(path, parent)
    if bz.is_in_use(path):
        raise ArchiveError(f"backup became in use: {path}")
    _ordinary(path, parent)
    os.remove(path)
    return st.st_size


# --- plan execution ------------------------------------------------------------
def run_plan(plan: dict, level: int = 5, threads: int = 2, progress: Progress = None,
             stop_event: threading.Event | None = None) -> list[ArchiveResult | ArchiveError]:
    """Execute the 'archive' steps of a burpzip plan, in order.

    Free space is re-checked live for each file; per-file errors are collected
    and the run continues. Backups are never deleted here. ``stop_event`` is
    honoured between files.
    """
    results: list[ArchiveResult | ArchiveError] = []
    for step in plan.get("steps", []):
        if step.get("action") != "archive":
            continue
        if stop_event is not None and stop_event.is_set():
            break
        path = step.get("path", "")
        try:
            _ordinary(path)
            if os.path.isfile(path):
                size = os.path.getsize(path)
                _check_space(os.path.dirname(os.path.abspath(path)),
                             bz.archive_space_needed(size), path)
            results.append(archive_project(path, level=level, threads=threads,
                                           progress=progress))
        except ArchiveError as e:
            results.append(e)
        except OSError as e:
            results.append(ArchiveError(f"{path}: {e}"))
    return results
