"""burpzip - browse, archive, restore and open Burp Suite projects on Windows.

No arguments opens the desktop GUI. ``scan`` is read-only unless an explicit
``--plan`` output is requested. Destructive CLI actions require confirmation;
backups are never included in automatic cleanup. Archives are unencrypted.

Run ``python burpzip.py --help`` for commands and options.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import SimpleNamespace

# --- tuning -----------------------------------------------------------------
# Ratios are display/planning estimates, never free-space safety guarantees.
RATIO_EXPECTED = 0.15  # assumed archive fraction; actual compression may be poor
RATIO_WORST = 0.50  # legacy compatibility; admission uses archive_space_needed
SPACE_MARGIN = 512 * 1024**2  # always keep this much free
MIN_ARCHIVE_SIZE = 100 * 1024**2  # smaller projects are not worth archiving
MAX_DEPTH = 5
SKIP_DIRS = {"appdata", "$recycle.bin", "node_modules", "system volume information"}

BACKUP_RE = re.compile(r"\.burp\.backup(\..*)?$", re.IGNORECASE)
ARCHIVE_RE = re.compile(r"\.burp(\.\d{8}-\d{6})?\.7z$", re.IGNORECASE)


@dataclass
class Item:
    path: str
    kind: str  # project | backup | archive
    size: int
    mtime: float
    age_days: float
    in_use: bool = False
    notes: list[str] = field(default_factory=list)
    meta: dict | None = None
    native: str = "ordinary"  # ordinary | native | cloud | unknown | store
    native_ready: bool | None = None
    native_modified: bool | None = None
    native_resident: bool | None = None


# --- non-hydrating native guards ---------------------------------------------
def native_state(path: str | Path):
    """Query the inert leaf adapter; an unavailable/ambiguous query is protected."""
    try:
        import native_cfapi
        state = native_cfapi.classify_path(str(path))
        if state.kind not in ("ordinary", "native", "cloud", "unknown", "store"):
            raise ValueError("invalid native classification")
        return state
    except Exception as exc:
        return SimpleNamespace(kind="unknown", path=str(path), root_path=None,
                               root_id=None, file_id=None, identity=None, size=None,
                               ready=False, modified=None, note=f"native state unavailable: {exc}")


def require_ordinary_path(path: str | Path) -> None:
    """Refuse protected inputs and their enclosing folder before ordinary I/O."""
    import native_cfapi
    native_cfapi.require_ordinary_path(str(path))
    native_cfapi.require_ordinary_path(os.path.dirname(os.path.abspath(path)))


def protected_item(item) -> bool:
    return getattr(item, "native", "ordinary") != "ordinary" \
        or getattr(item, "kind", "") in ("native", "cloud", "unknown", "store")


def managed_project(state, path: str | Path) -> bool:
    """Only an identity-anchored own .burp leaf may use the native-open branch."""
    return state.kind == "native" and str(path).lower().endswith(".burp") \
        and bool(state.root_id and state.file_id and state.identity)


# --- helpers ----------------------------------------------------------------
def archive_space_needed(size: int) -> int:
    """Conservative staging admission: full input + overhead + free reserve."""
    return size + max(64 * 1024**2, (size + 19) // 20) + SPACE_MARGIN


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB", "MB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_age(days: float) -> str:
    if days < 1:
        return "today"
    if days < 2:
        return "yesterday"
    if days < 14:
        return f"{int(days)} days ago"
    if days < 60:
        return f"{int(days // 7)} weeks ago"
    if days < 730:
        return f"{int(days // 30)} months ago"
    return f"{int(days // 365)} years ago"


def is_in_use(path: str) -> bool:
    """True if another process (e.g. Burp) holds the file open.

    Opens with DELETE access and full sharing. Java opens project files
    without FILE_SHARE_DELETE, so this fails with a sharing violation while
    Burp has the file open. Read-only probe: nothing is written or deleted.
    """
    if native_state(path).kind != "ordinary":
        return True  # Never DELETE-probe a placeholder, foreign cloud file or store.
    if os.name != "nt":
        return False
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = ctypes.c_void_p
    DELETE, SHARE_ALL, OPEN_EXISTING = 0x00010000, 0x7, 3
    h = k32.CreateFileW(path, DELETE, SHARE_ALL, None, OPEN_EXISTING, 0, None)
    if h in (None, ctypes.c_void_p(-1).value):
        return ctypes.get_last_error() == 32  # ERROR_SHARING_VIOLATION
    k32.CloseHandle(ctypes.c_void_p(h))
    return False


def burp_running() -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=20
        ).stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False
    return "burpsuite" in out


def default_roots() -> list[Path]:
    return [Path.home()]


def walk(root: Path, depth: int = 0):
    root_kind = native_state(root).kind
    if root_kind in ("cloud", "unknown"):
        return  # Enumeration itself can ask another provider to populate a folder.
    try:
        entries = list(os.scandir(root))
    except OSError:
        return
    for e in entries:
        try:
            if e.is_dir(follow_symlinks=False):
                name = e.name.lower()
                if root_kind == "ordinary" and depth < MAX_DEPTH \
                        and name not in SKIP_DIRS and not name.startswith("."):
                    yield from walk(Path(e.path), depth + 1)
            elif e.is_file(follow_symlinks=False):
                yield e
        except OSError:
            continue


def classify(name: str) -> str | None:
    low = name.lower()
    if low.endswith(".burp"):
        return "project"
    if BACKUP_RE.search(low):
        return "backup"
    if low.endswith(".burpz") or ARCHIVE_RE.search(low):
        return "archive"
    return None


def _listing_meta(path: str) -> dict:
    """Read only the metadata entry; reject invalid presentation fields."""
    import archiver

    meta = archiver.read_meta(path)
    if not isinstance(meta, dict) or meta.get("tool") != "burpzip" \
            or type(meta.get("format")) is not int or meta["format"] != 1:
        raise ValueError("unsupported archive metadata")
    name = meta.get("orig_name")
    if not isinstance(name, str) or not name.lower().endswith(".burp") \
            or any(c in name for c in '/\\\\:') or name in (".burp", "..burp"):
        raise ValueError("invalid original project name")
    size, mtime = meta.get("size"), meta.get("mtime")
    if type(size) is not int or size < 0:
        raise ValueError("invalid original size")
    if type(mtime) not in (int, float) or not math.isfinite(mtime) or mtime < 0:
        raise ValueError("invalid last-edited time")
    sha = meta.get("sha256")
    if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{64}", sha) is None:
        raise ValueError("invalid project SHA-256")
    return meta


def _native_catalog(root_path: str | None, cache: dict) -> dict:
    """Read-only {casefolded name: store entry} for a Burp-folder root, or {}.

    Looks for the store beside the root (<root>-store) and the default store.
    Never takes the store lease or touches project contents.
    """
    if not root_path:
        return {}
    key = os.path.normcase(os.path.abspath(root_path))
    if key not in cache:
        cache[key] = {}
        candidates = [Path(str(root_path) + "-store"), DEFAULT_NATIVE_STORE]
        for store in candidates:
            try:
                path = native_store_path(store)
                if path is None:
                    continue
                from native_store import NativeStore
                native = NativeStore(str(path))
                if os.path.normcase(os.path.abspath(native.root)) != key:
                    continue
                cache[key] = {e["name"].casefold(): e for e in native.entries()}
                break
            except Exception:
                continue
    return cache[key]


def scan(roots: list[Path]) -> list[Item]:
    """Read-only listing. Archive age refers to the original project's edit."""
    now = time.time()
    seen: set[str] = set()
    items: list[Item] = []
    catalogs: dict = {}
    for root in roots:
        for e in walk(root):
            kind = classify(e.name)
            if not kind:
                continue
            key = os.path.normcase(os.path.abspath(e.path))
            if key in seen:
                continue
            seen.add(key)
            state = native_state(e.path)
            if state.kind != "ordinary":
                size = getattr(state, "size", None)
                mtime, meta = 0.0, None
                if state.kind == "native":
                    # From classification's metadata-only handle; protected entries are never stat()ed.
                    mtime = float(getattr(state, "mtime", 0.0) or 0.0)
                    entry = _native_catalog(getattr(state, "root_path", None), catalogs).get(
                        os.path.basename(e.path).casefold())
                    if entry is not None:
                        meta = {"archive_size": entry["archive_size"], "size": entry["size"],
                                "mtime": entry["mtime"]}
                items.append(Item(path=e.path, kind=kind,
                                  size=size if type(size) is int and size >= 0 else 0,
                                  mtime=mtime, age_days=(now - mtime) / 86400 if mtime else 0.0,
                                  in_use=True, meta=meta,
                                  notes=[f"{state.kind}: {getattr(state, 'note', '') or 'ordinary actions disabled'}"],
                                  native=state.kind, native_ready=getattr(state, "ready", None),
                                  native_modified=getattr(state, "modified", None),
                                  native_resident=getattr(state, "resident", None)))
                continue  # No metadata extraction, content reads or DELETE probe.
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue  # disappeared since walking
            edited = st.st_mtime
            meta = None
            notes: list[str] = []
            if kind == "archive":
                try:
                    meta = _listing_meta(e.path)
                    edited = float(meta["mtime"])
                except Exception as exc:
                    notes.append(f"archive metadata unavailable: {exc}; project age unknown")
            items.append(Item(path=e.path, kind=kind, size=st.st_size,
                              mtime=edited, age_days=max(0.0, (now - edited) / 86400),
                              in_use=is_in_use(e.path) if kind != "archive" else False,
                              notes=notes, meta=meta))
    return items


# --- planning ---------------------------------------------------------------
def backup_parent(path: str) -> str:
    """Replace only the file suffix, never a matching parent directory name."""
    return os.path.join(os.path.dirname(path), BACKUP_RE.sub(".burp", os.path.basename(path)))


def build_plan(items: list[Item], days: int, free: int,
               min_size: int = MIN_ARCHIVE_SIZE) -> dict:
    """Estimate an archive-only plan; backups always stay for manual review.

    Steps are in admission order, so promoted projects follow the projects
    whose estimated savings made them fit. Execution must re-check live space.
    A source matching an archive's size/mtime is not proof of identical bytes.
    """
    items = [i for i in items if not protected_item(i)]
    projects = {os.path.normcase(i.path): i for i in items if i.kind == "project"}
    steps: list[dict] = []
    sim_free = free

    for b in sorted((i for i in items if i.kind == "backup"), key=lambda i: -i.size):
        parent = projects.get(os.path.normcase(backup_parent(b.path)))
        if b.in_use:
            note = "in use, kept; manual review only"
        elif parent is None:
            note = "main project missing, kept as possible only copy"
        elif b.mtime > parent.mtime:
            note = "backup is newer than the project, manual review only"
        else:
            note = "backup kept; delete only by explicit manual action"
        steps.append({"action": "skip", "path": b.path, "size": b.size,
                      "frees": 0, "notes": [*b.notes, note]})

    candidates = sorted(
        (i for i in projects.values() if i.age_days >= days and i.size >= min_size),
        key=lambda i: -i.size,
    )
    pending: list[dict] = []
    for p in candidates:
        expected = int(p.size * RATIO_EXPECTED)
        step = {"action": "archive", "path": p.path, "size": p.size,
                "age_days": round(p.age_days, 1), "expected_archive": expected,
                "frees": 0, "notes": list(p.notes)}
        if p.in_use:
            step["action"] = "skip"
            step["notes"].append("open in Burp, skipped")
            steps.append(step)
        elif sim_free < archive_space_needed(p.size):
            step["action"] = "deferred"
            pending.append(step)
        else:
            step["frees"] = p.size - expected
            sim_free += step["frees"]
            steps.append(step)

    # Revisit until no new admission is possible. Append, never promote in place.
    while pending:
        remaining = []
        admitted = False
        for step in pending:
            if sim_free >= archive_space_needed(step["size"]):
                step["action"] = "archive"
                step["notes"].append("after earlier archives (estimated savings)")
                step["frees"] = step["size"] - step["expected_archive"]
                sim_free += step["frees"]
                steps.append(step)
                admitted = True
            else:
                remaining.append(step)
        pending = remaining
        if not admitted:
            break
    for step in pending:
        step["notes"].append(f"needs {human_size(archive_space_needed(step['size']))} "
                             "free including overhead and reserve, deferred")
        steps.append(step)

    return {"free_now": free, "free_after": sim_free, "days": days,
            "min_size": min_size, "steps": steps}


def build_volume_plan(items: list[Item], days: int,
                      min_size: int = MIN_ARCHIVE_SIZE,
                      roots: list[Path] | None = None) -> dict:
    """Budget alongside-source archives per volume, never across volumes.

    Root and item-parent stat/disk probes are read-only. Unavailable folders or
    volume budgets fail closed at zero with notes. Aggregate free fields are
    for display only; admission and estimated savings stay in each volume pool.
    """
    pools: dict[str, dict] = {}
    folders: dict[str, str] = {}

    def volume_for(folder: Path) -> str | None:
        folder = Path(os.path.abspath(folder))
        key = os.path.normcase(str(folder))
        if key in folders:
            return folders[key]
        if native_state(folder).kind != "ordinary":
            return None
        notes = []
        try:
            volume = str(os.stat(folder).st_dev)
        except OSError as exc:
            volume = f"unavailable:{key}"
            notes.append(f"volume unavailable for {folder}: {exc}; zero budget")
        if volume not in pools:
            free = 0
            if not notes:
                try:
                    free = shutil.disk_usage(folder).free
                except OSError as exc:
                    notes.append(f"free space unavailable for {folder}: {exc}; zero budget")
            pools[volume] = {"items": [], "free": free, "notes": notes}
        folders[key] = volume
        return volume

    for root in roots or []:
        volume_for(root)
    for i in items:
        if protected_item(i):
            continue
        volume = volume_for(Path(i.path).parent)
        if volume is not None:
            pools[volume]["items"].append(i)

    steps = []
    volumes = []
    for volume, pool in pools.items():
        plan = build_plan(pool["items"], days, pool["free"], min_size)
        for step in plan["steps"]:
            step["notes"].extend(pool["notes"])
        steps.extend(plan["steps"])
        volumes.append({"volume": volume, "free_now": plan["free_now"],
                        "free_after": plan["free_after"], "notes": list(pool["notes"])})
    return {"free_now": sum(v["free_now"] for v in volumes),
            "free_after": sum(v["free_after"] for v in volumes),
            "days": days, "min_size": min_size, "steps": steps, "volumes": volumes}


# --- output -----------------------------------------------------------------
def print_report(items: list[Item], plan: dict, running: bool) -> None:
    if sys.stdout is None:
        return
    w = shutil.get_terminal_size((140, 20)).columns
    name_w = max(30, min(60, w - 70))
    home = str(Path.home())

    def folder(path: str) -> str:
        d = str(Path(path).parent)
        return "~" + d[len(home):] if d.lower().startswith(home.lower()) else d

    def row(i: Item, extra: str = "") -> str:
        name = Path(i.path).name
        name = name if len(name) <= name_w else name[: name_w - 1] + "~"
        flag = "  IN USE" if i.in_use else ""
        age = "unknown" if protected_item(i) or i.kind == "archive" and i.meta is None \
            else human_age(i.age_days)
        notes = f"  ({'; '.join(i.notes)})" if i.notes else ""
        return (f"  {name:<{name_w}} {folder(i.path):<22} {human_size(i.size):>9}  "
                f"{age:<15}{extra}{flag}{notes}")

    print(f"\nBurp running: {'YES - open projects are skipped' if running else 'no'}")
    for kind, title in (("project", "PROJECTS"), ("backup", "LEFTOVER BACKUPS"), ("archive", "ARCHIVES")):
        group = sorted((i for i in items if i.kind == kind), key=lambda i: i.age_days)
        if not group:
            continue
        total = sum(i.size for i in group)
        print(f"\n{title}  ({len(group)} files, {human_size(total)})")
        for i in group:
            old = kind == "project" and i.age_days >= plan["days"]
            small = kind == "project" and i.size < plan["min_size"]
            print(row(i, "  small" if small else "  old" if old else ""))

    print(f"\nDRY-RUN PLAN  (archive projects not edited for {plan['days']}+ days; nothing has been changed)")
    totals: dict[str, list[int]] = {}
    for n, s in enumerate(plan["steps"], 1):
        t = totals.setdefault(s["action"], [0, 0])
        t[0] += 1
        t[1] += s["frees"]
        note = f"  ({'; '.join(s['notes'])})" if s["notes"] else ""
        frees = f"frees ~{human_size(s['frees'])}" if s["frees"] else ""
        print(f"  {n:>2}. {s['action']:<13} {Path(s['path']).name[:name_w]:<{name_w}} "
              f"{folder(s['path']):<22} {frees}{note}")
    print("\nSUMMARY")
    for action, (count, freed) in totals.items():
        print(f"  {action:<13} {count:>3} files   frees ~{human_size(freed)}")
    volumes = plan.get("volumes")
    if volumes is not None:
        for volume in volumes:
            note = f" ({'; '.join(volume['notes'])})" if volume.get("notes") else ""
            print(f"  volume {volume['volume']}: free now {human_size(volume['free_now'])}; "
                  f"estimated after ~{human_size(volume['free_after'])}{note}")
        print(f"  aggregate free now    {human_size(plan['free_now'])} (distinct volume snapshots)")
        print(f"  aggregate after       ~{human_size(plan['free_after'])} estimated; "
              "no space transfers between volumes")
    else:
        print(f"  free space now        {human_size(plan['free_now'])}")
        print(f"  free space after      ~{human_size(plan['free_after'])} estimated")
    print(f"  estimates assume archives at {int(RATIO_EXPECTED*100)}% of original")


class CliUsageError(ValueError):
    """Invalid CLI input, reported without a traceback."""


def _nonnegative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _deadline(value: str) -> int:
    number = _positive(value)
    if number > 86400:
        raise argparse.ArgumentTypeError("must be <= 86400 seconds")
    return number


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="burpzip", description=__doc__)
    sub = ap.add_subparsers(dest="cmd")

    def scan_options(parser):
        parser.add_argument("--days", type=_nonnegative, default=_config()["days"],
                            help="projects not edited for this many days or more")
        parser.add_argument("--min-mb", type=_nonnegative, default=MIN_ARCHIVE_SIZE // 1024**2,
                            help="skip projects smaller than this many MiB")
        parser.add_argument("--root", action="append", type=Path,
                            help="folder to scan (repeatable; default: home folder)")

    def compression(parser, threads=True):
        parser.add_argument("--level", type=int, choices=range(10), default=5,
                            help="7-Zip compression level 0..9 (default: 5)")
        if threads:
            parser.add_argument("--threads", type=_positive, default=2,
                                help="compression threads, >=1 (default: 2)")

    def confirmation(parser):
        parser.add_argument("--yes", action="store_true",
                            help="explicitly confirm the described deletion(s) without prompting")

    sc = sub.add_parser("scan", help="read-only listing and dry-run plan")
    scan_options(sc)
    sc.add_argument("--plan", type=Path, help="create a NEW .json plan; never overwrite")
    archive = sub.add_parser("archive", help="archive projects; confirm before deleting originals")
    archive.add_argument("paths", nargs="+", type=Path)
    compression(archive)
    archive.add_argument("--keep-original", action="store_true",
                         help="create verified archives without deleting the projects")
    confirmation(archive)
    old = sub.add_parser("archive-old", help="print and confirm an old-project archive plan")
    scan_options(old)
    compression(old)
    confirmation(old)
    restore = sub.add_parser("restore", help="restore a project, retain archive, never overwrite")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--dest", type=Path, help="new destination PROJECT FILE, not a folder")
    op = sub.add_parser("open", help="open an archive or project through the Burp launcher")
    op.add_argument("path", type=Path)
    rezip = sub.add_parser("rezip", help="re-compress a closed project, then remove its unpacked copy")
    rezip.add_argument("project", type=Path)
    compression(rezip, threads=False)
    confirmation(rezip)
    backup = sub.add_parser("delete-backup", help="explicitly delete one reviewed backup")
    backup.add_argument("path", type=Path)
    backup.add_argument("--force-newer", action="store_true",
                        help="allow a newer backup; type YES or combine with --yes")
    confirmation(backup)
    sub.add_parser("register", help="explicitly register this user's .burpz association")
    sub.add_parser("unregister", help="explicitly remove burpzip's per-user association")
    sub.add_parser("gui", help="open the desktop GUI (also the no-arguments default)")
    burp = sub.add_parser("burp", help="start the Burp-folder provider if needed, launch Burp, and "
                                       "stop the provider after Burp exits (provider = with-burp)")
    burp.add_argument("--project", help="optional .burp project to open")
    native = sub.add_parser("native", help="experimental native-open commands (activation release-gated)")
    commands = native.add_subparsers(dest="native_cmd", required=True)
    init = commands.add_parser("init", help="register a NEW empty root; explicit experimental consent")
    init.add_argument("--root", type=Path, required=True)
    init.add_argument("--store", type=Path, required=True)
    init.add_argument("--experimental", action="store_true", required=True)
    init.add_argument("--yes", action="store_true", help="explicitly consent to native registration")
    add = commands.add_parser("add", help="import a verified archive (input kept unless --move)")
    add.add_argument("--store", type=Path, required=True)
    add.add_argument("archive", type=Path)
    add.add_argument("--move", action="store_true",
                     help="remove the input .burpz after its store copy is verified")
    add.add_argument("--yes", action="store_true", help="explicitly confirm --move removal")
    rezip = commands.add_parser("rezip", help="re-zip unpacked projects back to placeholders")
    rezip.add_argument("--store", type=Path, required=True)
    pick = rezip.add_mutually_exclusive_group(required=True)
    pick.add_argument("--name", help="one Burp-folder project, e.g. Example.burp")
    pick.add_argument("--idle-days", type=_nonnegative, help="all unpacked projects unchanged this long")
    rezip.add_argument("--level", type=int, choices=range(10), default=5, metavar="0-9")
    mode = commands.add_parser("provider-mode", help="when the provider runs: logon | with-burp | manual")
    mode.add_argument("mode", choices=("logon", "with-burp", "manual"))
    mode.add_argument("--store", type=Path, help="default: the store in burpzip.ini")
    stop = commands.add_parser("stop", help="ask a running (also hidden) provider to disconnect")
    stop.add_argument("--store", type=Path, required=True)
    auto = commands.add_parser("autostart", help="start the provider hidden at Windows logon")
    auto.add_argument("--store", type=Path, required=True)
    toggle = auto.add_mutually_exclusive_group(required=True)
    toggle.add_argument("--enable", action="store_true", help="add a Startup shortcut and start now")
    toggle.add_argument("--disable", action="store_true", help="remove the Startup shortcut")
    for command in ("serve", "status", "materialize", "export", "detach"):
        parser = commands.add_parser(command, help={
            "serve": "run the provider in the foreground; stop disconnects only",
            "status": "inspect native store/root status without activation",
            "materialize": "make imports resident, preserving later edits",
            "export": "export current bytes or a historical snapshot to a NEW ordinary path",
            "detach": "explicit materialize/revert; full unregister remains safety-gated",
        }[command])
        parser.add_argument("--store", type=Path, required=True)
        if command != "status":
            parser.add_argument("--deadline-seconds", type=_deadline, default=600,
                                help="whole-job deadline 1..86400 seconds (default: 600)")
        if command == "serve":
            parser.add_argument("--idle-days", type=_nonnegative, default=None,
                                help="re-zip unpacked projects untouched this many days "
                                     "(0 = off; default: idle_days in burpzip.ini, else 10)")
            ask = parser.add_mutually_exclusive_group()
            ask.add_argument("--ask-on-close", dest="ask_on_close", action="store_const", const=True,
                             default=None, help="ask to re-zip when Burp closes a changed project")
            ask.add_argument("--no-ask-on-close", dest="ask_on_close", action="store_const", const=False,
                             help="do not ask (default: ask_on_close in burpzip.ini, else yes)")
        if command == "export":
            parser.add_argument("--name", required=True, help="managed project filename")
            parser.add_argument("--dest", type=Path, required=True, help="NEW ordinary project file")
            mode = parser.add_mutually_exclusive_group(required=True)
            mode.add_argument("--current", action="store_true", help="capture current resident edits")
            mode.add_argument("--snapshot", action="store_true", help="historical import; NOT a backup of later edits")
        elif command == "detach":
            parser.add_argument("--yes", action="store_true", help="explicitly consent to materialize/revert")
    return ap


def _say(message: str, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    if stream is not None:
        print(message, file=stream)
    elif error:
        import launcher
        launcher.gui_message(message, error=True)


def _confirm(question: str, yes: bool = False, typed: bool = False) -> bool:
    if yes:
        return True
    try:
        if sys.stdin is None or not sys.stdin.isatty() or sys.stdout is None:
            _say("Confirmation unavailable; nothing changed. Use --yes to explicitly confirm.", error=True)
            return False
        answer = input(question + (" [type YES] " if typed else " [y/N] ")).strip()
    except (EOFError, OSError):
        return False
    return answer == "YES" if typed else answer.lower() in ("y", "yes")


def _require_file(path: Path, kinds: tuple[str, ...], *, managed: bool = False,
                  read_archive: bool = False) -> str:
    state = native_state(path)
    if managed and managed_project(state, path) and classify(path.name) in kinds:
        return str(path)  # Native metadata proves the leaf; do not open its contents.
    if state.kind != "ordinary" and not (read_archive and state.kind == "store"):
        raise CliUsageError(f"{state.kind} path is protected; ordinary action refused: {path}")
    if not read_archive:
        require_ordinary_path(path)
    if not path.is_file():
        raise CliUsageError(f"file not found: {path}")
    if classify(path.name) not in kinds:
        raise CliUsageError(f"expected {' or '.join(kinds)} file, got: {path}")
    return str(path)


def _plan_output(path: Path, items: list[Item] | tuple[Item, ...] = ()) -> None:
    require_ordinary_path(path)
    if path.suffix.lower() != ".json" or ":" in path.name:
        raise CliUsageError("--plan must name a new ordinary .json file, never a project, archive or ADS")
    key = os.path.normcase(os.path.realpath(path))
    if any(key == os.path.normcase(os.path.realpath(i.path)) for i in items):
        raise CliUsageError(f"--plan would replace a scanned input: {path}")
    if os.path.lexists(path):
        raise CliUsageError(f"plan output already exists; choose a new .json file: {path}")
    if not path.parent.is_dir():
        raise CliUsageError(f"plan output folder not found: {path.parent}")


def _scan_plan(args) -> tuple[list[Item], dict, bool]:
    roots = args.root or default_roots()
    for root in roots:
        state = native_state(root)
        if state.kind in ("cloud", "unknown"):
            raise CliUsageError(f"scan root is {state.kind}; enumeration refused: {root}")
        if not root.is_dir():
            raise CliUsageError(f"scan root is not an existing folder: {root}")
    output = getattr(args, "plan", None)
    if output is not None:
        _plan_output(output)
    items = scan(roots)
    running = burp_running()
    plan = build_volume_plan(items, args.days, args.min_mb * 1024**2, roots=roots)
    plan.update(created=time.strftime("%Y-%m-%d %H:%M:%S"), roots=[str(r) for r in roots],
                burp_running=running, items=[asdict(i) for i in items])
    return items, plan, running


def _result(result) -> None:
    if result is None:
        _say("Project unchanged; unpacked copy removed, verified archive kept.")
    else:
        disposition = "original removed" if result.deleted_original else "original kept"
        _say(f"{result.archive_path}: {human_size(result.original_size)} -> "
             f"{human_size(result.archive_size)}; {disposition}")


STARTUP_SHORTCUT = "Burpzip native provider.lnk"
DEFAULT_NATIVE_STORE = Path.home() / "Downloads" / "BurpProjects-store"
_NO_WINDOW = 0x08000000      # CREATE_NO_WINDOW
_DETACHED = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP


def _config() -> dict:
    import config
    try:
        return config.load()
    except Exception:
        return config.defaults()


def native_store_path(configured: str | os.PathLike | None = None) -> Path | None:
    """The given store, else the one in burpzip.ini, else the default one, if it exists."""
    import native_store
    for candidate in (configured, _config().get("store") or None, DEFAULT_NATIVE_STORE):
        if candidate and (Path(candidate) / native_store.MARKER).is_file():
            return Path(os.path.abspath(candidate))
    return None


def provider_running(store: str | os.PathLike) -> bool:
    """True when another process holds the store lease (i.e. `native serve`).

    Cheap: only tries the exclusive lockfile, never reloads the catalog.
    """
    import native_store
    lockfile = os.path.join(os.path.abspath(store), native_store.LOCKFILE)
    if not os.path.isfile(lockfile):
        return False
    try:
        native_store._ExclusiveLease(lockfile).close()
    except Exception:
        return True
    return False


def start_provider(store: str | os.PathLike) -> bool:
    """Start a hidden `native serve` for *store*; False if one is already running."""
    import launcher
    if provider_running(store):
        return False
    script = os.path.abspath(__file__)
    subprocess.Popen([launcher.resolve_pythonw(), script, "native", "serve", "--store",
                      os.path.abspath(store)],
                     cwd=os.path.dirname(script), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                     creationflags=_DETACHED if os.name == "nt" else 0)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if provider_running(store):
            return True
        time.sleep(0.25)
    raise CliUsageError("provider did not start; see serve.log in the store")


def stop_provider(store: str | os.PathLike, timeout: float = 60) -> bool:
    """Ask a running provider to disconnect; False if none was running."""
    import native_provider
    if not provider_running(store):
        return False
    native_provider.request_stop(str(store))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not provider_running(store):
            return True
        time.sleep(0.25)
    raise CliUsageError(f"provider did not stop within {timeout:.0f} seconds; see serve.log in the store")


@contextlib.contextmanager
def paused_provider(store: str | os.PathLike):
    """Free the store lease for a mutation, then restart the provider if it ran."""
    was_running = stop_provider(store)
    try:
        yield
    finally:
        if was_running:
            start_provider(store)


def remove_verified_input(archive: str | os.PathLike, entry: dict) -> bool:
    """Delete an imported .burpz only if byte-identical to the verified store copy."""
    import hashlib
    require_ordinary_path(archive)
    digest = hashlib.sha256()
    with open(archive, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != entry["archive_sha256"]:
        return False
    os.remove(archive)
    return True


def _remove_imported(archive: Path, entry: dict, yes: bool) -> bool:
    if not _confirm(f"Remove {archive}? Its verified copy is in the native store.", yes):
        _say("Input archive kept.")
        return False
    if not remove_verified_input(archive, entry):
        _say("Input changed since import; kept.", error=True)
        return False
    return True


def _startup_shortcut() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise CliUsageError("APPDATA is not set; cannot locate the Startup folder")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / STARTUP_SHORTCUT


def autostart_enabled() -> bool:
    try:
        return _startup_shortcut().is_file()
    except CliUsageError:
        return False


def set_autostart(store: str | os.PathLike, enable: bool) -> Path:
    """Add/remove the per-user Startup shortcut that runs a hidden `native serve`."""
    shortcut = _startup_shortcut()
    if not enable:
        if shortcut.exists():
            shortcut.unlink()
        return shortcut
    from native_store import NativeStore
    store = os.path.abspath(store)
    NativeStore(store).status()  # Must be an existing valid store.
    import launcher
    script = os.path.abspath(__file__)
    _write_shortcut(shortcut, launcher.resolve_pythonw(), [script, "native", "serve", "--store", store],
                    "Burpzip native-open provider")
    return shortcut


def _write_shortcut(link: Path, target: str, arguments: list[str], description: str,
                    icon: str | None = None) -> None:
    """Create a .lnk via WScript.Shell; values travel in environment variables only."""
    ps = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:BZ_LNK);"
          "$s.TargetPath=$env:BZ_EXE;$s.Arguments=$env:BZ_ARGS;"
          "$s.WorkingDirectory=$env:BZ_DIR;$s.WindowStyle=7;$s.Description=$env:BZ_DESC;"
          "if ($env:BZ_ICON) { $s.IconLocation=$env:BZ_ICON };$s.Save()")
    env = {**os.environ, "BZ_LNK": str(link), "BZ_EXE": target,
           "BZ_ARGS": subprocess.list2cmdline(arguments), "BZ_DESC": description,
           "BZ_DIR": os.path.dirname(os.path.abspath(__file__)), "BZ_ICON": icon or ""}
    link.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], env=env,
                   check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=60,
                   creationflags=_NO_WINDOW if os.name == "nt" else 0)


BURP_SHORTCUT = "Burp Suite (Burpzip).lnk"


def _desktop_dir() -> Path:
    """The real Desktop folder (it may be redirected, e.g. to OneDrive)."""
    if os.name == "nt":
        buffer = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buffer) == 0:  # CSIDL_DESKTOPDIRECTORY
            return Path(buffer.value)
    return Path.home() / "Desktop"


def burp_shortcut_paths() -> list[Path]:
    """Desktop and Start-menu "Burp Suite (Burpzip)" shortcuts."""
    paths = [_desktop_dir() / BURP_SHORTCUT]
    try:
        paths.append(_startup_shortcut().parent.parent / BURP_SHORTCUT)  # ...\Start Menu\Programs
    except CliUsageError:
        pass
    return paths


def burp_shortcuts_enabled() -> bool:
    return any(p.is_file() for p in burp_shortcut_paths())


def set_burp_shortcuts(enable: bool) -> list[Path]:
    """Add/remove shortcuts that run `burpzip.py burp` (provider + Burp together)."""
    links = burp_shortcut_paths()
    if not enable:
        for link in links:
            if link.is_file():
                link.unlink()
        return links
    import launcher
    script = os.path.abspath(__file__)
    for link in links:
        _write_shortcut(link, launcher.resolve_pythonw(), [script, "burp"],
                        "Burp Suite with the Burpzip Burp-folder provider",
                        icon=launcher.burp_exe_for_icon())
    return links


def apply_provider_mode(store: str | os.PathLike, mode: str, *, save: bool = False) -> dict:
    """logon: Startup shortcut; with-burp: Burp shortcuts; manual: neither."""
    import config
    if mode not in config.PROVIDER_MODES:
        raise CliUsageError(f"provider mode must be one of {', '.join(config.PROVIDER_MODES)}")
    set_autostart(store, mode == "logon")
    links = set_burp_shortcuts(mode == "with-burp")
    started = start_provider(store) if mode == "logon" else False
    if save:
        settings = _config()
        settings.update(provider=mode, store=str(os.path.abspath(store)))
        config.save(settings)
    return {"provider": mode, "autostart_at_logon": mode == "logon",
            "burp_shortcuts": [str(p) for p in links] if mode == "with-burp" else [],
            "started_now": started}


def run_with_burp(project: str | None = None, *, poll: float = 3.0, settle: float = 25.0,
                  appear: float = 120.0) -> dict:
    """What the "Burp Suite (Burpzip)" shortcut runs.

    Starts the provider if needed, launches Burp, waits until every Burp process
    has exited (Burp's launcher exits early, so processes are watched, not the
    launcher), then - in with-burp mode, and only if this run started it - asks
    the provider to stop. The provider defers the stop while a "Re-zip it now?"
    question is still open.
    """
    import launcher
    ensure_config()
    settings = _config()
    store = native_store_path()
    started = bool(store) and start_provider(store)
    command = launcher.find_burp() + ([f"--project-file={os.path.abspath(project)}"] if project else [])
    subprocess.Popen(command, cwd=os.path.dirname(command[0]) or None, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                     creationflags=_DETACHED if os.name == "nt" else 0)
    deadline = time.monotonic() + appear
    while not burp_running() and time.monotonic() < deadline:
        time.sleep(poll)
    while burp_running():
        time.sleep(poll)
    stop_requested = False
    if started and settings["provider"] == "with-burp":
        time.sleep(settle)  # Let the close watcher notice the release and ask.
        import native_provider
        native_provider.request_stop(str(store))
        stop_requested = True
    return {"burp": "exited", "provider_started": started, "provider_stop_requested": stop_requested}


def ensure_config() -> dict | None:
    """First run of this version: write burpzip.ini from the old GUI settings and an
    existing Burp folder, so nothing changes for existing users.

    Skipped when burpzip.ini exists or BURPZIP_CONFIG points elsewhere (tests).
    Returns the settings written, or None.
    """
    import config
    if config.exists() or os.environ.get("BURPZIP_CONFIG"):
        return None
    settings, found = config.defaults(), False
    legacy = Path(os.environ.get("APPDATA") or Path.home()) / "burpzip" / "gui_settings.json"
    try:
        data = json.loads(legacy.read_text(encoding="utf-8"))
        found = True
        for key in ("days", "min_size_mb", "level", "extra_folders"):
            if key in data:
                settings[key] = data[key]
        settings["store"] = data.get("native_store") or ""
    except (OSError, ValueError, AttributeError):
        pass
    store = native_store_path(settings["store"] or None)
    if store is not None:
        found = True
        settings["store"] = str(store)
        try:
            from native_store import NativeStore
            settings["folder"] = NativeStore(str(store)).root
        except Exception:
            pass
        settings["provider"] = "logon" if autostart_enabled() else "manual"
    if not found:
        return None
    config.save(settings)
    return settings


def _autostart(store: Path, *, enable: bool) -> dict:
    shortcut = set_autostart(store, enable)
    if not enable:
        return {"autostart": False, "shortcut": str(shortcut)}
    started = start_provider(store)
    return {"autostart": True, "shortcut": str(shortcut), "started_now": started,
            "log": os.path.join(os.path.abspath(store), "serve.log")}


def _native_dispatch(args) -> int:
    command = args.native_cmd
    if command == "init":
        _say("Experimental native registration creates an owned Windows sync root.\n"
             "Use a NEW empty NTFS folder and a separate external store. Other readers can\n"
             "hydrate imports; hydrated files stay resident. Stop never unregisters;\n"
             "full detach is unavailable without proven namespace exclusion. No Burp validation.")
        if not _confirm("Consent to registering this new experimental root?", args.yes):
            _say("Cancelled; nothing changed.")
            return 1
    elif command == "detach":
        _say("Detach materializes/reverts current content and retains store/recovery state.\n"
             "Without proven namespace exclusion it retains registration and returns incomplete.")
        if not _confirm("Consent to experimental materialize/revert and safe detach attempt?", args.yes):
            _say("Cancelled; nothing changed.")
            return 1
    if command not in ("status", "stop") and not (command == "export" and args.snapshot) \
            and not (command == "autostart" and args.disable):
        import native_cfapi
        if getattr(native_cfapi, "NATIVE_RELEASE_READY", False) is not True:
            raise CliUsageError("native activation disabled until real native safety gates pass; "
                                "--experimental/--yes do not bypass the release gate")
    if command == "status":
        from native_store import NativeStore
        result = NativeStore(str(args.store)).status()
    elif command == "init":
        import native_store
        result = native_store.init_root(str(args.root), str(args.store))
    elif command == "add":
        import native_store
        with paused_provider(args.store):
            result = native_store.add_archive(str(args.store), str(args.archive))
        if args.move:
            result = {**result, "input_removed": _remove_imported(args.archive, result, args.yes)}
    elif command == "rezip":
        import native_provider
        with paused_provider(args.store):
            if args.name:
                result = native_provider.rezip_project(str(args.store), args.name, level=args.level)
            else:
                result = native_provider.rezip_idle(str(args.store), idle_days=int(args.idle_days),
                                                    level=args.level)
    elif command == "stop":
        result = {"status": "stopped" if stop_provider(args.store) else "not running",
                  "registration_retained": True}
    elif command == "autostart":
        result = _autostart(args.store, enable=args.enable)
    elif command == "provider-mode":
        store = native_store_path(args.store)
        if store is None:
            raise CliUsageError("no Burp folder store found; run 'native init' or set store in burpzip.ini")
        result = apply_provider_mode(store, args.mode, save=True)
    else:
        import native_provider
        deadline = args.deadline_seconds
        if command == "serve":
            settings = _config()
            idle = args.idle_days if args.idle_days is not None else settings["idle_days"]
            ask = args.ask_on_close if args.ask_on_close is not None else settings["ask_on_close"]
            result = native_provider.serve_root(str(args.store), deadline_seconds=deadline,
                                                idle_days=int(idle), ask_on_close=bool(ask))
        elif command == "materialize":
            with paused_provider(args.store):
                result = native_provider.materialize_root(str(args.store), deadline_seconds=deadline)
        elif command == "export":
            require_ordinary_path(args.dest)
            if os.path.lexists(args.dest):
                raise CliUsageError(f"destination already exists: {args.dest}")
            if not args.dest.parent.is_dir():
                raise CliUsageError(f"destination folder not found: {args.dest.parent}")
            if args.snapshot:
                _say("Historical import snapshot only; NOT a backup of later edits.")
            with paused_provider(args.store):
                result = native_provider.export_project(str(args.store), args.name, str(args.dest),
                                                         current=args.current, deadline_seconds=deadline)
        elif command == "detach":
            stop_provider(args.store)  # Detached roots are not served again.
            result = native_provider.detach_root(str(args.store), deadline_seconds=deadline)
        else:
            raise CliUsageError(f"unknown native command: {command}")
    if result is not None:
        _say(json.dumps(result, indent=2, ensure_ascii=False) if isinstance(result, (dict, list))
             else str(result))
    if command == "detach" and (not isinstance(result, dict) or result.get("detached") is not True):
        _say("Incomplete detach; registration/recovery state retained.", error=True)
        return 1
    return 0


def _dispatch(args) -> int:
    if args.cmd == "native":
        return _native_dispatch(args)
    if args.cmd == "burp":
        result = run_with_burp(args.project)
        _say(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    if args.cmd in (None, "gui"):
        import gui
        gui.main([])
        return 0
    if args.cmd in ("scan", "archive-old"):
        items, plan, running = _scan_plan(args)
        print_report(items, plan, running)
        if args.cmd == "scan":
            if args.plan is not None:
                _plan_output(args.plan, items)
                # Exclusive creation also protects against a race after validation.
                with args.plan.open("x", encoding="utf-8") as output:
                    json.dump(plan, output, indent=2, ensure_ascii=False, allow_nan=False)
                _say(f"\nPlan written to {args.plan}")
            return 0
        count = sum(s["action"] == "archive" for s in plan["steps"])
        if not count:
            _say("No projects can be archived in this plan.")
            return 0
        if not _confirm(f"Archive {count} project(s) and delete their originals after verification?", args.yes):
            _say("Cancelled; nothing changed.")
            return 1
        import archiver
        results = archiver.run_plan(plan, level=args.level, threads=args.threads)
        failed = False
        for result in results:
            if isinstance(result, Exception):
                _say(f"error: {result}", error=True)
                failed = True
            else:
                _result(result)
        return int(failed)
    if args.cmd == "open":
        path = _require_file(args.path, ("archive", "project"), managed=True)
        import launcher
        return launcher.cli_open(path)
    if args.cmd in ("register", "unregister"):
        import launcher
        if args.cmd == "register":
            _say(launcher.register_association())
        else:
            launcher.unregister_association()
            _say("Burpzip association removed.")
        return 0

    import archiver
    if args.cmd == "archive":
        # Validate the whole batch before any mutation, and de-duplicate inputs.
        paths = {}
        for path in args.paths:
            value = _require_file(path, ("project",))
            paths.setdefault(os.path.normcase(os.path.realpath(path)), value)
        if not args.keep_original and not _confirm(
                f"Archive {len(paths)} project(s) and delete originals after verification?", args.yes):
            _say("Cancelled; nothing changed.")
            return 1
        failed = False
        for path in paths.values():
            try:
                _result(archiver.archive_project(path, level=args.level, threads=args.threads,
                                                delete_original=not args.keep_original))
            except (archiver.ArchiveError, OSError) as exc:
                _say(f"error: {path}: {exc}", error=True)
                failed = True
        return int(failed)
    if args.cmd == "restore":
        path = _require_file(args.archive, ("archive",), read_archive=True)
        if args.dest is not None:
            require_ordinary_path(args.dest)
            if os.path.lexists(args.dest):
                raise CliUsageError(f"destination already exists: {args.dest}")
            if not args.dest.parent.is_dir():
                raise CliUsageError(f"destination folder not found: {args.dest.parent}")
        _say(f"Restored: {archiver.restore_project(path, dest_path=str(args.dest) if args.dest else None)}")
        return 0
    if args.cmd == "rezip":
        path = _require_file(args.project, ("project",))
        if not _confirm("Re-compress this project and remove the unpacked copy after verification?", args.yes):
            _say("Cancelled; nothing changed.")
            return 1
        _result(archiver.rezip_after_use(path, level=args.level))
        return 0
    if args.cmd == "delete-backup":
        path = _require_file(args.path, ("backup",))
        parent = Path(backup_parent(path))
        require_ordinary_path(parent)
        if not parent.is_file():
            raise CliUsageError(f"main project missing, backup may be the only copy: {parent}")
        if args.path.stat().st_mtime > parent.stat().st_mtime and not args.force_newer:
            raise CliUsageError("backup is newer than the project; manual review and --force-newer required")
        if not _confirm(f"Permanently delete backup {args.path}?", args.yes, typed=args.force_newer):
            _say("Cancelled; nothing changed.")
            return 1
        freed = archiver.delete_backup(path, force_newer=args.force_newer)
        _say(f"Backup deleted: {args.path}; freed {human_size(freed)}")
        return 0
    raise CliUsageError(f"unknown command: {args.cmd}")


def main(argv: list[str] | None = None) -> int:
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
    args = _parser().parse_args(argv)
    try:
        return _dispatch(args)
    except CliUsageError as exc:
        _say(f"error: {exc}", error=True)
        return 2
    except Exception as exc:
        _say(f"error: {exc}", error=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
