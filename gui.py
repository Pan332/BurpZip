"""burpzip GUI - a ttk desktop app to browse, archive and restore Burp projects.

All slow work (scanning, 7z, hashing, waiting for Burp) runs in ONE background
worker thread fed by a task queue. The worker never touches Tk: it posts
messages to a UI queue which the Tk thread drains with ``root.after`` polling.

``archiver`` and ``launcher`` are imported lazily so this module loads (and the
table works) even when those modules are missing; actions that need them show
a clear error instead.

Usage:
    python gui.py [--days 14] [--root DIR ...]
"""
from __future__ import annotations

import copy
import importlib
import inspect
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import burpzip  # noqa: E402

MB = 1024**2
POLL_MS = 100
LEVELS = {"Normal (5)": 5, "Ultra (9)": 9}
DEFAULT_SETTINGS: dict[str, Any] = {
    "native_store": "",
    "folder": "",
    "provider": "logon",
    "ask_on_close": True,
    "idle_days": 10,
    "burp_path": "",
    "days": 10,
    "min_size_mb": burpzip.MIN_ARCHIVE_SIZE // MB,
    "level": 5,
    "extra_folders": [],
}

# --- engagement grouping ----------------------------------------------------
ENGAGEMENT_ID_RE = re.compile(r"\[\s*([A-Za-z]{1,8}\d{4}-\d+)\s*\]")
LEADING_DATE_RE = re.compile(r"^\s*\d{4}[-_.]\d{1,2}[-_.]\d{1,2}[-_ ]*")
EXT_RE = re.compile(
    r"(\.\d{8}-\d{6}\.burpz|\.burpz|\.burp\.backup.*|\.burp(\.\d{8}-\d{6})?\.7z|\.burp)$",
    re.IGNORECASE,
)
TOKEN_SPLIT_RE = re.compile(r"[\s\-_().\[\]{}]+")
NOISE_TOKEN_RE = re.compile(
    r"^(round\d*|rnd\d*|r\d+|revisit\d*|reviste\d*|revist\d*|retest\d*|re|init|initial|"
    r"backup|bak|copy|final|v\d+|\d{1,2})$",
    re.IGNORECASE,
)


def engagement_key(name: str) -> str:
    """Return a grouping key for a project/backup/archive file name.

    A bracketed engagement id such as ``[VA2026-00123]`` wins. Otherwise the
    leading date, extension and round/revisit/init/backup/copy-number tokens
    are stripped and the rest is lower-cased and joined with ``-``.
    """
    base = Path(name).name
    m = ENGAGEMENT_ID_RE.search(base)
    if m:
        return m.group(1).upper()
    stem = EXT_RE.sub("", base)
    stem = LEADING_DATE_RE.sub("", stem)
    tokens = [t for t in TOKEN_SPLIT_RE.split(stem) if t]
    kept = [t.lower() for t in tokens if not NOISE_TOKEN_RE.match(t)]
    if kept:
        return "-".join(kept)
    return stem.lower() or base.lower()


# --- pure presentation helpers -----------------------------------------------
def item_meta(item: Any) -> dict | None:
    """The archive meta dict of an item, or None (defensive)."""
    meta = getattr(item, "meta", None)
    return meta if isinstance(meta, dict) else None


def item_status(item: Any, days: float, min_size: int) -> str:
    """Status label: Archived / In use / Backup / Small / Old / Active."""
    kind = getattr(item, "kind", "")
    native = getattr(item, "native", "ordinary")
    if native == "ordinary" and kind in ("native", "cloud", "unknown", "store"):
        native = kind
    if native == "native":
        if getattr(item, "native_modified", False):
            return "Burp folder: unpacked (edited)"
        if getattr(item, "native_resident", False) or getattr(item, "native_ready", False):
            return "Burp folder: unpacked"
        return "Burp folder: zipped"
    if native != "ordinary":
        return {"cloud": "Cloud protected", "store": "Burp folder store"}.get(native, "Unknown protected")
    if kind == "archive":
        return "Zipped (.burpz)"
    if getattr(item, "in_use", False):
        return "In use"
    if kind == "backup":
        return "Backup"
    if item.size < min_size:
        return "Small"
    if item.age_days >= days:
        return "Old"
    return "Active"


def status_tag(status: str) -> str:
    """Treeview tag name for a status label."""
    if status.startswith(("Burp folder", "Cloud", "Unknown")):
        return "protected"
    return {"Old": "old", "In use": "inuse", "Backup": "backup",
            "Zipped (.burpz)": "archived", "Small": "small"}.get(status, "active")


def folder_display(path: str, home: str | None = None) -> str:
    """Parent folder of *path*, shown as ``~\\...`` when under the home dir."""
    home = home if home is not None else str(Path.home())
    d = str(Path(path).parent)
    if home and d.lower().startswith(home.lower()):
        return "~" + d[len(home):]
    return d


def original_size(item: Any) -> int:
    """Project size: meta size for archives (when known), else file size."""
    meta = item_meta(item)
    if getattr(item, "kind", "") == "archive" and meta and meta.get("size"):
        return int(meta["size"])
    return int(item.size)


def edited_epoch(item: Any) -> float:
    """When the PROJECT was last edited (meta mtime for archives)."""
    meta = item_meta(item)
    if getattr(item, "kind", "") == "archive" and meta and meta.get("mtime"):
        return float(meta["mtime"])
    return float(item.mtime)


def archived_date(item: Any) -> str:
    """YYYY-MM-DD the archive was created (meta archived_at, else file mtime)."""
    meta = item_meta(item)
    if meta and meta.get("archived_at"):
        return str(meta["archived_at"])[:10]
    return time.strftime("%Y-%m-%d", time.localtime(item.mtime))


def is_burp_folder(item: Any) -> bool:
    return getattr(item, "native", "ordinary") == "native"


def native_zipped(item: Any) -> bool:
    """A Burp-folder project that is currently a small placeholder."""
    return is_burp_folder(item) and not getattr(item, "native_resident", False)


def native_saved(item: Any) -> int:
    meta = item_meta(item)
    if not native_zipped(item) or not meta or not meta.get("archive_size"):
        return 0
    return max(0, int(item.size) - int(meta["archive_size"]))


def edited_text(item: Any, now: float | None = None) -> str:
    """Human 'Last edited' cell, plus archived date for archives."""
    if is_burp_folder(item) and item.mtime:
        now = now if now is not None else time.time()
        return burpzip.human_age(max(0.0, (now - item.mtime) / 86400))
    if burpzip.protected_item(item):
        return "unknown (protected)"
    now = now if now is not None else time.time()
    age = max(0.0, (now - edited_epoch(item)) / 86400)
    text = burpzip.human_age(age)
    if getattr(item, "kind", "") == "archive":
        text += f" (archived {archived_date(item)})"
    return text


def archive_text(item: Any) -> str:
    """'<archive size> (<n>% saved)' for archives, '' otherwise."""
    meta = item_meta(item)
    if is_burp_folder(item):
        if not meta or not meta.get("archive_size"):
            return ""
        zip_size = burpzip.human_size(int(meta["archive_size"]))
        if not native_zipped(item):
            return f"unpacked (zip {zip_size})"
        saved = max(0.0, 1 - int(meta["archive_size"]) / item.size) * 100 if item.size else 0
        return f"{zip_size} zip ({saved:.0f}% saved)"
    if getattr(item, "kind", "") != "archive":
        return ""
    orig = original_size(item)
    text = burpzip.human_size(item.size)
    if item_meta(item) and orig > 0:
        saved = max(0.0, 1 - item.size / orig) * 100
        text += f" ({saved:.0f}% saved)"
    return text


def row_values(item: Any, days: float, min_size: int, home: str | None = None,
               now: float | None = None) -> dict[str, str]:
    """All display cells of one table row."""
    return {
        "name": Path(item.path).name,
        "folder": folder_display(item.path, home),
        "size": burpzip.human_size(original_size(item)),
        "edited": edited_text(item, now),
        "status": item_status(item, days, min_size),
        "archive": archive_text(item),
    }


SORT_KEYS: dict[str, Callable[[Any], Any]] = {
    "name": lambda i: Path(i.path).name.lower(),
    "folder": lambda i: str(Path(i.path).parent).lower(),
    "size": original_size,
    "edited": edited_epoch,
    "status": lambda i: (getattr(i, "kind", ""), bool(getattr(i, "in_use", False)), i.age_days),
    "archive": lambda i: i.size if getattr(i, "kind", "") == "archive"
    else (native_saved(i) if is_burp_folder(i) else -1),
}


def matches_filter(item: Any, text: str, home: str | None = None) -> bool:
    """Case-insensitive substring match on file name or folder."""
    text = text.strip().lower()
    if not text:
        return True
    return (text in Path(item.path).name.lower()
            or text in folder_display(item.path, home).lower())


def summarize(items: Iterable[Any]) -> dict[str, int]:
    """Totals for the summary bar."""
    s = {"projects": 0, "project_bytes": 0, "archives": 0, "archive_bytes": 0,
         "saved_bytes": 0, "backups": 0, "backup_bytes": 0,
         "burp_folder": 0, "burp_folder_saved": 0}
    for i in items:
        kind = getattr(i, "kind", "")
        if is_burp_folder(i):
            s["burp_folder"] += 1
            s["burp_folder_saved"] += native_saved(i)
            if not native_zipped(i):
                s["project_bytes"] += i.size  # Unpacked: really on disk.
            continue
        if kind == "project":
            s["projects"] += 1
            s["project_bytes"] += i.size
        elif kind == "backup":
            s["backups"] += 1
            s["backup_bytes"] += i.size
        elif kind == "archive":
            s["archives"] += 1
            s["archive_bytes"] += i.size
            if item_meta(i):
                s["saved_bytes"] += max(0, original_size(i) - i.size)
    return s


def archive_only_plan(plan: dict) -> dict:
    """Copy of a build_plan() result in which backups are never deleted.

    Leftover backups are deleted only by explicit per-file user action, so
    every ``delete-backup`` step becomes ``skip`` here.
    """
    out = dict(plan)
    steps = []
    for s in plan.get("steps", []):
        s = dict(s)
        if s.get("action") == "delete-backup":
            s["action"] = "skip"
            s["frees"] = 0
            s["notes"] = list(s.get("notes", [])) + ["backups are deleted only by hand"]
        steps.append(s)
    out["steps"] = steps
    return out


def result_text(res: Any) -> str:
    """Short human text for an archiver/launcher return value."""
    if res is None:
        return "unchanged copy removed (archive kept)"
    if isinstance(res, list):
        return "; ".join(result_text(r) for r in res) or "nothing to do"
    if isinstance(res, Exception):
        return f"FAILED: {res}"
    if hasattr(res, "archive_path") and hasattr(res, "original_size"):
        orig = int(res.original_size) or 1
        return (f"{Path(res.archive_path).name} {burpzip.human_size(res.archive_size)} "
                f"({max(0.0, 1 - res.archive_size / orig) * 100:.0f}% saved)"
                + ("" if res.deleted_original else ", original kept"))
    if isinstance(res, dict) and "status" in res:
        return f"{res['status']} {Path(res.get('project', '')).name}"
    return str(res)


def plan_summary(plan: dict) -> str:
    """Multi-line text describing a plan for the confirm dialog."""
    archive = [s for s in plan["steps"] if s["action"] == "archive"]
    other = [s for s in plan["steps"] if s["action"] != "archive"]
    total = sum(s["size"] for s in archive)
    frees = sum(s["frees"] for s in archive)
    lines = [
        f"Archive {len(archive)} project(s), {burpzip.human_size(total)} in total.",
        f"Expected to free ~{burpzip.human_size(frees)} "
        f"(assumes archives at {int(burpzip.RATIO_EXPECTED * 100)}% of original).",
        f"Free space now {burpzip.human_size(plan['free_now'])}, "
        f"after ~{burpzip.human_size(plan['free_now'] + frees)}.",
        f"Not archived: {len(other)} (skipped / deferred / backups).",
        "Each archive is verified (7z test + SHA-256) before the original is deleted.",
        "",
    ]
    for s in archive:
        lines.append(f"  archive   {Path(s['path']).name}  {burpzip.human_size(s['size'])}")
    for s in other:
        note = "; ".join(s.get("notes") or [])
        lines.append(f"  {s['action']:<9} {Path(s['path']).name}  {note}")
    return "\n".join(lines)


# --- lazy module access -------------------------------------------------------
class MissingFeature(RuntimeError):
    """Raised when archiver/launcher (or one of their functions) is unavailable."""


def load_function(module: str, name: str) -> Callable:
    """Import *module* lazily and return its function *name*."""
    try:
        mod = importlib.import_module(module)
    except Exception as exc:  # ImportError or a broken module
        raise MissingFeature(f"{module}.py could not be loaded ({exc}).\n"
                             f"This action needs {module}.{name}().") from exc
    fn = getattr(mod, name, None)
    if not callable(fn):
        raise MissingFeature(f"{module}.py has no function {name}().")
    return fn


ALIASES: dict[str, tuple[str, ...]] = {
    "stop_event": ("stop_event", "stop", "cancel_event", "cancel"),
    "log": ("log", "logger", "on_log", "log_fn"),
    "progress": ("progress",),
    "on_state": ("on_state",),
    "level": ("level", "compression_level", "mx"),
    "confirm": ("confirm", "ask", "on_confirm", "confirm_fn"),
    "force": ("force_newer", "force"),
    "dest_dir": ("dest_dir",),
}


def call_flexible(fn: Callable, *args: Any, **options: Any) -> Any:
    """Call *fn* passing only the keyword options it accepts.

    Option names are canonical (see ALIASES); each is passed under the first
    alias the function's signature declares. Functions taking ``**kwargs``
    receive the canonical names. ``None`` values are never passed.
    """
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(*args)
    var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
    kwargs: dict[str, Any] = {}
    for canon, value in options.items():
        if value is None:
            continue
        for alias in ALIASES.get(canon, (canon,)):
            if alias in params:
                kwargs[alias] = value
                break
        else:
            if var_kw:
                kwargs[canon] = value
    return fn(*args, **kwargs)


def accepts_option(fn: Callable, canon: str) -> bool:
    """True if *fn* declares one of the aliases of option *canon*."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return any(a in params for a in ALIASES.get(canon, (canon,)))


# --- settings ----------------------------------------------------------------
def default_settings_path() -> Path:
    """burpzip.ini next to burpzip.py (see config.py)."""
    import config
    return config.config_path()


def load_settings(path: Path | None) -> dict[str, Any]:
    """Defaults overlaid with the saved settings file (if any).

    *.ini is burpzip.ini (config.py); a legacy JSON file is still read.
    """
    s = dict(DEFAULT_SETTINGS)
    s["extra_folders"] = []
    if path and path.suffix.lower() == ".ini":
        import config
        c = config.load(path)
        s.update({k: c[k] for k in ("folder", "provider", "ask_on_close", "idle_days", "burp_path",
                                    "days", "min_size_mb", "level", "extra_folders")})
        s["native_store"] = c["store"]
        return s
    if path and path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            s.update({k: data[k] for k in DEFAULT_SETTINGS if k in data})
        except (OSError, ValueError):
            pass
    return s


def save_settings(path: Path | None, settings: dict[str, Any]) -> None:
    """Persist settings; silently ignored when *path* is None or unwritable."""
    if not path:
        return
    if path.suffix.lower() == ".ini":
        import config
        c = config.load(path)
        c.update({k: settings[k] for k in ("folder", "provider", "ask_on_close", "idle_days", "burp_path",
                                           "days", "min_size_mb", "level", "extra_folders") if k in settings})
        c["store"] = settings.get("native_store", "") or ""
        try:
            config.save(c, path)
        except OSError:
            pass
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    except OSError:
        pass


# --- the app -------------------------------------------------------------------
class BurpZipApp:
    """Main window: table, summary bar, actions, progress bar and log pane."""

    COLUMNS = ("folder", "size", "edited", "status", "archive")
    HEADINGS = {"name": "Name", "folder": "Folder", "size": "Size",
                "edited": "Last edited", "status": "Status", "archive": "Archive (saved)"}

    def __init__(self, root: tk.Misc, roots: list[Path] | None = None, days: int | None = None,
                 items: list[Any] | None = None, settings_path: Path | None = None,
                 autoscan: bool = True) -> None:
        self.root = root
        self.settings_path = settings_path
        self.settings = load_settings(settings_path)
        if days is not None:
            self.settings["days"] = days
        self.base_roots = [Path(r) for r in (roots or burpzip.default_roots())]
        self.home = str(Path.home())
        self.items: list[Any] = list(items or [])
        self.burp_running: bool | None = None
        self.free_bytes: int | None = None
        self.by_iid: dict[str, Any] = {}
        self.sort_col, self.sort_rev = "edited", True
        self.busy = False
        self.stop_event = threading.Event()
        self.closing = threading.Event()
        self._tasks: queue.Queue = queue.Queue()
        self._ui: queue.Queue = queue.Queue()
        self._after_id: str | None = None
        self._polling = False  # modal Tk dialogs can dispatch nested callbacks
        self._last_stage: tuple[str, int] | None = None
        self._action_buttons: list[ttk.Button] = []
        self._all_buttons: list[ttk.Button] = []
        self._provider_tick = 0

        self._build()
        # File operations must finish safely even while the window is closing.
        self._worker = threading.Thread(target=self._worker_loop, name="burpzip-worker",
                                        daemon=False)
        self._worker.start()
        self._after_id = self.root.after(POLL_MS, self._poll)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh()
        if autoscan and items is None:
            self.rescan()

    # ----- layout ------------------------------------------------------------
    def _build(self) -> None:
        self.root.title("burpzip - Burp project archiver")
        self.root.geometry("1180x720")
        self.root.minsize(820, 480)
        self._build_menu()
        self._build_toolbar()
        self._build_filterbar()
        self._build_bottom()   # packed before the table so the table takes the rest
        self._build_summary()
        self._build_table()

    def _build_menu(self) -> None:
        bar = tk.Menu(self.root)
        f = tk.Menu(bar, tearoff=False)
        f.add_command(label="Rescan", command=self.rescan)
        f.add_command(label="Settings...", command=self.open_settings)
        f.add_separator()
        f.add_command(label="Exit", command=self.on_close)
        bar.add_cascade(label="File", menu=f)
        t = tk.Menu(bar, tearoff=False)
        t.add_command(label="Register double-click for .burpz", command=self.register_assoc)
        t.add_command(label="Unregister double-click for .burpz", command=self.unregister_assoc)
        t.add_command(label="Check .burpz association", command=self.check_assoc)
        bar.add_cascade(label="Tools", menu=t)
        n = tk.Menu(bar, tearoff=False)
        n.add_command(label="Set up Burp folder...", command=self.setup_burp_folder)
        n.add_command(label="Open Burp folder", command=self.open_burp_folder)
        n.add_separator()
        n.add_command(label="Start provider", command=self.start_provider)
        n.add_command(label="Stop provider", command=self.stop_provider)
        modes = tk.Menu(n, tearoff=False)
        self.mode_var = tk.StringVar(value=self.settings.get("provider", "logon"))
        for value, label in (("logon", "Start at Windows logon"),
                             ("with-burp", "Start with Burp (\"Burp Suite (Burpzip)\" shortcut)"),
                             ("manual", "Manual (start it yourself)")):
            modes.add_radiobutton(label=label, value=value, variable=self.mode_var,
                                  command=self.set_provider_mode)
        n.add_cascade(label="Provider mode", menu=modes)
        n.add_command(label="Show provider log", command=self.show_provider_log)
        bar.add_cascade(label="Burp folder", menu=n)
        self.root.config(menu=bar)
        self.menubar = bar

    def _button(self, parent: tk.Widget, text: str, cmd: Callable,
                action: bool = True) -> ttk.Button:
        b = ttk.Button(parent, text=text, command=cmd)
        b.pack(side="left", padx=2)
        self._all_buttons.append(b)
        if action:
            self._action_buttons.append(b)
        return b

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(6, 6, 6, 2))
        bar.pack(side="top", fill="x")
        self._button(bar, "Rescan", self.rescan)
        self._button(bar, "Archive selected", self.archive_selected)
        self._button(bar, "Archive all old...", self.archive_all_old)
        self._button(bar, "Open", self.open_selected)
        self._button(bar, "Restore only", self.restore_selected)
        self._button(bar, "Add to Burp folder", self.add_to_burp_folder)
        self._button(bar, "Unpack now", self.unpack_selected)
        self._button(bar, "Re-zip", self.rezip_selected)
        self._button(bar, "Show in Explorer", self.show_in_explorer, action=False)
        self._button(bar, "Delete backup...", self.delete_backup_selected)
        self._button(bar, "Settings...", self.open_settings)
        self.stop_btn = self._button(bar, "Stop", self.request_stop, action=False)
        self.stop_btn.state(["disabled"])

    def _build_filterbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(6, 2))
        bar.pack(side="top", fill="x")
        ttk.Label(bar, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh())
        ttk.Entry(bar, textvariable=self.search_var, width=40).pack(side="left", padx=4)
        self.group_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Group by engagement", variable=self.group_var,
                        command=self.refresh).pack(side="left", padx=10)
        self.burp_lbl = ttk.Label(bar, text="Burp: ?")
        self.burp_lbl.pack(side="right")
        self.provider_lbl = ttk.Label(bar, text="Provider: ?")
        self.provider_lbl.pack(side="right", padx=12)

    def _build_table(self) -> None:
        frame = ttk.Frame(self.root, padding=(6, 2))
        frame.pack(side="top", fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=self.COLUMNS, show="tree headings",
                                 selectmode="extended")
        widths = {"folder": 230, "size": 85, "edited": 230, "status": 80, "archive": 150}
        self.tree.heading("#0", text="Name", command=lambda: self.sort_by("name"))
        self.tree.column("#0", width=380, stretch=True)
        for c in self.COLUMNS:
            self.tree.heading(c, text=self.HEADINGS[c], command=lambda c=c: self.sort_by(c))
            self.tree.column(c, width=widths[c], anchor="e" if c == "size" else "w",
                             stretch=c in ("folder", "edited"))
        self.tree.tag_configure("old", background="#fff0d0")
        self.tree.tag_configure("inuse", background="#ffd6d6")
        self.tree.tag_configure("backup", background="#ece4f7")
        self.tree.tag_configure("archived", foreground="#1f6b2a")
        self.tree.tag_configure("small", foreground="#777777")
        self.tree.tag_configure("protected", foreground="#6b4a87")
        self.tree.tag_configure("group", font=("Segoe UI", 9, "bold"))
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.open_selected())

    def _build_summary(self) -> None:
        self.summary_var = tk.StringVar(value="")
        ttk.Label(self.root, textvariable=self.summary_var, padding=(8, 3),
                  relief="groove").pack(side="bottom", fill="x", padx=6)

    def _build_bottom(self) -> None:
        logf = ttk.Frame(self.root, padding=(6, 0, 6, 6))
        logf.pack(side="bottom", fill="x")
        self.log_text = tk.Text(logf, height=7, wrap="word", state="disabled",
                                font=("Consolas", 9))
        ls = ttk.Scrollbar(logf, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=ls.set)
        self.log_text.pack(side="left", fill="x", expand=True)
        ls.pack(side="right", fill="y")
        bottom = ttk.Frame(self.root, padding=(6, 4))
        bottom.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(bottom, mode="determinate", length=260)
        self.progress.pack(side="right")

    # ----- settings helpers --------------------------------------------------------
    @property
    def days(self) -> int:
        return int(self.settings["days"])

    @property
    def min_size(self) -> int:
        return int(self.settings["min_size_mb"]) * MB

    @property
    def level(self) -> int:
        return int(self.settings["level"])

    def scan_roots(self) -> list[Path]:
        """Base roots plus the extra folders from Settings."""
        roots = list(self.base_roots)
        for f in self.settings.get("extra_folders", []):
            p = Path(f)
            if p not in roots:
                roots.append(p)
        return roots

    # ----- table -------------------------------------------------------------------
    def visible_items(self) -> list[Any]:
        """Items passing the search filter, in the current sort order."""
        key = SORT_KEYS.get(self.sort_col, SORT_KEYS["edited"])
        shown = [i for i in self.items if matches_filter(i, self.search_var.get(), self.home)]
        return sorted(shown, key=key, reverse=self.sort_rev)

    def refresh(self) -> None:
        """Rebuild the table and summary from self.items (Tk thread only)."""
        selected = {self.by_iid[i].path for i in self.tree.selection() if i in self.by_iid}
        self.tree.delete(*self.tree.get_children())
        self.by_iid.clear()
        shown = self.visible_items()
        if self.group_var.get():
            self._fill_grouped(shown)
        else:
            for it in shown:
                self._insert_item("", it)
        keep = [iid for iid, it in self.by_iid.items() if it.path in selected]
        if keep:
            self.tree.selection_set(keep)
        self._update_heading_arrows()
        self._update_summary()

    def _fill_grouped(self, shown: list[Any]) -> None:
        groups: dict[str, list[Any]] = {}
        for it in shown:
            groups.setdefault(engagement_key(Path(it.path).name), []).append(it)
        order = sorted(groups, key=lambda k: -max(edited_epoch(i) for i in groups[k]))
        for key in order:
            members = groups[key]
            total = sum(original_size(i) for i in members)
            gid = self.tree.insert("", "end", text=f"{key}   ({len(members)} files)", open=True,
                                   values=("", burpzip.human_size(total), "", "", ""),
                                   tags=("group",))
            for it in members:
                self._insert_item(gid, it)

    def _insert_item(self, parent: str, it: Any) -> str:
        v = row_values(it, self.days, self.min_size, self.home)
        iid = self.tree.insert(parent, "end", text=v["name"],
                               values=tuple(v[c] for c in self.COLUMNS),
                               tags=(status_tag(v["status"]),))
        self.by_iid[iid] = it
        return iid

    def sort_by(self, col: str) -> None:
        """Header click: sort by *col*, toggling direction on repeat clicks."""
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = col, col in ("size", "edited", "archive")
        self.refresh()

    def _update_heading_arrows(self) -> None:
        arrow = " ▼" if self.sort_rev else " ▲"
        for c in ("name",) + self.COLUMNS:
            text = self.HEADINGS[c] + (arrow if c == self.sort_col else "")
            self.tree.heading("#0" if c == "name" else c, text=text)

    def _update_summary(self) -> None:
        s = summarize(self.items)
        hs = burpzip.human_size
        free = hs(self.free_bytes) if self.free_bytes is not None else "?"
        self.summary_var.set(
            f"Projects: {s['projects']} ({hs(s['project_bytes'])})    "
            f"Zipped (.burpz): {s['archives']} ({hs(s['archive_bytes'])}, "
            f"saved {hs(s['saved_bytes'])})    "
            f"Backups: {s['backups']} ({hs(s['backup_bytes'])})    "
            + (f"Burp folder: {s['burp_folder']} (saved {hs(s['burp_folder_saved'])})    "
               if s["burp_folder"] else "")
            + f"Free disk: {free}")
        if self.burp_running is None:
            self.burp_lbl.configure(text="Burp: ?", foreground="")
        elif self.burp_running:
            self.burp_lbl.configure(text="● Burp running", foreground="#b00020")
        else:
            self.burp_lbl.configure(text="Burp not running", foreground="#1f6b2a")

    def selected_items(self, kinds: tuple[str, ...] | None = None) -> list[Any]:
        """Selected items (a selected group row means all its members)."""
        out = []
        for iid in self.tree.selection():
            it = self.by_iid.get(iid)
            if it is None:
                out.extend(self.by_iid[c] for c in self.tree.get_children(iid)
                           if c in self.by_iid)
            else:
                out.append(it)
        seen: set[str] = set()
        uniq = []
        for it in out:
            if it.path not in seen and (kinds is None or it.kind in kinds):
                seen.add(it.path)
                uniq.append(it)
        return uniq

    # ----- worker plumbing -----------------------------------------------------------
    def submit(self, name: str, fn: Callable[[], None]) -> bool:
        """Queue *fn* for the single worker. Refused while busy or closing."""
        if self.closing.is_set():
            return False
        if self.busy:
            messagebox.showinfo("burpzip", "Another task is still running. Wait or press Stop.",
                                parent=self.root)
            return False
        self.stop_event.clear()
        self.set_busy(True, name)
        self._tasks.put((name, fn))
        return True

    def _worker_loop(self) -> None:
        while True:
            task = self._tasks.get()
            if task is None:
                return
            name, fn = task
            try:
                fn()
            except MissingFeature as exc:
                self.post("error", str(exc))
            except Exception as exc:  # report every failure, keep the worker alive
                self.post("log", f"ERROR in {name}: {type(exc).__name__}: {exc}")
                self.post("error", f"{name} failed:\n{exc}")
            finally:
                self.post("idle", name)

    def post(self, kind: str, *payload: Any) -> None:
        """Send a message from the worker to the Tk thread."""
        self._ui.put((kind, payload))

    def wlog(self, *msg: Any) -> None:
        """Worker-side log callback (thread-safe)."""
        self.post("log", " ".join(str(m) for m in msg))

    def wprogress(self, stage: str, fraction: float | None = None) -> None:
        """Worker-side archiver progress callback; throttled to whole percents."""
        pct = -1 if fraction is None else int(fraction * 100)
        if self._last_stage == (stage, pct):
            return
        self._last_stage = (stage, pct)
        self.post("stage", stage, fraction)

    def wstate(self, state: str) -> None:
        """Worker-side launcher state callback (waiting-open, in-use, ...)."""
        text = {"waiting-open": "Waiting for Burp to open the project...",
                "in-use": "Burp is using the project; close it in Burp when done.",
                "released": "Burp has closed the project.",
                "timeout": "Burp did not open the project.",
                "stopped": "Stopped waiting."}.get(state, state)
        self.post("log", text)

    def ask_from_worker(self, question: str, title: str = "burpzip") -> bool:
        """Ask yes/no on the Tk thread; blocks the WORKER (never Tk) for the answer."""
        if self.closing.is_set():
            return False
        reply: queue.Queue = queue.Queue(maxsize=1)
        self.post("ask", title, question, reply)
        while not self.closing.is_set():
            try:
                return bool(reply.get(timeout=0.5))
            except queue.Empty:
                continue
        return False

    def _poll(self) -> None:
        if self._polling:
            return
        self._after_id = None  # this scheduled callback is now running
        self._polling = True
        self._provider_tick += 1
        if self._provider_tick % 50 == 1:
            self.update_provider_status()
        try:
            try:
                while True:
                    kind, payload = self._ui.get_nowait()
                    self._handle(kind, payload)
            except queue.Empty:
                pass
        finally:
            self._polling = False
            if self.closing.is_set() and not self._worker.is_alive():
                self._finish_close()
            else:
                # No nested poll may destroy Tk while a dialog is still active.
                self._after_id = self.root.after(POLL_MS, self._poll)

    def _handle(self, kind: str, payload: tuple) -> None:
        if kind == "log":
            self.log(payload[0])
        elif kind == "progress":
            done, total = payload
            self.progress.stop()
            self.progress.configure(mode="determinate", maximum=max(1, total), value=done)
        elif kind == "stage":
            stage, fraction = payload
            pct = f" {fraction * 100:.0f}%" if isinstance(fraction, (int, float)) else ""
            self.status_var.set(f"Working: {stage}{pct}")
        elif kind == "scan":
            self.items, self.free_bytes, self.burp_running = payload
            self.refresh()
        elif kind == "ask":
            title, question, reply = payload
            answer = False
            try:
                if not self.closing.is_set():
                    answer = bool(messagebox.askyesno(title, question, parent=self.root))
            finally:
                # A close requested during a modal dialog still declines it.
                reply.put(answer and not self.closing.is_set())
        elif kind == "error":
            if self.closing.is_set():
                self.log(payload[0])
            else:
                messagebox.showerror("burpzip", payload[0], parent=self.root)
        elif kind == "idle":
            self.set_busy(False, payload[0])
        elif kind == "provider":
            self.update_provider_status()
        elif kind == "native_store":
            self.settings["native_store"] = payload[0]
            save_settings(self.settings_path, self.settings)
            self.update_provider_status()
        elif kind == "mode":
            self.settings["provider"] = payload[0]
            self.mode_var.set(payload[0])
            save_settings(self.settings_path, self.settings)
        elif kind == "folder":
            self.settings["folder"] = payload[0]
            save_settings(self.settings_path, self.settings)

    def set_busy(self, busy: bool, name: str = "") -> None:
        """Toggle conflicting buttons, Stop and the progress bar."""
        self.busy = busy
        if self.closing.is_set():
            for b in self._all_buttons:
                b.state(["disabled"])
            self.status_var.set("Closing - waiting for the current file to finish safely...")
            return
        for b in self._action_buttons:
            b.state(["disabled"] if busy else ["!disabled"])
        self.stop_btn.state(["!disabled"] if busy else ["disabled"])
        if busy:
            self.status_var.set(f"Working: {name}...")
            self.progress.configure(mode="indeterminate", value=0)
            self.progress.start(15)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
            stopped = " (stopped)" if self.stop_event.is_set() else ""
            self.status_var.set(f"Ready - last task: {name}{stopped}")

    def request_stop(self) -> None:
        """Ask the worker to stop between files."""
        self.stop_event.set()
        self.log("Stop requested - stopping after the current file.")

    def log(self, msg: str) -> None:
        """Append a line to the log pane (Tk thread only)."""
        self.log_text.configure(state="normal")
        self.log_text.insert("end", time.strftime("%H:%M:%S ") + msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ----- worker jobs (run on the worker thread only) ------------------------------
    def _scan_job(self) -> None:
        roots = [r for r in self.scan_roots()
                 if burpzip.native_state(r).kind not in ("cloud", "unknown") and r.exists()]
        self.post("log", "Scanning " + ", ".join(str(r) for r in roots) + " ...")
        items = burpzip.scan(roots)
        try:
            ordinary = [r for r in roots if burpzip.native_state(r).kind == "ordinary"]
            free = shutil.disk_usage(ordinary[0]).free if ordinary else None
        except OSError:
            free = None
        running = burpzip.burp_running()
        self.post("scan", items, free, running)
        self.post("log", f"Found {len(items)} files.")

    def _archive_paths_job(self, paths: list[str]) -> None:
        archive_project = load_function("archiver", "archive_project")
        for n, path in enumerate(paths):
            if self.stop_event.is_set():
                self.post("log", "Stopped before " + Path(path).name)
                break
            self.post("progress", n, len(paths))
            self.post("log", f"Archiving {Path(path).name} (level {self.level}) ...")
            try:
                res = call_flexible(archive_project, path, level=self.level, log=self.wlog,
                                    progress=self.wprogress, stop_event=self.stop_event)
                self.post("log", f"  done: {result_text(res)}")
            except Exception as exc:
                self.post("log", f"  FAILED {Path(path).name}: {exc} (original kept)")
        self.post("progress", len(paths), len(paths))
        self._scan_job()

    def _run_plan_job(self, plan: dict) -> None:
        try:
            run_plan = load_function("archiver", "run_plan")
        except MissingFeature:
            run_plan = None
        if run_plan is not None and accepts_option(run_plan, "stop_event"):
            res = call_flexible(run_plan, plan, level=self.level, log=self.wlog,
                                progress=self.wprogress, stop_event=self.stop_event)
            self.post("log", f"Plan finished: {result_text(res)}")
            self._scan_job()
        else:  # per-file loop so Stop is honoured between files
            paths = [s["path"] for s in plan["steps"] if s["action"] == "archive"]
            self._archive_paths_job(paths)

    def _open_job(self, fn: Callable, path: str) -> None:
        self.post("log", f"Opening {Path(path).name} ...")
        res = call_flexible(fn, path, confirm=self.ask_from_worker, log=self.wlog,
                            progress=self.wprogress, on_state=self.wstate,
                            stop_event=self.stop_event, level=self.level)
        self.post("log", f"Open finished: {result_text(res)}")
        self._scan_job()

    # ----- actions (Tk thread) ----------------------------------------------------------
    def _need(self, module: str, name: str) -> Callable | None:
        try:
            return load_function(module, name)
        except MissingFeature as exc:
            messagebox.showerror("burpzip", str(exc), parent=self.root)
            return None

    def _info(self, msg: str) -> None:
        messagebox.showinfo("burpzip", msg, parent=self.root)

    def _ordinary_action(self, item: Any) -> bool:
        if burpzip.protected_item(item):
            self._info("Burp-folder, cloud, unknown and store rows are protected from ordinary actions.")
            return False
        try:
            burpzip.require_ordinary_path(item.path)
        except Exception as exc:
            self._info(f"Protected path; ordinary action refused: {exc}")
            return False
        return True

    def rescan(self) -> None:
        self.submit("Rescan", self._scan_job)

    def archive_selected(self) -> None:
        items = self.selected_items(("project",))
        if not items:
            self._info("Select one or more projects (.burp) first.")
            return
        items = [i for i in items if self._ordinary_action(i)]
        busy = [i for i in items if i.in_use]
        items = [i for i in items if not i.in_use]
        if busy:
            self.log("Skipping (open in Burp): " + ", ".join(Path(i.path).name for i in busy))
        if not items or not self._need("archiver", "archive_project"):
            return
        total = sum(i.size for i in items)
        if not messagebox.askyesno(
                "Archive selected",
                f"Archive {len(items)} project(s), {burpzip.human_size(total)}?\n\n"
                "Each one is compressed to a .burpz next to it, verified, and only then "
                "the original .burp is deleted.", parent=self.root):
            return
        paths = [i.path for i in items]
        self.submit("Archive selected", lambda: self._archive_paths_job(paths))

    def make_plan(self) -> dict:
        """Plan copied items with independent disk budgets; never delete backups.

        Archive presence alone is not evidence that a source is unchanged.
        The archiver verifies content before deleting an unpacked project.
        """
        pool = []
        for i in self.items:
            if getattr(i, "kind", "") in ("project", "backup", "archive") \
                    and not burpzip.protected_item(i):
                c = copy.copy(i)
                c.notes = list(getattr(i, "notes", []))
                pool.append(c)
        return archive_only_plan(burpzip.build_volume_plan(
            pool, self.days, self.min_size, roots=self.scan_roots()))

    def archive_all_old(self) -> None:
        if not self._need("archiver", "archive_project"):
            return
        plan = self.make_plan()
        if not any(s["action"] == "archive" for s in plan["steps"]):
            self._info(f"Nothing to archive: no project older than {self.days} days and at "
                       f"least {self.settings['min_size_mb']} MB that fits the free space.")
            return
        store = self.native_store()
        text = plan_summary(plan)
        if store is not None:
            text += ("\n\nThey go straight into the Burp folder: each project is zipped and verified, "
                     "the original .burp is deleted, and a same-named project appears in "
                     f"{store.with_name(store.name.removesuffix('-store'))} for Burp's "
                     "'Open existing project'. A project whose name is already in the Burp folder "
                     "keeps an ordinary .burpz next to where it was.")
        if not self.confirm_text("Archive all old projects", text, "Archive"):
            return
        if store is None:
            self.submit("Archive all old", lambda: self._run_plan_job(plan))
            return
        work = [("project", s["path"]) for s in plan["steps"] if s["action"] == "archive"]
        self.submit("Archive all old", lambda: self._add_to_burp_job(store, work))

    def open_selected(self) -> None:
        items = self.selected_items(("project", "archive"))
        if len(items) != 1:
            self._info("Select exactly one project or archive to open.")
            return
        it = items[0]
        state = burpzip.native_state(it.path)
        if state.kind != "ordinary":
            if it.kind != "project" or not burpzip.managed_project(state, it.path):
                self._info("Only an identity-anchored own native project can open; cloud/store/unknown paths are protected.")
                return
        elif not self._ordinary_action(it):
            return
        name = "open_project" if it.kind == "project" else "open_archive"
        fn = self._need("launcher", name)
        if fn:
            self.submit("Open " + it.kind, lambda: self._open_job(fn, it.path))

    def restore_selected(self) -> None:
        items = self.selected_items(("archive",))
        if len(items) != 1:
            self._info("Select exactly one archive (.burpz) to restore.")
            return
        if not self._ordinary_action(items[0]):
            return
        fn = self._need("archiver", "restore_project")
        if not fn:
            return
        path = items[0].path

        def job() -> None:
            self.post("log", f"Restoring {Path(path).name} ...")
            res = call_flexible(fn, path, log=self.wlog, progress=self.wprogress,
                                stop_event=self.stop_event)
            self.post("log", f"Restored: {res}")
            self._scan_job()
        self.submit("Restore", job)

    def show_in_explorer(self) -> None:
        items = self.selected_items()
        if items:
            subprocess.Popen(["explorer", f"/select,{os.path.normpath(items[0].path)}"])

    def delete_backup_selected(self) -> None:
        items = self.selected_items(("backup",))
        if len(items) != 1:
            self._info("Select exactly one leftover backup row.")
            return
        b = items[0]
        if not self._ordinary_action(b):
            return
        parent = burpzip.backup_parent(b.path)
        try:
            burpzip.require_ordinary_path(parent)
        except Exception as exc:
            self._info(f"Main project is protected; backup kept: {exc}")
            return
        if b.in_use or burpzip.is_in_use(b.path):
            messagebox.showerror("burpzip", "This backup is open in Burp; close it first.",
                                 parent=self.root)
            return
        if not os.path.isfile(parent):
            messagebox.showerror("burpzip", "The main project is missing, so this backup may "
                                 "be the only copy. It will not be deleted.", parent=self.root)
            return
        fn = self._need("archiver", "delete_backup")
        if not fn:
            return
        p_mtime = os.path.getmtime(parent)
        newer = b.mtime > p_mtime
        if not self.confirm_delete_backup(b, parent, p_mtime, newer):
            return

        def job() -> None:
            res = call_flexible(fn, b.path, force=True if newer else None, log=self.wlog)
            self.post("log", f"Deleted backup {Path(b.path).name}: {res}")
            self._scan_job()
        self.submit("Delete backup", job)

    def register_assoc(self) -> None:
        self._assoc_job("register_association", "Registered double-click for .burpz")

    def unregister_assoc(self) -> None:
        self._assoc_job("unregister_association", "Unregistered double-click for .burpz")

    def check_assoc(self) -> None:
        fn = self._need("launcher", "is_association_registered")
        if fn:
            try:
                state = "registered" if fn() else "not registered"
            except Exception as exc:
                state = f"unknown ({exc})"
            self._info(f".burpz double-click is {state}.")

    def _assoc_job(self, name: str, done: str) -> None:
        fn = self._need("launcher", name)
        if not fn:
            return

        def job() -> None:
            res = fn()
            self.post("log", f"{done}. {res if res is not None else ''}")
        self.submit(name, job)

    # ----- Burp folder (native open) ----------------------------------------------------
    def native_store(self) -> Path | None:
        return burpzip.native_store_path(self.settings.get("native_store") or None)

    def update_provider_status(self) -> None:
        store = self.native_store()
        if store is None:
            self.provider_lbl.configure(text="No Burp folder", foreground="")
            return
        try:
            running = burpzip.provider_running(store)
        except Exception:
            running = None
        text, color = {True: ("\u25cf Provider running", "#1f6b2a"),
                       False: ("Provider stopped", "#b00020"),
                       None: ("Provider: ?", "")}[running]
        self.provider_lbl.configure(text=text, foreground=color)

    def _require_store(self) -> Path | None:
        store = self.native_store()
        if store is None:
            self._info("Set up the Burp folder first (Burp folder > Set up Burp folder...).")
        return store

    def setup_burp_folder(self) -> None:
        store = self.native_store()
        if store is not None:
            self._info(f"The Burp folder is already set up.\n\nStore: {store}")
            return
        root = Path.home() / "Downloads" / "BurpProjects"
        if not messagebox.askyesno(
                "Set up Burp folder",
                f"Create the Burp folder at\n{root}\n\nwith its archive store at\n{root}-store ?\n\n"
                "Burp's 'Open existing project' can then open archived projects from this folder; "
                "Burpzip unpacks them on first open.\n\nChoose No to pick another NEW, EMPTY folder.",
                parent=self.root):
            chosen = filedialog.askdirectory(parent=self.root,
                                             title="Choose a NEW, EMPTY folder for Burp projects")
            if not chosen:
                return
            root = Path(chosen)
        store = root.with_name(root.name + "-store")
        mode = self.ask_provider_mode()
        if mode is None:
            return

        def job() -> None:
            import native_store
            for folder in (root, store):
                folder.mkdir(exist_ok=True)
                if any(folder.iterdir()):
                    raise RuntimeError(f"{folder} is not empty; choose a new empty folder")
            native_store.init_root(str(root), str(store))
            self.post("native_store", str(store))
            self.post("folder", str(root))
            burpzip.apply_provider_mode(store, mode)
            self.post("mode", mode)
            burpzip.start_provider(store)  # Serve now in every mode.
            self.post("provider")
            self.post("log", f"Burp folder ready: {root} (store {store}). "
                             "Use 'Add to Burp folder' to put projects in it.")
        self.submit("Set up Burp folder", job)

    def open_burp_folder(self) -> None:
        store = self._require_store()
        if store is None:
            return
        try:
            import native_store
            root = native_store.NativeStore(str(store)).root
        except Exception as exc:
            messagebox.showerror("burpzip", f"Cannot read the Burp folder: {exc}", parent=self.root)
            return
        os.startfile(root)  # type: ignore[attr-defined]  # Windows only

    def show_provider_log(self) -> None:
        store = self._require_store()
        if store is None:
            return
        log = store / "serve.log"
        if not log.is_file():
            self._info("The provider has not written a log yet.")
            return
        os.startfile(log)  # type: ignore[attr-defined]

    def start_provider(self) -> None:
        store = self._require_store()
        if store is None:
            return

        def job() -> None:
            started = burpzip.start_provider(store)
            self.post("log", "Provider started." if started else "Provider was already running.")
            self.post("provider")
        self.submit("Start provider", job)

    def stop_provider(self) -> None:
        store = self._require_store()
        if store is None:
            return
        if not messagebox.askyesno(
                "Stop provider", "Stop the provider?\n\nArchived (not yet unpacked) projects in the "
                "Burp folder cannot be opened in Burp until it runs again. Unpacked projects keep working.",
                parent=self.root):
            return

        def job() -> None:
            stopped = burpzip.stop_provider(store)
            self.post("log", "Provider stopped." if stopped else "Provider was not running.")
            self.post("provider")
        self.submit("Stop provider", job)

    def ask_provider_mode(self) -> str | None:
        """Small modal choice of when the background provider runs."""
        d = self._dialog("Provider mode")
        frm = ttk.Frame(d, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="When should the background provider run?\n"
                            "(Burp can only open still-zipped projects while it runs.)").pack(anchor="w")
        choice = tk.StringVar(value=self.settings.get("provider", "logon"))
        for value, label in (("logon", "At Windows logon (recommended, always works)"),
                             ("with-burp", "Only with Burp: use the \"Burp Suite (Burpzip)\" shortcut"),
                             ("manual", "Manual: I start it myself")):
            ttk.Radiobutton(frm, text=label, value=value, variable=choice).pack(anchor="w", pady=1)
        result: list[str | None] = [None]

        def ok() -> None:
            result[0] = choice.get()
            d.destroy()
        row = ttk.Frame(d, padding=8)
        row.pack(fill="x")
        ttk.Button(row, text="Cancel", command=d.destroy).pack(side="right")
        ttk.Button(row, text="OK", command=ok).pack(side="right", padx=6)
        d.grab_set()
        self.root.wait_window(d)
        return result[0]

    def set_provider_mode(self) -> None:
        mode = self.mode_var.get()
        store = self._require_store()
        if store is None:
            self.mode_var.set(self.settings.get("provider", "logon"))
            return

        def job() -> None:
            try:
                result = burpzip.apply_provider_mode(store, mode)
                where = {"logon": "The provider now starts when you log in to Windows.",
                         "with-burp": "Use the \"Burp Suite (Burpzip)\" shortcut (Desktop / Start menu) "
                                      "to open Burp; it starts and stops the provider.",
                         "manual": "Start the provider yourself (Burp folder > Start provider)."}[mode]
                self.post("log", f"Provider mode: {mode}. {where}")
                self.post("mode", mode)
                if result.get("burp_shortcuts"):
                    self.post("log", "Shortcuts: " + "; ".join(result["burp_shortcuts"]))
            except Exception:
                self.post("mode", self.settings.get("provider", "logon"))
                raise
        if not self.submit("Provider mode", job):
            self.mode_var.set(self.settings.get("provider", "logon"))

    def first_run(self) -> None:
        """No burpzip.ini and no Burp folder yet: offer the Burp folder once."""
        if messagebox.askyesno(
                "Welcome to Burpzip",
                "Set up a Burp folder now?\n\nProjects in it stay zipped and open directly from "
                "Burp's 'Open existing project'. You can also do this later from the Burp folder menu.",
                parent=self.root):
            self.setup_burp_folder()
        save_settings(self.settings_path, self.settings)  # Ask only once.

    def add_to_burp_folder(self) -> None:
        store = self._require_store()
        if store is None:
            return
        items = [i for i in self.selected_items(("project", "archive")) if self._ordinary_action(i)]
        busy = [i for i in items if i.in_use]
        items = [i for i in items if not i.in_use]
        if busy:
            self.log("Skipping (open in Burp): " + ", ".join(Path(i.path).name for i in busy))
        if not items:
            self._info("Select one or more projects (.burp) or archives (.burpz) first.")
            return
        projects = sum(i.kind == "project" for i in items)
        text = f"Add {len(items)} item(s) to the Burp folder?\n\n"
        if projects:
            text += ("Projects (.burp) are compressed first and verified; then the original .burp "
                     "is deleted.\n")
        text += ("Each archive is verified, copied into the Burp folder's store, then removed from "
                 "its current folder. A same-named project appears in the Burp folder for Burp's "
                 "'Open existing project'.")
        if not messagebox.askyesno("Add to Burp folder", text, parent=self.root):
            return
        work = [(i.kind, i.path) for i in items]
        self.submit("Add to Burp folder", lambda: self._add_to_burp_job(store, work))

    def _add_to_burp_job(self, store: Path, work: list[tuple[str, str]]) -> None:
        import native_store
        archive_project = load_function("archiver", "archive_project")
        try:
            with burpzip.paused_provider(store):
                for n, (kind, path) in enumerate(work):
                    if self.stop_event.is_set():
                        self.post("log", "Stopped before " + Path(path).name)
                        break
                    self.post("progress", n, len(work))
                    try:
                        archive = path
                        if kind == "project":
                            self.post("log", f"Archiving {Path(path).name} (level {self.level}) ...")
                            res = call_flexible(archive_project, path, level=self.level,
                                                progress=self.wprogress, stop_event=self.stop_event)
                            archive = res.archive_path
                        self.post("log", f"Adding {Path(archive).name} to the Burp folder ...")
                        entry = native_store.add_archive(str(store), archive)
                        kept = "" if burpzip.remove_verified_input(archive, entry) \
                            else f"; {Path(archive).name} kept (it changed during import)"
                        self.post("log", f"  done: {entry['name']} is in the Burp folder{kept}")
                    except Exception as exc:
                        self.post("log", f"  FAILED {Path(path).name}: {exc} (files kept)")
                self.post("progress", len(work), len(work))
        finally:
            self.post("provider")
        self._scan_job()

    def unpack_selected(self) -> None:
        store = self._require_store()
        if store is None:
            return
        names = []
        for it in self.selected_items(("project",)):
            state = burpzip.native_state(it.path)
            if burpzip.managed_project(state, it.path):
                names.append(Path(it.path).name)
        if not names:
            self._info("Select one or more projects in the Burp folder first.")
            return

        def job() -> None:
            import native_provider
            try:
                with burpzip.paused_provider(store):
                    self.post("log", "Unpacking " + ", ".join(names) + " ...")
                    native_provider.materialize_root(str(store), names=names)
                    self.post("log", "Unpacked; Burp opens them without waiting.")
            finally:
                self.post("provider")
            self._scan_job()
        self.submit("Unpack now", job)

    def _managed_names(self) -> list[str]:
        names = []
        for it in self.selected_items(("project",)):
            if burpzip.managed_project(burpzip.native_state(it.path), it.path):
                names.append(Path(it.path).name)
        return names

    def rezip_selected(self) -> None:
        store = self._require_store()
        if store is None:
            return
        names = self._managed_names()
        if not names:
            self._info("Select one or more projects in the Burp folder first.")
            return
        if not messagebox.askyesno(
                "Re-zip", f"Re-zip {len(names)} project(s) back to small placeholders?\n\n"
                "Each project's current contents (including everything Burp saved) are zipped and "
                "verified first; it then shrinks to a placeholder and unpacks again on next open. "
                "Projects still open in Burp are skipped.", parent=self.root):
            return

        def job() -> None:
            import native_provider
            try:
                with burpzip.paused_provider(store):
                    for name in names:
                        if self.stop_event.is_set():
                            self.post("log", "Stopped before " + name)
                            break
                        self.post("log", f"Re-zipping {name} (level {self.level}) ...")
                        try:
                            done = native_provider.rezip_project(str(store), name, level=self.level)
                        except Exception as exc:
                            self.post("log", f"  skipped {name}: {exc} (project unchanged)")
                            continue
                        if done["status"] == "rezipped":
                            self.post("log", f"  done: {burpzip.human_size(done['size'])} -> "
                                             f"{burpzip.human_size(done['archive_size'])}")
                        else:
                            self.post("log", f"  skipped {name}: {done.get('reason')}")
            finally:
                self.post("provider")
            self._scan_job()
        self.submit("Re-zip", job)

    # ----- dialogs ---------------------------------------------------------------------
    def _dialog(self, title: str) -> tk.Toplevel:
        d = tk.Toplevel(self.root)
        d.title(title)
        d.transient(self.root)
        return d

    def confirm_text(self, title: str, text: str, ok: str = "OK") -> bool:
        """Modal dialog showing *text* with OK/Cancel; True if OK."""
        d = self._dialog(title)
        result = {"ok": False}
        t = tk.Text(d, width=96, height=min(28, text.count("\n") + 3), wrap="none",
                    font=("Consolas", 9))
        t.insert("1.0", text)
        t.configure(state="disabled")
        t.pack(fill="both", expand=True, padx=8, pady=8)
        row = ttk.Frame(d, padding=8)
        row.pack(fill="x")

        def done(v: bool) -> None:
            result["ok"] = v
            d.destroy()
        ttk.Button(row, text="Cancel", command=lambda: done(False)).pack(side="right")
        ttk.Button(row, text=ok, command=lambda: done(True)).pack(side="right", padx=6)
        d.grab_set()
        self.root.wait_window(d)
        return result["ok"]

    def confirm_delete_backup(self, b: Any, parent: str, p_mtime: float, newer: bool) -> bool:
        """Show backup vs project dates; if the backup is newer, demand typing YES."""
        def fmt(t: float) -> str:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))
        d = self._dialog("Delete leftover backup")
        msg = (f"Backup:   {Path(b.path).name}\n  edited {fmt(b.mtime)}   "
               f"{burpzip.human_size(b.size)}\n\n"
               f"Project:  {Path(parent).name}\n  edited {fmt(p_mtime)}\n")
        ttk.Label(d, text=msg, justify="left", padding=10,
                  font=("Consolas", 9)).pack(anchor="w")
        typed = tk.StringVar()
        if newer:
            tk.Label(d, text="WARNING: the BACKUP IS NEWER than the project.\n"
                     "It may hold work the project does not. Deleting it can lose data.\n"
                     "Type YES to delete it anyway.", fg="white", bg="#b00020",
                     font=("Segoe UI", 10, "bold"), justify="left", padx=10, pady=8
                     ).pack(fill="x", padx=10)
            ttk.Entry(d, textvariable=typed, width=12).pack(padx=10, pady=6, anchor="w")
        result = {"ok": False}

        def ok() -> None:
            if newer and typed.get().strip() != "YES":
                messagebox.showwarning("burpzip", "Type YES (capitals) to confirm.", parent=d)
                return
            result["ok"] = True
            d.destroy()
        row = ttk.Frame(d, padding=8)
        row.pack(fill="x")
        ttk.Button(row, text="Cancel", command=d.destroy).pack(side="right")
        ttk.Button(row, text="Delete backup", command=ok).pack(side="right", padx=6)
        d.grab_set()
        self.root.wait_window(d)
        return result["ok"]

    def open_settings(self) -> None:
        """Settings dialog: days, min size, compression level, extra folders."""
        d = self._dialog("Settings")
        frm = ttk.Frame(d, padding=10)
        frm.pack(fill="both", expand=True)
        days = tk.StringVar(value=str(self.days))
        mins = tk.StringVar(value=str(self.settings["min_size_mb"]))
        lvl_name = next((k for k, v in LEVELS.items() if v == self.level), "Normal (5)")
        level = tk.StringVar(value=lvl_name)
        ttk.Label(frm, text="Archive projects not edited for (days):").grid(
            row=0, column=0, sticky="w")
        ttk.Spinbox(frm, from_=1, to=3650, textvariable=days, width=8).grid(
            row=0, column=1, sticky="w")
        ttk.Label(frm, text="Minimum project size (MB):").grid(row=1, column=0, sticky="w")
        ttk.Spinbox(frm, from_=0, to=100000, textvariable=mins, width=8).grid(
            row=1, column=1, sticky="w")
        ttk.Label(frm, text="Compression level:").grid(row=2, column=0, sticky="w")
        ttk.Combobox(frm, textvariable=level, values=list(LEVELS), state="readonly",
                     width=12).grid(row=2, column=1, sticky="w")
        ttk.Label(frm, text="Extra scan folders:").grid(row=3, column=0, sticky="nw",
                                                        pady=(8, 0))
        lb = tk.Listbox(frm, height=5, width=56)
        for f in self.settings.get("extra_folders", []):
            lb.insert("end", f)
        lb.grid(row=4, column=0, columnspan=2, sticky="we")
        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=2, sticky="w", pady=4)
        ttk.Label(frm, text="Burp folder:").grid(row=6, column=0, sticky="w", pady=(10, 0))
        ask_var = tk.BooleanVar(value=bool(self.settings.get("ask_on_close", True)))
        ttk.Checkbutton(frm, text="Ask to re-zip when Burp closes a changed project",
                        variable=ask_var).grid(row=7, column=0, columnspan=2, sticky="w")
        ttk.Label(frm, text="Re-zip projects untouched for (days, 0 = never):").grid(
            row=8, column=0, sticky="w")
        idle = tk.StringVar(value=str(self.settings.get("idle_days", 10)))
        ttk.Spinbox(frm, from_=0, to=3650, textvariable=idle, width=8).grid(row=8, column=1, sticky="w")
        ttk.Label(frm, text="Burp Suite program (empty = find automatically):").grid(
            row=9, column=0, sticky="w", pady=(6, 0))
        burp_path = tk.StringVar(value=self.settings.get("burp_path", ""))
        ttk.Entry(frm, textvariable=burp_path, width=56).grid(row=10, column=0, sticky="we")

        def browse_burp() -> None:
            p = filedialog.askopenfilename(parent=d, title="Burp Suite program",
                                           filetypes=[("Programs", "*.exe"), ("All files", "*.*")])
            if p:
                burp_path.set(os.path.normpath(p))
        ttk.Button(frm, text="Browse...", command=browse_burp).grid(row=10, column=1, sticky="w")

        def add() -> None:
            p = filedialog.askdirectory(parent=d)
            if p:
                lb.insert("end", os.path.normpath(p))

        def remove() -> None:
            for i in reversed(lb.curselection()):
                lb.delete(i)
        ttk.Button(btns, text="Add folder...", command=add).pack(side="left")
        ttk.Button(btns, text="Remove", command=remove).pack(side="left", padx=4)

        def save() -> None:
            try:
                new = {"days": max(1, int(days.get())), "min_size_mb": max(0, int(mins.get())),
                       "level": LEVELS[level.get()], "extra_folders": list(lb.get(0, "end")),
                       "ask_on_close": bool(ask_var.get()), "idle_days": max(0, int(idle.get())),
                       "burp_path": burp_path.get().strip()}
            except (ValueError, KeyError):
                messagebox.showerror("burpzip", "Days and size must be whole numbers.",
                                     parent=d)
                return
            provider_changed = any(new[k] != self.settings.get(k) for k in ("ask_on_close", "idle_days"))
            folders_changed = new["extra_folders"] != self.settings.get("extra_folders", [])
            self.settings.update(new)
            save_settings(self.settings_path, self.settings)
            d.destroy()
            self.refresh()
            store = self.native_store()
            if provider_changed and store is not None and burpzip.provider_running(store):
                def restart() -> None:  # serve reads ask_on_close / idle_days at start
                    burpzip.stop_provider(store)
                    burpzip.start_provider(store)
                    self.post("log", "Provider restarted with the new settings.")
                    self.post("provider")
                self.submit("Restart provider", restart)
            elif folders_changed and not self.busy:
                self.rescan()
        row = ttk.Frame(d, padding=8)
        row.pack(fill="x")
        ttk.Button(row, text="Cancel", command=d.destroy).pack(side="right")
        ttk.Button(row, text="Save", command=save).pack(side="right", padx=6)
        d.grab_set()

    # ----- shutdown ---------------------------------------------------------------------
    def on_close(self) -> None:
        if self.closing.is_set():
            return
        if self.busy and not messagebox.askyesno(
                "burpzip", "A task is running. Stop after the current file and quit?\n"
                "The window stays open until the current file finishes safely.",
                parent=self.root):
            return
        self.close()

    def close(self) -> None:
        """Request shutdown; keep polling until the worker finishes and exits."""
        if self.closing.is_set():
            return
        self.closing.set()
        self.stop_event.set()
        self.set_busy(self.busy)
        for n in range(self.menubar.index("end") + 1):
            self.menubar.entryconfigure(n, state="disabled")
        self._tasks.put(None)  # consumed only after the current job returns
        if self._polling:
            return  # the outer poll owns finalization after its dialog returns
        if not self._worker.is_alive():
            self._finish_close()
        elif self._after_id is None:
            self._after_id = self.root.after(POLL_MS, self._poll)

    def _finish_close(self) -> None:
        """Destroy Tk only when no worker can still own a file or need the UI."""
        if self._polling or self._worker.is_alive():
            return
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        self.busy = False
        self.progress.stop()
        try:
            self.root.destroy()
        except tk.TclError:
            pass


def main(roots: list[Path] | None = None, days: int | None = None) -> None:
    """Start the GUI; only an explicit days argument overrides saved settings."""
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("vista")
    except tk.TclError:
        pass
    burpzip.ensure_config()  # First run of this version: carry existing settings over.
    import config
    app = BurpZipApp(root, roots=roots, days=days, settings_path=default_settings_path())
    if not config.exists() and app.native_store() is None:
        root.after(600, app.first_run)
    root.mainloop()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(prog="burpzip-gui")
    ap.add_argument("--days", type=int, default=None)
    ap.add_argument("--root", action="append", type=Path)
    a = ap.parse_args()
    main(a.root, a.days)
