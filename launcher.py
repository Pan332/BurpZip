"""launcher - open Burp projects from burpzip archives and manage .burpz association.

Flow for a double-clicked ``<name>.<stamp>.burpz``::

    restore (archiver.restore_project) -> launch Burp with --project-file
    -> wait until Burp has opened AND released the file (file lock, not process
       exit: BurpSuite.exe is an install4j launcher that may exit early)
    -> ask "Re-compress <name> now?" -> archiver.rezip_after_use

Burp discovery prefers the install4j launcher ``BurpSuite.exe``. A read-only
inspection of the install (2026.9.1) showed: BurpSuite.vmoptions only holds
``-XX:MaxRAMPercentage=50`` plus ``-include-options settings.vmoptions`` /
``user.vmoptions``; the launcher embeds main class ``burp.StartBurp`` and
``burpsuite.jar`` with no fixed program arguments, so (standard install4j
behaviour) command-line arguments are forwarded to ``main()``; arguments of
the form ``-J<opt>`` would go to the JVM instead. ``--project-file=PATH``
therefore reaches Burp unchanged.

File association is per-user (HKCU) only; no admin needed. The registry root
is the module-level ``CLASSES_ROOT`` so tests can point it at a scratch key.

Python interpreter choice for the association (``resolve_pythonw``): we prefer
``pythonw.exe`` next to the *real* base interpreter (``sys._base_executable``
then ``sys.executable``) so a deleted venv cannot break double-click. The one
exception is a Microsoft Store Python: its real install lives in the versioned
folder ``C:\\Program Files\\WindowsApps\\PythonSoftwareFoundation...\\`` which
changes on every update and is not supported for direct execution, so there we
use the per-package App Execution Alias under
``%LOCALAPPDATA%\\Microsoft\\WindowsApps\\<package>\\pythonw.exe``, which is
stable across updates.

Pure stdlib. Windows only for the registry/launch parts.
"""
from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

try:  # winreg exists only on Windows; keep the module importable elsewhere.
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore[assignment]

# --- constants ----------------------------------------------------------------
CLASSES_ROOT = r"Software\Classes"  # under HKEY_CURRENT_USER; tests override
PROGID = "BurpZip.Archive"
EXTENSION = ".burpz"
FRIENDLY_TYPE_NAME = "Burp project archive"

EXE_NAMES = ("BurpSuite.exe", "BurpSuitePro.exe")
INSTALL_DIR_NAMES = ("BurpSuitePro", "BurpSuite", "BurpSuiteProfessional")
FREE_POLLS_REQUIRED = 3  # consecutive "not in use" polls before "released"

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
SHCNE_ASSOCCHANGED = 0x08000000
SHCNF_IDLIST = 0x0000

Progress = Optional[Callable[[str, Optional[float]], None]]
StateCallback = Optional[Callable[[str], None]]


class LauncherError(Exception):
    """Raised when Burp cannot be found/launched or an open flow is refused."""


# --- Burp discovery -----------------------------------------------------------
def _read_reg_str(root: int, subkey: str, name: str = "") -> str | None:
    """Read a string registry value; None if missing or not readable."""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(root, subkey) as k:
            value, _ = winreg.QueryValueEx(k, name)
    except OSError:
        return None
    return value if isinstance(value, str) and value else None


def _app_path_dirs() -> list[str]:
    """Install dirs from HKCU/HKLM ``App Paths\\BurpSuite*.exe``."""
    out: list[str] = []
    if winreg is None:
        return out
    base = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for exe in EXE_NAMES:
            val = _read_reg_str(root, rf"{base}\{exe}")
            if val:
                out.append(os.path.dirname(os.path.expandvars(val.strip('"'))))
    return out


def _uninstall_dirs() -> list[str]:
    """``InstallLocation`` of uninstall entries whose DisplayName starts with Burp Suite."""
    out: list[str] = []
    if winreg is None:
        return out
    base = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            key = winreg.OpenKey(root, base)
        except OSError:
            continue
        with key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                name = _read_reg_str(root, rf"{base}\{sub}", "DisplayName") or ""
                if name.lower().startswith("burp suite"):
                    loc = _read_reg_str(root, rf"{base}\{sub}", "InstallLocation")
                    if loc:
                        out.append(os.path.expandvars(loc))
    return out


def _registry_dirs() -> list[str]:
    """All install dirs advertised in the registry (App Paths first)."""
    return _app_path_dirs() + _uninstall_dirs()


def _default_dirs() -> list[str]:
    """Well-known install locations from the environment."""
    out: list[str] = []
    for var, sub in (("LOCALAPPDATA", "Programs"), ("ProgramFiles", ""),
                     ("ProgramW6432", ""), ("ProgramFiles(x86)", "")):
        base = os.environ.get(var)
        if base:
            out += [os.path.join(base, sub, n) if sub else os.path.join(base, n)
                    for n in INSTALL_DIR_NAMES]
    return out


def _candidate_dirs() -> list[str]:
    """Registry dirs then default dirs, de-duplicated, order preserved."""
    seen: set[str] = set()
    out: list[str] = []
    for d in _registry_dirs() + _default_dirs():
        key = os.path.normcase(os.path.abspath(d))
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _java_command(install_dir: str) -> list[str] | None:
    """Bundled-JRE fallback ``[javaw, -jar, burpsuite.jar]`` or None."""
    jar = os.path.join(install_dir, "burpsuite.jar")
    if not os.path.isfile(jar):
        return None
    for exe in ("javaw.exe", "java.exe"):  # javaw: no console window
        java = os.path.join(install_dir, "jre", "bin", exe)
        if os.path.isfile(java):
            return [java, "-jar", jar]
    return None


def find_burp() -> list[str]:
    """Command prefix that launches Burp Suite; append ``--project-file=...``.

    Prefers the install4j launcher (BurpSuite.exe) in any candidate dir, then
    falls back to ``jre\\bin\\javaw.exe -jar burpsuite.jar``. Raises
    LauncherError when nothing is found.
    """
    try:
        import config
        custom = config.load().get("burp_path") or ""
    except Exception:
        custom = ""
    if custom:
        if os.path.isfile(custom):
            return [custom]
        raise LauncherError(f"burp_path in burpzip.ini does not exist: {custom}")
    dirs = [d for d in _candidate_dirs() if os.path.isdir(d)]
    for d in dirs:
        for exe in EXE_NAMES:
            path = os.path.join(d, exe)
            if os.path.isfile(path):
                return [path]
    for d in dirs:
        cmd = _java_command(d)
        if cmd:
            return cmd
    raise LauncherError("Burp Suite not found (looked in registry App Paths/uninstall "
                        "keys, %LOCALAPPDATA%\\Programs and %ProgramFiles%)")


def burp_exe_for_icon() -> str | None:
    """Path of BurpSuite*.exe for the DefaultIcon, or None."""
    try:
        cmd = find_burp()
    except LauncherError:
        return None
    exe = cmd[0]
    return exe if os.path.basename(exe).lower().startswith("burpsuite") else None


# --- launching ----------------------------------------------------------------
def _ordinary(path: str) -> None:
    import burpzip
    try:
        burpzip.require_ordinary_path(path)
    except Exception as exc:
        raise LauncherError(f"ordinary launch flow refused for {path}: {exc}") from exc


def _launch_state(path: str):
    import burpzip
    state = burpzip.native_state(path)
    if state.kind != "ordinary" and not burpzip.managed_project(state, path):
        raise LauncherError(f"{state.kind} path is not an owned native project: {path}")
    return state


def launch_burp(project_path: str) -> subprocess.Popen:
    """Start Burp on the same ordinary/identity-anchored managed path."""
    _launch_state(project_path)
    cmd = find_burp()
    project = os.path.abspath(project_path)
    argv = [*cmd, f"--project-file={project}"]
    flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        return subprocess.Popen(
            argv, cwd=os.path.dirname(cmd[0]) or None, creationflags=flags,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True)
    except OSError as e:
        raise LauncherError(f"could not start Burp ({argv[0]}): {e}") from e


def open_project(project_path: str) -> subprocess.Popen:
    """Launch a project; native opening never waits or schedules re-compression."""
    state = _launch_state(project_path)
    if state.kind == "native":
        return launch_burp(project_path)
    _ordinary(project_path)
    if not os.path.isfile(project_path):
        raise LauncherError(f"project not found: {project_path}")
    return launch_burp(project_path)


def _sleep(seconds: float, stop_event: threading.Event | None) -> bool:
    """Sleep; return True if stop_event got set."""
    if stop_event is None:
        time.sleep(seconds)
        return False
    return stop_event.wait(seconds)


def wait_until_released(path: str, appear_timeout: float = 600, poll: float = 3.0,
                        stop_event: threading.Event | None = None,
                        on_state: StateCallback = None,
                        free_polls: int = FREE_POLLS_REQUIRED) -> bool:
    """Wait for Burp to open ``path`` and then let go of it.

    Phase 1: poll until the file is in use (Burp has it open). If that does
    not happen within ``appear_timeout`` seconds return False. Phase 2: poll
    until the file is free for ``free_polls`` consecutive polls (Burp may
    briefly close/reopen the file while loading), then return True.
    States reported to ``on_state``: waiting-open, in-use, released, timeout,
    stopped. A set ``stop_event`` returns False.
    """
    import burpzip
    _ordinary(path)  # Native opening has no ordinary lock/wait/re-zip session.

    def state(s: str) -> None:
        if on_state:
            on_state(s)

    state("waiting-open")
    deadline = time.monotonic() + appear_timeout
    while not burpzip.is_in_use(path):
        if time.monotonic() >= deadline:
            state("timeout")
            return False
        if _sleep(poll, stop_event):
            state("stopped")
            return False
    state("in-use")
    free = 0
    while free < free_polls:
        if _sleep(poll, stop_event):
            state("stopped")
            return False
        free = 0 if burpzip.is_in_use(path) else free + 1
    state("released")
    return True


# --- open flow ----------------------------------------------------------------
def _target_for(archive_path: str) -> str:
    """Where restore_project would put the project (orig_name next to archive)."""
    import archiver

    _ordinary(archive_path)
    meta = archiver.read_meta(archive_path)
    name = os.path.basename(str(meta.get("orig_name") or ""))
    if not name.lower().endswith(".burp"):
        raise LauncherError(f"archive metadata has no valid orig_name: {archive_path}")
    return os.path.join(os.path.dirname(os.path.abspath(archive_path)), name)


def open_archive(archive_path: str, confirm: Callable[[str], bool] | None = None,
                 progress: Progress = None, level: int = 5, threads: int = 2,
                 appear_timeout: float = 600, poll: float = 3.0,
                 stop_event: threading.Event | None = None,
                 on_state: StateCallback = None) -> dict:
    """Restore -> launch Burp -> wait for release -> optionally re-compress.

    If the project is already unpacked next to the archive it is launched
    as-is (no restore). Re-compression requires ``confirm(question)`` to
    approve explicitly; without a callback the unpacked project is kept. Returns a
    summary dict: archive, project, restored, launched, released, rezipped,
    new_archive (path or None when the unchanged copy was just deleted),
    status (rezipped | kept | not-opened).
    """
    import archiver
    import burpzip

    archive_path = os.path.abspath(archive_path)
    _ordinary(archive_path)
    project = _target_for(archive_path)
    _ordinary(project)
    name = os.path.basename(project)
    summary = {"archive": archive_path, "project": project, "restored": False,
               "launched": False, "released": False, "rezipped": False,
               "new_archive": None, "status": "not-opened"}
    if os.path.exists(project):
        already_open = burpzip.is_in_use(project)
    else:
        archiver.restore_project(archive_path, project, progress=progress)
        summary["restored"] = True
        already_open = False
    if not already_open:  # never start a 2nd Burp on a file that is open
        launch_burp(project)
        summary["launched"] = True
    if not wait_until_released(project, appear_timeout, poll, stop_event, on_state):
        return summary
    summary["released"] = True
    summary["status"] = "kept"
    if confirm is None or not confirm(f"Burp has closed {name}.\n\nRe-compress {name} now?"):
        return summary
    # Compare against the archive we restored from; when we did not restore,
    # let the archiver pick the newest version.
    ref = archive_path if summary["restored"] else None
    _ordinary(project)
    _ordinary(archive_path)
    result = archiver.rezip_after_use(project, ref, level=level, threads=threads,
                                      progress=progress)
    summary["rezipped"] = True
    summary["status"] = "rezipped"
    summary["new_archive"] = getattr(result, "archive_path", None) if result else None
    return summary


# --- file association (HKCU) ----------------------------------------------------
def _is_store_install(path: str) -> bool:
    """True for paths inside the (versioned) Store package install folder."""
    p = os.path.normcase(os.path.abspath(path))
    return f"{os.sep}program files{os.sep}windowsapps{os.sep}" in p


def resolve_pythonw(candidates: list[str] | None = None) -> str:
    """Pick a stable pythonw.exe for the association command (see module doc)."""
    if candidates is None:
        candidates = [getattr(sys, "_base_executable", "") or "", sys.executable]
    fallback: str | None = None
    for exe in candidates:
        if not exe:
            continue
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if not os.path.isfile(w):
            continue
        if _is_store_install(w):
            continue
        if "windowsapps" in os.path.normcase(w):  # Store alias: stable, keep as fallback
            fallback = fallback or w
            continue
        return w
    if fallback:
        return fallback
    raise LauncherError("pythonw.exe not found next to the running interpreter")


def default_script() -> str:
    """burpzip.py next to this module (the association entry point)."""
    return str(Path(__file__).with_name("burpzip.py").resolve())


def open_command(python_exe: str, script: str) -> str:
    """The shell\\open\\command string."""
    return f'"{python_exe}" "{script}" open "%1"'


def _set(subkey: str, value: str, name: str = "") -> None:
    """Create HKCU\\<CLASSES_ROOT>\\subkey and set a REG_SZ value."""
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, rf"{CLASSES_ROOT}\{subkey}", 0,
                            winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)


def _get(subkey: str, name: str = "") -> str | None:
    return _read_reg_str(winreg.HKEY_CURRENT_USER, rf"{CLASSES_ROOT}\{subkey}", name)


def _delete_tree(root: int, subkey: str) -> None:
    """Recursively delete a registry key; missing keys are ignored."""
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            children = []
            i = 0
            while True:
                try:
                    children.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except FileNotFoundError:
        return
    for c in children:
        _delete_tree(root, rf"{subkey}\{c}")
    try:
        winreg.DeleteKey(root, subkey)
    except FileNotFoundError:
        pass


def _key_is_empty(subkey: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{CLASSES_ROOT}\{subkey}") as k:
            n_sub, n_val, _ = winreg.QueryInfoKey(k)
    except FileNotFoundError:
        return False
    return n_sub == 0 and n_val == 0


def _notify_shell() -> None:
    """Tell Explorer that file associations changed."""
    if os.name == "nt":
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)


def register_association(python_exe: str | None = None, script: str | None = None) -> str:
    """Associate .burpz with ``pythonw burpzip.py open "%1"`` for this user.

    Returns the command string written.
    """
    if winreg is None:
        raise LauncherError("file association needs Windows")
    python_exe = python_exe or resolve_pythonw()
    script = script or default_script()
    cmd = open_command(python_exe, script)
    _set(PROGID, FRIENDLY_TYPE_NAME)
    _set(PROGID, FRIENDLY_TYPE_NAME, "FriendlyTypeName")
    icon = burp_exe_for_icon()
    if icon:
        _set(rf"{PROGID}\DefaultIcon", f"{icon},0")
    _set(rf"{PROGID}\shell", "open")
    _set(rf"{PROGID}\shell\open", "Open in Burp (burpzip)")
    _set(rf"{PROGID}\shell\open\command", cmd)
    _set(EXTENSION, PROGID)
    _set(rf"{EXTENSION}\OpenWithProgids", "", PROGID)
    _notify_shell()
    return cmd


def unregister_association() -> None:
    """Remove the ProgID; drop .burpz only where it still points at us."""
    if winreg is None:
        raise LauncherError("file association needs Windows")
    hk = winreg.HKEY_CURRENT_USER
    _delete_tree(hk, rf"{CLASSES_ROOT}\{PROGID}")
    owl = rf"{CLASSES_ROOT}\{EXTENSION}\OpenWithProgids"
    try:
        with winreg.OpenKey(hk, owl, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, PROGID)
    except FileNotFoundError:
        pass
    if _key_is_empty(rf"{EXTENSION}\OpenWithProgids"):
        winreg.DeleteKey(hk, owl)
    if _get(EXTENSION) == PROGID:
        with winreg.OpenKey(hk, rf"{CLASSES_ROOT}\{EXTENSION}", 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, "")
    if _key_is_empty(EXTENSION):
        winreg.DeleteKey(hk, rf"{CLASSES_ROOT}\{EXTENSION}")
    _notify_shell()


def is_association_registered() -> bool:
    """True if .burpz maps to our ProgID and it has an open command."""
    if winreg is None:
        return False
    return _get(EXTENSION) == PROGID and bool(_get(rf"{PROGID}\shell\open\command"))


# --- tiny GUI helpers (for double-click launches without a console) -------------
def gui_confirm(question: str, title: str = "burpzip") -> bool:
    """Yes/No dialog in a throwaway hidden Tk root."""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.withdraw()
    try:
        return bool(messagebox.askyesno(title, question, parent=root))
    finally:
        root.destroy()


def gui_message(text: str, title: str = "burpzip", error: bool = False) -> None:
    """Info or error dialog in a throwaway hidden Tk root."""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.withdraw()
    try:
        (messagebox.showerror if error else messagebox.showinfo)(title, text, parent=root)
    finally:
        root.destroy()


STATE_TEXT = {
    "waiting-open": "Waiting for Burp to open the project...",
    "in-use": "Burp is using the project. Close it in Burp when you are done.",
    "released": "Burp has closed the project.",
    "timeout": "Burp did not open the project.",
    "stopped": "Stopped.",
}


class GuiProgress:
    """Small Tk window: status label, progress bar, Cancel button.

    Work runs in a background thread (``run``); ``progress``, ``state`` and
    ``confirm`` are thread-safe and marshal to the Tk thread via a queue.
    Cancel sets ``stop_event`` (honoured while waiting for Burp).
    """

    def __init__(self, title: str = "burpzip", withdraw: bool = False) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.stop_event = threading.Event()
        self._q: queue.Queue = queue.Queue()
        self.root = tk.Tk()
        if withdraw:
            self.root.withdraw()
        self.root.title(title)
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.cancel)
        self.text = tk.StringVar(value="Starting...")
        ttk.Label(self.root, textvariable=self.text, width=60, wraplength=420).pack(
            padx=16, pady=(14, 6), anchor="w")
        self.bar = ttk.Progressbar(self.root, length=420, maximum=1.0)
        self.bar.pack(padx=16, pady=6)
        ttk.Button(self.root, text="Cancel waiting", command=self.cancel).pack(pady=(4, 12))

    # thread-safe callbacks -------------------------------------------------
    def progress(self, stage: str, fraction: float | None = None) -> None:
        self._q.put(("progress", stage, fraction))

    def state(self, s: str) -> None:
        self._q.put(("text", STATE_TEXT.get(s, s), None))

    def confirm(self, question: str) -> bool:
        if threading.current_thread() is threading.main_thread():
            return self._ask(question)
        done = threading.Event()
        box: list[bool] = []
        self._q.put(("confirm", question, (done, box)))
        done.wait()
        return bool(box and box[0])

    def cancel(self) -> None:
        self.stop_event.set()

    # Tk-thread side -----------------------------------------------------------
    def _ask(self, question: str) -> bool:
        from tkinter import messagebox

        return bool(messagebox.askyesno(self.root.title(), question, parent=self.root))

    def _apply(self, kind: str, a, b) -> None:
        if kind == "progress":
            pct = f" {b * 100:.0f}%" if isinstance(b, (int, float)) else ""
            self.text.set(f"{str(a).capitalize()}...{pct}")
            if isinstance(b, (int, float)):
                self.bar.stop()
                self.bar.configure(mode="determinate", value=max(0.0, min(1.0, b)))
            else:
                self.bar.configure(mode="indeterminate")
                self.bar.start(15)
        elif kind == "text":
            self.text.set(a)
            self.bar.configure(mode="indeterminate")
            self.bar.start(15)
        elif kind == "confirm":
            done, box = b
            box.append(self._ask(a))
            done.set()

    def _pump(self, worker: threading.Thread) -> None:
        try:
            while True:
                self._apply(*self._q.get_nowait())
        except queue.Empty:
            pass
        if worker.is_alive():
            self.root.after(150, self._pump, worker)
        else:
            self.root.quit()

    def run(self, func: Callable[["GuiProgress"], object]):
        """Run ``func(self)`` in a worker thread with the window up; return/raise its outcome."""
        out: dict = {}

        def target() -> None:
            try:
                out["result"] = func(self)
            except BaseException as e:  # re-raised on the Tk thread
                out["error"] = e

        worker = threading.Thread(target=target, daemon=True)
        worker.start()
        self.root.after(50, self._pump, worker)
        self.root.mainloop()
        worker.join()
        self.destroy()
        if "error" in out:
            raise out["error"]
        return out.get("result")

    def destroy(self) -> None:
        try:
            self.root.destroy()
        except Exception:
            pass


def gui_progress(title: str = "burpzip") -> GuiProgress:
    """Create the progress window (call ``.run(func)`` on it)."""
    return GuiProgress(title)


# --- entry point for "burpzip.py open <file>" -----------------------------------
def _console_confirm(question: str) -> bool:
    """Only an interactive explicit yes approves; redirected stdin is not consent."""
    try:
        if sys.stdin is None or not sys.stdin.isatty():
            return False
        return input(question.replace("\n\n", " ") + " [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, OSError, RuntimeError, ValueError):
        return False


def _console_progress(stage: str, fraction: float | None = None) -> None:
    pct = f" {fraction * 100:5.1f}%" if fraction is not None else ""
    print(f"\r  {stage:<10}{pct}", end="", flush=True)


def describe(summary: dict) -> str:
    """One-paragraph human summary of an open_archive result."""
    name = os.path.basename(summary["project"])
    if summary["status"] == "not-opened":
        return f"Burp did not open {name}; the project was left in place."
    if summary["status"] == "kept":
        return f"{name} was left unpacked."
    if summary["new_archive"]:
        return f"{name} was re-compressed to {os.path.basename(summary['new_archive'])}."
    return f"{name} was unchanged; the unpacked copy was removed (archive kept)."


def cli_open(path: str, gui: bool | None = None) -> int:
    """Handle ``open <file>``: .burpz -> open_archive, .burp -> open_project.

    ``gui`` defaults to True when there is no console (pythonw / double-click).
    """
    if gui is None:
        gui = sys.stdout is None
    try:
        if path.lower().endswith(".burp"):
            open_project(path)
            return 0
        if gui:
            win = gui_progress(f"burpzip - {os.path.basename(path)}")
            summary = win.run(lambda w: open_archive(
                path, confirm=w.confirm, progress=w.progress, on_state=w.state,
                stop_event=w.stop_event))
            gui_message(describe(summary))
        else:
            summary = open_archive(path, confirm=_console_confirm, progress=_console_progress,
                                   on_state=lambda s: print("\n" + STATE_TEXT.get(s, s)))
            print("\n" + describe(summary))
        return 0
    except Exception as e:  # report every failure; nothing else to clean up here
        msg = f"{type(e).__name__}: {e}"
        if gui:
            gui_message(msg, error=True)
        else:
            print(f"\nerror: {msg}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    """``python launcher.py open FILE | register | unregister | status``."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 2 and args[0] == "open":
        return cli_open(args[1])
    if args == ["register"]:
        print(register_association())
        return 0
    if args == ["unregister"]:
        unregister_association()
        return 0
    if args == ["status"]:
        print("registered" if is_association_registered() else "not registered")
        return 0
    print(main.__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
