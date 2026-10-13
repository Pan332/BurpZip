"""burpzip.ini: the one settings file, kept next to burpzip.py.

Plain INI so it is easy to read and edit by hand; the GUI reads and writes the
same file. Paths under your profile are written as %USERPROFILE%\\... so the
file also works on another person's machine. Invalid values fall back to the
defaults instead of stopping the tool.
"""
from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Any

CONFIG_NAME = "burpzip.ini"
PROVIDER_MODES = ("logon", "with-burp", "manual")
DEFAULTS: dict[str, Any] = {
    "folder": "", "store": "", "provider": "logon", "ask_on_close": True, "idle_days": 10,
    "days": 10, "min_size_mb": 100, "level": 5, "burp_path": "", "extra_folders": [],
}
_SECTIONS = {
    "burp_folder": ("folder", "store", "provider", "ask_on_close", "idle_days"),
    "archive": ("days", "min_size_mb", "level", "burp_path", "extra_folders"),
}
_PATHS = ("folder", "store", "burp_path")
HEADER = """\
; Burpzip settings. Edit here or in the GUI (File > Settings).
; %USERPROFILE% and other %VARIABLES% are expanded.
;
; [burp_folder]
;   folder        folder Burp opens projects from (the registered Burp folder)
;   store         separate folder holding the 7-Zip archives; never edit by hand
;   provider      logon     = start the background provider when you log in to Windows
;                 with-burp = start it with the "Burp Suite (Burpzip)" shortcut and
;                             stop it after Burp exits
;                 manual    = only when you start it yourself
;   ask_on_close  yes/no: ask to re-zip when Burp closes a project it changed
;   idle_days     re-zip unpacked projects neither saved nor unpacked for this many days (0 = never)
; [archive]
;   days          "Archive all old" picks projects not edited for this many days
;   min_size_mb   ignore projects smaller than this
;   level         7-Zip compression level 0-9
;   burp_path     Burp Suite executable; empty = find it automatically
;   extra_folders more folders to scan, one per line (indented)

"""


def config_path() -> Path:
    """burpzip.ini next to this file, or BURPZIP_CONFIG when set (tests, portable use)."""
    override = os.environ.get("BURPZIP_CONFIG")
    return Path(override) if override else Path(__file__).resolve().with_name(CONFIG_NAME)


def exists(path: Path | None = None) -> bool:
    return (path or config_path()).is_file()


def defaults() -> dict[str, Any]:
    return {k: list(v) if isinstance(v, list) else v for k, v in DEFAULTS.items()}


def _expand(value: str) -> str:
    return os.path.expandvars(value.strip())


def _compact(value: str) -> str:
    """Write paths under the user's profile as %USERPROFILE%\\... (shareable)."""
    home = os.path.expanduser("~")
    if value and os.path.normcase(value).startswith(os.path.normcase(home)):
        rest = value[len(home):]
        if rest == "" or rest[0] in "\\/":
            return "%USERPROFILE%" + rest
    return value


def _parse(key: str, raw: str) -> Any:
    raw = raw.strip()
    if key in _PATHS:
        return _expand(raw) if raw else ""
    if key == "extra_folders":
        return [_expand(line) for line in raw.splitlines() if line.strip()]
    if key == "provider":
        if raw not in PROVIDER_MODES:
            raise ValueError(raw)
        return raw
    if key == "ask_on_close":
        value = raw.lower()
        if value in ("yes", "true", "on", "1"):
            return True
        if value in ("no", "false", "off", "0"):
            return False
        raise ValueError(raw)
    number = int(raw)
    if number < 0 or (key == "level" and number > 9) or (key == "days" and number < 1):
        raise ValueError(raw)
    return number


def load(path: Path | None = None) -> dict[str, Any]:
    """Defaults overlaid with every valid value in the file (if it exists)."""
    settings = defaults()
    path = path or config_path()
    if not path.is_file():
        return settings
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return settings
    for section, keys in _SECTIONS.items():
        for key in keys:
            raw = parser.get(section, key, fallback=None)
            if raw is None:
                continue
            try:
                settings[key] = _parse(key, raw)
            except ValueError:
                pass  # Keep the default for an invalid value.
    return settings


def save(settings: dict[str, Any], path: Path | None = None) -> Path:
    """Write every setting (missing ones as defaults); atomic replace."""
    path = path or config_path()
    parser = configparser.ConfigParser(interpolation=None)
    for section, keys in _SECTIONS.items():
        parser.add_section(section)
        for key in keys:
            value = settings.get(key, DEFAULTS[key])
            if key in _PATHS:
                text = _compact(str(value or ""))
            elif key == "extra_folders":
                text = "".join("\n" + _compact(str(f)) for f in value or [])
            elif key == "ask_on_close":
                text = "yes" if value else "no"
            else:
                text = str(value)
            parser.set(section, key, text)
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf-8") as out:
        out.write(HEADER)
        parser.write(out)
    os.replace(temporary, path)
    return path
