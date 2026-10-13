# Burpzip

A Windows/Python desktop tool and CLI for listing, archiving, restoring and opening Burp Suite project files. It uses ordinary **unencrypted 7z archives**, not transparent filesystem compression. An optional **Burp folder** lets Burp's own *Open existing project* open archived projects directly; see [below](#burp-folder-open-archived-projects-from-burp-itself).

## Prerequisites

- Windows 10/11 and Python 3.10 or newer with Tkinter (tested with Python 3.12 and Tk 8.6). The standard Windows Python installer normally includes Tkinter.
- [7-Zip](https://www.7-zip.org/) installed in its usual Program Files folder, or `7z.exe`/`7za.exe` available on `PATH`.
- Burp Suite installed to use **Open in Burp**. Archiving/restoring does not launch Burp.
- No third-party Python packages are required.
- For the optional **Burp folder**: Windows 10 version 1709 or newer (or Windows 11), 64-bit Python, and a local NTFS drive for the Burp folder and its store. No administrator rights are needed.

Keep all `*.py` files together (`burpzip.py`, `archiver.py`, `launcher.py`, `gui.py`, and `native_cfapi.py`, `native_store.py`, `native_provider.py` for the Burp folder). Installing the prerequisites is your own explicit action; the tool does not install software or register file associations automatically.

## Quick start

From this folder in PowerShell or Command Prompt:

```text
python burpzip.py
```

No arguments opens the GUI. You can also run `Start-Burpzip.cmd`, which invokes the script from its own folder without changing system settings. `python burpzip.py gui` is equivalent.

The GUI scans the home folder by default and offers a file table, filters, age/size settings, archive/restore/open actions, and explicit file-association actions. Add other folders through Settings. The scanner descends up to five directory levels and skips hidden-name folders, AppData, node_modules, the recycle bin and System Volume Information; it is not a complete disk index.

Start with a read-only listing of a folder you choose:

```text
python burpzip.py scan --root "D:\Burp Projects" --days 14 --min-mb 100
```

This does not write a plan unless you explicitly supply `--plan`. Plan output must be a **new `.json` file in an existing directory**. Existing files, project/archive paths and scanned inputs are never overwritten; choose a new filename for every export.

```text
python burpzip.py scan --root "D:\Burp Projects" --plan "D:\Plans\burpzip-review-01.json"
python burpzip.py --help
python burpzip.py archive --help
```

`--root` is repeatable. Sizes supplied with `--min-mb` are MiB (1024² bytes). Age and minimum size must be nonnegative, compression level must be 0–9, and thread count must be at least 1. Normal compression defaults to level 5 and two threads.

## CLI commands

### Archive specific projects

```text
python burpzip.py archive "D:\Burp Projects\Example.burp" --level 5 --threads 2
python burpzip.py archive "D:\Burp Projects\A.burp" "D:\Burp Projects\B.burp" --keep-original
```

By default, archiving removes each original **after the archive is verified**. You must explicitly answer `y`/`yes` to the `[y/N]` prompt, or supply `--yes`. Blank answers, `n`, EOF and noninteractive stdin do not authorize deletion. `--keep-original` creates a verified archive without removing the original and therefore does not ask for deletion confirmation.

Archive failures are reported with a nonzero exit status. Files held open by Burp are refused. Close the project in Burp before archiving it.

### Archive old projects from a reviewed plan

```text
python burpzip.py archive-old --root "D:\Burp Projects" --days 30 --min-mb 100 --level 5 --threads 2
```

This prints the plan before asking for confirmation. For an unattended run, `--yes` explicitly authorizes the displayed archive operations and removal of their verified originals. Backups and existing archives are not deletion targets. Backups appear as manual-review/skip entries and contribute **zero** estimated freed space.

The planner emits projects in admission order: a larger project that depends on earlier estimated savings follows those prerequisite files. Execution rechecks actual free space per file; savings estimates are not a guarantee that every planned file will fit. Any per-file failure makes the command return nonzero.

### Restore without overwriting

```text
python burpzip.py restore "D:\Burp Projects\Example.20261012-101500.burpz"
python burpzip.py restore "D:\Burp Projects\Example.20261012-101500.burpz" --dest "E:\Work\Example.burp"
```

The default is the original project filename beside the archive. `--dest` names the **full new project file path**, not a directory. Its parent directory must already exist. Existing destinations are refused. The archive is retained, and restored bytes are checked against the stored size/SHA-256.

### Open a project or archive

```text
python burpzip.py open "D:\Burp Projects\Example.burp"
python burpzip.py open "D:\Burp Projects\Example.20261012-101500.burpz"
```

An archive is restored as needed, then passed to the discovered Burp installation using `--project-file`. The launcher waits for Burp's project-file lock to be released rather than relying solely on the launcher's process exiting. Re-compression after use is a prompt, not a scheduled automatic deletion. An already-unpacked project is not overwritten by opening its archive.

Burp's **recent-file list cannot transparently open a compressed project**. Use this tool, or the explicit `.burpz` association below, rather than expecting an archived `.burp` path to keep working in Burp.

### Re-compress after use

```text
python burpzip.py rezip "D:\Burp Projects\Example.burp" --level 5
```

Confirmation is required because the unpacked project will be removed. Changed content produces a new versioned archive; unchanged content can remove the unpacked copy while retaining its verified reference archive. `--yes` explicitly confirms this removal.

### Delete a reviewed backup

```text
python burpzip.py delete-backup "D:\Burp Projects\Example.burp.backup"
python burpzip.py delete-backup "D:\Burp Projects\Example.burp.backup" --force-newer
```

Backup deletion is **permanent**, not a recycle-bin operation. The main project must exist and the backup must not be in use. A newer backup is refused unless `--force-newer` is explicitly supplied. With that flag, interactive confirmation requires the exact text `YES`; unattended deletion requires both `--force-newer --yes`. Review the contents yourself before discarding a potentially newer copy. Ordinary scans/archive-old runs never delete backups.

### Optional double-click association

Only when you choose to change the association:

```text
python burpzip.py register
python burpzip.py unregister
```

`register` writes a per-user Windows association for `.burpz`, using `pythonw.exe` to invoke `burpzip.py open` without a console. It does not require administrator access. Windows may still ask you to select the default app. `unregister` removes Burpzip's association entries. Keep the tool folder and Python installation available while the association is registered; unregister before moving/removing the tool. Neither command is run by installation, scanning or `--help`.

## Burp folder: open archived projects from Burp itself

Put archived projects in a **Burp folder**. Each one appears there as a normal-looking `.burp` file. In Burp, choose **Open existing project** and pick it (after the first time it is in Burp's recent list). Burpzip unpacks it with 7-Zip **into that same file** while Burp opens it. Burp is not redirected anywhere, archives stay unencrypted 7z, and NTFS compression is not used.

How it works: the Burp folder is registered with Windows Cloud Files. Each project in it is a placeholder that shows the full size but uses almost no disk until opened. A small background **provider** (`pythonw`, no window) answers Windows when a placeholder is first read: it extracts the archive, checks its SHA-256, writes the bytes into the placeholder, reads them back and checks again before Windows releases the file.

### In the GUI

Menu **Burp folder**:

- **Set up Burp folder...** creates `Downloads\BurpProjects` (or a new empty folder you choose) plus its store `...-store`, registers it, starts the provider and optionally starts it at every logon.
- **Start provider / Stop provider**, **Start provider automatically at logon**, **Open Burp folder**, **Show provider log**.

Toolbar:

- **Add to Burp folder**: for selected `.burpz` archives, verifies each one, copies it into the store, and removes it from its old folder only if the copy is byte-identical. For selected `.burp` projects, archives them first (the original `.burp` is deleted after verification, as with *Archive selected*).
- **Archive all old**: when a Burp folder is set up, old projects go straight into it in one step (zipped, verified, original deleted, same-named project appears in the Burp folder). Without a Burp folder it makes ordinary `.burpz` archives as before.
- **Unpack now**: unpacks selected Burp-folder projects ahead of time, so Burp does not wait.
- **Re-zip**: zips the selected Burp-folder projects' *current* contents (everything Burp saved), verifies the zip, and shrinks each back to a small placeholder. Projects still open in Burp are skipped.

The top bar shows **● Provider running** / **Provider stopped**. Burp-folder rows show *Burp folder: zipped*, *Burp folder: unpacked* or *Burp folder: unpacked (edited)*, while ordinary archives show *Zipped (.burpz)*. Ordinary archive/delete actions are blocked on Burp-folder rows.

### On the command line

```text
python burpzip.py native init --root <NEW_EMPTY_FOLDER> --store <NEW_SEPARATE_FOLDER> --experimental
python burpzip.py native add --store <STORE> [--move] <EXISTING.burpz>
python burpzip.py native autostart --store <STORE> --enable | --disable
python burpzip.py native serve --store <STORE> [--idle-days 10] [--no-ask-on-close]   (foreground; autostart runs this hidden)
python burpzip.py native rezip --store <STORE> --name <Project.burp> | --idle-days <N>
python burpzip.py native stop --store <STORE>
python burpzip.py native status --store <STORE>
python burpzip.py native materialize --store <STORE>
python burpzip.py native export --store <STORE> --name <Project.burp> --dest <NEW.burp> --snapshot
python burpzip.py native detach --store <STORE>
```

`add`, `materialize`, `export` and `detach` pause a running provider and restart it afterwards. The provider logs to `serve.log` in the store.

### Limits

- **The provider must be running** for a not-yet-unpacked project to open; otherwise Windows reports an error and no wrong data is served. Autostart covers this after logon.
- **When Burp closes a project it changed**, the running provider asks *"Re-zip it now to free the space?"* (Yes/No). Yes re-zips it right away; No keeps it unpacked and does not ask again until the next open and close. `serve --no-ask-on-close` turns the question off.
- After a project is opened it stays unpacked and editable until it is **re-zipped**: either with the **Re-zip** button, by answering Yes above, or automatically by the running provider once it has been **neither saved nor unpacked for 10 days** (checked hourly; `serve --idle-days N` changes it, `0` turns it off). Re-zip happens only when Burp does not have the project open: Burpzip locks out other writers, zips the current bytes, verifies the zip, switches the placeholder to it, and only then deletes the previous zip. If it is interrupted, the next start finishes or abandons the switch based on the file's actual state.
- Your edits are authoritative. The store's archive is a **historical snapshot, not a backup of later edits**, and is never written over a project that was unpacked or changed. `export --snapshot` restores that historical copy; `export --current` is not supported.
- Unpacking needs room for the unpacked project plus a 512 MiB reserve (it streams straight into place; no temporary copy). Re-zipping needs room for a temporary copy and the new zip.
- The first open of a large still-zipped project makes Burp wait while it unpacks (about 3 minutes for 4 GB). Use **Unpack now** beforehand to avoid the wait.
- Stopping the provider only disconnects. Burpzip never unregisters the Burp folder automatically (Windows unregistration can permanently delete not-yet-unpacked placeholders). `detach` converts projects back to ordinary files and reports an incomplete detach.
- Other programs that read files (antivirus, indexers, Explorer previews) can also trigger unpacking.
- Do not edit the store folder by hand. Burpzip refuses to open a store whose catalog, journal or archives were changed.

Verified on Windows 11 with live tests on throwaway folders: registration, placeholder creation, refusal while the provider is stopped, same-path unpacking on first open, *Unpack now*, local edits surviving provider restarts, status/materialize/detach on edited projects, re-zip of an edited project and reopening its edited bytes, in-use detection, the ask-on-close flow, and unpacking a real 4.1 GB project (first data after 3 s, done in about 3 minutes). Burp opened, edited and saved a managed project in manual tests. Burp's behavior across versions, crashes during save, and very large projects have not been tested extensively; keep important projects backed up.

## Architecture

### Two ways to keep a project zipped

The zip is the same in both: a `.burpz` file, an ordinary unencrypted 7-Zip archive holding the original `.burp` and `burpzip-meta.json` (original name, size, last-edit time, SHA-256). What differs is where it lives and what stands in for the project.

```text
Ordinary archive                          Burp folder (native)
----------------                          --------------------
Downloads\                                Downloads\BurpProjects\          <- Burp opens files here
  Example.20261012-101500.burpz             Example.burp   (placeholder: full size shown,
  (no .burp any more)                                       ~0 bytes on disk until opened)
                                          Downloads\BurpProjects-store\
Open with Burpzip: unzip next to it,        archives\<uuid>\import.burpz   <- the same kind of zip
then launch Burp                          Open from Burp itself: Windows asks Burpzip for the bytes
```

### Components

| Module | Role |
|---|---|
| `burpzip.py` | CLI entry point, scanner and space planner, metadata-only protection of Burp-folder/cloud/store paths, provider control (start, stop, pause, autostart shortcut). |
| `gui.py` | Tk GUI. One background worker thread does all file work; the Tk thread only shows results and dialogs. |
| `archiver.py` | 7-Zip archive / verify / restore of `.burpz` files. Refuses protected paths. |
| `launcher.py` | Finds and launches Burp; the ordinary open-then-re-zip flow; optional `.burpz` double-click association. |
| `native_cfapi.py` | `ctypes` adapter for Windows Cloud Files (`CldApi.dll`): register a folder, create/inspect/update placeholders, serve data callbacks, path classification, in-use probe. |
| `native_store.py` | The store: catalog, append-only journal, exclusive lease, immutable archive copies and manifests, staging folders, re-zip generations and crash recovery. |
| `native_provider.py` | The background provider: answers Windows callbacks, unpacks and verifies, re-zips, hourly idle sweep, ask-on-close watcher, `serve` loop. |

### Store layout

```text
Downloads\BurpProjects\                     registered Cloud Files sync root (flat, .burp only)
    Example.burp                            placeholder, or the unpacked project after first open
Downloads\BurpProjects-store\               never edit by hand
    .burpzip-native-store.json              catalog: one entry per project generation
    native-journal.jsonl                    append-only journal, written before every catalog change
    .burpzip-native.lock                    exclusive lease, held by whoever is changing the store
    serve.log                               provider log (also the only output of the hidden provider)
    archives\<uuid>\import.burpz            the 7-Zip archive of that generation
    archives\<uuid>\manifest.json           write-once copy of the entry's identity fields
```

Each catalog entry moves through phases: `placeholder` -> `staged` -> `transferred` -> `ack-intent` -> `resident`. A re-zip creates a new entry (a new generation) and marks the previous one `superseded`; `reverted` is used by `detach`. A catalog change is first appended to the journal and flushed, then the catalog is replaced atomically; a catalog that does not match the journal is refused rather than guessed at.

Ownership is checked by identity, not by path: the sync root carries a root identity (marker, root UUID, Windows file ID of the folder), and every placeholder carries a file identity (marker, root UUID, entry UUID, SHA-256 of its archive). A callback or file whose identity does not match the catalog is refused.

### Opening a project (first read)

```text
Burp opens BurpProjects\Example.burp
  -> Windows: no data on disk yet; holds Burp's read and calls the provider (FETCH_DATA)
  -> provider: checks the placeholder identity against the catalog
     1. checks the zip file's own SHA-256 against the catalog (proves it is the
        exact zip that was fully verified when it was added)
     2. streams 7-Zip's output straight into the same file through Windows
        (TRANSFER_DATA, 1 MiB at a time), hashing it on the way; the first data
        arrives within seconds
     3. checks the streamed size and SHA-256 against burpzip-meta.json
     4. Windows asks for validation (VALIDATE_DATA); the provider reads the
        stored bytes back (RETRIEVE_DATA) and checks the SHA-256 again
     5. journals "ack-intent": from now on this file is never rewritten from the archive
     6. acknowledges the validation (ACK_DATA) and marks the entry resident
  -> Windows releases Burp's read; Burp sees a normal, complete file
```

Windows cancels a request that receives no data for about 60 seconds (progress reports do not extend this), so the provider streams instead of extracting first; every piece it sends resets that timer. Each request also has an overall deadline. Every callback runs on a Windows thread; the provider copies what it needs and hands the work to one worker thread, so Python errors never cross back into Windows.

### Re-zipping

```text
Re-zip button / Yes after Burp closes it / unchanged for 10 days
  -> check Burp does not have the file open
  -> open it with other writers and deleters locked out
  -> copy the current bytes to %TEMP%, zip with 7-Zip, verify (7z test + SHA-256)
  -> store the new zip as a new "prepared" generation (journaled)
  -> CfUpdatePlaceholder: same file, new identity, data dropped, marked in sync
  -> mark the new generation current and the old one superseded; delete the old zip
```

If anything fails before the switch, the new generation is abandoned and the project stays as it was. If the process stops between the switch and the catalog update, the next start compares the file's actual identity with both generations and finishes or abandons the switch.

### Background provider

- Started at logon by a shortcut in your Startup folder: `pythonw burpzip.py native serve --store <store>`. No window, no service, no administrator rights.
- Holds the store lease while running. Commands that change the store (`add`, *Add to Burp folder*, *Unpack now*, *Re-zip*, *Archive all old*) pause it, do their work, and start it again.
- Stops when asked through a `serve.stop` request file (`native stop`, or the GUI). Stopping disconnects only; the folder stays registered.
- Every 10 seconds (ask-on-close) it checks unpacked projects: when one that Burp changed is released, it asks on a separate thread so serving continues while the dialog waits. Every hour it re-zips projects neither saved nor unpacked for 10 days.

### Safety rules the code enforces

- Verify before delete: no project or zip is removed until its replacement has passed a 7-Zip test and a full SHA-256 check.
- Your edits win: once a project is unpacked, the journal blocks any rewrite from its archive; only a new archive of the current bytes can replace it.
- No automatic unregistration: Windows unregistration can delete not-yet-unpacked placeholders, so Burpzip never does it.
- Metadata only: ordinary scans and commands classify Burp-folder, cloud and store paths without reading their contents, and refuse to archive, delete or overwrite them.
- No encryption, no cloud upload: everything stays local in plain 7-Zip.

### Windows behaviour confirmed by the live tests

- Windows hides a placeholder's reparse tag from ordinary programs (it reads as 0), so Burpzip asks Cloud Files directly whether a file is a placeholder.
- A provider's callback threads see the sync-root folder as a reparse point with that hidden tag.
- `ACK_DATA` is accepted only for validation requests; a read (`FETCH_DATA`) is completed by its transfers.
- After a local edit, Windows no longer counts the edited ranges as validated, so Burpzip treats "fully on disk" (resident) separately from "validated".
- Turning an unpacked file back into a placeholder needs `CF_UPDATE_FLAG_ALLOW_PARTIAL`, because the always-full flag otherwise blocks it.
- Opening a file for delete access only reads no data, so it is a safe test of whether Burp still has a project open.
- A data request that receives nothing for about 60 seconds is cancelled (`ERROR_CLOUD_FILE_REQUEST_TIMEOUT`), whatever progress is reported. Large projects failed this way until unpacking was changed to stream.
- An unpacked project keeps its original (possibly months-old) last-edited time, so "idle" is measured from the later of the last save and the last unpack.

## Archive contents and space requirements

New archives are named:

```text
<project stem>.<YYYYMMDD-HHMMSS>.burpz
```

Each holds the original `.burp` file and a small `burpzip-meta.json` record, including original filename/path, size, last-edit time, SHA-256, archive creation time and compression level. Metadata and project data are **unencrypted by design**; protect archives as you would the original Burp project. The scanner reads only the metadata entry for archive age/size presentation. Corrupt, unsupported or password-protected archives get a metadata-unavailable note, not a claim that they can be restored. Legacy `.burp[.YYYYMMDD-HHMMSS].7z` filenames are recognized for listing; restoration still needs valid Burpzip metadata.

- Archive admission reserves the full input size plus an overhead allowance (the larger of 64 MiB or 5%) plus a **512 MiB free-space reserve**. This is conservative admission, not a guarantee against other programs filling the disk concurrently.
- Scan/GUI plans budget each distinct source volume separately, because new archives are stored beside their projects. Estimated savings on one volume cannot make a project on another volume fit; roots sharing a volume share its budget only once. Per-volume `free_after` and aggregate after-space totals are **estimates**, not transferable capacity. If a volume or its free space cannot be queried, that pool gets zero budget and an explanatory note.
- Restoring needs the **full original project size plus the 512 MiB reserve** on the destination volume. Compressed size is not the space needed to open the project. Archives remain on disk during/after restore.
- The dry-run's assumed 15% archive size and estimated freed space are **estimates only**. Some projects compress poorly or may not save space. No universal 85% savings is promised, and no real-user savings benchmark is claimed here.
- Unsupported metadata or source timestamps (for example, a pre-1970/negative modification time) are refused with the source kept. New archive metadata is reader-validated before an original can be removed.
- Size/mtime matches with an existing archive are not evidence that the bytes match, and never authorize skipping verification or automatically deleting a source.
- Stop is **between files**, not an immediate abort of the current file's hashing/compression/verification. It may take time to finish current work. Do not force-close the interpreter expecting an instantaneous safe shutdown.

Keep an independent backup of important project data. Compression verification is not a substitute for backups.

## Tests

Run the complete test suite from this folder:

```text
python -m unittest discover -v
```

For just the scanner/CLI tests:

```text
python -m unittest -v test_burpzip test_cli
```

The suite uses temporary synthetic projects. Cross-module lifecycle tests exercise real 7-Zip archive/restore/re-compression with temporary Windows file-lock holders; Burp launches and confirmation dialogs are mocked. GUI tests use withdrawn Tk windows rather than a visible application. Association tests redirect registry writes to the isolated scratch key `HKCU\Software\BurpZipTest`, clean it up, and do not change production file associations.

Native-mode tests (`test_native_cfapi`, `test_native_store`, `test_native_provider`, `test_native_cli`) use injected recording DLLs or a simulated Cloud Files adapter that follows the live Windows protocol, with real 7-Zip on temporary synthetic files; they never register a sync root. `test_native_live` registers throwaway sync roots under `%TEMP%\burpzip-native-test-*` and runs only when `BURPZIP_NATIVE_LIVE=1` is set; it never unregisters, so remove those test roots afterwards.

Some compression/lifecycle tests require Windows and 7-Zip; GUI tests require a working Tk display even when windows are withdrawn. No actual Burp process or real Burp project was used, so these tests do **not** establish compatibility with a particular Burp installation or project version.
