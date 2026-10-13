"""Inert, stdlib-only Windows x64 Cloud Files leaf adapter.

This is a release-gated prototype, NOT an operational/accepted Burp provider.
Importing this module loads no DLL, registers nothing and reads no file contents.
Nonhydrating inspection is independent of the activation gate. Production
unregister/dehydrate/update/restart-hydration are intentionally not bound.

ABI data: Microsoft's win32metadata cfapi.h (current SDK declaration layout),
https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/cfapi.h
and https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention .
The fixed layout below is version 1, including RequestKey/PlaceholderManagement.
8-byte C key structs/LARGE_INTEGER unions are integer-class by-value on x64;
using int64 avoids ctypes' unsupported union-by-value paths. HRESULT is int32;
operation completion status is a DISTINCT signed NTSTATUS, never an HRESULT.
Native ABI/lifecycle, zero-file/EOF, protected export and namespace exclusion
still need separately authorized live tests. Fake-DLL tests prove no native ABI.
"""
from __future__ import annotations

import ctypes as C
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
import math
import ntpath
import os
import platform
import re
import stat
import struct
import tempfile
import threading
import uuid


# Live Windows gates passed on synthetic roots (register, placeholder, offline
# refusal, same-path hydration, edit, materialize, detach) and Burp opened a
# managed project. Set False to block all native activation again.
NATIVE_RELEASE_READY = True
ABI_LAYOUT_VERSION = 1
STORE_MARKER = ".burpzip-native-store.json"
IDENTITY_VERSION = 1
_ROOT_MAGIC = b"BZCFROOT"
_FILE_MAGIC = b"BZCFFILE"
_MAX_IDENTITY = 4096
_MAX_ROOT_IDENTITY = 65536
_MAX_QUERY = 1024 * 1024
_MAX_CHUNK = 16 * 1024 * 1024

DWORD = C.c_uint32
ULONG = C.c_uint32
USHORT = C.c_uint16
WCHAR = C.c_uint16  # c_wchar is 4 bytes on non-Windows; SDK WCHAR is always 2.
HRESULT = C.c_int32
NTSTATUS = C.c_int32
LARGE_INTEGER = C.c_int64
CF_CONNECTION_KEY = C.c_int64
CF_TRANSFER_KEY = C.c_int64
CF_REQUEST_KEY = C.c_int64
HANDLE = C.c_void_p
PVOID = C.c_void_p

CF_HYDRATION_POLICY_FULL = 2
CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED = 1
CF_POPULATION_POLICY_ALWAYS_FULL = 3
CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC = 2
CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL = 8
CF_UPDATE_FLAG_MARK_IN_SYNC = 0x2
CF_UPDATE_FLAG_DEHYDRATE = 0x4
CF_UPDATE_FLAG_ALWAYS_FULL = 0x200
# Live Windows: dehydrating an ALWAYS_FULL placeholder is refused (0x800701B2)
# unless ALLOW_PARTIAL clears that flag in the same call.
CF_UPDATE_FLAG_ALLOW_PARTIAL = 0x400
CF_CREATE_FLAG_STOP_ON_ERROR = 1
CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH = 4
CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION = 8
CF_CALLBACK_TYPE_FETCH_DATA = 0
CF_CALLBACK_TYPE_VALIDATE_DATA = 1
CF_CALLBACK_TYPE_CANCEL_FETCH_DATA = 2
CF_CALLBACK_TYPE_NONE = 0xFFFFFFFF
CF_OPERATION_TYPE_TRANSFER_DATA = 0
CF_OPERATION_TYPE_RETRIEVE_DATA = 1
CF_OPERATION_TYPE_ACK_DATA = 2
CF_SYNC_ROOT_INFO_STANDARD = 1
CF_PLACEHOLDER_INFO_STANDARD = 1
CF_PLACEHOLDER_RANGE_INFO_ONDISK = 1
CF_PLACEHOLDER_RANGE_INFO_VALIDATED = 2
CF_PLACEHOLDER_RANGE_INFO_MODIFIED = 3
CF_PLACEHOLDER_STATE_PLACEHOLDER = 1
CF_PLACEHOLDER_STATE_SYNC_ROOT = 2
CF_PLACEHOLDER_STATE_IN_SYNC = 8
CF_PLACEHOLDER_STATE_PARTIAL = 16
CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK = 32
CF_PLACEHOLDER_STATE_INVALID = 0xFFFFFFFF
CF_OPEN_FILE_FLAG_EXCLUSIVE = 1
CF_OPEN_FILE_FLAG_WRITE_ACCESS = 2
CF_OPEN_FILE_FLAG_FOREGROUND = 8
CF_EOF = -1
STATUS_CLOUD_FILE_UNSUCCESSFUL = C.c_int32(0xC000CF12).value
STATUS_CLOUD_FILE_REQUEST_CANCELED = C.c_int32(0xC000CF1B).value

# winerror.h: these alone establish absence of a registered root. Any other
# failure (access denied, unavailable DLL, malformed result, etc.) is UNKNOWN.
ERROR_NOT_A_CLOUD_SYNC_ROOT = 405
ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT = 390
ERROR_MORE_DATA = 234
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_HANDLE_EOF = 38
ERROR_NOT_A_CLOUD_FILE = 376
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_DIRECTORY = 0x10
_CLOUD_ATTRIBUTES = 0x1000 | 0x40000 | 0x400000
_INVALID_HANDLE = C.c_void_p(-1).value


class NativeError(RuntimeError):
    """Native failure or insufficient evidence for a safe operation."""


@dataclass
class PathState:
    kind: str = "ordinary"
    path: str = ""
    root_path: str | None = None
    root_id: str | None = None
    file_id: str | None = None
    identity: bytes = b""
    size: int = 0
    ready: bool = False
    modified: bool = False
    note: str = ""
    # Every byte is on disk. Differs from `ready` (also validated): Windows
    # stops counting ranges as validated once they are edited locally.
    resident: bool = False
    mtime: float = 0.0  # Last write (epoch), from handle metadata; never reads data.


@dataclass(frozen=True)
class Snapshot:
    """A resident placeholder held open with writers/deleters denied."""
    fd: int
    handle: int
    path: str
    file_id: str
    size: int
    mtime: float

    def read(self, count: int) -> bytes:
        return os.read(self.fd, count)


@dataclass(frozen=True)
class Request:
    event: str = "fetch"
    path: str = ""
    identity: bytes = b""
    connection: int = 0
    transfer: int = 0
    request_key: int = 0
    offset: int = 0
    length: int = 0
    file_size: int = 0
    flags: int = 0


class GUID(C.Structure):
    _fields_ = [("Data1", DWORD), ("Data2", USHORT), ("Data3", USHORT),
                ("Data4", C.c_ubyte * 8)]


class FILE_BASIC_INFO(C.Structure):
    _fields_ = [("CreationTime", LARGE_INTEGER), ("LastAccessTime", LARGE_INTEGER),
                ("LastWriteTime", LARGE_INTEGER), ("ChangeTime", LARGE_INTEGER),
                ("FileAttributes", DWORD)]


class CF_PLATFORM_INFO(C.Structure):
    _fields_ = [("BuildNumber", DWORD), ("RevisionNumber", DWORD),
                ("IntegrationNumber", DWORD)]


class CF_FS_METADATA(C.Structure):
    _fields_ = [("BasicInfo", FILE_BASIC_INFO), ("FileSize", LARGE_INTEGER)]


class CF_HYDRATION_POLICY(C.Structure):
    _fields_ = [("Primary", USHORT), ("Modifier", USHORT)]


class CF_POPULATION_POLICY(C.Structure):
    _fields_ = [("Primary", USHORT), ("Modifier", USHORT)]


class CF_SYNC_POLICIES(C.Structure):
    _fields_ = [("StructSize", ULONG), ("Hydration", CF_HYDRATION_POLICY),
                ("Population", CF_POPULATION_POLICY), ("InSync", DWORD),
                ("HardLink", DWORD), ("PlaceholderManagement", DWORD)]


class CF_SYNC_REGISTRATION(C.Structure):
    _fields_ = [("StructSize", ULONG), ("ProviderName", C.c_wchar_p),
                ("ProviderVersion", C.c_wchar_p), ("SyncRootIdentity", PVOID),
                ("SyncRootIdentityLength", DWORD), ("FileIdentity", PVOID),
                ("FileIdentityLength", DWORD), ("ProviderId", GUID)]


class CF_PLACEHOLDER_CREATE_INFO(C.Structure):
    _fields_ = [("RelativeFileName", C.c_wchar_p), ("FsMetadata", CF_FS_METADATA),
                ("FileIdentity", PVOID), ("FileIdentityLength", DWORD),
                ("Flags", DWORD), ("Result", HRESULT), ("CreateUsn", LARGE_INTEGER)]


class CF_CALLBACK_INFO(C.Structure):
    _fields_ = [("StructSize", DWORD), ("ConnectionKey", CF_CONNECTION_KEY),
                ("CallbackContext", PVOID), ("VolumeGuidName", C.c_wchar_p),
                ("VolumeDosName", C.c_wchar_p), ("VolumeSerialNumber", DWORD),
                ("SyncRootFileId", LARGE_INTEGER), ("SyncRootIdentity", PVOID),
                ("SyncRootIdentityLength", DWORD), ("FileId", LARGE_INTEGER),
                ("FileSize", LARGE_INTEGER), ("FileIdentity", PVOID),
                ("FileIdentityLength", DWORD), ("NormalizedPath", C.c_wchar_p),
                ("TransferKey", CF_TRANSFER_KEY), ("PriorityHint", C.c_ubyte),
                ("CorrelationVector", PVOID), ("ProcessInfo", PVOID),
                ("RequestKey", CF_REQUEST_KEY)]


class CF_CALLBACK_FETCH_DATA(C.Structure):
    _fields_ = [("Flags", DWORD), ("RequiredFileOffset", LARGE_INTEGER),
                ("RequiredLength", LARGE_INTEGER), ("OptionalFileOffset", LARGE_INTEGER),
                ("OptionalLength", LARGE_INTEGER), ("LastDehydrationTime", LARGE_INTEGER),
                ("LastDehydrationReason", DWORD)]


class CF_CALLBACK_VALIDATE_DATA(C.Structure):
    _fields_ = [("Flags", DWORD), ("RequiredFileOffset", LARGE_INTEGER),
                ("RequiredLength", LARGE_INTEGER)]


class CF_CANCEL_FETCH_DATA(C.Structure):
    _fields_ = [("FileOffset", LARGE_INTEGER), ("Length", LARGE_INTEGER)]


class CF_CALLBACK_CANCEL(C.Structure):
    _fields_ = [("Flags", DWORD), ("FetchData", CF_CANCEL_FETCH_DATA)]


class CF_CALLBACK_UNION(C.Union):
    # FetchData is the largest SDK alternative. Other callbacks are not bound.
    _fields_ = [("FetchData", CF_CALLBACK_FETCH_DATA),
                ("ValidateData", CF_CALLBACK_VALIDATE_DATA), ("Cancel", CF_CALLBACK_CANCEL)]


class CF_CALLBACK_PARAMETERS(C.Structure):
    _anonymous_ = ("Data",)
    _fields_ = [("ParamSize", ULONG), ("Data", CF_CALLBACK_UNION)]


# No callback is constructed at import. This declares a Python type only.
_CALLBACK_FACTORY = getattr(C, "WINFUNCTYPE", C.CFUNCTYPE)
CF_CALLBACK = _CALLBACK_FACTORY(None, C.POINTER(CF_CALLBACK_INFO),
                                 C.POINTER(CF_CALLBACK_PARAMETERS))


class CF_CALLBACK_REGISTRATION(C.Structure):
    _fields_ = [("Type", DWORD), ("Callback", CF_CALLBACK)]


class CF_OPERATION_INFO(C.Structure):
    _fields_ = [("StructSize", ULONG), ("Type", DWORD),
                ("ConnectionKey", CF_CONNECTION_KEY), ("TransferKey", CF_TRANSFER_KEY),
                ("CorrelationVector", PVOID), ("SyncStatus", PVOID),
                ("RequestKey", CF_REQUEST_KEY)]


class CF_TRANSFER_DATA(C.Structure):
    _fields_ = [("Flags", DWORD), ("CompletionStatus", NTSTATUS), ("Buffer", PVOID),
                ("Offset", LARGE_INTEGER), ("Length", LARGE_INTEGER)]


class CF_RETRIEVE_DATA(C.Structure):
    _fields_ = [("Flags", DWORD), ("Buffer", PVOID), ("Offset", LARGE_INTEGER),
                ("Length", LARGE_INTEGER), ("ReturnedLength", LARGE_INTEGER)]


class CF_ACK_DATA(C.Structure):
    _fields_ = [("Flags", DWORD), ("CompletionStatus", NTSTATUS),
                ("Offset", LARGE_INTEGER), ("Length", LARGE_INTEGER)]


class CF_OPERATION_UNION(C.Union):
    # RetrieveData is the largest SDK alternative; others are deliberately absent.
    _fields_ = [("TransferData", CF_TRANSFER_DATA), ("RetrieveData", CF_RETRIEVE_DATA),
                ("AckData", CF_ACK_DATA)]


class CF_OPERATION_PARAMETERS(C.Structure):
    _anonymous_ = ("Data",)
    _fields_ = [("ParamSize", ULONG), ("Data", CF_OPERATION_UNION)]


class CF_SYNC_ROOT_STANDARD_INFO(C.Structure):
    _fields_ = [("SyncRootFileId", LARGE_INTEGER), ("HydrationPolicy", CF_HYDRATION_POLICY),
                ("PopulationPolicy", CF_POPULATION_POLICY), ("InSyncPolicy", DWORD),
                ("HardLinkPolicy", DWORD), ("ProviderStatus", DWORD),
                ("ProviderName", WCHAR * 256), ("ProviderVersion", WCHAR * 256),
                ("SyncRootIdentityLength", ULONG), ("SyncRootIdentity", C.c_ubyte * 1)]


class CF_PLACEHOLDER_STANDARD_INFO(C.Structure):
    _fields_ = [("OnDiskDataSize", LARGE_INTEGER), ("ValidatedDataSize", LARGE_INTEGER),
                ("ModifiedDataSize", LARGE_INTEGER), ("PropertiesSize", LARGE_INTEGER),
                ("PinState", DWORD), ("InSyncState", DWORD), ("FileId", LARGE_INTEGER),
                ("SyncRootFileId", LARGE_INTEGER), ("FileIdentityLength", ULONG),
                ("FileIdentity", C.c_ubyte * 1)]


class CF_FILE_RANGE(C.Structure):
    _fields_ = [("StartingOffset", LARGE_INTEGER), ("Length", LARGE_INTEGER)]


class FILETIME(C.Structure):
    _fields_ = [("Low", DWORD), ("High", DWORD)]


class BY_HANDLE_FILE_INFORMATION(C.Structure):
    _fields_ = [("FileAttributes", DWORD), ("CreationTime", FILETIME),
                ("LastAccessTime", FILETIME), ("LastWriteTime", FILETIME),
                ("VolumeSerialNumber", DWORD), ("FileSizeHigh", DWORD),
                ("FileSizeLow", DWORD), ("NumberOfLinks", DWORD),
                ("FileIndexHigh", DWORD), ("FileIndexLow", DWORD)]


class FILE_ATTRIBUTE_TAG_INFO(C.Structure):
    _fields_ = [("FileAttributes", DWORD), ("ReparseTag", DWORD)]


# Constant external layout expectations, NOT assertions derived from ctypes itself.
# Full field offsets are checked at activation; host-independent tests can check
# this table on any 64-bit host without loading Windows DLLs.
ABI_X64_V1 = {
    GUID: (16, {"Data1": 0, "Data2": 4, "Data3": 6, "Data4": 8}),
    FILE_BASIC_INFO: (40, {"CreationTime": 0, "LastAccessTime": 8, "LastWriteTime": 16,
                           "ChangeTime": 24, "FileAttributes": 32}),
    CF_PLATFORM_INFO: (12, {"BuildNumber": 0, "RevisionNumber": 4, "IntegrationNumber": 8}),
    CF_FS_METADATA: (48, {"BasicInfo": 0, "FileSize": 40}),
    CF_HYDRATION_POLICY: (4, {"Primary": 0, "Modifier": 2}),
    CF_POPULATION_POLICY: (4, {"Primary": 0, "Modifier": 2}),
    CF_SYNC_POLICIES: (24, {"StructSize": 0, "Hydration": 4, "Population": 8,
                           "InSync": 12, "HardLink": 16, "PlaceholderManagement": 20}),
    CF_SYNC_REGISTRATION: (72, {"StructSize": 0, "ProviderName": 8, "ProviderVersion": 16,
                                "SyncRootIdentity": 24, "SyncRootIdentityLength": 32,
                                "FileIdentity": 40, "FileIdentityLength": 48, "ProviderId": 52}),
    CF_PLACEHOLDER_CREATE_INFO: (88, {"RelativeFileName": 0, "FsMetadata": 8,
                                     "FileIdentity": 56, "FileIdentityLength": 64,
                                     "Flags": 68, "Result": 72, "CreateUsn": 80}),
    CF_CALLBACK_INFO: (152, {"StructSize": 0, "ConnectionKey": 8, "CallbackContext": 16,
                            "VolumeGuidName": 24, "VolumeDosName": 32, "VolumeSerialNumber": 40,
                            "SyncRootFileId": 48, "SyncRootIdentity": 56,
                            "SyncRootIdentityLength": 64, "FileId": 72, "FileSize": 80,
                            "FileIdentity": 88, "FileIdentityLength": 96, "NormalizedPath": 104,
                            "TransferKey": 112, "PriorityHint": 120, "CorrelationVector": 128,
                            "ProcessInfo": 136, "RequestKey": 144}),
    CF_CALLBACK_FETCH_DATA: (56, {"Flags": 0, "RequiredFileOffset": 8, "RequiredLength": 16,
                                  "OptionalFileOffset": 24, "OptionalLength": 32,
                                  "LastDehydrationTime": 40, "LastDehydrationReason": 48}),
    CF_CALLBACK_VALIDATE_DATA: (24, {"Flags": 0, "RequiredFileOffset": 8, "RequiredLength": 16}),
    CF_CANCEL_FETCH_DATA: (16, {"FileOffset": 0, "Length": 8}),
    CF_CALLBACK_CANCEL: (24, {"Flags": 0, "FetchData": 8}),
    CF_CALLBACK_PARAMETERS: (64, {"ParamSize": 0, "Data": 8}),
    CF_CALLBACK_REGISTRATION: (16, {"Type": 0, "Callback": 8}),
    CF_OPERATION_INFO: (48, {"StructSize": 0, "Type": 4, "ConnectionKey": 8,
                            "TransferKey": 16, "CorrelationVector": 24, "SyncStatus": 32,
                            "RequestKey": 40}),
    CF_TRANSFER_DATA: (32, {"Flags": 0, "CompletionStatus": 4, "Buffer": 8,
                           "Offset": 16, "Length": 24}),
    CF_RETRIEVE_DATA: (40, {"Flags": 0, "Buffer": 8, "Offset": 16, "Length": 24,
                           "ReturnedLength": 32}),
    CF_ACK_DATA: (24, {"Flags": 0, "CompletionStatus": 4, "Offset": 8, "Length": 16}),
    CF_OPERATION_PARAMETERS: (48, {"ParamSize": 0, "Data": 8}),
    CF_SYNC_ROOT_STANDARD_INFO: (1064, {"SyncRootFileId": 0, "HydrationPolicy": 8,
                                       "PopulationPolicy": 12, "InSyncPolicy": 16,
                                       "HardLinkPolicy": 20, "ProviderStatus": 24,
                                       "ProviderName": 28, "ProviderVersion": 540,
                                       "SyncRootIdentityLength": 1052, "SyncRootIdentity": 1056}),
    CF_PLACEHOLDER_STANDARD_INFO: (64, {"OnDiskDataSize": 0, "ValidatedDataSize": 8,
                                       "ModifiedDataSize": 16, "PropertiesSize": 24,
                                       "PinState": 32, "InSyncState": 36, "FileId": 40,
                                       "SyncRootFileId": 48, "FileIdentityLength": 56,
                                       "FileIdentity": 60}),
    CF_FILE_RANGE: (16, {"StartingOffset": 0, "Length": 8}),
    BY_HANDLE_FILE_INFORMATION: (52, {"FileAttributes": 0, "CreationTime": 4,
                                      "LastAccessTime": 12, "LastWriteTime": 20,
                                      "VolumeSerialNumber": 28, "FileSizeHigh": 32,
                                      "FileSizeLow": 36, "NumberOfLinks": 40,
                                      "FileIndexHigh": 44, "FileIndexLow": 48}),
    FILE_ATTRIBUTE_TAG_INFO: (8, {"FileAttributes": 0, "ReparseTag": 4}),
}


def verify_abi() -> None:
    if C.sizeof(PVOID) != 8:
        raise NativeError("CFAPI activation requires the checked Windows x64 ABI")
    for typ, (size, offsets) in ABI_X64_V1.items():
        if C.sizeof(typ) != size:
            raise NativeError(f"ABI v1 size mismatch: {typ.__name__}")
        for name, offset in offsets.items():
            if getattr(typ, name).offset != offset:
                raise NativeError(f"ABI v1 offset mismatch: {typ.__name__}.{name}")


def _signed64(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not -(1 << 63) <= value < 1 << 64:
        raise NativeError("Invalid 64-bit native key")
    return C.c_int64(value).value


def _check_hr(value, operation: str) -> None:
    code = int(value.value if hasattr(value, "value") else value) & 0xFFFFFFFF
    if code & 0x80000000:
        raise NativeError(f"{operation} failed (HRESULT 0x{code:08x})")


def _hr_win32(value: int) -> int:
    return 0x80070000 | value


def _uuid_bytes(value: str) -> bytes:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise NativeError("Native identity requires a UUID") from exc
    if parsed.int == 0:
        raise NativeError("Nil UUID is not a native ownership identity")
    return parsed.bytes


def root_identity(root_id: str, root_file_id: str) -> bytes:
    if not isinstance(root_file_id, str) or not root_file_id or "\x00" in root_file_id:
        raise NativeError("Missing OS volume/root file identity")
    encoded = root_file_id.encode("utf-8")
    if len(encoded) > 1024:
        raise NativeError("Root OS identity too long")
    return _ROOT_MAGIC + struct.pack("<HH", IDENTITY_VERSION, len(encoded)) + _uuid_bytes(root_id) + encoded


def decode_root_identity(identity: bytes) -> dict:
    if not isinstance(identity, bytes) or len(identity) < 29 or identity[:8] != _ROOT_MAGIC:
        raise NativeError("Unrecognized root ownership identity")
    version, length = struct.unpack_from("<HH", identity, 8)
    if version != IDENTITY_VERSION or not 0 < length <= 1024 or len(identity) != 28 + length:
        raise NativeError("Malformed/version-incompatible root ownership identity")
    try:
        root_id = str(uuid.UUID(bytes=identity[12:28]))
        root_file_id = identity[28:].decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise NativeError("Malformed root ownership identity") from exc
    if root_identity(root_id, root_file_id) != identity:
        raise NativeError("Noncanonical root identity")
    return {"version": version, "root_id": root_id, "root_file_id": root_file_id}


def file_identity(root_id: str, file_id: str, archive_sha: str) -> bytes:
    if not isinstance(archive_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", archive_sha):
        raise NativeError("Native identity requires the immutable archive SHA-256")
    return (_FILE_MAGIC + struct.pack("<H", IDENTITY_VERSION) + _uuid_bytes(root_id)
            + _uuid_bytes(file_id) + bytes.fromhex(archive_sha))


def decode_file_identity(identity: bytes) -> dict:
    if not isinstance(identity, bytes) or len(identity) != 74 or identity[:8] != _FILE_MAGIC:
        raise NativeError("Unrecognized placeholder identity")
    version = struct.unpack_from("<H", identity, 8)[0]
    if version != IDENTITY_VERSION:
        raise NativeError("Unsupported placeholder identity version")
    root_id = str(uuid.UUID(bytes=identity[10:26]))
    file_id = str(uuid.UUID(bytes=identity[26:42]))
    archive_sha = identity[42:].hex()
    if file_identity(root_id, file_id, archive_sha) != identity:
        raise NativeError("Noncanonical placeholder identity")
    return {"version": version, "root_id": root_id, "file_id": file_id,
            "archive_sha256": archive_sha}


def _absolute(path) -> str:
    try:
        text = os.fspath(path)
    except TypeError as exc:
        raise NativeError("Expected a filesystem path") from exc
    if not isinstance(text, str) or not text or "\x00" in text:
        raise NativeError("Invalid filesystem path")
    return os.path.abspath(text)


def _cloud_stat(info) -> bool:
    tag = getattr(info, "st_reparse_tag", 0)
    attrs = getattr(info, "st_file_attributes", 0)
    # Cloud Files disguises its reparse tag (reads as 0) for threads not in
    # expose mode, e.g. a provider's callback threads see the sync root as
    # REPARSE_POINT + tag 0. Junctions/symlinks always report their real tag.
    disguised = bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT) and tag == 0
    return bool(attrs & _CLOUD_ATTRIBUTES or disguised or (tag & 0xFFFF0FFF) == 0x9000001A)


_LINK_NOTE = "Non-cloud link/reparse ancestry"


def _metadata_chain(path: str) -> tuple[list[tuple[str, object]], PathState | None]:
    """lstat only: neither marker nor project contents are ever opened/read.

    Scan ALL ancestors before native lookup, including for a nonexistent leaf.
    A marker's mere presence protects its directory even if corrupt or a link.
    Non-cloud reparse points and inaccessible ancestry are ambiguous, not ordinary.
    """
    chain = []
    current = path
    while True:
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            info = None
        except OSError as exc:
            return chain, PathState("unknown", path, note=f"Cannot inspect ancestry: {exc}")
        if info is not None:
            attrs = getattr(info, "st_file_attributes", 0)
            if stat.S_ISLNK(info.st_mode) or (attrs & FILE_ATTRIBUTE_REPARSE_POINT and not _cloud_stat(info)):
                return chain, PathState("unknown", path, note=_LINK_NOTE)
            chain.append((current, info))
            if stat.S_ISDIR(info.st_mode):
                try:
                    os.lstat(os.path.join(current, STORE_MARKER))
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    return chain, PathState("unknown", path, note=f"Cannot exclude store marker: {exc}")
                else:
                    return chain, PathState("store", path, root_path=current,
                                            note="Durable native-store marker present (contents not read)")
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return chain, None


def _covers(ranges: list[tuple[int, int]], size: int) -> bool:
    # Empty-file readiness is a separate live-native EOF gate, not vacuous truth.
    if size <= 0:
        return False
    end = 0
    for offset, length in sorted(ranges):
        if offset < 0 or length <= 0 or offset + length > (1 << 63) - 1:
            raise NativeError("Malformed placeholder ranges")
        if offset > end:
            return False
        end = max(end, offset + length)
    return end >= size


def _inside(path: str, root: str) -> bool:
    mod = ntpath if ntpath.splitdrive(root)[0] else os.path
    try:
        return mod.normcase(mod.commonpath((path, root))) == mod.normcase(mod.normpath(root))
    except ValueError:
        return False


def _copy_request(event: str, info: CF_CALLBACK_INFO, params: CF_CALLBACK_PARAMETERS) -> Request:
    if info.StructSize < 152:
        raise NativeError("Unsupported callback-info ABI (RequestKey absent)")
    if event == "fetch":
        member, minimum = params.FetchData, 64
        offset, length = member.RequiredFileOffset, member.RequiredLength
    elif event == "validate":
        member, minimum = params.ValidateData, 32
        offset, length = member.RequiredFileOffset, member.RequiredLength
    elif event == "cancel":
        member, minimum = params.Cancel, 32
        offset, length = member.FetchData.FileOffset, member.FetchData.Length
    else:
        raise NativeError("Unsupported callback type")
    if params.ParamSize < minimum:
        raise NativeError("Truncated callback parameters")
    if not 0 < info.FileIdentityLength <= _MAX_IDENTITY or not info.FileIdentity:
        raise NativeError("Missing/bounded placeholder callback identity")
    identity = C.string_at(info.FileIdentity, info.FileIdentityLength)
    decode_file_identity(identity)
    normalized = info.NormalizedPath
    if not normalized or "\x00" in normalized:
        raise NativeError("Missing callback path")
    if not ntpath.splitdrive(normalized)[0]:
        volume = info.VolumeDosName or info.VolumeGuidName
        if not volume:
            raise NativeError("Missing callback volume")
        normalized = volume.rstrip("\\") + "\\" + normalized.lstrip("\\")
    if info.FileSize < 0 or offset < 0 or length < CF_EOF:
        raise NativeError("Invalid callback range/size")
    return Request(event, str(normalized), bytes(identity), int(info.ConnectionKey),
                   int(info.TransferKey), int(info.RequestKey), int(offset), int(length),
                   int(info.FileSize), int(member.Flags))


@dataclass
class Connection:
    root: str
    identity: bytes
    root_id: str
    key: int = 0
    callbacks: list = field(default_factory=list)
    table: object = None
    errors: list[str] = field(default_factory=list)
    closing: bool = False
    active: int = 0
    condition: threading.Condition = field(default_factory=threading.Condition)


class WindowsCfApi:
    """Lazy API. test_mode is ONLY for explicitly authorized synthetic roots.

    The adapter accepts injected DLL objects to test signatures/values. This
    never bypasses the production release gate. Passing test_mode=True does not
    prove the native gates and limits mutation to burpzip-native-test-* folders
    underneath tempfile.gettempdir(). No destructor performs native cleanup.
    """

    def __init__(self, *, test_mode: bool = False, cfapi=None, kernel32=None):
        self.test_mode = bool(test_mode)
        self._cf = cfapi
        self._kernel = kernel32
        self._bound = False
        self._connections: dict[int, Connection] = {}
        self._retained: list[Connection] = []
        self._registered: dict[str, bytes] = {}

    def ensure_supported(self, test_mode: bool = False) -> None:
        verify_abi()
        if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
            raise NativeError("Native CFAPI requires Windows x64; ordinary mode is unaffected")
        if not NATIVE_RELEASE_READY and not (self.test_mode or test_mode):
            raise NativeError("Native activation is disabled: live ABI/lifecycle/integrity gates unproved")

    def _load(self) -> None:
        if self._bound:
            return
        verify_abi()
        if self._cf is None or self._kernel is None:
            if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
                raise NativeError("Nonhydrating native queries require Windows x64")
            try:
                # LOAD_LIBRARY_SEARCH_SYSTEM32, never the cwd/archive directory.
                self._cf = C.WinDLL("CldApi.dll", use_last_error=True, winmode=0x800)
                self._kernel = C.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
            except (OSError, AttributeError) as exc:
                raise NativeError(f"Windows Cloud Files API unavailable: {exc}") from exc
        p = C.POINTER
        signatures = {
            "CfGetPlatformInfo": (HRESULT, [p(CF_PLATFORM_INFO)]),
            "CfGetSyncRootInfoByPath": (HRESULT, [C.c_wchar_p, DWORD, PVOID, DWORD, p(DWORD)]),
            "CfGetPlaceholderInfo": (HRESULT, [HANDLE, DWORD, PVOID, DWORD, p(DWORD)]),
            "CfGetPlaceholderRangeInfo": (HRESULT, [HANDLE, DWORD, LARGE_INTEGER, LARGE_INTEGER,
                                                   PVOID, DWORD, p(DWORD)]),
            "CfGetPlaceholderStateFromAttributeTag": (DWORD, [DWORD, DWORD]),
            "CfRegisterSyncRoot": (HRESULT, [C.c_wchar_p, p(CF_SYNC_REGISTRATION), p(CF_SYNC_POLICIES), DWORD]),
            "CfCreatePlaceholders": (HRESULT, [C.c_wchar_p, p(CF_PLACEHOLDER_CREATE_INFO), DWORD, DWORD, p(DWORD)]),
            "CfConnectSyncRoot": (HRESULT, [C.c_wchar_p, p(CF_CALLBACK_REGISTRATION), PVOID, DWORD, p(CF_CONNECTION_KEY)]),
            "CfDisconnectSyncRoot": (HRESULT, [CF_CONNECTION_KEY]),
            "CfExecute": (HRESULT, [p(CF_OPERATION_INFO), p(CF_OPERATION_PARAMETERS)]),
            "CfReportProviderProgress": (HRESULT, [CF_CONNECTION_KEY, CF_TRANSFER_KEY, LARGE_INTEGER, LARGE_INTEGER]),
            "CfHydratePlaceholder": (HRESULT, [HANDLE, LARGE_INTEGER, LARGE_INTEGER, DWORD, PVOID]),
            "CfRevertPlaceholder": (HRESULT, [HANDLE, DWORD, PVOID]),
            "CfOpenFileWithOplock": (HRESULT, [C.c_wchar_p, DWORD, p(HANDLE)]),
            "CfReferenceProtectedHandle": (C.c_ubyte, [HANDLE]),
            "CfGetWin32HandleFromProtectedHandle": (HANDLE, [HANDLE]),
            "CfReleaseProtectedHandle": (None, [HANDLE]),
            "CfCloseHandle": (None, [HANDLE]),
            "CfUpdatePlaceholder": (HRESULT, [HANDLE, p(CF_FS_METADATA), PVOID, DWORD, p(CF_FILE_RANGE),
                                              DWORD, DWORD, PVOID, PVOID]),
        }
        win_signatures = {
            "CreateFileW": (HANDLE, [C.c_wchar_p, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE]),
            "CloseHandle": (C.c_int32, [HANDLE]),
            "GetFileInformationByHandle": (C.c_int32, [HANDLE, p(BY_HANDLE_FILE_INFORMATION)]),
            "GetFileInformationByHandleEx": (C.c_int32, [HANDLE, DWORD, PVOID, DWORD]),
            "GetVolumePathNameW": (C.c_int32, [C.c_wchar_p, C.c_wchar_p, DWORD]),
            "GetVolumeInformationW": (C.c_int32, [C.c_wchar_p, C.c_wchar_p, DWORD, p(DWORD),
                                                 p(DWORD), p(DWORD), C.c_wchar_p, DWORD]),
        }
        try:
            for dll, items in ((self._cf, signatures), (self._kernel, win_signatures)):
                for name, (restype, args) in items.items():
                    func = getattr(dll, name)
                    func.restype, func.argtypes = restype, args
        except AttributeError as exc:
            raise NativeError(f"Required native export missing: {exc}") from exc
        self._bound = True

    def _mutation(self, path: str | None = None) -> None:
        self.ensure_supported()
        if self.test_mode and path is not None:
            absolute = _absolute(path)
            temp = _absolute(tempfile.gettempdir())
            if not _inside(absolute, temp) or absolute == temp:
                raise NativeError("Test mutation requires a dedicated synthetic tempfile root")
            relative = os.path.relpath(absolute, temp)
            if not relative.split(os.sep)[0].startswith("burpzip-native-test-"):
                raise NativeError("Test root must be named burpzip-native-test-* under the temporary directory")
        self._load()

    @contextmanager
    def _metadata_handle(self, path: str):
        self._load()
        # READ_ATTRIBUTES only, SHARE_READ|WRITE|DELETE, OPEN_REPARSE_POINT:
        # no READ_DATA, no oplock, no ordinary content read, no hydration.
        handle = self._kernel.CreateFileW(path, 0x80, 7, None, 3, 0x02000000 | 0x00200000, None)
        if hasattr(handle, "value"):
            handle = handle.value
        if handle in (None, 0, _INVALID_HANDLE):
            raise NativeError(f"Cannot open nonhydrating metadata handle: {path}")
        try:
            yield handle
        except BaseException:
            self._kernel.CloseHandle(handle)  # Never mask the original error.
            raise
        if not self._kernel.CloseHandle(handle):
            raise NativeError("Metadata CloseHandle failed")

    def _handle_info(self, handle) -> BY_HANDLE_FILE_INFORMATION:
        info = BY_HANDLE_FILE_INFORMATION()
        if not self._kernel.GetFileInformationByHandle(handle, C.byref(info)):
            raise NativeError("GetFileInformationByHandle failed")
        return info

    @staticmethod
    def _os_id(info: BY_HANDLE_FILE_INFORMATION) -> str:
        ident = (int(info.FileIndexHigh) << 32) | int(info.FileIndexLow)
        if not ident:
            raise NativeError("Zero OS file identity")
        return f"{info.VolumeSerialNumber:08x}:{ident:016x}"

    def file_id(self, path) -> str:
        absolute = _absolute(path)
        _, protected = _metadata_chain(absolute)
        if protected is not None and protected.kind != "store":
            raise NativeError(protected.note)
        with self._metadata_handle(absolute) as handle:
            return self._os_id(self._handle_info(handle))

    def _query(self, call, operation: str, initial: int = 8192) -> tuple[object, int]:
        capacity = initial
        while capacity <= _MAX_QUERY:
            buffer = C.create_string_buffer(capacity)
            returned = DWORD()
            hr = int(call(buffer, capacity, C.byref(returned))) & 0xFFFFFFFF
            if hr in (_hr_win32(ERROR_MORE_DATA), _hr_win32(ERROR_INSUFFICIENT_BUFFER)):
                capacity = max(capacity * 2, int(returned.value))
                continue
            _check_hr(hr, operation)
            if returned.value > capacity:
                raise NativeError(f"{operation}: invalid returned length")
            return buffer, int(returned.value)
        raise NativeError(f"{operation}: bounded metadata query exceeded")

    def inspect_root(self, path) -> dict | None:
        absolute = _absolute(path)
        chain, protected = _metadata_chain(absolute)
        if protected is not None:
            raise NativeError(protected.note)
        if not chain:
            raise NativeError("No existing ancestor for root inspection")
        self._load()
        candidate = chain[0][0]
        buffer = C.create_string_buffer(8192)
        returned = DWORD()
        hr = int(self._cf.CfGetSyncRootInfoByPath(candidate, CF_SYNC_ROOT_INFO_STANDARD,
                                                 buffer, len(buffer), C.byref(returned))) & 0xFFFFFFFF
        if hr in (_hr_win32(ERROR_NOT_A_CLOUD_SYNC_ROOT), _hr_win32(ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT)):
            if any(_cloud_stat(s) for _, s in chain):
                raise NativeError("Cloud attributes without a resolvable sync root")
            return None
        if hr in (_hr_win32(ERROR_MORE_DATA), _hr_win32(ERROR_INSUFFICIENT_BUFFER)):
            buffer, count = self._query(
                lambda b, n, r: self._cf.CfGetSyncRootInfoByPath(candidate, CF_SYNC_ROOT_INFO_STANDARD, b, n, r),
                "CfGetSyncRootInfoByPath")
        else:
            _check_hr(hr, "CfGetSyncRootInfoByPath")
            count = int(returned.value)
        tail = CF_SYNC_ROOT_STANDARD_INFO.SyncRootIdentity.offset
        if not tail <= count <= len(buffer):
            raise NativeError("Truncated sync-root metadata")
        info = C.cast(buffer, C.POINTER(CF_SYNC_ROOT_STANDARD_INFO)).contents
        length = int(info.SyncRootIdentityLength)
        if length > _MAX_ROOT_IDENTITY or tail + length > count:
            raise NativeError("Invalid sync-root identity length")
        identity = bytes(buffer.raw[tail:tail + length])
        root_path, root_file_id = None, None
        root_os_id = int(info.SyncRootFileId) & 0xFFFFFFFFFFFFFFFF
        for ancestor, metadata in chain:
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            observed = self.file_id(ancestor)
            if int(observed.split(":")[1], 16) == root_os_id:
                root_path, root_file_id = ancestor, observed
                break
        if root_path is None:
            raise NativeError("Cannot anchor sync root to its OS directory identity")
        owned = None
        if identity.startswith(_ROOT_MAGIC):
            owned = decode_root_identity(identity)
            if owned["root_file_id"] != root_file_id:
                raise NativeError("Root ownership/OS volume-file identity mismatch")
        return {"root_path": root_path, "root_id": owned["root_id"] if owned else None,
                "root_file_id": root_file_id, "file_id": root_file_id, "identity": identity,
                "owned": owned is not None,
                "policies": {"hydration": int(info.HydrationPolicy.Primary),
                             "hydration_modifier": int(info.HydrationPolicy.Modifier),
                             "population": int(info.PopulationPolicy.Primary),
                             "hardlink": int(info.HardLinkPolicy)}}

    def _ranges(self, handle, info_class: int, size: int) -> list[tuple[int, int]]:
        if size <= 0:
            return []
        buffer, count = self._query(
            lambda b, n, r: self._cf.CfGetPlaceholderRangeInfo(handle, info_class,
                                                              LARGE_INTEGER(0), LARGE_INTEGER(CF_EOF), b, n, r),
            "CfGetPlaceholderRangeInfo")
        if count % 16:
            raise NativeError("Truncated placeholder range entry")
        ranges = []
        for pos in range(0, count, 16):
            offset, length = struct.unpack_from("<qq", buffer.raw, pos)
            if offset < 0 or length <= 0 or offset + length > (1 << 63) - 1:
                raise NativeError("Invalid placeholder range")
            ranges.append((offset, length))
        return ranges

    def inspect(self, path) -> PathState:
        absolute = _absolute(path)
        chain, protected = _metadata_chain(absolute)
        if protected is not None:
            return protected
        root = self.inspect_root(absolute)
        if root is None:
            return PathState("ordinary", absolute, note="No cloud sync root")
        state = PathState("native" if root["owned"] else "cloud", absolute,
                          root_path=root["root_path"], root_id=root["root_id"],
                          note="Owned sync root" if root["owned"] else "Foreign cloud sync root")
        if not chain or chain[0][0] != absolute:
            state.note += "; nonexistent leaf protected by ancestry"
            return state
        if os.path.normcase(absolute) == os.path.normcase(root["root_path"]):
            # The sync-root folder itself answers CfGetPlaceholderInfo too, but
            # it carries the ROOT identity, not a file placeholder identity.
            state.file_id = root["root_file_id"]
            state.note += " folder"
            return state
        with self._metadata_handle(absolute) as handle:
            before = self._handle_info(handle)
            state.file_id = self._os_id(before)
            write = (int(before.LastWriteTime.High) << 32) | int(before.LastWriteTime.Low)
            state.mtime = write / 10_000_000 - 11644473600 if write else 0.0
            state.size = (int(before.FileSizeHigh) << 32) | int(before.FileSizeLow)
            tag = FILE_ATTRIBUTE_TAG_INFO()
            if not self._kernel.GetFileInformationByHandleEx(handle, 9, C.byref(tag), C.sizeof(tag)):
                raise NativeError("FileAttributeTagInfo query failed")
            bits = int(self._cf.CfGetPlaceholderStateFromAttributeTag(tag.FileAttributes, tag.ReparseTag))
            if bits == CF_PLACEHOLDER_STATE_INVALID:
                raise NativeError("Invalid cloud placeholder state")
            # Windows disguises placeholders from non-exposing processes: the
            # reparse tag reads as 0, so attribute/tag bits alone can miss one.
            # Ask Cloud Files directly; only NOT_A_CLOUD_FILE means "not one".
            if not bits & CF_PLACEHOLDER_STATE_PLACEHOLDER and self._is_placeholder(handle):
                bits |= CF_PLACEHOLDER_STATE_PLACEHOLDER
            if not bits & CF_PLACEHOLDER_STATE_PLACEHOLDER:
                # Resident ordinary/reverted children remain namespace-protected;
                # absence of placeholder identity never authorizes archive replay.
                state.modified = not bool(before.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                state.resident = state.modified
                state.note += "; no placeholder identity (ordinary/reverted namespace entry)"
                return state
            buffer, count = self._query(
                lambda b, n, r: self._cf.CfGetPlaceholderInfo(handle, CF_PLACEHOLDER_INFO_STANDARD, b, n, r),
                "CfGetPlaceholderInfo")
            tail = CF_PLACEHOLDER_STANDARD_INFO.FileIdentity.offset
            if count < tail:
                raise NativeError("Truncated placeholder metadata")
            info = C.cast(buffer, C.POINTER(CF_PLACEHOLDER_STANDARD_INFO)).contents
            length = int(info.FileIdentityLength)
            if length > _MAX_IDENTITY or tail + length > count:
                raise NativeError("Invalid placeholder identity length")
            state.identity = bytes(buffer.raw[tail:tail + length])
            if (int(info.FileId) & 0xFFFFFFFFFFFFFFFF) != int(state.file_id.split(":")[1], 16):
                raise NativeError("Placeholder/OS file identity mismatch")
            if (int(info.SyncRootFileId) & 0xFFFFFFFFFFFFFFFF) != int(root["root_file_id"].split(":")[1], 16):
                raise NativeError("Placeholder/root identity mismatch")
            if root["owned"]:
                decoded = decode_file_identity(state.identity)
                if decoded["root_id"] != root["root_id"]:
                    raise NativeError("Placeholder belongs to a different native root")
            if any(value < 0 for value in (info.OnDiskDataSize, info.ValidatedDataSize, info.ModifiedDataSize)):
                raise NativeError("Negative placeholder data counters")
            ondisk = self._ranges(handle, CF_PLACEHOLDER_RANGE_INFO_ONDISK, state.size)
            validated = self._ranges(handle, CF_PLACEHOLDER_RANGE_INFO_VALIDATED, state.size)
            modified = self._ranges(handle, CF_PLACEHOLDER_RANGE_INFO_MODIFIED, state.size)
            state.modified = bool(info.ModifiedDataSize or modified or info.InSyncState != 1)
            state.resident = bool(not before.FileAttributes & FILE_ATTRIBUTE_DIRECTORY
                                  and _covers(ondisk, state.size)
                                  and not bits & (CF_PLACEHOLDER_STATE_PARTIAL
                                                  | CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK))
            state.ready = state.resident and _covers(validated, state.size)
            after = self._handle_info(handle)
            if (self._os_id(after), after.FileSizeHigh, after.FileSizeLow,
                after.LastWriteTime.Low, after.LastWriteTime.High) != (
                    state.file_id, before.FileSizeHigh, before.FileSizeLow,
                    before.LastWriteTime.Low, before.LastWriteTime.High):
                raise NativeError("File identity/size/write indicator changed during inspection")
            if state.size == 0:
                state.note += "; empty-file readiness remains live-native gated"
        return state

    def _is_placeholder(self, handle) -> bool:
        probe = C.create_string_buffer(C.sizeof(CF_PLACEHOLDER_STANDARD_INFO))
        returned = DWORD()
        hr = int(self._cf.CfGetPlaceholderInfo(handle, CF_PLACEHOLDER_INFO_STANDARD, probe, len(probe),
                                               C.byref(returned))) & 0xFFFFFFFF
        if hr == _hr_win32(ERROR_NOT_A_CLOUD_FILE):
            return False
        if hr in (0, _hr_win32(ERROR_MORE_DATA), _hr_win32(ERROR_INSUFFICIENT_BUFFER)):
            return True
        _check_hr(hr, "CfGetPlaceholderInfo probe")
        return True

    def _owned_root(self, root) -> dict:
        found = self.inspect_root(root)
        if not found or not found["owned"] or os.path.normcase(found["root_path"]) != os.path.normcase(_absolute(root)):
            raise NativeError("Operation requires the exact owned sync root")
        if found["policies"] != {"hydration": 2, "hydration_modifier": 1, "population": 3, "hardlink": 0}:
            raise NativeError("Owned-root policies differ from the checked v1 contract")
        return found

    def _require_ntfs(self, root: str) -> None:
        volume, fs = C.create_unicode_buffer(32768), C.create_unicode_buffer(64)
        if not self._kernel.GetVolumePathNameW(root, volume, len(volume)):
            raise NativeError("Cannot determine root volume")
        if not self._kernel.GetVolumeInformationW(volume.value, None, 0, None, None, None, fs, len(fs)):
            raise NativeError("Cannot inspect root filesystem")
        if fs.value.upper() != "NTFS":
            raise NativeError("Prototype root requires local NTFS")
        if root.startswith("\\\\"):
            raise NativeError("UNC/network sync roots are unsupported")

    def register(self, root, identity: bytes) -> None:
        absolute = _absolute(root)
        self._mutation(absolute)
        decoded = decode_root_identity(identity)
        chain, protected = _metadata_chain(absolute)
        if protected is not None or not chain or chain[0][0] != absolute or not stat.S_ISDIR(chain[0][1].st_mode):
            raise NativeError("Registration requires a new empty ordinary directory")
        if self.inspect_root(absolute) is not None:
            raise NativeError("Directory is already under a cloud sync root")
        with os.scandir(absolute) as entries:
            if next(entries, None) is not None:
                raise NativeError("Registration requires an empty directory")
        actual_id = self.file_id(absolute)
        if decoded["root_file_id"] != actual_id:
            raise NativeError("Registration identity does not match root OS identity")
        self._require_ntfs(absolute)
        blob = C.create_string_buffer(identity)
        registration = CF_SYNC_REGISTRATION()
        registration.StructSize = C.sizeof(registration)
        registration.ProviderName = "Burpzip Native Prototype"
        registration.ProviderVersion = "1"
        registration.SyncRootIdentity = C.cast(blob, PVOID)
        registration.SyncRootIdentityLength = len(identity)
        # Stable ProviderId is telemetry only, NEVER an ownership credential.
        registration.ProviderId = GUID.from_buffer_copy(uuid.UUID("8b4a76b7-2d55-4825-a5f4-f2b6e616f350").bytes_le)
        policies = CF_SYNC_POLICIES()
        policies.StructSize = C.sizeof(policies)
        policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL
        policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED
        policies.Population.Primary = CF_POPULATION_POLICY_ALWAYS_FULL
        policies.InSync = 0x00FFFFFF  # TRACK_ALL; never PRESERVE_INSYNC_FOR_SYNC_ENGINE.
        _check_hr(self._cf.CfRegisterSyncRoot(absolute, C.byref(registration), C.byref(policies), 0),
                  "CfRegisterSyncRoot")
        self._registered[absolute] = bytes(identity)
        # Never unregister after uncertain success/postcondition failure.
        observed = self._owned_root(absolute)
        if observed["identity"] != identity or self.file_id(absolute) != actual_id:
            raise NativeError("Registration postcondition failed; registration retained")

    def create(self, root, name: str, size: int, mtime: float, identity: bytes) -> str:
        absolute = _absolute(root)
        self._mutation(absolute)
        found = self._owned_root(absolute)
        decoded = decode_file_identity(identity)
        if decoded["root_id"] != found["root_id"]:
            raise NativeError("Placeholder identity/root mismatch")
        if (not isinstance(name, str) or not name or name in (".", "..")
                or any(char in name for char in '\\/:\x00<>"|?*') or name.endswith((".", " "))
                or name.lower().split(".")[0] in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
                or not name.lower().endswith(".burp")):
            raise NativeError("Placeholder requires a safe flat .burp filename")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size < 1 << 63:
            raise NativeError("Invalid placeholder size")
        if not isinstance(mtime, (int, float)) or isinstance(mtime, bool) or not math.isfinite(mtime):
            raise NativeError("Invalid placeholder modification time")
        stamp = int((mtime + 11644473600) * 10000000)
        if not 0 < stamp < 1 << 63:
            raise NativeError("Modification time outside supported FILETIME range")
        target = os.path.join(absolute, name)
        if os.path.lexists(target):
            raise NativeError("Placeholder destination already exists")
        blob = C.create_string_buffer(identity)
        item = CF_PLACEHOLDER_CREATE_INFO()
        item.RelativeFileName = name
        item.FsMetadata.FileSize = size
        item.FsMetadata.BasicInfo.FileAttributes = 0x80  # NORMAL, never a directory.
        item.FsMetadata.BasicInfo.LastWriteTime = stamp
        item.FsMetadata.BasicInfo.CreationTime = stamp
        item.FsMetadata.BasicInfo.LastAccessTime = stamp
        item.FsMetadata.BasicInfo.ChangeTime = stamp
        item.FileIdentity = C.cast(blob, PVOID)
        item.FileIdentityLength = len(identity)
        item.Flags = CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
        item.Result = C.c_int32(0x80004005).value  # Catch success without per-entry output.
        processed = DWORD()
        _check_hr(self._cf.CfCreatePlaceholders(absolute, C.byref(item), 1, CF_CREATE_FLAG_STOP_ON_ERROR,
                                               C.byref(processed)), "CfCreatePlaceholders")
        if processed.value != 1:
            raise NativeError("Placeholder was not processed; preserve recovery state")
        _check_hr(item.Result, "CfCreatePlaceholders entry")
        observed = self.inspect(target)
        if observed.kind != "native" or observed.identity != identity or observed.size != size or not observed.file_id:
            raise NativeError("Placeholder creation postcondition failed; preserve recovery state")
        if self.file_id(absolute) != found["root_file_id"]:
            raise NativeError("Root replaced during placeholder creation")
        return observed.file_id

    def connect(self, root, on_request_callable) -> Connection:
        absolute = _absolute(root)
        self._mutation(absolute)
        found = self._owned_root(absolute)
        if not callable(on_request_callable):
            raise NativeError("A callback handler is required")
        connection = Connection(absolute, found["identity"], found["root_id"])
        for event in ("fetch", "validate", "cancel"):
            def dispatch(info_pointer, params_pointer, event=event):
                request = None
                with connection.condition:
                    connection.active += 1
                try:
                    if not info_pointer or not params_pointer:
                        raise NativeError("Null native callback metadata")
                    info = info_pointer.contents
                    # Check the header before accessing any later native fields.
                    if info.StructSize < 152:
                        raise NativeError("Unsupported native callback-info version")
                    if (info.SyncRootIdentityLength != len(connection.identity)
                            or not info.SyncRootIdentity
                            or C.string_at(info.SyncRootIdentity, info.SyncRootIdentityLength) != connection.identity):
                        raise NativeError("Callback root ownership mismatch")
                    request = _copy_request(event, info, params_pointer.contents)
                    if not _inside(request.path, connection.root):
                        raise NativeError("Callback escaped registered root")
                    if decode_file_identity(request.identity)["root_id"] != connection.root_id:
                        raise NativeError("Callback placeholder/root mismatch")
                    with connection.condition:
                        if not connection.key and not connection.closing:
                            connection.key = request.connection
                            self._connections.setdefault(request.connection, connection)
                    if not connection.closing:
                        on_request_callable(request)
                except BaseException as exc:
                    # ctypes callbacks must NEVER propagate Python exceptions.
                    with connection.condition:
                        connection.errors.append(f"{type(exc).__name__}: {exc}")
                        del connection.errors[:-32]
                    if request is not None and not connection.closing:
                        try:
                            self.fail(request, STATUS_CLOUD_FILE_UNSUCCESSFUL)
                        except BaseException:
                            pass  # Native failure already retained; callback cannot throw.
                finally:
                    with connection.condition:
                        connection.active -= 1
                        connection.condition.notify_all()
            connection.callbacks.append(CF_CALLBACK(dispatch))
        table = (CF_CALLBACK_REGISTRATION * 4)()
        for index, typ in enumerate((0, 1, 2)):
            table[index].Type = typ
            table[index].Callback = connection.callbacks[index]
        table[3].Type = CF_CALLBACK_TYPE_NONE
        table[3].Callback = CF_CALLBACK()
        connection.table = table
        self._retained.append(connection)  # Retain even if native connect fails ambiguously.
        key = CF_CONNECTION_KEY()
        _check_hr(self._cf.CfConnectSyncRoot(absolute, table, None,
                                            CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH | CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
                                            C.byref(key)), "CfConnectSyncRoot")
        with connection.condition:
            adopted = connection.key
            connection.key = int(key.value)
            if not connection.key or (adopted and adopted != connection.key)                     or self._connections.get(connection.key, connection) is not connection:
                raise NativeError("Invalid/duplicate native connection key; callbacks retained")
            self._connections[connection.key] = connection
        return connection

    def disconnect(self, connection: Connection) -> None:
        self._mutation(connection.root)
        if self._connections.get(connection.key) is not connection:
            raise NativeError("Unknown native connection")
        connection.closing = True
        try:
            _check_hr(self._cf.CfDisconnectSyncRoot(CF_CONNECTION_KEY(connection.key)), "CfDisconnectSyncRoot")
        except BaseException:
            connection.closing = False
            raise
        with connection.condition:
            drained = connection.condition.wait_for(lambda: connection.active == 0, timeout=5.0)
        if not drained:
            raise NativeError("Native callbacks have not drained; references retained")
        del self._connections[connection.key]
        self._retained.remove(connection)
        # Caller still strongly owns connection and its table/callbacks. No
        # unregister, deletion, dehydration or clearing ALWAYS_FULL occurs here.

    def _request(self, request: Request) -> Connection:
        if not isinstance(request, Request) or request.event not in ("fetch", "validate"):
            raise NativeError("Cannot operate on a canceled/unknown request")
        connection = self._connections.get(_signed64(request.connection))
        if connection is None or connection.closing:
            raise NativeError("Request has no live owned native connection")
        self._mutation(connection.root)
        if not _inside(request.path, connection.root):
            raise NativeError("Request path escaped its root")
        if decode_file_identity(request.identity)["root_id"] != connection.root_id:
            raise NativeError("Request identity/root mismatch")
        _signed64(request.transfer)
        _signed64(request.request_key)
        return connection

    @staticmethod
    def _range(request: Request, offset: int, length: int, *, eof: bool = False) -> None:
        if (not isinstance(offset, int) or isinstance(offset, bool)
                or not isinstance(length, int) or isinstance(length, bool)
                or not 0 <= offset < 1 << 63 or request.file_size < 0):
            raise NativeError("Invalid native operation range")
        if eof and length == CF_EOF:
            if offset % 4096:
                raise NativeError("Native EOF range offset must be 4KiB aligned")
            return
        if length <= 0 or offset + length > request.file_size or offset + length >= 1 << 63:
            raise NativeError("Native operation must cover existing bytes without resizing")
        if offset % 4096 or (length % 4096 and offset + length != request.file_size):
            raise NativeError("Native range must be 4KiB aligned except exact EOF")

    def _execute(self, request: Request, typ: int, member: str, params: CF_OPERATION_PARAMETERS) -> None:
        self._request(request)
        info = CF_OPERATION_INFO()
        info.StructSize = C.sizeof(info)
        info.Type = typ
        info.ConnectionKey = _signed64(request.connection)
        info.TransferKey = _signed64(request.transfer)
        info.RequestKey = _signed64(request.request_key)
        # ParamSize is the chosen member's end, NOT sizeof the complete union.
        params.ParamSize = CF_OPERATION_PARAMETERS.Data.offset + C.sizeof(getattr(params, member))
        _check_hr(self._cf.CfExecute(C.byref(info), C.byref(params)), "CfExecute")

    def transfer(self, request: Request, offset: int, data: bytes) -> None:
        if not isinstance(data, bytes) or not 0 < len(data) <= _MAX_CHUNK:
            raise NativeError("Transfer requires a bounded nonempty bytes chunk")
        self._range(request, offset, len(data))
        buffer = C.create_string_buffer(data)
        params = CF_OPERATION_PARAMETERS()
        params.TransferData.Buffer = C.cast(buffer, PVOID)
        params.TransferData.Offset = offset
        params.TransferData.Length = len(data)
        self._execute(request, CF_OPERATION_TYPE_TRANSFER_DATA, "TransferData", params)

    def retrieve(self, request: Request, offset: int, length: int) -> bytes:
        """RETRIEVE_DATA reads persisted, transferred bytes BEFORE positive ACK.

        Microsoft documents fetch OR validate contexts. The provider owns the
        whole-file integrity/journal ordering; this never opens READ_DATA on the
        blocked placeholder and never ACKs, marks in-sync, or replays an archive.
        """
        self._range(request, offset, length)
        if length > _MAX_CHUNK:
            raise NativeError("Retrieve chunk exceeds bounded buffer")
        buffer = C.create_string_buffer(length)
        params = CF_OPERATION_PARAMETERS()
        params.RetrieveData.Buffer = C.cast(buffer, PVOID)
        params.RetrieveData.Offset = offset
        params.RetrieveData.Length = length
        params.RetrieveData.ReturnedLength = -1
        self._execute(request, CF_OPERATION_TYPE_RETRIEVE_DATA, "RetrieveData", params)
        if params.RetrieveData.ReturnedLength != length:
            raise NativeError("Persisted retrieval returned a short/invalid length; do not acknowledge")
        return bytes(buffer.raw)

    def ack(self, request: Request, offset: int, length: int, status: int = 0) -> None:
        self._range(request, offset, length, eof=True)
        if not isinstance(status, int) or not -(1 << 31) <= status < 1 << 32:
            raise NativeError("Invalid operation NTSTATUS")
        params = CF_OPERATION_PARAMETERS()
        params.AckData.CompletionStatus = C.c_int32(status).value
        params.AckData.Offset = offset
        params.AckData.Length = length
        self._execute(request, CF_OPERATION_TYPE_ACK_DATA, "AckData", params)

    def fail(self, request: Request, status: int = STATUS_CLOUD_FILE_UNSUCCESSFUL) -> None:
        """Fail fetch with TRANSFER_DATA; validation with ACK_DATA; cancel is inert."""
        if request.event == "cancel":
            return
        if not isinstance(status, int) or not -(1 << 31) <= status < 1 << 32 or not (status & 0x80000000):
            raise NativeError("Failure requires a failing NTSTATUS, not HRESULT success")
        # Callback-required ranges can be unaligned. Expand to a documented
        # aligned range without touching bytes. ACK supports CF_EOF; transfer
        # does not. Empty-file failed transfer remains separately native-gated.
        offset = (request.offset // 4096) * 4096
        if request.event == "validate":
            self.ack(request, offset, CF_EOF, status)
            return
        if request.event != "fetch" or request.file_size <= 0 or offset >= request.file_size:
            raise NativeError("Empty/EOF fetch failure completion remains live-native gated")
        required_end = request.file_size if request.length == CF_EOF else request.offset + request.length
        end = min(request.file_size, ((required_end + 4095) // 4096) * 4096)
        self._range(request, offset, end - offset)
        params = CF_OPERATION_PARAMETERS()
        params.TransferData.CompletionStatus = C.c_int32(status).value
        params.TransferData.Offset = offset
        params.TransferData.Length = end - offset
        self._execute(request, CF_OPERATION_TYPE_TRANSFER_DATA, "TransferData", params)

    def progress(self, request: Request, total: int, completed: int) -> None:
        self._request(request)
        if (not isinstance(total, int) or not isinstance(completed, int)
                or isinstance(total, bool) or isinstance(completed, bool)
                or not 0 <= completed <= total < 1 << 63):
            raise NativeError("Invalid provider progress")
        _check_hr(self._cf.CfReportProviderProgress(CF_CONNECTION_KEY(_signed64(request.connection)),
                                                   CF_TRANSFER_KEY(_signed64(request.transfer)),
                                                   LARGE_INTEGER(total), LARGE_INTEGER(completed)),
                  "CfReportProviderProgress")

    @contextmanager
    def _protected(self, path: str, flags: int):
        protected = HANDLE()
        _check_hr(self._cf.CfOpenFileWithOplock(path, flags, C.byref(protected)), "CfOpenFileWithOplock")
        if not protected.value or protected.value == _INVALID_HANDLE:
            raise NativeError("Invalid protected handle")
        referenced = False
        try:
            if not self._cf.CfReferenceProtectedHandle(protected):
                raise NativeError("Protected handle reference failed/oplock broken")
            referenced = True
            borrowed = self._cf.CfGetWin32HandleFromProtectedHandle(protected)
            if hasattr(borrowed, "value"):
                borrowed = borrowed.value
            if borrowed in (None, 0, _INVALID_HANDLE):
                raise NativeError("Invalid borrowed asynchronous Win32 handle")
            # Borrowed handle is NEVER CloseHandle'd; reference pins it here.
            yield borrowed
        finally:
            if referenced:
                self._cf.CfReleaseProtectedHandle(protected)
            self._cf.CfCloseHandle(protected)

    def hydrate(self, path) -> None:
        absolute = _absolute(path)
        self._mutation(absolute)
        state = self.inspect(absolute)
        if state.kind != "native" or not state.identity or not state.file_id:
            raise NativeError("Hydration requires an owned existing placeholder")
        if state.ready or (state.resident and state.modified):
            return  # Fully on disk; current local edits are authoritative.
        if state.modified:
            raise NativeError("Cannot hydrate ambiguous modified/partial data")
        if state.size == 0:
            raise NativeError("Zero-file hydration remains live-native gated")
        # Nonexclusive foreground handle: NEVER hold an exclusive source oplock
        # across hydration or provider-needed locks. Explicit CfHydrate only.
        with self._protected(absolute, CF_OPEN_FILE_FLAG_FOREGROUND) as handle:
            if self._os_id(self._handle_info(handle)) != state.file_id:
                raise NativeError("Hydration file replaced")
            _check_hr(self._cf.CfHydratePlaceholder(handle, LARGE_INTEGER(0), LARGE_INTEGER(CF_EOF), 0, None),
                      "CfHydratePlaceholder")
        current = self.inspect(absolute)
        if current.file_id != state.file_id or current.identity != state.identity or not current.ready:
            raise NativeError("Hydration readiness postcondition failed")

    def revert(self, path) -> None:
        absolute = _absolute(path)
        self._mutation(absolute)
        state = self.inspect(absolute)
        if state.kind != "native" or not state.identity or not state.file_id or not state.resident:
            raise NativeError("Reversion requires a fully resident native placeholder")
        # Preserve local edits; readiness, not the import hash, authorizes revert.
        with self._protected(absolute, CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS) as handle:
            info = self._handle_info(handle)
            if self._os_id(info) != state.file_id or ((int(info.FileSizeHigh) << 32) | int(info.FileSizeLow)) != state.size:
                raise NativeError("Reversion source replaced/changed")
            _check_hr(self._cf.CfRevertPlaceholder(handle, 0, None), "CfRevertPlaceholder")
        current = self.inspect(absolute)
        if current.file_id != state.file_id or current.size != state.size or current.identity:
            raise NativeError("Reversion postcondition failed; registration retained")

    @contextmanager
    def locked_snapshot(self, path, expected_file_id: str):
        """Hold a read+write handle that denies other writers/deleters.

        Yields a Snapshot whose bytes cannot change while it is open. Opening
        fails (NativeError "in use") while Burp or anything else has the file.
        Only a fully resident owned placeholder qualifies; nothing is hydrated.
        """
        import msvcrt
        absolute = _absolute(path)
        self._mutation(absolute)
        state = self.inspect(absolute)
        if state.kind != "native" or not state.identity or state.file_id != expected_file_id \
                or not state.resident:
            raise NativeError("Re-zip requires the owned, fully resident placeholder")
        handle = self._kernel.CreateFileW(absolute, 0x80000000 | 0x40000000, 1, None, 3, 0, None)
        if hasattr(handle, "value"):
            handle = handle.value
        if handle in (None, 0, _INVALID_HANDLE):
            error = C.get_last_error()
            raise NativeError("Project is in use (open in Burp?)" if error == 32
                              else f"Cannot lock project for re-zip (WinError {error})")
        try:
            info = self._handle_info(handle)
            if self._os_id(info) != expected_file_id:
                raise NativeError("Project file was replaced")
            size = (int(info.FileSizeHigh) << 32) | int(info.FileSizeLow)
            write = (int(info.LastWriteTime.High) << 32) | int(info.LastWriteTime.Low)
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except BaseException:
            self._kernel.CloseHandle(handle)
            raise
        snapshot = Snapshot(fd=fd, handle=handle, path=absolute, file_id=expected_file_id,
                            size=size, mtime=write / 10_000_000 - 11644473600)
        try:
            yield snapshot
        finally:
            os.close(fd)  # Closes the handle.

    def dehydrate_locked(self, snapshot: "Snapshot", identity: bytes, size: int, mtime: float) -> None:
        """Turn the locked resident file into a dehydrated placeholder of a NEW generation.

        Callers must first have stored a verified archive of exactly these bytes.
        """
        self._mutation(snapshot.path)
        decode_file_identity(identity)
        if size != snapshot.size:
            raise NativeError("Re-zip size differs from the locked snapshot")
        stamp = int((mtime + 11644473600) * 10000000)
        meta = CF_FS_METADATA()
        meta.FileSize = size
        meta.BasicInfo.FileAttributes = 0x80
        meta.BasicInfo.LastWriteTime = meta.BasicInfo.ChangeTime = stamp
        span = CF_FILE_RANGE()
        span.StartingOffset, span.Length = 0, size
        blob = C.create_string_buffer(identity)
        _check_hr(self._cf.CfUpdatePlaceholder(
            snapshot.handle, C.byref(meta), C.cast(blob, PVOID), len(identity), C.byref(span), 1,
            CF_UPDATE_FLAG_DEHYDRATE | CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_ALLOW_PARTIAL,
            None, None), "CfUpdatePlaceholder")
        state = self.inspect(snapshot.path)
        if state.identity != identity or state.resident or state.file_id != snapshot.file_id \
                or state.size != size:
            raise NativeError("Re-zip placeholder postcondition failed; new archive retained")

    def in_use(self, path) -> bool:
        """True while another process (e.g. Burp) has an owned, unpacked project open.

        DELETE-only access reads no data, so it cannot trigger hydration; Java
        opens project files without FILE_SHARE_DELETE, so an open file refuses it.
        Anything that is not an owned fully resident placeholder counts as busy.
        """
        absolute = _absolute(path)
        self._load()
        state = self.inspect(absolute)
        if state.kind != "native" or not state.identity or not state.resident:
            return True
        handle = self._kernel.CreateFileW(absolute, 0x00010000, 7, None, 3, 0, None)
        if hasattr(handle, "value"):
            handle = handle.value
        if handle in (None, 0, _INVALID_HANDLE):
            return True  # Sharing violation, or anything else: treat as busy.
        self._kernel.CloseHandle(handle)
        return False

    def set_always_full(self, path) -> bool:
        """Best effort: re-mark a fully hydrated placeholder ALWAYS_FULL."""
        absolute = _absolute(path)
        self._mutation(absolute)
        handle = self._kernel.CreateFileW(absolute, 0x80000000, 7, None, 3, 0, None)
        if hasattr(handle, "value"):
            handle = handle.value
        if handle in (None, 0, _INVALID_HANDLE):
            return False
        try:
            hr = self._cf.CfUpdatePlaceholder(handle, None, None, 0, None, 0,
                                              CF_UPDATE_FLAG_ALWAYS_FULL, None, None)
            return (int(hr) & 0x80000000) == 0
        finally:
            self._kernel.CloseHandle(handle)

    def export_current(self, path, dest) -> None:
        # No ordinary read/copy or snapshot fallback. A safe implementation needs
        # tested overlapped borrowed-handle reads, reference-per-I/O break abort,
        # stable metadata/change indicators and verified no-clobber publication.
        raise NativeError("Current-content export unavailable: protected asynchronous snapshot/oplock-break gate unproved")


def classify_path(path, *, _resolved: bool = False) -> PathState:
    """Nonhydrating ownership protection, including nonexistent descendants.

    Unsupported Windows/query failures are unknown and block ordinary actions.
    A foreign provider's hydrated file is cloud even without recall attributes.
    On non-Windows, only lstat/store/link protection is applicable; no DLL loads.
    """
    absolute = _absolute(path)
    chain, protected = _metadata_chain(absolute)
    if protected is not None and protected.note == _LINK_NOTE and not _resolved:
        # Ordinary mode historically followed junctions/mount points/directory
        # links ABOVE a project (e.g. a second disk mounted at C:\Data). Judge
        # the resolved target once. A link/reparse leaf itself stays unknown,
        # and native operations keep using the strict lexical chain.
        try:
            leaf = os.lstat(absolute)
        except FileNotFoundError:
            leaf = None
        except OSError:
            return protected
        leaf_linked = leaf is not None and (stat.S_ISLNK(leaf.st_mode) or (
            getattr(leaf, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT and not _cloud_stat(leaf)))
        if not leaf_linked:
            try:
                resolved = os.path.realpath(absolute, strict=False)
            except (OSError, ValueError):
                return protected
            if os.path.normcase(resolved) != os.path.normcase(absolute):
                state = classify_path(resolved, _resolved=True)
                return replace(state, path=absolute,
                               note=(state.note + "; " if state.note else "") + f"via link to {resolved}")
        return protected
    if protected is not None:
        return protected
    if os.name != "nt":
        if any(_cloud_stat(info) for _, info in chain):
            return PathState("unknown", absolute, note="Cloud metadata on unsupported platform")
        return PathState("ordinary", absolute)
    try:
        return WindowsCfApi().inspect(absolute)
    except (NativeError, OSError, ValueError) as exc:
        return PathState("unknown", absolute, note=str(exc))


def require_ordinary_path(path) -> None:
    state = classify_path(path)
    if state.kind != "ordinary":
        raise NativeError(f"Ordinary operation blocked for {state.kind} path {state.path}: {state.note}")
