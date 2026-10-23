"""Advanced Remote Windows Filesystem operations.

Provides Windows-native drive enumeration, special folder discovery, directory
listing with attributes, safe file read/write with atomic swap and conflict
detection, recycle-bin deletion, copy/move, recursive search, and directory
change notifications (ReadDirectoryChangesW).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Optional
import zipfile

IS_WINDOWS = os.name == "nt"
MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB maximum for text editor loading
DEFAULT_LISTING_LIMIT = 5000

# --------------------------------------------------------------------------
# Windows API structures & functions
# --------------------------------------------------------------------------

if IS_WINDOWS:
    k32 = ctypes.windll.kernel32
    shell32 = ctypes.windll.shell32

    # Drive types
    DRIVE_UNKNOWN = 0
    DRIVE_NO_ROOT_DIR = 1
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_REMOTE = 4
    DRIVE_CDROM = 5
    DRIVE_RAMDISK = 6

    DRIVE_TYPE_NAMES = {
        DRIVE_UNKNOWN: "Unknown",
        DRIVE_NO_ROOT_DIR: "No Root",
        DRIVE_REMOVABLE: "Removable Drive",
        DRIVE_FIXED: "Local Disk",
        DRIVE_REMOTE: "Network Drive",
        DRIVE_CDROM: "CD/DVD Drive",
        DRIVE_RAMDISK: "RAM Disk",
    }

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_ushort),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", wintypes.LPVOID),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_MOVE = 0x0001
    FO_COPY = 0x0002
    FO_DELETE = 0x0003
    FO_RENAME = 0x0004

    FOF_MULTIDESTFILES = 0x0001
    FOF_CONFIRMMOUSE = 0x0002
    FOF_SILENT = 0x0004
    FOF_RENAMEONCOLLISION = 0x0008
    FOF_NOCONFIRMATION = 0x0010
    FOF_WANTMAPPINGHANDLE = 0x0020
    FOF_ALLOWUNDO = 0x0040          # Preserves Recycle Bin!
    FOF_FILESONLY = 0x0080
    FOF_SIMPLEPROGRESS = 0x0100
    FOF_NOCONFIRMMKDIR = 0x0200
    FOF_NOERRORUI = 0x0400
    FOF_NOCOPYSECURITYATTRIBS = 0x0800
    FOF_NORECURSION = 0x1000
    FOF_NO_CONNECTED_ELEMENTS = 0x2000
    FOF_WANTNUKEWARNING = 0x4000
    FOF_NORECURSEREPARSE = 0x8000

    # Special folders CSIDL
    CSIDL_DESKTOP = 0x0000
    CSIDL_PERSONAL = 0x0005        # Documents
    CSIDL_MYPICTURES = 0x0027
    CSIDL_MYMUSIC = 0x000d
    CSIDL_MYVIDEO = 0x000e
    CSIDL_DOWNLOADS = 0x0028      # May not be present on older Windows, fallback used


# --------------------------------------------------------------------------
# Special Folders & Quick Access
# --------------------------------------------------------------------------

def get_special_folders() -> dict[str, str]:
    """Retrieve verified paths for common Windows user directories."""
    folders: dict[str, str] = {}
    user_home = os.path.expanduser("~")

    if IS_WINDOWS:
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        shell = ctypes.windll.shell32

        def _get_csidl(csidl: int) -> str:
            if shell.SHGetFolderPathW(None, csidl, None, 0, buf) == 0:
                val = buf.value
                if val and os.path.isdir(val):
                    return val
            return ""

        desktop = _get_csidl(0x0000)
        docs = _get_csidl(0x0005)
        pics = _get_csidl(0x0027)
        music = _get_csidl(0x000d)
        videos = _get_csidl(0x000e)

        # Downloads folder: check user profile Downloads
        downloads = os.path.join(user_home, "Downloads")
        if not os.path.isdir(downloads):
            downloads = _get_csidl(0x0028)

        if desktop: folders["Desktop"] = desktop
        if docs: folders["Documents"] = docs
        if downloads and os.path.isdir(downloads): folders["Downloads"] = downloads
        if pics: folders["Pictures"] = pics
        if music: folders["Music"] = music
        if videos: folders["Videos"] = videos

    # Fallbacks
    if "Desktop" not in folders and os.path.isdir(os.path.join(user_home, "Desktop")):
        folders["Desktop"] = os.path.join(user_home, "Desktop")
    if "Documents" not in folders and os.path.isdir(os.path.join(user_home, "Documents")):
        folders["Documents"] = os.path.join(user_home, "Documents")
    if "Downloads" not in folders and os.path.isdir(os.path.join(user_home, "Downloads")):
        folders["Downloads"] = os.path.join(user_home, "Downloads")

    folders["User Profile"] = user_home
    return folders


# --------------------------------------------------------------------------
# Drive Enumeration (This PC)
# --------------------------------------------------------------------------

def list_drives() -> list[dict[str, Any]]:
    """Enumerate all logical drives with volume labels, types, and capacity."""
    drives: list[dict[str, Any]] = []

    if IS_WINDOWS:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if not (bitmask & (1 << i)):
                continue
            letter_root = f"{chr(65 + i)}:\\"
            clean_letter = f"{chr(65 + i)}:"
            dtype_code = ctypes.windll.kernel32.GetDriveTypeW(letter_root)
            type_name = DRIVE_TYPE_NAMES.get(dtype_code, "Unknown Drive")

            vol_buf = ctypes.create_unicode_buffer(261)
            fs_buf = ctypes.create_unicode_buffer(261)
            serial = ctypes.c_ulong()
            max_len = ctypes.c_ulong()
            flags = ctypes.c_ulong()

            accessible = False
            total_bytes = 0
            free_bytes = 0
            used_bytes = 0
            percent_used = 0.0

            # Suppress Windows error dialog (e.g. empty CD drive)
            old_err_mode = ctypes.windll.kernel32.SetErrorMode(0x0001)  # SEM_FAILCRITICALERRORS
            try:
                ok = ctypes.windll.kernel32.GetVolumeInformationW(
                    letter_root, vol_buf, 261, ctypes.byref(serial),
                    ctypes.byref(max_len), ctypes.byref(flags), fs_buf, 261
                )
                if ok:
                    accessible = True
                try:
                    usage = shutil.disk_usage(letter_root)
                    total_bytes = usage.total
                    free_bytes = usage.free
                    used_bytes = usage.used
                    if total_bytes > 0:
                        percent_used = round((used_bytes / total_bytes) * 100, 1)
                    accessible = True
                except (OSError, PermissionError):
                    pass
            finally:
                ctypes.windll.kernel32.SetErrorMode(old_err_mode)

            label = vol_buf.value.strip() or ("Local Disk" if dtype_code == DRIVE_FIXED else type_name)
            drives.append({
                "letter": clean_letter,
                "path": letter_root,
                "name": f"{label} ({clean_letter})",
                "label": label,
                "type": type_name,
                "drive_type": type_name,
                "type_code": dtype_code,
                "filesystem": fs_buf.value or "Unknown",
                "fs_type": fs_buf.value or "Unknown",
                "total": total_bytes,
                "free": free_bytes,
                "used": used_bytes,
                "percent": percent_used,
                "percent_used": percent_used,
                "accessible": accessible,
            })
    else:
        # Non-Windows fallback (Linux/macOS)
        root_usage = shutil.disk_usage("/")
        pct = round((root_usage.used / root_usage.total) * 100, 1) if root_usage.total else 0
        drives.append({
            "letter": "/",
            "path": "/",
            "name": "Root (/)",
            "label": "Root Filesystem",
            "type": "Root",
            "drive_type": "Root",
            "type_code": 3,
            "filesystem": "posix",
            "fs_type": "posix",
            "total": root_usage.total,
            "free": root_usage.free,
            "used": root_usage.used,
            "percent": pct,
            "percent_used": pct,
            "accessible": True,
        })

    return drives


# --------------------------------------------------------------------------
# Directory Listing
# --------------------------------------------------------------------------

def list_directory(path: str = "", limit: int = DEFAULT_LISTING_LIMIT) -> dict[str, Any]:
    """Return a comprehensive Windows-style listing of `path`.
    
    If path is empty or 'This PC', returns the drives view.
    """
    cleaned = (path or "").strip().strip('"')
    if not cleaned or cleaned.lower() in ("this pc", "this_pc", "my pc", "computer"):
        return {
            "is_this_pc": True,
            "path": "This PC",
            "parent": None,
            "drives": list_drives(),
            "special_folders": get_special_folders(),
            "items": [],
        }

    # Normalize Windows drive or folder path
    target = os.path.expanduser(cleaned)
    if IS_WINDOWS and len(target) == 2 and target[1] == ":":
        target += "\\"
    target = os.path.abspath(target)

    if not os.path.exists(target):
        return {"error": f"Path not found: {target}", "path": target, "is_this_pc": False, "items": []}
    if not os.path.isdir(target):
        return {"error": f"Not a directory: {target}", "path": target, "is_this_pc": False, "items": []}

    parent = os.path.dirname(target)
    if parent == target:  # At drive root (e.g. C:\)
        parent = "This PC"

    items: list[dict[str, Any]] = []
    total_files = 0
    total_dirs = 0
    total_size = 0

    try:
        entries = os.scandir(target)
    except PermissionError:
        return {
            "error": "Access denied. Your remote account does not have permission to view this directory.",
            "path": target,
            "parent": parent,
            "is_this_pc": False,
            "items": [],
        }
    except OSError as err:
        return {"error": str(err), "path": target, "parent": parent, "is_this_pc": False, "items": []}

    with entries:
        raw_list = []
        for entry in entries:
            raw_list.append(entry)
            if len(raw_list) >= limit:
                break

    # Sort directories first, then alphabetically case-insensitive
    raw_list.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))

    for entry in raw_list:
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
            is_symlink = entry.is_symlink()
            stat_res = entry.stat(follow_symlinks=False)
            size = 0 if is_dir else stat_res.st_size
            mod_time = int(stat_res.st_mtime)
            created_time = int(stat_res.st_ctime)

            ext = "" if is_dir else os.path.splitext(entry.name)[1].lower()
            attributes = []
            if IS_WINDOWS:
                file_attr = getattr(stat_res, "st_file_attributes", 0)
                if file_attr & 0x0001: attributes.append("R")  # Read-only
                if file_attr & 0x0002: attributes.append("H")  # Hidden
                if file_attr & 0x0004: attributes.append("S")  # System
                if file_attr & 0x0020: attributes.append("A")  # Archive

            if is_dir:
                total_dirs += 1
            else:
                total_files += 1
                total_size += size

            items.append({
                "name": entry.name,
                "path": entry.path,
                "dir": is_dir,
                "symlink": is_symlink,
                "size": size,
                "ext": ext,
                "modified": mod_time,
                "created": created_time,
                "attributes": "".join(attributes),
            })
        except (OSError, PermissionError):
            items.append({
                "name": entry.name,
                "path": os.path.join(target, entry.name),
                "dir": False,
                "symlink": False,
                "size": 0,
                "ext": os.path.splitext(entry.name)[1].lower(),
                "modified": 0,
                "created": 0,
                "attributes": "?",
            })

    return {
        "is_this_pc": False,
        "path": target,
        "parent": parent,
        "items": items,
        "total_files": total_files,
        "total_dirs": total_dirs,
        "total_size": total_size,
        "special_folders": get_special_folders(),
    }


# --------------------------------------------------------------------------
# File Metadata / Properties
# --------------------------------------------------------------------------

def get_properties(path: str) -> dict[str, Any]:
    """Retrieve in-depth Windows file/folder metadata."""
    target = os.path.abspath(os.path.expanduser(path.strip().strip('"')))
    if not os.path.exists(target):
        return {"error": f"Path not found: {target}"}

    try:
        st = os.stat(target, follow_symlinks=False)
        is_dir = stat.S_ISDIR(st.st_mode)
        ext = "" if is_dir else os.path.splitext(target)[1].lower()

        # SHA-256 for files under 20 MB
        sha = ""
        if not is_dir and st.st_size <= 20 * 1024 * 1024:
            try:
                hasher = hashlib.sha256()
                with open(target, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)
                sha = hasher.hexdigest()
            except Exception:
                sha = "(unreadable)"

        attrs = []
        if IS_WINDOWS:
            attr_mask = getattr(st, "st_file_attributes", 0)
            if attr_mask & 0x0001: attrs.append("Read-Only")
            if attr_mask & 0x0002: attrs.append("Hidden")
            if attr_mask & 0x0004: attrs.append("System")
            if attr_mask & 0x0020: attrs.append("Archive")
            if attr_mask & 0x0800: attrs.append("Compressed")
            if attr_mask & 0x4000: attrs.append("Encrypted")

        return {
            "path": target,
            "name": os.path.basename(target) or target,
            "dir": is_dir,
            "extension": ext,
            "size": st.st_size,
            "created": int(st.st_ctime),
            "modified": int(st.st_mtime),
            "accessed": int(st.st_atime),
            "attributes": attrs,
            "sha256": sha,
        }
    except Exception as err:
        return {"error": str(err), "path": target}


# --------------------------------------------------------------------------
# Remote File Editor Read & Safe Save
# --------------------------------------------------------------------------

def read_file_content(path: str, max_bytes: int = MAX_READ_BYTES) -> dict[str, Any]:
    """Read a text file with encoding detection, BOM info, and content hash."""
    target = os.path.abspath(os.path.expanduser(path.strip().strip('"')))
    if not os.path.isfile(target):
        return {"error": f"File does not exist or is a directory: {target}"}

    try:
        size = os.path.getsize(target)
        if size > max_bytes:
            return {
                "error": f"File is too large to edit in browser ({size} bytes, limit is {max_bytes} bytes).",
                "too_large": True,
                "size": size,
            }

        with open(target, "rb") as handle:
            raw = handle.read()

        sha = hashlib.sha256(raw).hexdigest()
        encoding = "utf-8"
        has_bom = False

        if raw.startswith(b"\xef\xbb\xbf"):
            encoding = "utf-8-sig"
            has_bom = True
        elif raw.startswith(b"\xff\xfe"):
            encoding = "utf-16-le"
            has_bom = True
        elif raw.startswith(b"\xfe\xff"):
            encoding = "utf-16-be"
            has_bom = True

        # Check for null bytes to prevent loading raw binary files
        if b"\x00" in raw and not encoding.startswith("utf-16"):
            return {
                "error": "This file contains binary data and cannot be safely edited as plain text.",
                "is_binary": True,
                "size": size,
            }

        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            try:
                text = raw.decode("cp1252")  # Windows-1252 fallback
                encoding = "cp1252"
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="replace")
                encoding = "utf-8 (lossy)"

        # Detect line endings
        line_ending = "\r\n" if "\r\n" in text else "\n"

        return {
            "success": True,
            "path": target,
            "name": os.path.basename(target),
            "content": text,
            "sha": sha,
            "sha256": sha,
            "size": size,
            "encoding": encoding,
            "has_bom": has_bom,
            "line_ending": line_ending,
            "modified": int(os.path.getmtime(target)),
        }
    except PermissionError:
        return {"error": "Access denied. Cannot read file."}
    except Exception as err:
        return {"error": str(err)}


def save_file_content(path: str, content: str, expected_sha: str = "",
                      encoding: str = "utf-8", line_ending: Optional[str] = None) -> dict[str, Any]:
    """Atomically write modified text content with conflict detection.
    
    If `expected_sha` is provided and the file on disk was modified by another
    process, aborts with a concurrency warning.
    """
    target = os.path.abspath(os.path.expanduser(path.strip().strip('"')))
    parent_dir = os.path.dirname(target)
    os.makedirs(parent_dir, exist_ok=True)

    # Optimistic concurrency check
    if os.path.exists(target) and expected_sha:
        try:
            with open(target, "rb") as check_f:
                current_sha = hashlib.sha256(check_f.read()).hexdigest()
            if current_sha != expected_sha:
                return {
                    "error": "Concurrency conflict: This file has changed on the remote PC since you opened it.",
                    "conflict": True,
                    "current_sha": current_sha,
                }
        except OSError:
            pass

    # Normalize line endings if requested
    text_to_save = content
    if line_ending:
        norm_ending = line_ending.upper()
        if norm_ending in ("CRLF", "\\R\\N", "\r\n"):
            text_to_save = text_to_save.replace("\r\n", "\n").replace("\n", "\r\n")
        elif norm_ending in ("LF", "\\N", "\n"):
            text_to_save = text_to_save.replace("\r\n", "\n")

    # Normalize encoding
    enc = encoding or "utf-8"
    if enc == "utf-8 (lossy)":
        enc = "utf-8"

    try:
        encoded_data = text_to_save.encode(enc, errors="replace")
    except Exception:
        encoded_data = text_to_save.encode("utf-8", errors="replace")

    # Atomic write to temporary file in the same directory, then replace
    temp_target = None
    try:
        fd, temp_target = tempfile.mkstemp(dir=parent_dir, prefix="syspy_save_", suffix=".tmp")
        with os.fdopen(fd, "wb") as tmp_f:
            tmp_f.write(encoded_data)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())

        os.replace(temp_target, target)
        new_sha = hashlib.sha256(encoded_data).hexdigest()
        return {
            "success": True,
            "path": target,
            "bytes_written": len(encoded_data),
            "sha": new_sha,
            "sha256": new_sha,
            "modified": int(os.path.getmtime(target)),
        }
    except Exception as err:
        if temp_target and os.path.exists(temp_target):
            try:
                os.remove(temp_target)
            except OSError:
                pass
        return {"error": f"Failed to save file: {err}"}


# --------------------------------------------------------------------------
# Creation, Renaming, Deletion (with Recycle Bin)
# --------------------------------------------------------------------------

def create_directory(path: str) -> dict[str, Any]:
    """Create a new directory on the remote PC."""
    raw = path.strip().strip('"').strip("'")
    if not raw:
        return {"error": "Folder path cannot be empty."}
    target = os.path.abspath(os.path.expanduser(raw))
    name = os.path.basename(target)
    if any(c in '<>:"/\\|?*' for c in name):
        return {"error": f"Folder name contains invalid characters (< > : \" / \\ | ? *): {name}"}
    try:
        if os.path.exists(target):
            return {"error": f"Folder or file already exists: {target}"}
        os.makedirs(target, exist_ok=False)
        return {"success": True, "path": target}
    except PermissionError:
        is_adm = bool(ctypes.windll.shell32.IsUserAnAdmin()) if IS_WINDOWS else False
        hint = "" if is_adm else " (Administrator rights required for protected paths like C:\\. Click 'Elevate to Admin')"
        return {"error": f"Permission denied: Access denied to '{target}'{hint}"}
    except Exception as err:
        return {"error": str(err)}


def create_file(path: str, initial_content: str = "") -> dict[str, Any]:
    """Create a new file on the remote PC."""
    raw = path.strip().strip('"').strip("'")
    if not raw:
        return {"error": "File path cannot be empty."}
    target = os.path.abspath(os.path.expanduser(raw))
    name = os.path.basename(target)
    if any(c in '<>:"/\\|?*' for c in name):
        return {"error": f"Filename contains invalid characters (< > : \" / \\ | ? *): {name}"}
    try:
        if os.path.exists(target):
            return {"error": f"File already exists: {target}"}
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="") as f:
            f.write(initial_content)
        return {"success": True, "path": target}
    except PermissionError:
        is_adm = bool(ctypes.windll.shell32.IsUserAnAdmin()) if IS_WINDOWS else False
        hint = "" if is_adm else " (Administrator rights required for protected paths like C:\\. Click 'Elevate to Admin')"
        return {"error": f"Permission denied: Access denied to '{target}'{hint}"}
    except Exception as err:
        return {"error": str(err)}


def rename_item(old_path: str, new_name: str) -> dict[str, Any]:
    """Rename a file or directory."""
    src = os.path.abspath(os.path.expanduser(old_path.strip().strip('"')))
    if not os.path.exists(src):
        return {"error": f"Source item not found: {src}"}

    # Clean new filename
    clean_name = os.path.basename(new_name.strip().strip('"'))
    if not clean_name:
        return {"error": "Invalid destination name."}

    dst = os.path.join(os.path.dirname(src), clean_name)
    if os.path.exists(dst):
        return {"error": f"An item with name '{clean_name}' already exists in this folder."}

    try:
        os.rename(src, dst)
        return {"success": True, "old_path": src, "new_path": dst}
    except Exception as err:
        return {"error": f"Rename failed: {err}"}


def delete_item(path: str, permanent: bool = False) -> dict[str, Any]:
    """Delete a file or directory. Prefers Windows Recycle Bin unless permanent=True."""
    target = os.path.abspath(os.path.expanduser(path.strip().strip('"')))
    if not os.path.exists(target):
        return {"error": f"Path not found: {target}"}

    # Safety check: prevent deleting root drives
    if IS_WINDOWS and (len(target) <= 3 and target[1:3] in (":", ":\\")):
        return {"error": "Safety violation: Cannot delete filesystem root drive."}
    if not IS_WINDOWS and target in ("/", ""):
        return {"error": "Safety violation: Cannot delete filesystem root."}

    if not permanent and IS_WINDOWS:
        try:
            # Send to Windows Recycle Bin via SHFileOperationW
            op = SHFILEOPSTRUCTW()
            op.hwnd = None
            op.wFunc = FO_DELETE
            op.pFrom = target + "\0\0"
            op.pTo = None
            op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT
            res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
            if res == 0 and not op.fAnyOperationsAborted and not os.path.exists(target):
                return {"success": True, "path": target, "recycled": True}
        except Exception:
            pass  # Fall through to permanent removal if Recycle Bin fails

    # Permanent deletion
    try:
        if os.path.isdir(target):
            shutil.rmtree(target)
        else:
            os.remove(target)
        return {"success": True, "path": target, "recycled": False}
    except Exception as err:
        return {"error": f"Deletion failed: {err}"}


def copy_or_move(sources: list[str], destination_dir: str, is_move: bool = False,
                 conflict: str = "replace", conflict_resolution: str = "") -> dict[str, Any]:
    """Copy or move multiple items to a destination directory with conflict options.
    
    conflict: 'replace' | 'skip' | 'keep_both'
    """
    if conflict_resolution:
        conflict = conflict_resolution
    dst_dir = os.path.abspath(os.path.expanduser(destination_dir.strip().strip('"')))
    if not os.path.isdir(dst_dir):
        return {"error": f"Destination directory not found: {dst_dir}"}

    results = []
    for src_raw in sources:
        src = os.path.abspath(os.path.expanduser(src_raw.strip().strip('"')))
        if not os.path.exists(src):
            results.append({"source": src, "error": "Not found"})
            continue

        base_name = os.path.basename(src)
        target_path = os.path.join(dst_dir, base_name)

        if os.path.exists(target_path):
            if conflict == "skip":
                results.append({"source": src, "skipped": True})
                continue
            elif conflict == "keep_both":
                name, ext = os.path.splitext(base_name)
                counter = 1
                while os.path.exists(target_path):
                    target_path = os.path.join(dst_dir, f"{name} ({counter}){ext}")
                    counter += 1
            elif conflict == "replace":
                try:
                    if os.path.isdir(target_path):
                        shutil.rmtree(target_path)
                    else:
                        os.remove(target_path)
                except Exception as err:
                    results.append({"source": src, "error": f"Could not replace existing: {err}"})
                    continue

        try:
            if is_move:
                shutil.move(src, target_path)
            else:
                if os.path.isdir(src):
                    shutil.copytree(src, target_path)
                else:
                    shutil.copy2(src, target_path)
            results.append({"source": src, "destination": target_path, "success": True})
        except Exception as err:
            results.append({"source": src, "error": str(err)})

    return {"success": True, "operation": "move" if is_move else "copy", "items": results}


# --------------------------------------------------------------------------
# Remote Search Engine
# --------------------------------------------------------------------------

def search_filesystem(root_path: str, query: str, max_results: int = 250,
                      match_case: bool = False) -> dict[str, Any]:
    """Case-insensitive/sensitive progressive file finder."""
    start_root = os.path.abspath(os.path.expanduser(root_path.strip().strip('"')))
    if not os.path.isdir(start_root):
        return {"error": f"Search root not found: {start_root}"}

    needle = query if match_case else query.lower()
    matches: list[dict[str, Any]] = []

    try:
        for current_dir, dirs, files in os.walk(start_root, topdown=True):
            # Exclude system/hidden heavy cache folders
            dirs[:] = [d for d in dirs if not d.startswith("$") and d not in ("node_modules", ".git")]

            for name in files + dirs:
                target_name = name if match_case else name.lower()
                if needle in target_name:
                    full_path = os.path.join(current_dir, name)
                    try:
                        st = os.stat(full_path, follow_symlinks=False)
                        matches.append({
                            "name": name,
                            "path": full_path,
                            "dir": stat.S_ISDIR(st.st_mode),
                            "size": 0 if stat.S_ISDIR(st.st_mode) else st.st_size,
                            "modified": int(st.st_mtime),
                        })
                    except (OSError, PermissionError):
                        pass

                    if len(matches) >= max_results:
                        return {"results": matches, "truncated": True, "count": len(matches)}
    except Exception as err:
        return {"error": str(err), "results": matches}

    return {"results": matches, "truncated": False, "count": len(matches)}


# --------------------------------------------------------------------------
# Streaming & Archive Helpers (Zip Downloads)
# --------------------------------------------------------------------------

def prepare_zip_download(path: str) -> str:
    """Pack a directory or file into a temp ZIP archive for download."""
    target = os.path.abspath(os.path.expanduser(path.strip().strip('"').strip("'")))
    if not os.path.exists(target):
        raise FileNotFoundError(f"Path does not exist: {target}")

    base_folder = os.path.basename(target.rstrip("\\/"))
    if not base_folder:
        base_folder = target.replace(":", "").replace("\\", "_").replace("/", "_").strip("_") or "archive"

    temp_dir = tempfile.mkdtemp(prefix="syspy_zip_")
    archive_base = os.path.join(temp_dir, base_folder)

    if os.path.isfile(target):
        zip_path = f"{archive_base}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(target, os.path.basename(target))
        return zip_path
    elif os.path.isdir(target):
        zip_path = f"{archive_base}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root_dir, _dirs, filenames in os.walk(target):
                for fname in filenames:
                    file_path = os.path.join(root_dir, fname)
                    arcname = os.path.relpath(file_path, target)
                    try:
                        zf.write(file_path, arcname)
                    except (OSError, PermissionError):
                        # Gracefully skip system-locked or inaccessible files (e.g. NTUSER.DAT, open logs)
                        continue
        return zip_path
    return target


def save_upload(destination_dir: str, filename: str, data: bytes) -> str:
    """Save uploaded binary data safely to destination directory."""
    dest = os.path.abspath(os.path.expanduser(destination_dir or "."))
    os.makedirs(dest, exist_ok=True)
    safe_filename = os.path.basename(filename) or "upload.bin"
    target_path = os.path.join(dest, safe_filename)
    with open(target_path, "wb") as handle:
        handle.write(data)
    return target_path


# --------------------------------------------------------------------------
# Legacy / Shell command wrappers
# --------------------------------------------------------------------------

def read_text(path: str) -> str:
    res = read_file_content(path)
    return res.get("content") or res.get("error", "failed to read")


def write_text(path: str, content: str) -> str:
    res = save_file_content(path, content)
    return "ok" if res.get("success") else res.get("error", "failed to write")


def make_directory(path: str) -> str:
    res = create_directory(path)
    return "ok" if res.get("success") else res.get("error", "failed to create directory")


def delete(path: str) -> str:
    res = delete_item(path, permanent=False)
    return "ok" if res.get("success") else res.get("error", "failed to delete")


def find(root: str, pattern: str) -> list[str]:
    res = search_filesystem(root, pattern)
    return [item["path"] for item in res.get("results", [])]


def zip_path(path: str) -> str:
    return prepare_zip_download(path)


