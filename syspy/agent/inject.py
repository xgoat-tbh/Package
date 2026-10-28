"""Process injection module (EXPERIMENTAL).

Performs CreateRemoteThread + LoadLibraryA injection.
Note: Requires the target architecture to match and a valid companion DLL path.
"""

from __future__ import annotations

import ctypes
import os

IS_WINDOWS = os.name == "nt"

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04


def inject_dll(pid: int, dll_path: str) -> bool:
    """Inject a DLL into the given process ID (experimental)."""
    if not IS_WINDOWS or not os.path.isfile(dll_path):
        return False
    kernel32 = ctypes.windll.kernel32
    dll_bytes = os.path.abspath(dll_path).encode("ascii")

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False

    try:
        remote_mem = kernel32.VirtualAllocEx(
            h_process, None, len(dll_bytes) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        if not remote_mem:
            return False

        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            h_process, remote_mem, dll_bytes, len(dll_bytes) + 1, ctypes.byref(written)
        ):
            return False

        h_loadlib = kernel32.GetProcAddress(
            kernel32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryA"
        )
        if not h_loadlib:
            return False

        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, h_loadlib, remote_mem, 0, None
        )
        if not h_thread:
            return False

        kernel32.WaitForSingleObject(h_thread, 5000)
        kernel32.CloseHandle(h_thread)
        return True
    finally:
        kernel32.CloseHandle(h_process)
