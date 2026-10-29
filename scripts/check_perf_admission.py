"""Check one owned child's userspace perf admission; never launch a browser.

No privilege changes, retries, profiling data or arbitrary process attachment.
The disabled event is opened once and immediately closed without collecting data.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import struct
import sys


def read_paranoid() -> int | None:
    try:
        with Path('/proc/sys/kernel/perf_event_paranoid').open() as handle:
            value = handle.read(32).strip()
        return int(value) if value and len(value) < 12 else None
    except (OSError, ValueError):
        return None


def perf_open(pid: int) -> int:
    # Linux x86_64 ABI, checked before use. PERF_TYPE_SOFTWARE/page-faults.
    # Match future user-only sampling admission, but leave the event disabled.
    attr = ctypes.create_string_buffer(128)
    struct.pack_into('=IIQQQQQ', attr, 0, 1, 128, 2, 1, 15, 0, 1 | 32 | 64)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    fd = libc.syscall(ctypes.c_long(298), ctypes.byref(attr), ctypes.c_int(pid),
                      ctypes.c_int(-1), ctypes.c_int(-1), ctypes.c_ulong(8))
    if fd < 0:
        code = ctypes.get_errno()
        raise OSError(code, 'perf admission failed')
    return fd


def probe_child() -> dict:
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        # This synthetic same-UID child stays alive until the parent releases it.
        # It executes no external program and never starts Chromium.
        os.close(write_fd)
        try:
            os.read(read_fd, 1)
        finally:
            os.close(read_fd)
            os._exit(0)
    os.close(read_fd)
    try:
        try:
            fd = perf_open(pid)  # Exactly one attempt; no fallback or retry.
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                return {'status': 'permission_denied', 'errno': exc.errno}
            return {'status': 'unavailable', 'errno': exc.errno}
        else:
            os.close(fd)
            return {'status': 'admitted', 'errno': None}
    finally:
        os.close(write_fd)  # EOF releases only our child, even on open failure.
        os.waitpid(pid, 0)


def check() -> dict:
    result = {'schema_version': 1, 'perf_event_paranoid': read_paranoid(),
              'scope': 'owned_synthetic_child_userspace', 'event_disabled': True}
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        return result | {'status': 'unsupported_platform', 'errno': None}
    try:
        return result | probe_child()
    except OSError as exc:
        return result | {'status': 'probe_setup_failed', 'errno': exc.errno}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
